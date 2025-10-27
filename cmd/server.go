package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/censys-research/censeye-ng/pkg/censeye"
	"github.com/censys-research/censeye-ng/pkg/config"
	censys "github.com/censys/censys-sdk-go"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	socketPath   string
	wsDepth      int
	wsAtTime     string
	wsSocketPath string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run censeye-ng in server mode",
	Run:   runServer,
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type wsRequest struct {
	Host   string `json:"host"`
	Depth  int    `json:"depth"`
	AtTime string `json:"at_time,omitempty"`
}

func handleConn(ctx context.Context, ce *censeye.Censeye) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Errorf("WebSocket error: %v", err)
				}
				break
			}

			var req wsRequest
			if err := json.Unmarshal(message, &req); err != nil {
				log.Errorf("Invalid request format: %v", err)
				continue
			}

			opts := []censeye.RunOpt{censeye.WithDepth(req.Depth)}
			if strings.TrimSpace(req.AtTime) != "" {
				if parsed := parseDateString(req.AtTime); !parsed.IsZero() {
					opts = append(opts, censeye.WithAtTime(&parsed))
				} else {
					log.Errorf("Invalid date format: %s", req.AtTime)
				}
			}

			host := parseIP(req.Host)
			log.Infof("fetching %s (depth: %d)", host, req.Depth)

			res, err := ce.Run(ctx, host, opts...)
			if err != nil {
				errMsg := fmt.Sprintf("error: %v", err)
				conn.WriteMessage(websocket.TextMessage, []byte(errMsg))
				continue
			}

			type report struct {
				Reports   []*censeye.Report    `json:"reports"`
				PivotTree []*censeye.PivotNode `json:"pivot_tree,omitempty"`
			}

			r := &censeye.Reporter{}
			j, err := json.Marshal(
				report{Reports: res,
					PivotTree: r.CreatePivotTree(res),
				})
			if err != nil {
				log.Errorf("Failed to marshal result: %v", err)
				continue
			}

			if err := conn.WriteMessage(messageType, j); err != nil {
				log.Errorf("Failed to write response: %v", err)
				break
			}
		}
	}
}

func runServer(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	org, token, err := getCreds()
	if err != nil {
		log.Fatalf("error getting credentials: %v", err)
	}

	var conf *config.Config
	if configFile != "" {
		conf, err = config.ParseFile(configFile)
		if err != nil {
			log.Fatalf("error parsing config file: %v", err)
		}
	} else {
		conf = config.NewConfig()
	}

	if pivotThresh != -1 {
		conf.Rarity.Max = uint64(pivotThresh)
	}

	if cacheDuration != config.DefaultCacheDuration {
		conf.CacheDuration = cacheDuration
	}

	if nParallel != config.DefaultWorkers {
		conf.Workers = nParallel
	}

	if len(pivotableFields) > 0 {
		conf.PivotableFields = pivotableFields
	}

	ce := censeye.New(
		censeye.WithClient(censys.New(
			censys.WithSecurity(token),
			censys.WithOrganizationID(org),
		)),
		censeye.WithConfig(conf),
	)

	os.RemoveAll(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to create Unix socket: %v", err)
	}
	defer listener.Close()
	os.Chmod(socketPath, 0600)

	log.Infof("listening on %s", socketPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handleConn(ctx, ce))

	server := &http.Server{Handler: mux}
	shutdownCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	log.Info("server started. Press Ctrl+C to stop.")
	<-shutdownCtx.Done()

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(timeoutCtx)
	os.Remove(socketPath)
}

var testWsCmd = &cobra.Command{
	Use:   "test-ws [hosts...]",
	Short: "test the ws server",
	Args:  cobra.MinimumNArgs(1),
	Run:   runWsClient,
}

func runWsClient(cmd *cobra.Command, args []string) {
	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", wsSocketPath)
		},
	}

	conn, _, err := dialer.Dial("ws://unix/ws", nil)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	for i, host := range args {
		if len(args) > 1 {
			log.Infof("%d/%d: %s", i+1, len(args), host)
		}

		req := wsRequest{Host: host, Depth: wsDepth, AtTime: wsAtTime}
		reqJSON, err := json.Marshal(req)
		if err != nil {
			log.Errorf("Failed to marshal request: %v", err)
			continue
		}

		if err := conn.WriteMessage(websocket.TextMessage, reqJSON); err != nil {
			log.Fatalf("Failed to send: %v", err)
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			log.Errorf("Error reading: %v", err)
			break
		}

		fmt.Println(string(message))
	}
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().StringVarP(&socketPath, "socket", "s", "/tmp/censeye-ng.sock", "Unix socket path")

	serverCmd.AddCommand(testWsCmd)
	testWsCmd.Flags().IntVarP(&wsDepth, "depth", "d", 0, "Scan depth")
	testWsCmd.Flags().StringVarP(&wsAtTime, "at", "a", "", "Historical date")
	testWsCmd.Flags().StringVarP(&wsSocketPath, "socket", "s", "/tmp/censeye-ng.sock", "Socket path")
}
