package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/censys-research/censeye-ng/pkg/censeye"
	"github.com/censys-research/censeye-ng/pkg/config"
	censys "github.com/censys/censys-sdk-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rootCmd = &cobra.Command{
	Use:   "censeye-ng",
	Short: "finding things on the internet, one host and a thousand reports at a time",
	Args:  cobra.ArbitraryArgs,
	Run:   runCenseye,
}

var (
	organizationId  string
	logLevel        string
	depth           int
	outFormat       = "pretty"
	configFile      = ""
	pivotThresh     = -1
	cacheDuration   = config.DefaultCacheDuration // duration to keep things cached
	nParallel       = config.DefaultWorkers       // number of runs to be run in parallel. (auto-pivot feature only)
	noColors        = false                       // don't display colored output
	noLinks         = false                       // don't display hyperlinks in the output
	atTime          string                        // fetch historical information from a specific host
	showConf        = false                       // show the configuration file in yaml format before running the command
	pivotableFields []string                      // fields that should be considered for pivoting when depth > 1
	inputFile       string                        // file containing IPs to analyze (one per line or comma-separated)
)

func report(w io.Writer, rep []*censeye.Report) {
	type report struct {
		Reports   []*censeye.Report    `json:"reports"`
		PivotTree []*censeye.PivotNode `json:"pivot_tree"`
	}

	var ropt []string

	if noColors {
		ropt = append(ropt, "no-colors")
	}

	if noLinks {
		ropt = append(ropt, "no-links")
	} else {
		// the api used to generate hyperlinks in the output doesn't seem to conver all
		// supported terminals, so we default to forcing it on unless otherwise specified.
		os.Setenv("FORCE_HYPERLINK", "true")
	}

	switch outFormat {
	case "pretty", "table":
		r := censeye.NewReporter(w, ropt...)
		r.Tables(rep)
		r.Pivots(rep)
		r.PivotTree(rep)
	case "json":
		r := &censeye.Reporter{}
		crep := &report{
			Reports:   rep,
			PivotTree: r.CreatePivotTree(rep),
		}

		j, err := json.Marshal(crep)
		if err != nil {
			log.Errorf("error marshalling report to JSON: %v", err)
			return
		}
		fmt.Fprintf(w, "%s\n", j)
	}

}

func parseDateString(input string) time.Time {
	layouts := []string{
		time.RFC3339, "2006-01-02 15:04:05", "2006-01-02", "02 Jan 2006", "02-Jan-2006",
		"2006/01/02", "02/01/2006", "01/02/2006", "2006.01.02", "02.01.2006", "20060102",
		"02 Jan 06 15:04 MST", "02 Jan 2006 15:04:05", "2006-01-02T15:04:05Z07:00",
		time.RFC1123, time.RFC1123Z, time.RFC822, time.RFC822Z, time.RFC850,
		time.ANSIC, time.UnixDate, time.RubyDate, time.Kitchen,
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, input); err == nil {
			return t
		}
	}

	return time.Time{}
}

// re-fang (de-defang? undefang? whatever.) input hosts.
func parseIP(s string) string {
	replacements := []string{"[.]", ".]", "[."}
	remove := []string{`"`, ",", "\\'"}

	for _, r := range replacements {
		s = strings.ReplaceAll(s, r, ".")
	}
	for _, r := range remove {
		s = strings.ReplaceAll(s, r, "")
	}

	return strings.TrimSpace(s)
}

// parseIPList parses a string containing multiple IPs separated by commas or newlines
// Handles spaces gracefully and returns a slice of clean IPs
func parseIPList(input string) []string {
	var ips []string

	// First split by newlines to handle file input format
	lines := strings.Split(input, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Then split each line by commas
		parts := strings.Split(line, ",")
		for _, part := range parts {
			cleanIP := parseIP(part)
			if cleanIP != "" {
				ips = append(ips, cleanIP)
			}
		}
	}

	return ips
}

// readIPsFromFile reads IPs from a file, supporting both line-separated and comma-separated formats
func readIPsFromFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return parseIPList(string(content)), nil
}

func runCenseye(cmd *cobra.Command, args []string) {
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

	if showConf {
		y, err := yaml.Marshal(conf)
		if err != nil {
			log.Fatalf("error marshalling config to yaml: %v", err)
		}
		fmt.Println(string(y))
		os.Exit(0)
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
	if depth > 0 && conf.Rarity.Max >= 100 {
		log.Warn("Setting depth > 0 with a pivot threshold >= 100 may lead to a LOT queries. Consider adjusting the pivot threshold. Ctrl+C to cancel.")
		time.Sleep(5 * time.Second)
		log.Warn("Well, alrighty then... let's do this!")
	}

	// i like the charsets[21] spinner characters...
	s := spinner.New(spinner.CharSets[21], 100*time.Millisecond)
	statuscb := func(message string) {
		s.Suffix = " " + message
		if !s.Active() {
			s.Start()
		}
	}

	stopSpinner := func() {
		if s.Active() {
			s.Stop()
		}
	}

	ce := censeye.New(
		censeye.WithClient(censys.New(
			censys.WithSecurity(token),
			censys.WithOrganizationID(org),
		)),
		censeye.WithConfig(conf),
		censeye.WithStatusCallback(statuscb),
	)

	buildOpts := func() []censeye.RunOpt {
		opts := []censeye.RunOpt{censeye.WithDepth(depth)}
		if strings.TrimSpace(atTime) != "" {
			log.Infof("Using --at time: %s", atTime)
			if parsed := parseDateString(atTime); !parsed.IsZero() {
				opts = append(opts, censeye.WithAtTime(&parsed))
			} else {
				log.Fatalf("invalid date format for --at: %s", atTime)
			}
		}
		return opts
	}

	// Determine input source and parse IPs
	var allIPs []string

	if inputFile != "" {
		// File input mode
		if len(args) > 0 {
			log.Fatalf("cannot specify both file input and command line arguments")
		}
		allIPs, err = readIPsFromFile(inputFile)
		if err != nil {
			log.Fatalf("error reading input file: %v", err)
		}
	} else if len(args) > 0 {
		// Command line arguments
		if len(args) == 1 && strings.Contains(args[0], ",") {
			// Single argument with comma-separated IPs
			allIPs = parseIPList(args[0])
		} else {
			// Multiple arguments or single IP
			for _, arg := range args {
				cleanIP := parseIP(arg)
				if cleanIP != "" {
					allIPs = append(allIPs, cleanIP)
				}
			}
		}
	} else {
		// Stdin input mode
		scanner := bufio.NewScanner(os.Stdin)
		var allInputs []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				allInputs = append(allInputs, line)
			}
		}

		if len(allInputs) == 0 {
			log.Fatalf("no input provided")
		}

		// Parse all stdin input
		allInput := strings.Join(allInputs, "\n")
		allIPs = parseIPList(allInput)
	}

	if len(allIPs) == 0 {
		log.Fatalf("no valid IP addresses found in input")
	}

	// Determine if this is multi-IP mode
	multiIPMode := len(allIPs) > 1

	if multiIPMode && depth > 0 {
		log.Fatalf("depth cannot be set in multi-IP mode (unclear which common attributes to pivot on)")
	}

	if multiIPMode {
		// Multi-IP analysis mode
		log.Infof("processing %d hosts for common attribute analysis", len(allIPs))
		res, err := ce.RunMultiIP(ctx, allIPs, buildOpts()...)
		stopSpinner()

		if err != nil {
			fmt.Fprintf(os.Stderr, "error running multi-IP censeye: %v\n", err)
			log.Fatalf("error running multi-IP censeye: %v", err)
		}

		report(os.Stdout, res)
	} else {
		// Single-IP mode
		host := allIPs[0]
		log.Infof("processing host: %s", host)

		res, err := ce.Run(ctx, host, buildOpts()...)
		stopSpinner()

		if err != nil {
			fmt.Fprintf(os.Stderr, "error running censeye for %s: %v\n", host, err)
			log.Fatalf("error running censeye: %v", err)
		}

		report(os.Stdout, res)
	}

	fmt.Fprintln(os.Stderr, "Censys credits used: ", ce.GetCredits())
}

func getCreds() (string, string, error) {
	org := os.Getenv("CENSYS_PLATFORM_ORGID")
	tok := os.Getenv("CENSYS_PLATFORM_TOKEN")

	if organizationId != "" {
		org = organizationId
	}

	if org == "" || tok == "" {
		return "", "", fmt.Errorf("CENSYS_PLATFORM_ORGID and CENSYS_PLATFORM_TOKEN must be set")
	}

	return org, tok, nil
}

func initLogging() {
	log.SetOutput(os.Stderr)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		PadLevelText:  true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return f.Function + ": ", fmt.Sprintf("%s:%d", f.File, f.Line)
		},
	})

	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.WarnLevel)
	}
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&organizationId, "org", "O", "", "Organization ID")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "L", "", "Log level (debug, info*, warn, error, fatal, panic)")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Path to the configuration file")

	rootCmd.Flags().IntVarP(&depth, "depth", "d", 0, "Depth of the scan (default: 0)")
	rootCmd.Flags().StringVarP(&outFormat, "output", "o", outFormat, "Output format (pretty / json)")
	rootCmd.Flags().IntVarP(&pivotThresh, "pivot-threshold", "p", -1, "maximum number of hosts for a search term that will trigger a pivot")
	rootCmd.Flags().StringSliceVar(&pivotableFields, "pivotable", []string{}, "fields that should be considered for pivoting when depth > 1 (can be specified multiple times)")
	rootCmd.Flags().DurationVarP(&cacheDuration, "cache-duration", "C", cacheDuration, "Duration to keep the cache (default: 23h)")
	rootCmd.Flags().IntVar(&nParallel, "workers", nParallel, "Number of parallel workers (for auto-pivot feature only)")
	rootCmd.Flags().BoolVar(&noColors, "no-color", false, "Disable colored output")
	rootCmd.Flags().BoolVar(&noLinks, "no-link", false, "Disable hyperlinks in output")
	rootCmd.Flags().StringVarP(&atTime, "at", "a", "", "Fetch host data from a specific date (e.g., '2023-10-01 12:00:00')")
	rootCmd.Flags().StringVar(&atTime, "at-time", "", "alias for --at")
	rootCmd.Flags().BoolVar(&showConf, "showconf", showConf, "Show the configuration file in YAML format before running the command")
	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "File containing IP addresses (one per line or comma-separated)")

	cobra.OnInitialize(initLogging)
}
