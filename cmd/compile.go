package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/censys-research/censeye-ng/pkg/censeye"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile Censeye queries from a file",
	Run: func(cmd *cobra.Command, args []string) {
		var r io.Reader
		if len(args) == 0 || args[0] == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(args[0])
			if err != nil {
				log.Fatalf("error opening file %s: %v", args[0], err)
			}
			defer f.Close()
			r = f
		}

		data, err := io.ReadAll(r)
		if err != nil {
			log.Fatalf("error reading file %s: %v", args[0], err)
		}

		compiled, err := censeye.CompileRulesFromHostResult(data)
		if err != nil {
			log.Fatalf("error compiling rules: %v", err)
		}

		jout, err := json.MarshalIndent(compiled, "", "  ")
		if err != nil {
			log.Fatalf("error marshalling compiled rules to JSON: %v", err)
		}
		fmt.Println(string(jout))

	},
}

func init() {
	rootCmd.AddCommand(compileCmd)
}
