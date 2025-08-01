package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/censys-research/censeye-ng/pkg/censeye"
)

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading from stdin: %v\n", err)
		os.Exit(1)
	}

	compiled, err := censeye.CompileRulesFromHostResult(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error compiling rules: %v\n", err)
		os.Exit(1)
	}

	jout, err := json.MarshalIndent(compiled, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling compiled rules to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jout))
}
