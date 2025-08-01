package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type Field struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	var fields []Field
	if err := json.Unmarshal(data, &fields); err != nil {
		panic(err)
	}

	typeMap := make(map[string]string)
	for _, f := range fields {
		typeMap[f.Path] = f.Type
	}

	prefixesWithKeyValue := make(map[string]bool)

	for path := range typeMap {
		if strings.HasSuffix(path, ".key") {
			prefix := strings.TrimSuffix(path, ".key")
			if typeMap[prefix+".value"] != "" {
				prefixesWithKeyValue[prefix] = true
			}
		}
	}

	for _, f := range fields {
		if f.Type == "object" && prefixesWithKeyValue[f.Path] {
			fmt.Printf("%q,\n", f.Path)
		}
	}
}
