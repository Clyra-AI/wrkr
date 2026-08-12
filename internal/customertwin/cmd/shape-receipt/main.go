package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Clyra-AI/wrkr/internal/customertwin"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("shape-receipt", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "", "path to sanitized aggregate-count JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *inputPath == "" {
		_, _ = fmt.Fprintln(stderr, "--input is required")
		return 2
	}
	payload, err := os.ReadFile(*inputPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	var input customertwin.ShapeReceiptInput
	if err := json.Unmarshal(payload, &input); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(customertwin.CompareShape(input)); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
