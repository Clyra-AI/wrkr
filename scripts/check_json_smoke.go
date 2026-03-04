package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type rootPayload struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: go run scripts/check_json_smoke.go <path> <label>\n")
		os.Exit(6)
	}

	path := strings.TrimSpace(os.Args[1])
	label := strings.TrimSpace(os.Args[2])
	payload, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: read json output: %v\n", label, err)
		os.Exit(3)
	}

	var parsed rootPayload
	if err := json.Unmarshal(payload, &parsed); err != nil {
		fmt.Fprintf(os.Stderr, "%s: invalid json output: %v\n", label, err)
		os.Exit(3)
	}

	if strings.TrimSpace(parsed.Status) != "ok" {
		fmt.Fprintf(os.Stderr, "%s: expected status=ok, got %q\n", label, parsed.Status)
		os.Exit(3)
	}
	if strings.TrimSpace(parsed.Message) == "" {
		fmt.Fprintf(os.Stderr, "%s: expected non-empty message field\n", label)
		os.Exit(3)
	}
}
