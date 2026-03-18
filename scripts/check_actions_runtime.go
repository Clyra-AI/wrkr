package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Clyra-AI/wrkr/internal/ci/actionruntime"
)

func main() {
	root := os.Getenv("WRKR_ACTION_RUNTIME_ROOT")
	if root == "" {
		root = "."
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve runtime check root %s: %v\n", root, err)
		os.Exit(3)
	}

	findings, err := actionruntime.Scan(absRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	if len(findings) == 0 {
		fmt.Println("github actions runtime contract: pass")
		return
	}

	for _, line := range actionruntime.FormatFindings(findings) {
		fmt.Fprintln(os.Stderr, line)
	}
	os.Exit(3)
}
