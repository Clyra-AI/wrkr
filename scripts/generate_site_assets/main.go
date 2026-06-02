package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Clyra-AI/wrkr/internal/siteassets"
)

func main() {
	repoRoot := flag.String("repo-root", ".", "repository root")
	outputDir := flag.String("output-dir", filepath.Join("docs", "examples", "site-assets"), "site asset output directory")
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "generate_site_assets does not accept positional arguments")
		os.Exit(6)
	}

	if err := siteassets.Generate(*repoRoot, *outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate site assets: %v\n", err)
		os.Exit(1)
	}
}
