package main

import (
	"os"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
