package main

import (
	"fmt"
	"os"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/cmd"
)

var version = "1.0.0-dev"
var commit = "unknown"
var date = "unknown"

func main() {
	rootCmd := cmd.NewRootCommand(version, commit, date)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
