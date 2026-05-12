package main

import (
	"errors"
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
		if errors.Is(err, cmd.ErrFindingsFound) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
