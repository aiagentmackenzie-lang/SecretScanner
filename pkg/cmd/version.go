package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCommand(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("SecretScanner %s (commit: %s, built: %s)\n", version, commit, date)
			fmt.Println("A modern secret detection engine for SOC analysts and DevSecOps")
		},
	}
}
