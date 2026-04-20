package cmd

import (
	"github.com/spf13/cobra"
)

func NewRootCommand(version, commit, date string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "secretscanner",
		Short: "High-performance secret detection engine",
		Long: `SecretScanner is a modern secret detection engine designed for SOC analysts
and DevSecOps teams. It detects secrets in source code, configuration files,
and git history with high signal-to-noise ratio.`,
		Version: version,
	}

	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	// Add subcommands
	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newVersionCommand(version, commit, date))
	rootCmd.AddCommand(newVerifyCommand())
	rootCmd.AddCommand(newRulesCommand())
	rootCmd.AddCommand(newDockerCommand())

	return rootCmd
}
