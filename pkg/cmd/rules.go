package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
)

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List and manage detection rules",
		Long:  "View available detection rules and their configuration.",
	}

	cmd.AddCommand(newRulesListCommand())

	return cmd
}

func newRulesListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all detection rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			fmt.Printf("Available Detection Rules (%d total):\n\n", len(cfg.Rules))
			
			for _, rule := range cfg.Rules {
				fmt.Printf("  • %s\n", rule.ID)
				fmt.Printf("    Description: %s\n", rule.Description)
				fmt.Printf("    Severity:    %s\n", rule.Severity)
				if len(rule.Tags) > 0 {
					fmt.Printf("    Tags:        %v\n", rule.Tags)
				}
				if rule.Entropy > 0 {
					fmt.Printf("    Min Entropy: %.1f\n", rule.Entropy)
				}
				if len(rule.Keywords) > 0 {
					fmt.Printf("    Keywords:    %v\n", rule.Keywords)
				}
				fmt.Println()
			}

			return nil
		},
	}
}
