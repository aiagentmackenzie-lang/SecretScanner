package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/verify"
)

type verifyOptions struct {
	secret  string
	provider string
	json    bool
}

func newVerifyCommand() *cobra.Command {
	opts := &verifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify [secret]",
		Short: "Verify if a secret is valid via API check",
		Long: `Verify a discovered secret by making API calls to the provider.

Currently supported verification:
  - GitHub Tokens (GET /user)
  - Slack Tokens (auth.test)
  - Stripe Keys (tokens retrieve)
  - OpenAI Keys (v1/models)
  - Anthropic Keys (v1/models)

Note: This will make network requests to the provider's API.
Use with caution on production secrets.`,
		RunE: opts.run,
	}

	cmd.Flags().StringVar(&opts.provider, "provider", "", "Provider type (github, slack, stripe, openai, anthropic)")
	cmd.Flags().BoolVarP(&opts.json, "json", "j", false, "Output as JSON")

	return cmd
}

func (o *verifyOptions) run(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("secret required: secretscanner verify [secret]")
	}
	
	o.secret = args[0]
	
	// Determine provider from secret if not specified
	if o.provider == "" {
		o.provider = detectProvider(o.secret)
		if o.provider == "" {
			return fmt.Errorf("could not detect provider from secret prefix. Use --provider to specify")
		}
	}

	v := verify.NewVerifier()
	
	// Map provider name to rule ID
	ruleID := o.provider + "-pat"
	switch o.provider {
	case "github":
		ruleID = "github-pat"
	case "slack":
		if len(args[0]) > 4 && args[0][:4] == "xoxb" {
			ruleID = "slack-bot-token"
		} else {
			ruleID = "slack-user-token"
		}
	case "stripe":
		if len(args[0]) > 8 && args[0][:8] == "sk_live_" {
			ruleID = "stripe-live-secret"
		} else {
			ruleID = "stripe-test-secret"
		}
	case "openai":
		ruleID = "openai-api-key"
	case "anthropic":
		ruleID = "anthropic-api-key"
	}

	result, err := v.Verify(ruleID, o.secret)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if o.json {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Terminal output
	fmt.Printf("🔍 Verification Result\n")
	fmt.Printf("Provider: %s\n", o.provider)
	fmt.Printf("Status:   ")
	
	switch result.Status {
	case "valid":
		fmt.Printf("✅ VALID\n")
	case "invalid":
		fmt.Printf("❌ INVALID\n")
	case "revoked":
		fmt.Printf("⚠️  REVOKED\n")
	case "error":
		fmt.Printf("💥 ERROR\n")
	default:
		fmt.Printf("❓ UNKNOWN\n")
	}

	if result.Account != "" {
		fmt.Printf("Account:  %s\n", result.Account)
	}
	if result.Message != "" {
		fmt.Printf("Message:  %s\n", result.Message)
	}
	if result.Error != "" {
		fmt.Printf("Error:    %s\n", result.Error)
	}

	if len(result.Metadata) > 0 {
		fmt.Printf("Metadata:\n")
		for k, v := range result.Metadata {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	return nil
}

func detectProvider(secret string) string {
	// Detect provider from secret patterns
	if len(secret) > 4 {
		switch {
		case secret[:4] == "ghp_" || secret[:4] == "gho_" || secret[:4] == "ghs_":
			return "github"
		case secret[:4] == "xoxb" || secret[:4] == "xoxp":
			return "slack"
		case len(secret) > 8 && (secret[:8] == "sk_test_" || secret[:8] == "sk_live_"):
			return "stripe"
		case len(secret) > 9 && secret[:9] == "sk-ant-api-":
			return "anthropic"
		case len(secret) > 3 && secret[:3] == "sk-":
			return "openai"
		}
	}
	return ""
}
