package cmd

import (
	"fmt"
	"os"
	"time"
	
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/verify"
)

// verifyFindings verifies findings with provider APIs
func verifyFindings(findings []*scanner.Finding, statusFilter string) []*scanner.Finding {
	v := verify.NewVerifier()
	
	var verified []*scanner.Finding
	
	for _, finding := range findings {
		if !verify.IsVerifiableRule(finding.RuleID) {
			// Skip verification if not supported
			finding.Verified = boolPtr(false)
			verified = append(verified, finding)
			continue
		}
		
		// Show progress indicator
		fmt.Fprintf(os.Stderr, "Verifying %s... ", finding.RuleID)
		
		result, err := v.Verify(finding.RuleID, finding.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error\n")
			// Don't mark as verified on error
			verified = append(verified, finding)
			continue
		}
		
		fmt.Fprintf(os.Stderr, "%s\n", result.Status)
		
		// Set verification status
		isVerified := result.Status == "valid"
		finding.Verified = &isVerified
		
		// Add account info if available
		if result.Account != "" {
			finding.Account = result.Account
		}
		
		// Filter by status if requested
		if statusFilter != "" && result.Status != statusFilter {
			continue
		}
		
		if result.Status == "valid" || result.Status == "invalid" || result.Status == "revoked" || result.Status == "error" {
			finding.Message = result.Message
		}
		
		verified = append(verified, finding)
		
		// Rate limiting between verifications
		time.Sleep(500 * time.Millisecond)
	}
	
	return verified
}

func boolPtr(b bool) *bool {
	return &b
}
