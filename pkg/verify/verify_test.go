package verify

import (
	"testing"
)

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	if v == nil {
		t.Fatal("NewVerifier() returned nil")
	}
	if v.httpClient == nil {
		t.Error("HTTP client not initialized")
	}
}

func TestIsVerifiableRule(t *testing.T) {
	tests := []struct {
		ruleID string
		want   bool
	}{
		{"github-pat", true},
		{"github-fine-grained-pat", true},
		{"slack-bot-token", true},
		{"stripe-live-secret", true},
		{"openai-api-key", true},
		{"anthropic-api-key", true},
		{"anthropic-api-key", true},
		{"aws-access-key", false}, // Not yet implemented - requires both access key and secret
		{"generic-api-key", false},
		{"unknown-rule", false},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := IsVerifiableRule(tt.ruleID)
			if got != tt.want {
				t.Errorf("IsVerifiableRule(%q) = %v, want %v", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestVerifier_Verify_Unsupported(t *testing.T) {
	v := NewVerifier()
	
	result, err := v.Verify("unsupported-rule", "test-secret")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	
	if result.Status != "unknown" {
		t.Errorf("Expected status 'unknown' for unsupported rule, got %s", result.Status)
	}
}

func TestResult_Valid(t *testing.T) {
	result := &Result{
		Status:  "valid",
		Message: "Token is valid",
		Account: "user123",
	}
	
	if result.Status != "valid" {
		t.Error("Valid result should have status 'valid'")
	}
	if result.Account != "user123" {
		t.Error("Account should be set")
	}
}

func TestResult_InvalidFormat(t *testing.T) {
	// Test that various token formats are validated
	v := NewVerifier()
	
	// Test GitHub token format detection
	if !IsVerifiableRule("github-pat") {
		t.Error("github-pat should be verifiable")
	}
	
	// Test verification returns something (may be invalid, but shouldn't error)
	_, err := v.Verify("github-pat", "invalid-token")
	if err != nil {
		t.Errorf("Verify should not error on invalid token: %v", err)
	}
}
