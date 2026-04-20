package verify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Result represents the outcome of a verification
type Result struct {
	Status   string            `json:"status"`   // valid, invalid, revoked, error, unknown
	Account  string            `json:"account,omitempty"`
	Message  string            `json:"message,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// Verifier handles credential verification
type Verifier struct {
	httpClient *http.Client
}

// NewVerifier creates a new verifier with rate limiting
func NewVerifier() *Verifier {
	return &Verifier{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Verify checks a secret based on rule ID
func (v *Verifier) Verify(ruleID, secret string) (*Result, error) {
	// Rate limit all verifications
	time.Sleep(100 * time.Millisecond)

	switch ruleID {
	case "github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token":
		return v.verifyGitHub(secret)
	case "slack-bot-token", "slack-user-token":
		return v.verifySlack(secret)
	case "stripe-live-secret", "stripe-test-secret", "stripe-restricted-live":
		return v.verifyStripe(secret)
	case "openai-api-key":
		return v.verifyOpenAI(secret)
	case "anthropic-api-key":
		return v.verifyAnthropic(secret)
	default:
		return &Result{
			Status:  "unknown",
			Message: fmt.Sprintf("Verification not available for rule: %s", ruleID),
		}, nil
	}
}

func (v *Verifier) verifyGitHub(token string) (*Result, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SecretScanner/1.0")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		var user struct {
			Login string `json:"login"`
			ID    int    `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err == nil && user.Login != "" {
			return &Result{
				Status:  "valid",
				Account: user.Login,
				Message: fmt.Sprintf("GitHub token valid for user: %s", user.Login),
			}, nil
		}
		return &Result{
			Status:  "valid",
			Message: "GitHub token is valid",
		}, nil
	case 401:
		return &Result{
			Status:  "invalid",
			Message: "GitHub token is invalid or expired",
		}, nil
	case 403:
		return &Result{
			Status:  "revoked",
			Message: "GitHub token has been revoked or rate limited",
		}, nil
	default:
		return &Result{
			Status:  "error",
			Message: fmt.Sprintf("Unexpected response: %d", resp.StatusCode),
		}, nil
	}
}

func (v *Verifier) verifySlack(token string) (*Result, error) {
	req, err := http.NewRequest("POST", "https://slack.com/api/auth.test", strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
		User  string `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}

	if result.OK {
		return &Result{
			Status:  "valid",
			Account: fmt.Sprintf("%s/%s", result.Team, result.User),
			Message: fmt.Sprintf("Slack token valid for team: %s, user: %s", result.Team, result.User),
		}, nil
	}

	return &Result{
		Status:  "invalid",
		Message: fmt.Sprintf("Slack token invalid: %s", result.Error),
	}, nil
}

func (v *Verifier) verifyStripe(key string) (*Result, error) {
	// Determine if test or live
	keyType := "unknown"
	if strings.HasPrefix(key, "sk_live_") {
		keyType = "live"
	} else if strings.HasPrefix(key, "sk_test_") {
		keyType = "test"
	} else if strings.HasPrefix(key, "rk_live_") {
		keyType = "restricted_live"
	}

	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/account", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return &Result{
			Status:   "valid",
			Message:  fmt.Sprintf("Stripe %s key is valid", keyType),
			Metadata: map[string]string{"type": keyType},
		}, nil
	case 401:
		return &Result{
			Status:  "invalid",
			Message: "Stripe key is invalid or revoked",
		}, nil
	default:
		return &Result{
			Status:  "unknown",
			Message: fmt.Sprintf("Unexpected response from Stripe: %d", resp.StatusCode),
		}, nil
	}
}

func (v *Verifier) verifyOpenAI(key string) (*Result, error) {
	// Check if it's the new project-based format
	isProjectKey := strings.HasPrefix(key, "sk-proj-")

	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		msg := "OpenAI API key is valid"
		if isProjectKey {
			msg = "OpenAI project API key is valid"
		}
		return &Result{
			Status:   "valid",
			Message:  msg,
			Metadata: map[string]string{"type": map[bool]string{true: "project", false: "standard"}[isProjectKey]},
		}, nil
	case 401:
		return &Result{
			Status:  "invalid",
			Message: "OpenAI API key is invalid",
		}, nil
	default:
		return &Result{
			Status:  "error",
			Message: fmt.Sprintf("Unexpected response: %d", resp.StatusCode),
		}, nil
	}
}

func (v *Verifier) verifyAnthropic(key string) (*Result, error) {
	req, err := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return &Result{
			Status: "error",
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return &Result{
			Status:  "valid",
			Message: "Anthropic API key is valid",
		}, nil
	case 401:
		return &Result{
			Status:  "invalid",
			Message: "Anthropic API key is invalid",
		}, nil
	default:
		return &Result{
			Status:  "unknown",
			Message: fmt.Sprintf("Unexpected response from Anthropic: %d", resp.StatusCode),
		}, nil
	}
}

// IsVerifiableRule checks if a rule has verification support
func IsVerifiableRule(ruleID string) bool {
	verifiableRules := map[string]bool{
		"github-pat":               true,
		"github-fine-grained-pat":  true,
		"github-oauth":             true,
		"github-app-token":         true,
		"slack-bot-token":          true,
		"slack-user-token":         true,
		"stripe-live-secret":       true,
		"stripe-test-secret":       true,
		"stripe-restricted-live":   true,
		"openai-api-key":           true,
		"anthropic-api-key":        true,
	}
	return verifiableRules[ruleID]
}
