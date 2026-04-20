package scanner

import (
	"testing"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
)

func TestHasInlineIgnore(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		text     string
		matchPos int
		expected bool
	}{
		{
			name:     "shell comment ignore",
			text:     "api_key = 'secret' # secretscanner:allow",
			matchPos: 10,
			expected: true,
		},
		{
			name:     "go comment ignore",
			text:     "token := 'secret' // secretscanner:allow",
			matchPos: 10,
			expected: true,
		},
		{
			name:     "block comment ignore",
			text:     "key = 'secret' /* secretscanner:allow */",
			matchPos: 10,
			expected: true,
		},
		{
			name:     "html comment ignore",
			text:     "<!DOCTYPE html>\nkey = 'secret' <!-- secretscanner:allow -->",
			matchPos: 25,
			expected: true,
		},
		{
			name:     "no ignore",
			text:     "api_key = 'secret'",
			matchPos: 10,
			expected: false,
		},
		{
			name:     "ignore on different line",
			text:     "api_key = 'secret'\n# secretscanner:allow",
			matchPos: 10,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.hasInlineIgnore(tt.text, tt.matchPos)
			if got != tt.expected {
				t.Errorf("hasInlineIgnore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasCommitIgnore(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		commit   string
		expected bool
	}{
		{
			name:     "test commit",
			commit:   "abc123def456",
			expected: false, // default config doesn't have commits in allowlist
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.hasCommitIgnore(tt.commit)
			if got != tt.expected {
				t.Errorf("hasCommitIgnore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasStopwordMatch(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "contains example",
			content:  "example",
			expected: true,
		},
		{
			name:     "contains placeholder",
			content:  "placeholder_value_here",
			expected: true,
		},
		{
			name:     "contains test (no longer a stopword)",
			content:  "test_token_value",
			expected: false,
		},
		{
			name:     "legitimate secret",
			content:  "sk-1234567890abcdef",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.hasStopwordMatch(tt.content)
			if got != tt.expected {
				t.Errorf("hasStopwordMatch() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasStopwordMatch_CaseInsensitive(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		content string
		want    bool
	}{
		{"EXAMPLE", true},
		{"Example", true},
		{"example", true},
		{"PLACEHOLDER", true},
		{"placeholder", true},
		{"notastopword", false},
	}

	for _, tt := range tests {
		t.Run(tt.content, func(t *testing.T) {
			got := s.hasStopwordMatch(tt.content)
			if got != tt.want {
				t.Errorf("hasStopwordMatch(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}
