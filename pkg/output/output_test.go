package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

func TestJSONFormatter_Format(t *testing.T) {
	findings := []*scanner.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			Match:       "secret123",
			File:        "test.go",
			Line:        10,
			Column:      20,
			Severity:    "high",
			Entropy:     4.5,
			Fingerprint: "abc123",
		},
	}

	report := &scanner.Report{
		Findings:     findings,
		FilesScanned: 5,
		ScanTime:     time.Second,
		Version:      "1.0.0",
	}

	var buf bytes.Buffer
	formatter := &JSONFormatter{Redact: false}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("Format() produced empty output")
	}

	// Should be valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Errorf("Format() produced invalid JSON: %v", err)
	}

	// Should contain expected fields
	if decoded["version"] != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %v", decoded["version"])
	}
}

func TestJSONFormatter_Redact(t *testing.T) {
	findings := []*scanner.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			Match:       "supersecretpassword",
			File:        "test.go",
			Line:        10,
		},
	}

	report := &scanner.Report{Findings: findings}

	var buf bytes.Buffer
	formatter := &JSONFormatter{Redact: true}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	
	// Should not contain the full secret
	if strings.Contains(output, "supersecretpassword") {
		t.Error("Format() should redact secrets when Redact=true")
	}

	// Should contain redacted form
	if !strings.Contains(output, "***") {
		t.Error("Format() should include redaction marker")
	}
}

func TestCSVFormatter_Format(t *testing.T) {
	findings := []*scanner.Finding{
		{
			RuleID:      "aws-key",
			Description: "AWS Key",
			Match:       "AKIA...",
			File:        "config.json",
			Line:        5,
			Column:      10,
			Severity:    "critical",
			Tags:        []string{"aws", "key"},
		},
	}

	report := &scanner.Report{Findings: findings}

	var buf bytes.Buffer
	formatter := &CSVFormatter{}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Rule ID") {
		t.Error("CSV output should contain header")
	}
	if !strings.Contains(output, "aws-key") {
		t.Error("CSV output should contain finding data")
	}
	if !strings.Contains(output, "critical") {
		t.Error("CSV output should contain severity")
	}
}

func TestTerminalFormatter_Format(t *testing.T) {
	findings := []*scanner.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			Match:       "secret123",
			File:        "app.go",
			Line:        42,
			Severity:    "high",
			Entropy:     4.5,
		},
	}

	report := &scanner.Report{
		Findings:     findings,
		FilesScanned: 10,
		Version:      "1.0.0",
	}

	var buf bytes.Buffer
	formatter := &TerminalFormatter{}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	// Terminal output contains ANSI codes
	if output == "" {
		t.Error("Terminal output should not be empty")
	}
}

func TestTerminalFormatter_NoFindings(t *testing.T) {
	report := &scanner.Report{
		Findings: []*scanner.Finding{},
		Version:  "1.0.0",
	}

	var buf bytes.Buffer
	formatter := &TerminalFormatter{}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No secrets found") {
		t.Error("Terminal output should mention no secrets found")
	}
}

func TestSARIFFormatter_Format(t *testing.T) {
	findings := []*scanner.Finding{
		{
			RuleID:      "github-pat",
			Description: "GitHub PAT",
			Match:       "ghp_...",
			File:        "config.yml",
			Line:        25,
			Column:      15,
			Severity:    "high",
			Fingerprint: "abc123def456",
			Tags:        []string{"github", "token"},
			Entropy:     4.5,
		},
	}

	report := &scanner.Report{Findings: findings, Version: "1.0.0"}

	var buf bytes.Buffer
	formatter := &SARIFFormatter{}
	err := formatter.Format(report, &buf)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := buf.String()
	
	// Should be valid JSON
	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(output), &sarif); err != nil {
		t.Errorf("SARIF output is invalid JSON: %v", err)
	}

	// Should have required SARIF fields
	if sarif["version"] != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", sarif["version"])
	}

	// Should contain runs
	runs, ok := sarif["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Error("SARIF should contain runs")
	}
}

func TestSARIFFormatter_severityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		wantLevel string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "warning"},
	}

	for _, tt := range tests {
		got := severityToLevel(tt.severity)
		if got != tt.wantLevel {
			t.Errorf("severityToLevel(%q) = %q, want %q", tt.severity, got, tt.wantLevel)
		}
	}
}

func TestSARIFFormatter_severityToScore(t *testing.T) {
	tests := []struct {
		severity string
		minScore string
		maxScore string
	}{
		{"critical", "9.5", "9.5"},
		{"high", "8.0", "8.0"},
		{"medium", "6.5", "6.5"},
		{"low", "4.0", "4.0"},
	}

	for _, tt := range tests {
		got := severityToScore(tt.severity)
		if got != tt.minScore {
			t.Errorf("severityToScore(%q) = %q, want %q", tt.severity, got, tt.minScore)
		}
	}
}

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantFound bool
	}{
		{"json", "json", true},
		{"sarif", "sarif", true},
		{"csv", "csv", true},
		{"terminal", "terminal", true},
		{"unknown", "unknown", false},
		{"json upper", "JSON", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatter, found := GetFormatter(tt.format)
			if found != tt.wantFound {
				t.Errorf("GetFormatter(%q) found = %v, want %v", tt.format, found, tt.wantFound)
			}
			if found && formatter == nil {
				t.Error("GetFormatter() returned nil formatter when found")
			}
		})
	}
}

func BenchmarkJSONFormatter_Format(b *testing.B) {
	findings := []*scanner.Finding{
		{
			RuleID:      "test-rule",
			Description: "Test finding",
			Match:       "secret123",
			File:        "test.go",
			Line:        10,
			Severity:    "high",
			Entropy:     4.5,
		},
	}
	report := &scanner.Report{Findings: findings}
	formatter := &JSONFormatter{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		_ = formatter.Format(report, &buf)
	}
}
