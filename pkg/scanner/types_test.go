package scanner

import (
	"testing"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
)

func TestFinding_GenerateFingerprint(t *testing.T) {
	f1 := &Finding{
		RuleID: "aws-access-key",
		Match:  "AKIAFAKEKEYS4TESTING",
		File:   "test.go",
		Line:   10,
		Column: 20,
	}
	f1.Fingerprint = f1.GenerateFingerprint()

	f2 := &Finding{
		RuleID: "aws-access-key",
		Match:  "AKIAFAKEKEYS4TESTING",
		File:   "test.go",
		Line:   10,
		Column: 20,
	}
	f2.Fingerprint = f2.GenerateFingerprint()

	// Same finding should generate same fingerprint
	if f1.Fingerprint != f2.Fingerprint {
		t.Error("GenerateFingerprint() should return same hash for same finding")
	}

	f3 := &Finding{
		RuleID: "aws-secret-key",
		Match:  "AKIAFAKEKEYS4TESTING",
		File:   "test.go",
		Line:   10,
		Column: 20,
	}
	f3.Fingerprint = f3.GenerateFingerprint()

	// Different rule should generate different fingerprint
	if f1.Fingerprint == f3.Fingerprint {
		t.Error("GenerateFingerprint() should return different hash for different rules")
	}
}

func TestFinding_Redacted(t *testing.T) {
	tests := []struct {
		name   string
		match  string
		suffix string
	}{
		{
			name:   "long secret",
			match:  "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY",
			suffix: "m",
		},
		{
			name:   "short secret",
			match:  "short",
			suffix: "",
		},
		{
			name:   "exact 8 chars",
			match:  "abcdefgh",
			suffix: "h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Match: tt.match,
				Raw:   tt.match,
			}

			redacted := f.Redacted()

			if redacted.Raw != "" {
				t.Error("Redacted Raw field should be empty")
			}

			if redacted.Match == tt.match {
				t.Error("Redacted Match should be different from original")
			}

			if redacted.Match == "" {
				t.Error("Redacted Match should not be empty")
			}
		})
	}
}

func TestReport_Summary(t *testing.T) {
	findings := []*Finding{
		{RuleID: "test-1", Severity: "high"},
		{RuleID: "test-2", Severity: "critical"},
		{RuleID: "test-3", Severity: "medium"},
	}

	report := &Report{
		Findings:     findings,
		FilesScanned: 42,
	}

	summary := report.Summary()
	
	if summary == "" {
		t.Error("Summary() should not return empty string")
	}

	if summary == "Found 0 secrets" {
		t.Error("Summary should include finding count")
	}
}

func TestReport_SeverityCounts(t *testing.T) {
	findings := []*Finding{
		{RuleID: "test-1", Severity: "high"},
		{RuleID: "test-2", Severity: "high"},
		{RuleID: "test-3", Severity: "critical"},
		{RuleID: "test-4", Severity: "medium"},
	}

	report := &Report{
		Findings: findings,
	}

	counts := report.SeverityCounts()

	if counts["high"] != 2 {
		t.Errorf("Expected 2 high severity, got %d", counts["high"])
	}
	if counts["critical"] != 1 {
		t.Errorf("Expected 1 critical severity, got %d", counts["critical"])
	}
	if counts["medium"] != 1 {
		t.Errorf("Expected 1 medium severity, got %d", counts["medium"])
	}
	if counts["low"] != 0 {
		t.Errorf("Expected 0 low severity, got %d", counts["low"])
	}
}

func TestReport_FileSummary(t *testing.T) {
	findings := []*Finding{
		{RuleID: "test-1", File: "file1.go"},
		{RuleID: "test-2", File: "file1.go"},
		{RuleID: "test-3", File: "file2.go"},
	}

	report := &Report{
		Findings: findings,
	}

	summary := report.FileSummary()

	if len(summary["file1.go"]) != 2 {
		t.Errorf("Expected 2 findings in file1.go, got %d", len(summary["file1.go"]))
	}
	if len(summary["file2.go"]) != 1 {
		t.Errorf("Expected 1 finding in file2.go, got %d", len(summary["file2.go"]))
	}
}

func TestOptions_DefaultValues(t *testing.T) {
	opts := &Options{
		MaxFileSize: 100 * 1024 * 1024,
		Threads:     4,
	}

	if opts.MaxFileSize != 100*1024*1024 {
		t.Errorf("Expected MaxFileSize to be 100MB, got %d", opts.MaxFileSize)
	}

	if opts.Threads != 4 {
		t.Errorf("Expected Threads to be 4, got %d", opts.Threads)
	}
}

func TestFileInfo_IsText(t *testing.T) {
	tests := []struct {
		name     string
		isBinary bool
		isText   bool
	}{
		{
			name:     "text file",
			isBinary: false,
			isText:   true,
		},
		{
			name:     "binary file",
			isBinary: true,
			isText:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := &FileInfo{
				IsBinary: tt.isBinary,
			}
			if got := fi.IsText(); got != tt.isText {
				t.Errorf("IsText() = %v, want %v", got, tt.isText)
			}
		})
	}
}

func TestNew(t *testing.T) {
	cfg, err := config.LoadDefault()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	opts := &Options{
		MaxFileSize: 50 * 1024 * 1024,
		Threads:     2,
	}

	s := New(cfg, opts)

	if s == nil {
		t.Fatal("New() returned nil")
	}

	if s.config != cfg {
		t.Error("Scanner config not set correctly")
	}

	if s.options.MaxFileSize != opts.MaxFileSize {
		t.Error("Options not set correctly")
	}

	if s.keywords == nil {
		t.Error("Keywords map not initialized")
	}

	if s.compiledREs == nil {
		t.Error("Compiled regexes map not initialized")
	}
}

func TestNew_DefaultOptions(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	if s.options.Threads != 4 {
		t.Errorf("Expected default 4 threads, got %d", s.options.Threads)
	}

	if s.options.MaxFileSize != 100*1024*1024 {
		t.Errorf("Expected default 100MB max file size, got %d", s.options.MaxFileSize)
	}
}

func TestScanner_deduplicate(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	findings := []*Finding{
		{Fingerprint: "abc123", RuleID: "test-1"},
		{Fingerprint: "abc123", RuleID: "test-1"}, // duplicate
		{Fingerprint: "def456", RuleID: "test-2"},
	}

	unique := s.deduplicate(findings)

	if len(unique) != 2 {
		t.Errorf("Expected 2 unique findings, got %d", len(unique))
	}
}

func BenchmarkFinding_GenerateFingerprint(b *testing.B) {
	f := &Finding{
		RuleID: "aws-access-key",
		Match:  "AKIAFAKEKEYS4TESTING",
		File:   "test.go",
		Line:   10,
		Column: 20,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.GenerateFingerprint()
	}
}
