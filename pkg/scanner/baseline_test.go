package scanner

import (
	"path/filepath"
	"testing"
)

func TestBaselineStorage(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "test-baseline.json")

	// Create report
	report := &Report{
		Findings: []*Finding{
			{
				RuleID:      "test-rule",
				Fingerprint: "abc123",
				Match:       "secret123",
				File:        "test.go",
				Line:        10,
				Severity:    "high",
			},
		},
	}

	// Save baseline
	err := SaveBaseline(report, baselinePath)
	if err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}

	// Load baseline
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("LoadBaseline() error = %v", err)
	}

	// Verify loaded data
	if baseline.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", baseline.Version)
	}

	if len(baseline.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(baseline.Findings))
	}

	finding := baseline.Findings[0]
	if finding.RuleID != "test-rule" {
		t.Errorf("Expected rule ID 'test-rule', got %s", finding.RuleID)
	}
	if finding.Fingerprint != "abc123" {
		t.Errorf("Expected fingerprint 'abc123', got %s", finding.Fingerprint)
	}
}

func TestLoadBaseline_NotExist(t *testing.T) {
	_, err := LoadBaseline("/non/existent/path.json")
	if err == nil {
		t.Error("LoadBaseline() should return error for non-existent file")
	}
}

func TestFilterNewFindings(t *testing.T) {
	baseline := &BaselineStore{
		Findings: []BaselineFinding{
			{Fingerprint: "abc123", RuleID: "test-1"},
			{Fingerprint: "def456", RuleID: "test-2"},
		},
	}

	findings := []*Finding{
		{Fingerprint: "abc123", RuleID: "test-1"},       // Existing
		{Fingerprint: "new789", RuleID: "test-3"},        // New
		{Fingerprint: "newabc", RuleID: "test-4"},        // New
	}

	newFindings := FilterNewFindings(findings, baseline)

	if len(newFindings) != 2 {
		t.Errorf("Expected 2 new findings, got %d", len(newFindings))
	}

	fingerprintMap := make(map[string]bool)
	for _, f := range newFindings {
		fingerprintMap[f.Fingerprint] = true
	}

	if !fingerprintMap["new789"] || !fingerprintMap["newabc"] {
		t.Error("Expected 'new789' and 'newabc' to be in new findings")
	}

	if fingerprintMap["abc123"] {
		t.Error("'abc123' should not be in new findings")
	}
}

func TestFilterNewFindings_NoBaseline(t *testing.T) {
	findings := []*Finding{
		{Fingerprint: "abc123", RuleID: "test-1"},
		{Fingerprint: "def456", RuleID: "test-2"},
	}

	newFindings := FilterNewFindings(findings, nil)

	if len(newFindings) != 2 {
		t.Errorf("With no baseline, all findings should be new, got %d", len(newFindings))
	}
}

func TestCompareWithBaseline(t *testing.T) {
	baseline := &BaselineStore{
		Findings: []BaselineFinding{
			{Fingerprint: "old1", RuleID: "test-1", Match: "secret1"},
			{Fingerprint: "old2", RuleID: "test-2", Match: "secret2"},
		},
	}

	findings := []*Finding{
		{Fingerprint: "old1", RuleID: "test-1", Match: "secret1"}, // Existing
		{Fingerprint: "new1", RuleID: "test-3", Match: "secret3"}, // New
	}

	statuses := CompareWithBaseline(findings, baseline)

	if len(statuses) != 3 {
		t.Errorf("Expected 3 statuses (1 existing + 1 new + 1 resolved), got %d", len(statuses))
	}

	var newCount, existingCount, resolvedCount int
	for _, s := range statuses {
		switch s.Status {
		case StatusNew:
			newCount++
		case StatusExisting:
			existingCount++
		case StatusResolved:
			resolvedCount++
		}
	}

	if newCount != 1 {
		t.Errorf("Expected 1 new finding, got %d", newCount)
	}
	if existingCount != 1 {
		t.Errorf("Expected 1 existing finding, got %d", existingCount)
	}
	if resolvedCount != 1 {
		t.Errorf("Expected 1 resolved finding, got %d", resolvedCount)
	}
}

func TestGetStatistics(t *testing.T) {
	statuses := []FindingStatus{
		{Status: StatusNew, Finding: &Finding{Severity: "high"}},
		{Status: StatusNew, Finding: &Finding{Severity: "critical"}},
		{Status: StatusExisting, Finding: &Finding{Severity: "medium"}},
		{Status: StatusResolved, Finding: &Finding{Severity: "low"}},
	}

	stats := GetStatistics(statuses)

	if stats.Total != 4 {
		t.Errorf("Expected total 4, got %d", stats.Total)
	}
	if stats.New != 2 {
		t.Errorf("Expected 2 new, got %d", stats.New)
	}
	if stats.Existing != 1 {
		t.Errorf("Expected 1 existing, got %d", stats.Existing)
	}
	if stats.Resolved != 1 {
		t.Errorf("Expected 1 resolved, got %d", stats.Resolved)
	}

	if stats.BySeverity["high"] != 1 {
		t.Errorf("Expected 1 high severity, got %d", stats.BySeverity["high"])
	}
	if stats.BySeverity["critical"] != 1 {
		t.Errorf("Expected 1 critical severity, got %d", stats.BySeverity["critical"])
	}
}

func TestFinding_ToBaselineFinding(t *testing.T) {
	finding := &Finding{
		RuleID:      "test-rule",
		Fingerprint: "abc123",
		Match:       "secret123",
		File:        "test.go",
		Line:        10,
		Severity:    "high",
	}

	bf := finding.ToBaselineFinding()

	if bf.RuleID != "test-rule" {
		t.Errorf("Expected RuleID 'test-rule', got %s", bf.RuleID)
	}
	if bf.Line != 10 {
		t.Errorf("Expected Line 10, got %d", bf.Line)
	}
}

func TestComputeBaselineFingerprint(t *testing.T) {
	f1 := &Finding{
		RuleID:      "test-rule",
		Fingerprint: "abc123",
		Match:       "secret123",
		File:        "test.go",
		Line:        10,
	}

	f2 := &Finding{
		RuleID:      "test-rule",
		Fingerprint: "abc123",
		Match:       "secret123",
		File:        "test.go",
		Line:        20, // Different line
	}

	bfp1 := ComputeBaselineFingerprint(f1)
	bfp2 := ComputeBaselineFingerprint(f2)

	// Should be the same because they use rule + file + match prefix
	if bfp1 != bfp2 {
		t.Error("Baseline fingerprints should be the same regardless of line number")
	}

	f3 := &Finding{
		RuleID:      "different-rule",
		Fingerprint: "different",
		Match:       "secret123",
		File:        "test.go",
		Line:        10,
	}

	bfp3 := ComputeBaselineFingerprint(f3)
	if bfp1 == bfp3 {
		t.Error("Different rules should have different baseline fingerprints")
	}
}

func BenchmarkComputeBaselineFingerprint(b *testing.B) {
	f := &Finding{
		RuleID:      "test-rule",
		Fingerprint: "abc123",
		Match:       "secret123",
		File:        "test.go",
		Line:        10,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeBaselineFingerprint(f)
	}
}
