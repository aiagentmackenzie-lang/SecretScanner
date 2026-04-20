package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// BaselineStore represents a stored baseline for diff comparison
type BaselineStore struct {
	Version      string            `json:"version"`
	GeneratedAt  time.Time         `json:"generated_at"`
	Findings     []BaselineFinding `json:"findings"`
}

// BaselineFinding represents a finding stored in the baseline
type BaselineFinding struct {
	RuleID      string `json:"rule_id"`
	Fingerprint string `json:"fingerprint"`
	Match       string `json:"match"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
}

// ToBaselineFinding converts a Finding to BaselineFinding
func (f *Finding) ToBaselineFinding() BaselineFinding {
	return BaselineFinding{
		RuleID:      f.RuleID,
		Fingerprint: f.Fingerprint,
		Match:       f.Match,
		File:        f.File,
		Line:        f.Line,
		Severity:    f.Severity,
	}
}

// SaveBaseline saves a report as a baseline file
func SaveBaseline(report *Report, path string) error {
	baseline := &BaselineStore{
		Version:     "1.0",
		GeneratedAt: time.Now(),
		Findings:    make([]BaselineFinding, 0, len(report.Findings)),
	}

	for _, f := range report.Findings {
		baseline.Findings = append(baseline.Findings, f.ToBaselineFinding())
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	return nil
}

// LoadBaseline loads a baseline file
func LoadBaseline(path string) (*BaselineStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var baseline BaselineStore
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	return &baseline, nil
}

// FilterNewFindings returns only findings not present in the baseline
func FilterNewFindings(findings []*Finding, baseline *BaselineStore) []*Finding {
	if baseline == nil {
		return findings
	}

	// Build lookup map
	baselineFPs := make(map[string]bool)
	for _, bf := range baseline.Findings {
		baselineFPs[bf.Fingerprint] = true
	}

	// Filter to new findings only
	var newFindings []*Finding
	for _, f := range findings {
		if !baselineFPs[f.Fingerprint] {
			newFindings = append(newFindings, f)
		}
	}

	return newFindings
}

// ComputeBaselineFingerprint generates a fingerprint for baseline comparison
// that is resistant to line number changes
func ComputeBaselineFingerprint(f *Finding) string {
	// Use rule ID, file, and a hash of the secret (not exact match)
	// This helps handle cases where line numbers change but secret stays same
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte(f.File))
	// Include only first 8 chars of match to handle minor variations
	if len(f.Match) > 8 {
		h.Write([]byte(f.Match[:8]))
	} else {
		h.Write([]byte(f.Match))
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

// Status represents the status of findings relative to baseline
type Status int

const (
	StatusNew     Status = iota // Finding not in baseline
	StatusExisting              // Finding in baseline (known issue)
	StatusResolved              // Was in baseline but no longer found
)

// FindingStatus categorizes findings based on baseline comparison
type FindingStatus struct {
	Finding *Finding
	Status  Status
}

// CompareWithBaseline compares findings against baseline
func CompareWithBaseline(findings []*Finding, baseline *BaselineStore) []FindingStatus {
	if baseline == nil {
		// No baseline - all are new
		statuses := make([]FindingStatus, len(findings))
		for i, f := range findings {
			statuses[i] = FindingStatus{Finding: f, Status: StatusNew}
		}
		return statuses
	}

	// Build maps
	baselineFPs := make(map[string]BaselineFinding)
	for _, bf := range baseline.Findings {
		baselineFPs[bf.Fingerprint] = bf
	}

	currentFPs := make(map[string]*Finding)
	for _, f := range findings {
		currentFPs[f.Fingerprint] = f
	}

	// Categorize
	var statuses []FindingStatus

	// Check each current finding
	for _, f := range findings {
		if _, exists := baselineFPs[f.Fingerprint]; exists {
			statuses = append(statuses, FindingStatus{Finding: f, Status: StatusExisting})
		} else {
			statuses = append(statuses, FindingStatus{Finding: f, Status: StatusNew})
		}
	}

	// Check for resolved findings
	for fp, bf := range baselineFPs {
		if _, exists := currentFPs[fp]; !exists {
			// This finding was in baseline but not found now
			statuses = append(statuses, FindingStatus{
				Finding: &Finding{
					RuleID:      bf.RuleID,
					Fingerprint: bf.Fingerprint,
					Match:       bf.Match,
					File:        bf.File,
					Line:        bf.Line,
					Severity:    bf.Severity,
				},
				Status: StatusResolved,
			})
		}
	}

	return statuses
}

// Statistics represents baseline comparison statistics
type Statistics struct {
	Total       int
	New         int
	Existing    int
	Resolved    int
	BySeverity  map[string]int
}

// GetStatistics computes statistics from statuses
func GetStatistics(statuses []FindingStatus) Statistics {
	stats := Statistics{
		BySeverity: make(map[string]int),
	}

	for _, s := range statuses {
		stats.Total++
		
		switch s.Status {
		case StatusNew:
			stats.New++
		case StatusExisting:
			stats.Existing++
		case StatusResolved:
			stats.Resolved++
		}

		if s.Finding != nil {
			stats.BySeverity[s.Finding.Severity]++
		}
	}

	return stats
}
