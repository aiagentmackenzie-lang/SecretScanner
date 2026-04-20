package scanner

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Finding represents a detected secret
type Finding struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	Description string    `json:"description"`
	Match       string    `json:"match"`
	File        string    `json:"file"`
	Line        int       `json:"line"`
	Column      int       `json:"column"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags"`
	Entropy     float64   `json:"entropy"`
	Fingerprint string    `json:"fingerprint"`
	Timestamp   time.Time `json:"timestamp"`
	Verified    *bool     `json:"verified,omitempty"`
	Account     string    `json:"account,omitempty"`
	Message     string    `json:"message,omitempty"`
	Commit      string    `json:"commit,omitempty"`
	Author      string    `json:"author,omitempty"`
	Email       string    `json:"email,omitempty"`
	Date        time.Time `json:"date,omitempty"`
	Context     []string  `json:"context,omitempty"`
	Raw         string    `json:"raw,omitempty"`
}

// GenerateFingerprint creates a unique fingerprint for deduplication
func (f *Finding) GenerateFingerprint() string {
	// Create a unique hash based on rule, file, line, and matched content
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte(f.File))
	h.Write([]byte(fmt.Sprintf("%d:%d", f.Line, f.Column)))
	h.Write([]byte(f.Match))
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

// Redacted returns the finding with redacted secret content
func (f *Finding) Redacted() *Finding {
	redacted := *f
	if len(f.Match) > 8 {
		redacted.Match = f.Match[:4] + "***" + f.Match[len(f.Match)-4:]
	} else {
		redacted.Match = "***"
	}
	redacted.Raw = ""
	return &redacted
}

// Report represents the complete scan results
type Report struct {
	Findings       []*Finding     `json:"findings"`
	FilesScanned   int            `json:"files_scanned"`
	CommitsScanned int            `json:"commits_scanned,omitempty"`
	ScanTime       time.Duration  `json:"scan_time"`
	ScannedAt      time.Time      `json:"scanned_at"`
	Version        string         `json:"version"`
	Config         map[string]any `json:"config,omitempty"`
}

// Summary returns a brief summary of the report
func (r *Report) Summary() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Found %d secrets", len(r.Findings)))
	if r.FilesScanned > 0 {
		parts = append(parts, fmt.Sprintf("scanned %d files", r.FilesScanned))
	}
	if r.CommitsScanned > 0 {
		parts = append(parts, fmt.Sprintf("scanned %d commits", r.CommitsScanned))
	}
	parts = append(parts, fmt.Sprintf("in %s", r.ScanTime))
	return strings.Join(parts, ", ")
}

// SeverityCounts returns counts by severity
func (r *Report) SeverityCounts() map[string]int {
	counts := make(map[string]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// FileSummary returns findings grouped by file
func (r *Report) FileSummary() map[string][]*Finding {
	summary := make(map[string][]*Finding)
	for _, f := range r.Findings {
		summary[f.File] = append(summary[f.File], f)
	}
	return summary
}

// Options for scanner configuration
type Options struct {
	MaxFileSize int64
	Threads     int
	Verbose     bool
	Redact      bool
	Verify      bool
	ShowContext bool
}

// FileInfo represents information about a file being scanned
type FileInfo struct {
	Path       string
	Size       int64
	Content    []byte
	IsBinary   bool
	LineCount  int
}

// IsText returns true if the file appears to be text
func (fi *FileInfo) IsText() bool {
	return !fi.IsBinary
}
