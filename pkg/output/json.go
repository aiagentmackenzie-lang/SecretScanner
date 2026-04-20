package output

import (
	"encoding/json"
	"io"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// JSONFormatter outputs findings in JSON format
type JSONFormatter struct {
	Redact bool
}

// Format outputs the report in JSON format
func (f *JSONFormatter) Format(report *scanner.Report, w io.Writer) error {
	// Maybe redact findings
	findings := report.Findings
	if f.Redact {
		findings = make([]*scanner.Finding, len(report.Findings))
		for i, finding := range report.Findings {
			findings[i] = finding.Redacted()
		}
	}

	output := struct {
		Findings       []*scanner.Finding `json:"findings"`
		FilesScanned   int                `json:"files_scanned"`
		CommitsScanned int                `json:"commits_scanned,omitempty"`
		ScanTime       string             `json:"scan_time"`
		ScannedAt      string             `json:"scanned_at"`
		Version        string             `json:"version"`
		Summary        string             `json:"summary"`
	}{
		Findings:       findings,
		FilesScanned:   report.FilesScanned,
		CommitsScanned: report.CommitsScanned,
		ScanTime:       report.ScanTime.String(),
		ScannedAt:      report.ScannedAt.Format("2006-01-02T15:04:05Z"),
		Version:        report.Version,
		Summary:        report.Summary(),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// JSONLFormatter outputs findings as JSON Lines (one JSON object per line)
type JSONLFormatter struct {
	Redact bool
}

// Format outputs findings as JSONL
func (f *JSONLFormatter) Format(report *scanner.Report, w io.Writer) error {
	encoder := json.NewEncoder(w)
	
	for _, finding := range report.Findings {
		var output *scanner.Finding
		if f.Redact {
			output = finding.Redacted()
		} else {
			output = finding
		}
		
		if err := encoder.Encode(output); err != nil {
			return err
		}
	}
	
	return nil
}
