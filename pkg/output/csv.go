package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// CSVFormatter outputs findings in CSV format
type CSVFormatter struct {
	Redact bool
}

// Format outputs the report in CSV format
func (f *CSVFormatter) Format(report *scanner.Report, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{
		"Rule ID",
		"Description",
		"Match",
		"File",
		"Line",
		"Column",
		"Severity",
		"Tags",
		"Entropy",
		"Fingerprint",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write findings
	for _, finding := range report.Findings {
		displayFinding := finding
		if f.Redact {
			displayFinding = finding.Redacted()
		}
		verified := ""
		if finding.Verified != nil {
			verified = strconv.FormatBool(*finding.Verified)
		}

		fingerprint := finding.Fingerprint
		if len(fingerprint) > 16 {
			fingerprint = fingerprint[:16] + "..."
		}

		record := []string{
			displayFinding.RuleID,
			displayFinding.Description,
			displayFinding.Match,
			displayFinding.File,
			strconv.Itoa(displayFinding.Line),
			strconv.Itoa(displayFinding.Column),
			displayFinding.Severity,
			formatTags(displayFinding.Tags),
			fmt.Sprintf("%.2f", displayFinding.Entropy),
			fingerprint,
			verified,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}

func formatTags(tags []string) string {
	result := ""
	for i, tag := range tags {
		if i > 0 {
			result += ","
		}
		result += tag
	}
	return result
}
