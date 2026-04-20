package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// SARIFFormatter outputs findings in SARIF format for GitHub Code Scanning
type SARIFFormatter struct {
	Redact bool
}

// SARIF root structure
type sarifReport struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []sarifRun     `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	InformationURI  string          `json:"informationUri"`
	Rules           []sarifRule     `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Help             sarifMessage        `json:"help"`
	HelpURI          string              `json:"helpUri"`
	Properties       sarifRuleProps      `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Precision         string   `json:"precision"`
	SecuritySeverity    string   `json:"security-severity"`
	Tags               []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations"`
	PartialFingerprints sarifFingerprints `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	Snippet     sarifMessage `json:"snippet,omitempty"`
}

type sarifFingerprints struct {
	Primary string `json:"primary"`
}

// Format outputs the report in SARIF format
func (f *SARIFFormatter) Format(report *scanner.Report, w io.Writer) error {
	rulesMap := make(map[string]sarifRule)
	var results []sarifResult

	for _, finding := range report.Findings {
		// Add rule if not seen
		if _, ok := rulesMap[finding.RuleID]; !ok {
			rulesMap[finding.RuleID] = sarifRule{
				ID:   finding.RuleID,
				Name: finding.RuleID,
				ShortDescription: sarifMessage{
					Text: finding.Description,
				},
				FullDescription: sarifMessage{
					Text: finding.Description,
				},
				DefaultConfiguration: sarifRuleConfig{
					Level: severityToLevel(finding.Severity),
				},
				Help: sarifMessage{
					Text: finding.Description,
				},
				HelpURI:          fmt.Sprintf("https://github.com/aiagentmackenzie-lang/SecretScanner/blob/main/rules/%s.md", finding.RuleID),
				Properties: sarifRuleProps{
					Precision:        "high",
					SecuritySeverity: severityToScore(finding.Severity),
					Tags:             finding.Tags,
				},
			}
		}

		// Redact if requested
		displayFinding := finding
		if f.Redact {
			displayFinding = finding.Redacted()
		}

		// Create result
		result := sarifResult{
			RuleID: displayFinding.RuleID,
			Level:  severityToLevel(displayFinding.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s: %s", displayFinding.Description, displayFinding.Match),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{
							URI: filepath.ToSlash(displayFinding.File),
						},
						Region: sarifRegion{
							StartLine:   displayFinding.Line,
							StartColumn: displayFinding.Column,
							Snippet: sarifMessage{
								Text: truncate(displayFinding.Match, 100),
							},
						},
					},
				},
			},
			PartialFingerprints: sarifFingerprints{
				Primary: displayFinding.Fingerprint,
			},
		}

		results = append(results, result)
	}

	// Convert rules map to slice
	var rules []sarifRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	// Build SARIF report
	sarif := sarifReport{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "SecretScanner",
						Version:        report.Version,
						InformationURI: "https://github.com/aiagentmackenzie-lang/SecretScanner",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

func severityToScore(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "6.5"
	case "low":
		return "4.0"
	default:
		return "6.5"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
