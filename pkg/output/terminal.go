package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// TerminalFormatter outputs findings in human-readable terminal format
type TerminalFormatter struct {
	Redact bool
}

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[37m"
	colorBold   = "\033[1m"
)

// Format outputs the report in terminal format
func (f *TerminalFormatter) Format(report *scanner.Report, w io.Writer) error {
	// Header
	fmt.Fprintf(w, "%s%s╭──────────────────────────────────────────────────────────────────╮%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s│%s  SecretScanner Report                                          %s%s│%s\n", colorBold, colorCyan, colorReset, "  ", colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s╰──────────────────────────────────────────────────────────────────╯%s\n\n", colorBold, colorCyan, colorReset)

	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "%s%s✓%s No secrets found\n", colorBold, colorGreen, colorReset)
		fmt.Fprintf(w, "  Scanned in %s\n", report.ScanTime)
		return nil
	}

	// Summary
	severityCounts := report.SeverityCounts()
	fmt.Fprintf(w, "%sFound %d secrets%s\n\n", colorBold, len(report.Findings), colorReset)
	
	if count := severityCounts["critical"]; count > 0 {
		fmt.Fprintf(w, "  %s%sCRITICAL%s: %d\n", colorBold, colorRed, colorReset, count)
	}
	if count := severityCounts["high"]; count > 0 {
		fmt.Fprintf(w, "  %s%sHIGH%s:     %d\n", colorBold, colorRed, colorReset, count)
	}
	if count := severityCounts["medium"]; count > 0 {
		fmt.Fprintf(w, "  %s%sMEDIUM%s:   %d\n", colorBold, colorYellow, colorReset, count)
	}
	if count := severityCounts["low"]; count > 0 {
		fmt.Fprintf(w, "  %s%sLOW%s:      %d\n", colorBold, colorBlue, colorReset, count)
	}
	fmt.Fprintln(w)

	// Findings grouped by file
	fileGroups := report.FileSummary()
	for file, findings := range fileGroups {
		fmt.Fprintf(w, "%s%s📁 %s%s\n", colorBold, colorBlue, file, colorReset)
		
		for _, finding := range findings {
			severityColor := getSeverityColor(finding.Severity)
			
			// Finding header
			fmt.Fprintf(w, "  %s%s[%s]%s%s %s%s\n", 
				colorBold, severityColor, strings.ToUpper(finding.Severity), colorReset,
				severityColor, finding.RuleID, colorReset)
			
			// Location
			fmt.Fprintf(w, "    %sLine %d, Column %d%s\n",
				colorGray, finding.Line, finding.Column, colorReset)
			
			// Match (redact if requested)
			displayFinding := finding
			if f.Redact {
				displayFinding = finding.Redacted()
			}
			match := displayFinding.Match
			if len(match) > 40 {
				match = match[:20] + "..." + match[len(match)-20:]
			}
			fmt.Fprintf(w, "    %sMatch:%s %s\n", colorBold, colorReset, match)
			
			// Description
			fmt.Fprintf(w, "    %sDescription:%s %s\n", colorBold, colorReset, finding.Description)
			
			// Tags
			if len(finding.Tags) > 0 {
				fmt.Fprintf(w, "    %sTags:%s %s\n", colorBold, colorReset, strings.Join(finding.Tags, ", "))
			}
			
			// Entropy
			fmt.Fprintf(w, "    %sEntropy:%s %.2f\n", colorBold, colorReset, finding.Entropy)
			
			fmt.Fprintln(w)
		}
	}

	// Footer
	fmt.Fprintf(w, "\n%s───────────────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Fprintf(w, "  Scanned in %s\n", report.ScanTime)
	fmt.Fprintf(w, "  Version: %s\n", report.Version)

	return nil
}

func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return colorRed
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	case "low":
		return colorBlue
	default:
		return colorReset
	}
}
