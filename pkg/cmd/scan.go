package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/output"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

type scanOptions struct {
	sources         []string
	configFile      string
	format          string
	output          string
	severity        []string
	failOnFindings  bool
	staged          bool
	fromCommit      string
	toCommit        string
	baseline        string
	maxFileSize     int64
	threads         int
	verbose         bool
	redact          bool
	verify          bool
	verifyStatus    string
	gitLogOpts      string
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files, directories, or git repositories for secrets",
		Long: `Scan for secrets in files, directories, or git repositories.

Examples:
  # Scan current directory
  secretscanner scan .

  # Scan specific files
  secretscanner scan file1.txt file2.txt

  # Scan git repository history
  secretscanner scan --git .

  # Scan staged changes only
  secretscanner scan --staged

  # Output SARIF format for GitHub
  secretscanner scan --format sarif --output results.sarif

  # Only show high/critical severity
  secretscanner scan --severity high,critical`,
		RunE: opts.run,
	}

	// Flags
	cmd.Flags().StringVarP(&opts.configFile, "config", "c", "", "Config file path (TOML format)")
	cmd.Flags().StringVarP(&opts.format, "format", "f", "json", "Output format: json, sarif, csv, terminal")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringSliceVarP(&opts.severity, "severity", "s", nil, "Filter by severity: critical,high,medium,low")
	cmd.Flags().BoolVar(&opts.failOnFindings, "fail-on-findings", false, "Exit with code 1 if secrets found")
	cmd.Flags().BoolVar(&opts.staged, "staged", false, "Scan staged changes only (git)")
	cmd.Flags().StringVar(&opts.fromCommit, "from-commit", "", "Commit to start scanning from")
	cmd.Flags().StringVar(&opts.toCommit, "to-commit", "", "Commit to stop scanning at")
	cmd.Flags().StringVar(&opts.baseline, "baseline", "", "Baseline file to skip known findings")
	cmd.Flags().Int64Var(&opts.maxFileSize, "max-file-size", 100*1024*1024, "Maximum file size to scan (bytes)")
	cmd.Flags().IntVarP(&opts.threads, "threads", "t", 0, "Number of parallel threads (0 = auto)")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&opts.redact, "redact", false, "Redact secrets in output")
	cmd.Flags().BoolVar(&opts.verify, "verify", false, "Verify secrets with live API calls")
	cmd.Flags().StringVar(&opts.verifyStatus, "verify-status", "", "Filter by verification status: valid,invalid,revoked,error,unknown")
	cmd.Flags().StringVar(&opts.gitLogOpts, "log-opts", "", "Additional git log options")

	return cmd
}

func (o *scanOptions) run(cmd *cobra.Command, args []string) error {
	// Determine sources
	if len(args) == 0 {
		args = []string{"."}
	}
	o.sources = args

	// Load configuration
	cfg, err := o.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create scanner
	s := scanner.New(cfg, &scanner.Options{
		MaxFileSize: o.maxFileSize,
		Threads:     o.threads,
		Verbose:     o.verbose,
		Redact:      o.redact,
		Verify:      o.verify,
	})

	// Run scan
	startTime := time.Now()
	var findings []*scanner.Finding

	if o.staged {
		findings, err = s.ScanStaged(o.sources[0])
	} else if o.fromCommit != "" || o.toCommit != "" {
		findings, err = s.ScanGitRange(o.sources[0], o.fromCommit, o.toCommit)
	} else {
		// Check if source is a git repo
		for _, source := range o.sources {
			if isGitRepo(source) {
				f, err := s.ScanGit(source)
				if err != nil {
					return err
				}
				findings = append(findings, f...)
			} else {
				f, err := s.ScanFilesystem(source)
				if err != nil {
					return err
				}
				findings = append(findings, f...)
			}
		}
	}

	if err != nil {
		return err
	}

	// Apply severity filter
	if len(o.severity) > 0 {
		findings = filterBySeverity(findings, o.severity)
	}

	// Load baseline and filter
	if o.baseline != "" {
		findings, err = filterByBaseline(findings, o.baseline)
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}
	}

	// Verify findings if requested
	if o.verify {
		findings = verifyFindings(findings, o.verifyStatus)
	}

	// Generate report
	report := &scanner.Report{
		Findings:   findings,
		FilesScanned: s.GetStats().FilesScanned,
		ScanTime:   time.Since(startTime),
		ScannedAt:  time.Now(),
		Version:    cmd.Root().Version,
	}

	// Output results
	if err := o.outputResults(report); err != nil {
		return err
	}

	// Exit with appropriate code
	if o.failOnFindings && len(findings) > 0 {
		os.Exit(1)
	}

	return nil
}

func (o *scanOptions) loadConfig() (*config.Config, error) {
	if o.configFile != "" {
		return config.LoadFromFile(o.configFile)
	}
	return config.LoadDefault()
}

func (o *scanOptions) outputResults(report *scanner.Report) error {
	var formatter output.Formatter

	switch strings.ToLower(o.format) {
	case "json":
		formatter = &output.JSONFormatter{Redact: o.redact}
	case "sarif":
		formatter = &output.SARIFFormatter{}
	case "csv":
		formatter = &output.CSVFormatter{}
	case "terminal":
		formatter = &output.TerminalFormatter{}
	default:
		return fmt.Errorf("unknown output format: %s", o.format)
	}

	var out *os.File
	if o.output == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(o.output)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	return formatter.Format(report, out)
}

func isGitRepo(path string) bool {
	gitPath := filepath.Join(path, ".git")
	info, err := os.Stat(gitPath)
	return err == nil && info.IsDir()
}

func filterBySeverity(findings []*scanner.Finding, severities []string) []*scanner.Finding {
	severityMap := make(map[string]bool)
	for _, s := range severities {
		severityMap[strings.ToLower(s)] = true
	}

	var filtered []*scanner.Finding
	for _, f := range findings {
		if severityMap[strings.ToLower(f.Severity)] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterByBaseline(findings []*scanner.Finding, baselinePath string) ([]*scanner.Finding, error) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, err
	}

	var baseline scanner.Report
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}

	baselineFingerprints := make(map[string]bool)
	for _, f := range baseline.Findings {
		baselineFingerprints[f.Fingerprint] = true
	}

	var filtered []*scanner.Finding
	for _, f := range findings {
		if !baselineFingerprints[f.Fingerprint] {
			filtered = append(filtered, f)
		}
	}
	return filtered, nil
}
