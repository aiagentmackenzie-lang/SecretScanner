package scanner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	ahocorasick "github.com/cloudflare/ahocorasick"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/entropy"
)

// Scanner is the main secret detection engine
type Scanner struct {
	config       *config.Config
	options      *Options
	ahocorasick  *ahocorasick.Matcher
	keywords     map[string][]int // keyword -> rule indices
	compiledREs  map[int]*regexp.Regexp
	stats        Stats
	statsMu      sync.Mutex
}

// Stats holds scanning statistics
type Stats struct {
	FilesScanned int
}

// GetStats returns the current scanning statistics
func (s *Scanner) GetStats() Stats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	return s.stats
}

// incrementFilesScanned increments the file scanned counter
func (s *Scanner) incrementFilesScanned() {
	s.statsMu.Lock()
	s.stats.FilesScanned++
	s.statsMu.Unlock()
}

// New creates a new scanner instance
func New(cfg *config.Config, opts *Options) *Scanner {
	if opts == nil {
		opts = &Options{
			MaxFileSize: 100 * 1024 * 1024, // 100MB default
			Threads:     4,
		}
	}

	if opts.Threads <= 0 {
		opts.Threads = 4
	}

	s := &Scanner{
		config:      cfg,
		options:     opts,
		keywords:    make(map[string][]int),
		compiledREs: make(map[int]*regexp.Regexp),
		stats:       Stats{},
	}

	s.buildAhoCorasick()
	s.compileRegexes()

	return s
}

// buildAhoCorasick builds the Aho-Corasick matcher from rule keywords
func (s *Scanner) buildAhoCorasick() {
	var patterns []string
	seen := make(map[string]bool)

	for idx, rule := range s.config.Rules {
		for _, keyword := range rule.Keywords {
			if !seen[keyword] {
				patterns = append(patterns, keyword)
				seen[keyword] = true
			}
			s.keywords[keyword] = append(s.keywords[keyword], idx)
		}
	}

	if len(patterns) > 0 {
		// Case-insensitive matching
		var bytePatterns [][]byte
		for i := range patterns {
			bytePatterns = append(bytePatterns, []byte(strings.ToLower(patterns[i])))
		}
		matcher := ahocorasick.NewMatcher(bytePatterns)
		s.ahocorasick = matcher
	}
}

// compileRegexes pre-compiles all rule regex patterns
func (s *Scanner) compileRegexes() {
	for idx, rule := range s.config.Rules {
		if rule.Regex != "" {
			re, err := regexp.Compile(rule.Regex)
			if err == nil {
				s.compiledREs[idx] = re
			}
		}
	}
}

// ScanFilesystem scans files and directories
func (s *Scanner) ScanFilesystem(root string) ([]*Finding, error) {
	var findings []*Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobs := make(chan string, 100)

	// Start workers
	for i := 0; i < s.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				f, err := s.scanFile(path)
				s.incrementFilesScanned()
				if err != nil {
					continue
				}
				if len(f) > 0 {
					mu.Lock()
					findings = append(findings, f...)
					mu.Unlock()
				}
			}
		}()
	}

	// Walk directory
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			// Skip git dirs
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that are too large
		if info.Size() > s.options.MaxFileSize {
			return nil
		}

		// Check if file should be scanned
		if !s.shouldScanFile(path) {
			return nil
		}

		// Check allowlist
		if s.isAllowedPath(path) {
			return nil
		}

		jobs <- path
		return nil
	})

	close(jobs)
	wg.Wait()

	if err != nil {
		return nil, err
	}

	return s.deduplicate(findings), nil
}

// scanFile scans a single file
func (s *Scanner) scanFile(path string) ([]*Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Check if binary
	isBin := s.isBinary(content)
	if isBin {
		return nil, nil
	}

	return s.scanContent(path, content, "")
}

// scanContent scans file content for secrets
func (s *Scanner) scanContent(filename string, content []byte, commit string) ([]*Finding, error) {
	var findings []*Finding

	// Convert to string for processing
	text := string(content)

	// Check allowlists first
	if s.isAllowedPath(filename) {
		return findings, nil
	}

	if s.hasAllowlistMatch(text) {
		return findings, nil
	}

	// Get candidate rules using Aho-Corasick
	candidates := s.getCandidateRules(text)

	// Scan each candidate rule
	for ruleIdx := range candidates {
		rule := s.config.Rules[ruleIdx]
		
		// Check rule-specific allowlist
		if s.isRuleAllowed(&rule, filename, text) {
			continue
		}

		// Try regex match
		re, ok := s.compiledREs[ruleIdx]
		if !ok {
			continue
		}

		matches := re.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			secret := text[match[0]:match[1]]
			
			// Check entropy
			calc := entropy.New(rule.Entropy)
			if !calc.IsValid(secret) {
				continue
			}
			ent := calc.Calculate(secret)

			// Get line and column
			line, col := s.getPosition(text, match[0])

			// Check for inline ignore comment on this line
			if s.hasInlineIgnore(text, match[0]) {
				continue
			}

			// Get context
			context := s.getContext(text, match[0], match[1])

			finding := &Finding{
				RuleID:      rule.ID,
				Description: rule.Description,
				Match:       secret,
				File:        filename,
				Line:        line,
				Column:      col,
				Severity:    rule.Severity,
				Tags:        rule.Tags,
				Entropy:     ent,
				Commit:      commit,
				Raw:         secret,
				Context:     context,
			}
			finding.Fingerprint = finding.GenerateFingerprint()

			// Set verification status if requested
			if s.options.Verify && rule.Validate != "" {
				// TODO: Implement verification
				verified := false
				finding.Verified = &verified
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// getCandidateRules returns rule indices that match keywords in text
func (s *Scanner) getCandidateRules(text string) map[int]bool {
	candidates := make(map[int]bool)

	if s.ahocorasick == nil {
		// If no Aho-Corasick, check all rules
		for i := range s.config.Rules {
			candidates[i] = true
		}
		return candidates
	}

	// Search for keywords in lowercase text
	matches := s.ahocorasick.Match([]byte(strings.ToLower(text)))
	
	for _, match := range matches {
		// Get the matched pattern
		// This is a simplified version; actual implementation would need
		// to map back to the pattern
		for keyword, indices := range s.keywords {
			if strings.Contains(strings.ToLower(text), keyword) {
				for _, idx := range indices {
					candidates[idx] = true
				}
			}
		}
		_ = match // Use match to avoid unused error
	}

	return candidates
}

// isBinary checks if content appears to be binary
func (s *Scanner) isBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check for null bytes
	if bytes.Contains(content, []byte{0}) {
		return true
	}

	// Check percentage of non-printable characters
	const sampleSize = 1024
	sample := content
	if len(sample) > sampleSize {
		sample = sample[:sampleSize]
	}

	nonPrintable := 0
	for _, b := range sample {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(len(sample)) > 0.3
}

// isAllowedPath checks if path matches global allowlist patterns
func (s *Scanner) isAllowedPath(path string) bool {
	for _, allowlist := range s.config.Allowlist {
		for _, pattern := range allowlist.Paths {
			if matched, _ := regexp.MatchString(pattern, path); matched {
				return true
			}
		}
	}
	return false
}

// hasAllowlistMatch checks if content matches global allowlist regexes
func (s *Scanner) hasAllowlistMatch(content string) bool {
	for _, allowlist := range s.config.Allowlist {
		for _, pattern := range allowlist.Regexes {
			if matched, _ := regexp.MatchString(pattern, content); matched {
				return true
			}
		}
	}
	return false
}

// isRuleAllowed checks rule-specific allowlists
func (s *Scanner) isRuleAllowed(rule *config.Rule, filename, content string) bool {
	for _, allowlist := range rule.Allowlist {
		for _, pattern := range allowlist.Paths {
			if matched, _ := regexp.MatchString(pattern, filename); matched {
				return true
			}
		}
		for _, pattern := range allowlist.Regexes {
			if matched, _ := regexp.MatchString(pattern, content); matched {
				return true
			}
		}
	}
	return false
}

// getPosition converts byte offset to line and column
func (s *Scanner) getPosition(text string, offset int) (line, col int) {
	line = 1
	col = 1

	for i, c := range text {
		if i >= offset {
			break
		}
		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}

	return line, col
}

// getContext extracts lines around a match
func (s *Scanner) getContext(text string, start, end int) []string {
	lines := strings.Split(text, "\n")
	
	// Find which lines contain the match
	var startLine, endLine int
	currOffset := 0
	for i, line := range lines {
		lineEnd := currOffset + len(line)
		if currOffset <= start && start <= lineEnd {
			startLine = i
		}
		if currOffset <= end && end <= lineEnd+1 { // +1 for newline
			endLine = i
			break
		}
		currOffset = lineEnd + 1
	}

	// Get surrounding context (2 lines before and after)
	contextStart := startLine - 2
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endLine + 3
	if contextEnd > len(lines) {
		contextEnd = len(lines)
	}

	return lines[contextStart:contextEnd]
}

// shouldScanFile checks if a file should be scanned based on extension
func (s *Scanner) shouldScanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	
	// Skip known binary extensions
	binaryExts := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".zip": true, ".tar": true, ".gz": true, ".rar": true,
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".ttf": true, ".woff": true, ".woff2": true, ".eot": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	}

	if binaryExts[ext] {
		return false
	}

	// Skip lock files
	if strings.HasSuffix(path, "package-lock.json") || 
	   strings.HasSuffix(path, "yarn.lock") ||
	   strings.HasSuffix(path, "Cargo.lock") {
		return false
	}

	// Skip large minified files
	if strings.HasSuffix(path, ".min.js") || strings.HasSuffix(path, ".min.css") {
		return false
	}

	return true
}

// deduplicate removes duplicate findings
func (s *Scanner) deduplicate(findings []*Finding) []*Finding {
	seen := make(map[string]bool)
	var unique []*Finding

	for _, f := range findings {
		if !seen[f.Fingerprint] {
			seen[f.Fingerprint] = true
			unique = append(unique, f)
		}
	}

	return unique
}

// ScanGit scans a git repository
func (s *Scanner) ScanGit(repoPath string) ([]*Finding, error) {
	return s.ScanFilesystem(repoPath)
}

// ScanStaged scans staged git changes
func (s *Scanner) ScanStaged(repoPath string) ([]*Finding, error) {
	// TODO: Implement staged scanning using git
	return s.ScanFilesystem(repoPath)
}

// ScanGitRange scans git commits in a range
func (s *Scanner) ScanGitRange(repoPath, fromCommit, toCommit string) ([]*Finding, error) {
	// TODO: Implement git range scanning
	return s.ScanFilesystem(repoPath)
}

// ScanBuffer scans raw bytes directly
func (s *Scanner) ScanBuffer(filename string, content []byte) ([]*Finding, error) {
	return s.scanContent(filename, content, "")
}
