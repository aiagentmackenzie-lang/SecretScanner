package scanner

import (
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
	config      *config.Config
	options     *Options
	ahocorasick *ahocorasick.Matcher
	keywords    map[string][]int // keyword -> rule indices
	compiledREs map[int]*regexp.Regexp
	globalRegex []*regexp.Regexp // pre-compiled global allowlist regexes
	stats       Stats
	statsMu     sync.Mutex
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
	s.compileGlobalAllowlist()

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

// compileGlobalAllowlist pre-compiles global allowlist regex patterns
func (s *Scanner) compileGlobalAllowlist() {
	for _, allowlist := range s.config.Allowlist {
		for _, pattern := range allowlist.Regexes {
			re, err := regexp.Compile(pattern)
			if err == nil {
				s.globalRegex = append(s.globalRegex, re)
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

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Size() > s.options.MaxFileSize {
			return nil
		}

		if !s.shouldScanFile(path) {
			return nil
		}

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

	if s.isBinary(content) {
		return nil, nil
	}

	return s.scanContent(path, content, "")
}

// scanContent scans file content for secrets
func (s *Scanner) scanContent(filename string, content []byte, commit string) ([]*Finding, error) {
	var findings []*Finding

	text := string(content)

	// Only check path-based allowlists at file level
	if s.isAllowedPath(filename) {
		return findings, nil
	}

	// Get candidate rules using Aho-Corasick
	candidates := s.getCandidateRules(text)

	for ruleIdx := range candidates {
		rule := s.config.Rules[ruleIdx]

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

			// Check if the individual secret is allowlisted (per-match, not per-file)
			if s.isSecretAllowlisted(&rule, secret) {
				continue
			}

			// Check global allowlist against the matched secret, not the whole file
			if s.isSecretGloballyAllowlisted(secret) {
				continue
			}

			// Check entropy
			calc := entropy.New(rule.Entropy)
			if !calc.IsValid(secret) {
				continue
			}
			ent := calc.Calculate(secret)

			line, col := s.getPosition(text, match[0])

			if s.hasInlineIgnore(text, match[0]) {
				continue
			}

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

			if s.options.Verify && rule.Validate != "" {
				verified := false
				finding.Verified = &verified
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// isSecretGloballyAllowlisted checks if a specific matched secret matches global allowlist patterns
func (s *Scanner) isSecretGloballyAllowlisted(secret string) bool {
	for _, re := range s.globalRegex {
		if re.MatchString(secret) {
			return true
		}
	}
	return s.hasStopwordMatch(secret)
}

// hasStopwordMatch checks if the secret itself contains stopwords (not the whole file)
func (s *Scanner) hasStopwordMatch(secret string) bool {
	secretLower := strings.ToLower(secret)
	for _, allowlist := range s.config.Allowlist {
		for _, stopword := range allowlist.Stopwords {
			if strings.Contains(secretLower, strings.ToLower(stopword)) {
				return true
			}
		}
	}
	return false
}

// isSecretAllowlisted checks rule-specific allowlists against the matched secret
func (s *Scanner) isSecretAllowlisted(rule *config.Rule, secret string) bool {
	for _, allowlist := range rule.Allowlist {
		for _, pattern := range allowlist.Paths {
			if matched, _ := regexp.MatchString(pattern, secret); matched {
				return true
			}
		}
		for _, pattern := range allowlist.Regexes {
			if matched, _ := regexp.MatchString(pattern, secret); matched {
				return true
			}
		}
	}
	return false
}

// getCandidateRules returns rule indices that match keywords in text
func (s *Scanner) getCandidateRules(text string) map[int]bool {
	candidates := make(map[int]bool)

	if s.ahocorasick == nil {
		for i := range s.config.Rules {
			candidates[i] = true
		}
		return candidates
	}

	matches := s.ahocorasick.Match([]byte(strings.ToLower(text)))

	for _, match := range matches {
		_ = match
		for keyword, indices := range s.keywords {
			if strings.Contains(strings.ToLower(text), strings.ToLower(keyword)) {
				for _, idx := range indices {
					candidates[idx] = true
				}
			}
		}
	}

	return candidates
}

// isBinary checks if content appears to be binary
func (s *Scanner) isBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check for null bytes
	for i := 0; i < len(content); i++ {
		if content[i] == 0 {
			return true
		}
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

	var startLine, endLine int
	currOffset := 0
	for i, line := range lines {
		lineEnd := currOffset + len(line)
		if currOffset <= start && start <= lineEnd {
			startLine = i
		}
		if currOffset <= end && end <= lineEnd+1 {
			endLine = i
			break
		}
		currOffset = lineEnd + 1
	}

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

	if strings.HasSuffix(path, "package-lock.json") ||
		strings.HasSuffix(path, "yarn.lock") ||
		strings.HasSuffix(path, "Cargo.lock") {
		return false
	}

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
	return s.ScanFilesystem(repoPath)
}

// ScanGitRange scans git commits in a range
func (s *Scanner) ScanGitRange(repoPath, fromCommit, toCommit string) ([]*Finding, error) {
	return s.ScanFilesystem(repoPath)
}

// ScanBuffer scans raw bytes directly
func (s *Scanner) ScanBuffer(filename string, content []byte) ([]*Finding, error) {
	return s.scanContent(filename, content, "")
}