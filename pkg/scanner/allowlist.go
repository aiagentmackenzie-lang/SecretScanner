package scanner

import (
	"regexp"
	"strings"
)

// hasInlineIgnore checks if there's an inline ignore comment on the same line as the match
// Supports multiple formats: # secretscanner:allow, // secretscanner:allow, /* secretscanner:allow */
func (s *Scanner) hasInlineIgnore(text string, matchPos int) bool {
	// Find the line containing the match
	lineStart := matchPos
	for lineStart > 0 && text[lineStart-1] != '\n' {
		lineStart--
	}

	lineEnd := matchPos
	for lineEnd < len(text) && text[lineEnd] != '\n' {
		lineEnd++
	}

	line := text[lineStart:lineEnd]

	// Check for various ignore comment patterns
	ignorePatterns := [
]*regexp.Regexp{
		regexp.MustCompile(`(?i)#\s*secretscanner:allow`),                      // Shell, YAML, TOML, Python
		regexp.MustCompile(`(?i)//\s*secretscanner:allow`),                   // Go, C++, Java, JS
		regexp.MustCompile(`(?i)/\*\s*secretscanner:allow\s*\*/`),           // CSS, JS block
		regexp.MustCompile(`(?i)\{\{\s*/*\s*secretscanner:allow\s*\*/\s*\}\}`), // Go template
		regexp.MustCompile(`(?i)<!--\s*secretscanner:allow\s*-->`),     // HTML
		regexp.MustCompile(`(?i)\{\%\s*comment\s%\}secretscanner:allow`),  // Liquid
	}

	for _, pattern := range ignorePatterns {
		if pattern.MatchString(line) {
			return true
		}
	}

	return false
}

// hasCommitIgnore checks if a commit should be ignored
func (s *Scanner) hasCommitIgnore(commit string) bool {
	for _, allowlist := range s.config.Allowlist {
		for _, allowedCommit := range allowlist.Commits {
			if strings.HasPrefix(commit, allowedCommit) || commit == allowedCommit {
				return true
			}
		}
	}
	return false
}

// hasStopwordMatch checks if content contains stopwords that indicate false positive
func (s *Scanner) hasStopwordMatch(content string) bool {
	contentLower := strings.ToLower(content)
	for _, allowlist := range s.config.Allowlist {
		for _, stopword := range allowlist.Stopwords {
			if strings.Contains(contentLower, strings.ToLower(stopword)) {
				return true
			}
		}
	}
	return false
}

// isContentAllowed checks global allowlist rules against content
func (s *Scanner) isContentAllowed(content string) bool {
	return s.hasAllowlistMatch(content) || s.hasStopwordMatch(content)
}
