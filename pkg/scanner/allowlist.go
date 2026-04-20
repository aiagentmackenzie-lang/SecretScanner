package scanner

import (
	"regexp"
	"strings"
)

// hasInlineIgnore checks if there's an inline ignore comment on the same line as the match
func (s *Scanner) hasInlineIgnore(text string, matchPos int) bool {
	lineStart := matchPos
	for lineStart > 0 && text[lineStart-1] != '\n' {
		lineStart--
	}

	lineEnd := matchPos
	for lineEnd < len(text) && text[lineEnd] != '\n' {
		lineEnd++
	}

	line := text[lineStart:lineEnd]

	ignorePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)#\s*secretscanner:allow`),
		regexp.MustCompile(`(?i)//\s*secretscanner:allow`),
		regexp.MustCompile(`(?i)/\*\s*secretscanner:allow\s*\*/`),
		regexp.MustCompile(`(?i)\{\{\s*/*\s*secretscanner:allow\s*\*/\s*\}\}`),
		regexp.MustCompile(`(?i)<!--\s*secretscanner:allow\s*-->`),
		regexp.MustCompile(`(?i)\{\%\s*comment\s%\}secretscanner:allow`),
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