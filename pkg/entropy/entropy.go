package entropy

import (
	"math"
	"regexp"
	"strconv"
)

// Calculator computes Shannon entropy for secret validation
type Calculator struct {
	minEntropy float64
}

// New creates a new entropy calculator
func New(minEntropy float64) *Calculator {
	return &Calculator{minEntropy: minEntropy}
}

// Calculate returns Shannon entropy H = -Σp·log₂(p)
// For a string to be considered a secret:
// - High-confidence patterns: H >= 3.5
// - Generic patterns: H >= 5.0
// - Maximum theoretical: 8.0 (for ASCII)
func (c *Calculator) Calculate(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Character frequency counting
	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	// Shannon entropy calculation
	length := float64(len(data))
	entropy := 0.0

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Special handling for hex strings to reduce false positives
	// from sequential patterns (e.g., "0123456789abcdef")
	if isHexString(data) {
		// Check if it's actually sequential or repeated pattern
		if isSequentialOrRepeated(data) {
			entropy -= 1.2 / math.Log2(length)
		}
	}

	// Penalize all-lowercase or all-upercase (less random)
	if allLowerOrUpper(data) {
		entropy *= 0.8
	}

	return entropy
}

// IsValid checks if data meets the minimum entropy threshold
func (c *Calculator) IsValid(data string) bool {
	return c.Calculate(data) >= c.minEntropy
}

// isHexString checks if string is a valid hex string
func isHexString(s string) bool {
	if len(s) == 0 {
		return true // Empty string is valid hex
	}
	matched, _ := regexp.MatchString("^[0-9a-fA-F]+$", s)
	return matched
}

// isSequentialOrRepeated checks for obvious non-random patterns
func isSequentialOrRepeated(s string) bool {
	// Check for all same character
	allSame := true
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check for sequential digits (e.g., 123456789)
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return true
	}

	// Check for sequential hex (e.g., 0123456789abcdef)
	if isHexString(s) && len(s) >= 10 {
		lowercase := regexp.MustCompile("[a-f]").MatchString(s)
		if lowercase {
			// Check common hex patterns
			patterns := []string{"0123456789abcdef", "0123456789ABCDEF", "abcdef0123456789"}
			for _, pattern := range patterns {
				if containsPattern(s, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// containsPattern checks if s contains the pattern
func containsPattern(s, pattern string) bool {
	return len(s) >= len(pattern) && (stringSimilarity(s, pattern) > 0.8)
}

// stringSimilarity simple similarity check
func stringSimilarity(a, b string) float64 {
	if len(a) > len(b) {
		a = a[:len(b)]
	}
	matches := 0
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] == b[i] || a[i] == b[i]+32 || a[i]+32 == b[i] { // case insensitive
			matches++
		}
	}
	return float64(matches) / float64(minLen)
}

// allLowerOrUpper checks if string is all lowercase or all uppercase
func allLowerOrUpper(s string) bool {
	if len(s) == 0 {
		return false
	}
	hasLower := false
	hasUpper := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
		if hasLower && hasUpper {
			return false
		}
	}
	return hasLower || hasUpper
}

// CalculateWithPenalty returns entropy with additional penalties for patterns
func CalculateWithPenalty(data string, penalties []string) float64 {
	entropy := New(0).Calculate(data)

	// Apply penalties
	for _, penalty := range penalties {
		switch penalty {
		case "hex":
			if isHexString(data) {
				entropy *= 0.9
			}
		case "base64":
			if isBase64String(data) {
				entropy *= 0.95
			}
		case "lowercase":
			if isAllLowercase(data) {
				entropy *= 0.8
			}
		case "nosymbols":
			if !hasSymbol(data) {
				entropy *= 0.85
			}
		}
	}

	return entropy
}

func isBase64String(s string) bool {
	matched, _ := regexp.MatchString("^[A-Za-z0-9+/]+={0,2}$", s)
	return matched && len(s)%4 == 0
}

func isAllLowercase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return false
		}
	}
	return true
}

func hasSymbol(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return true
		}
	}
	return false
}
