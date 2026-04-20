package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
)

func TestScanner_isBinary(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "plain text",
			content:  []byte("Hello, World!"),
			expected: false,
		},
		{
			name:     "text with newlines",
			content:  []byte("Line 1\nLine 2\nLine 3"),
			expected: false,
		},
		{
			name:     "binary with null bytes",
			content:  []byte{0x48, 0x65, 0x6c, 0x00, 0x6f},
			expected: true,
		},
		{
			name:     "empty content",
			content:  []byte{},
			expected: false,
		},
		{
			name:     "mostly binary (>30% non-printable)",
			content:  append(make([]byte, 100), []byte("abc")...),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isBinary(tt.content)
			if got != tt.expected {
				t.Errorf("isBinary() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScanner_shouldScanFile(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "go file",
			path:     "test.go",
			expected: true,
		},
		{
			name:     "text file",
			path:     "config.txt",
			expected: true,
		},
		{
			name:     "jpg file",
			path:     "image.jpg",
			expected: false,
		},
		{
			name:     "lock file",
			path:     "package-lock.json",
			expected: false,
		},
		{
			name:     "minified js",
			path:     "bundle.min.js",
			expected: false,
		},
		{
			name:     "binary exe",
			path:     "program.exe",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.shouldScanFile(tt.path)
			if got != tt.expected {
				t.Errorf("shouldScanFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestScanner_getPosition(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	text := "Line 1\nLine 2\nLine 3"

	tests := []struct {
		name      string
		offset    int
		wantLine  int
		wantCol   int
	}{
		{
			name:     "first line",
			offset:   0,
			wantLine: 1,
			wantCol:  1,
		},
		{
			name:     "second line",
			offset:   7,
			wantLine: 2,
			wantCol:  1,
		},
		{
			name:     "third line",
			offset:   14,
			wantLine: 3,
			wantCol:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLine, gotCol := s.getPosition(text, tt.offset)
			if gotLine != tt.wantLine {
				t.Errorf("getPosition() line = %d, want %d", gotLine, tt.wantLine)
			}
			if gotCol != tt.wantCol {
				t.Errorf("getPosition() column = %d, want %d", gotCol, tt.wantCol)
			}
		})
	}
}

func TestScanner_getContext(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	text := "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

	context := s.getContext(text, 7, 12) // Match "Line 2"

	if len(context) == 0 {
		t.Error("getContext() returned empty context")
	}

	// Should include surrounding lines
	found := false
	for _, line := range context {
		if line == "Line 2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("getContext() should include the matching line")
	}
}

func TestScanner_ScanBuffer(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	content := []byte(`api_key = "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY"
database = "postgres"`)

	findings, err := s.ScanBuffer("test.go", content)
	if err != nil {
		t.Fatalf("ScanBuffer() error = %v", err)
	}

	// Should find the GitHub token
	found := false
	for _, f := range findings {
		if f.RuleID == "github-pat" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ScanBuffer() should find github-pat token")
	}
}

func TestScanner_ScanFilesystem(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	// Create temp directory with test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("github_pat=ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	findings, err := s.ScanFilesystem(tmpDir)
	if err != nil {
		t.Fatalf("ScanFilesystem() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "github-pat" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ScanFilesystem() should find github-pat token in temp directory")
	}
}

func TestScanner_ScanBuffer_NoFalsePositives(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	// Content with low entropy (should not trigger)
	content := []byte(`password = "example_password_123"
secret_key = "test_secret_key"
`) 

	findings, err := s.ScanBuffer("test.go", content)
	if err != nil {
		t.Fatalf("ScanBuffer() error = %v", err)
	}

	// Should filter out example/test secrets based on allowlist
	for _, f := range findings {
		if f.Match == "example_password_123" || f.Match == "test_secret_key" {
			t.Errorf("ScanBuffer() found false positive: %s", f.Match)
		}
	}
}

func TestScanner_isAllowedPath(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "vendor path",
			path:     "vendor/github.com/test/lib.go",
			expected: true,
		},
		{
			name:     "node_modules path",
			path:     "node_modules/express/index.js",
			expected: true,
		},
		{
			name:     "normal source file",
			path:     "src/main.go",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isAllowedPath(tt.path)
			if got != tt.expected {
				t.Errorf("isAllowedPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func BenchmarkScanBuffer(b *testing.B) {
	cfg, _ := config.LoadDefault()
	s := New(cfg, nil)
	content := []byte(`api_key = "ghp_FAKE0TOKEN0FOR0TESTING0PURPOSES0ONLY"
slack_token = "SLCK-BOT-TOKEN-FOR-BENCHMARK-TEST-CASE"
secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.ScanBuffer("test.go", content)
	}
}
