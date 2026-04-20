package docker

import (
	"bytes"
	"testing"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/config"
	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

func TestNewScanner(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := scanner.New(cfg, nil)
	dockers := NewScanner(s, nil)
	
	if dockers == nil {
		t.Fatal("NewScanner() returned nil")
	}
	if dockers.secretScanner != s {
		t.Error("secretScanner not set correctly")
	}
}

func TestNewScanner_WithOptions(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := scanner.New(cfg, nil)
	opts := &Options{
		MaxLayerSize: 100 * 1024 * 1024,
		Verbose:      true,
	}
	
	dockers := NewScanner(s, opts)
	if dockers.options.MaxLayerSize != opts.MaxLayerSize {
		t.Error("Options not set correctly")
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"test.exe", true},
		{"test.so", true},
		{"test.dylib", true},
		{"test.jpg", true},
		{"test.png", true},
		{"test.pdf", true},
		{"test.go", false},
		{"README.md", false},
		{"config.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryFile(tt.name)
			if got != tt.expected {
				t.Errorf("isBinaryFile(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestScanner_ScanTarball_Empty(t *testing.T) {
	cfg, _ := config.LoadDefault()
	s := scanner.New(cfg, nil)
	d := NewScanner(s, nil)
	
	// Empty tarball
	var buf bytes.Buffer
	result, err := d.ScanTarball(&buf)
	if err != nil {
		t.Fatalf("ScanTarball() error = %v", err)
	}
	
	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings from empty tarball, got %d", len(result.Findings))
	}
}

func TestImageResult(t *testing.T) {
	result := &ImageResult{
		ImageName:     "test:latest",
		ImageID:       "sha256:abc123",
		LayersScanned: 3,
	}
	
	if result.ImageName != "test:latest" {
		t.Error("ImageName not set correctly")
	}
	if result.LayersScanned != 3 {
		t.Errorf("Expected 3 layers scanned, got %d", result.LayersScanned)
	}
}
