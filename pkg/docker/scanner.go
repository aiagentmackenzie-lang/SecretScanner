package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aiagentmackenzie-lang/SecretScanner/pkg/scanner"
)

// Scanner handles Docker image scanning
type Scanner struct {
	secretScanner *scanner.Scanner
	options       *Options
}

// Options for Docker scanning
type Options struct {
	MaxLayerSize int64
	Verbose      bool
	Platform     string
}

// NewScanner creates a new Docker image scanner
func NewScanner(s *scanner.Scanner, opts *Options) *Scanner {
	if opts == nil {
		opts = &Options{
			MaxLayerSize: 500 * 1024 * 1024, // 500MB
		}
	}
	return &Scanner{
		secretScanner: s,
		options:       opts,
	}
}

// ImageResult contains scan results for an image
type ImageResult struct {
	ImageName     string              `json:"image_name"`
	ImageID       string              `json:"image_id"`
	LayersScanned int                 `json:"layers_scanned"`
	Findings      []*scanner.Finding  `json:"findings"`
	Errors        []string            `json:"errors,omitempty"`
}

// ScanImage scans a Docker image by name
func (s *Scanner) ScanImage(ctx context.Context, imageName string) (*ImageResult, error) {
	result := &ImageResult{
		ImageName: imageName,
		Findings:  make([]*scanner.Finding, 0),
	}

	// For now, this is a placeholder that would need actual Docker client integration
	// In a real implementation, this would:
	// 1. Pull the image if needed
	// 2. Export layers as tarballs
	// 3. Scan each layer's files
	// 4. Report findings with layer attribution

	return result, fmt.Errorf("docker scanning requires Docker daemon access (coming in v1.1)")
}

// ScanTarball scans a Docker image tarball (from docker save)
func (s *Scanner) ScanTarball(r io.Reader) (*ImageResult, error) {
	result := &ImageResult{
		Findings: make([]*scanner.Finding, 0),
		Errors:   make([]string, 0),
	}

	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("tar error: %v", err))
			continue
		}

		// Skip directories and large files
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Size > s.options.MaxLayerSize {
			result.Errors = append(result.Errors, fmt.Sprintf("skipping large file: %s (%d bytes)", header.Name, header.Size))
			continue
		}

		// Check if this is a layer tarball
		if strings.HasSuffix(header.Name, "/layer.tar") || strings.HasSuffix(header.Name, ".tar") {
			result.LayersScanned++
			
			// Scan the layer
			layerFindings, err := s.scanLayer(tr, header.Name)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("layer scan error: %v", err))
				continue
			}
			
			result.Findings = append(result.Findings, layerFindings...)
		}
	}

	return result, nil
}

// scanLayer scans an individual layer tarball
func (s *Scanner) scanLayer(r io.Reader, layerName string) ([]*scanner.Finding, error) {
	// Read the layer into memory (with size limit)
	buf := &bytes.Buffer{}
	limitedReader := io.LimitReader(r, s.options.MaxLayerSize)
	if _, err := io.Copy(buf, limitedReader); err != nil {
		return nil, err
	}

	// Check if it's gzip compressed
	var layerReader io.Reader = bytes.NewReader(buf.Bytes())
	if buf.Len() > 2 && buf.Bytes()[0] == 0x1f && buf.Bytes()[1] == 0x8b {
		// Gzip compressed
		gzr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			return nil, err
		}
		defer gzr.Close()
		layerReader = gzr
	}

	// Extract and scan files in the layer
	var findings []*scanner.Finding
	tr := tar.NewReader(layerReader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// Only scan regular files
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		// Skip binary files based on extension
		if isBinaryFile(header.Name) {
			continue
		}

		// Read file content
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tr, content); err != nil {
			continue
		}

		// Scan the file
		fileFindings, err := s.secretScanner.ScanBuffer(header.Name, content)
		if err != nil {
			continue
		}

		// Add layer context to findings
		for _, f := range fileFindings {
			f.Tags = append(f.Tags, "docker-layer")
			// Add layer info to context
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// isBinaryFile checks if file should be skipped based on extension
func isBinaryFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".o": true, ".a": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true,
	}
	return binaryExts[ext]
}

// ScanDirectory scans an extracted Docker image directory
func (s *Scanner) ScanDirectory(dir string) (*ImageResult, error) {
	result := &ImageResult{
		Findings: make([]*scanner.Finding, 0),
	}

	// Walk the directory
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if info.Size() > s.options.MaxLayerSize {
			return nil
		}
		if isBinaryFile(path) {
			return nil
		}

		// Read and scan file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		findings, err := s.secretScanner.ScanBuffer(path, content)
		if err != nil {
			return nil
		}

		result.Findings = append(result.Findings, findings...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// ScanFS scans a filesystem path (useful for container filesystems)
func (s *Scanner) ScanFS(dir string) (*ImageResult, error) {
	return s.ScanDirectory(dir)
}
