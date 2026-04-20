package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.toml")
	
	content := `
title = "Test Config"

[[allowlist]]
description = "Test allowlist"
paths = ['''vendor/''']

[[rules]]
id = "test-rule"
description = "Test Rule"
regex = '''test_[a-z]+'''
entropy = 3.0
keywords = ["test_"]
severity = "high"
tags = ["test", "rule"]
`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	cfg, err := LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if cfg.Title != "Test Config" {
		t.Errorf("Expected Title to be 'Test Config', got %s", cfg.Title)
	}

	if len(cfg.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(cfg.Rules))
	}

	if len(cfg.Allowlist) != 1 {
		t.Errorf("Expected 1 allowlist, got %d", len(cfg.Allowlist))
	}

	rule := cfg.Rules[0]
	if rule.ID != "test-rule" {
		t.Errorf("Expected rule ID to be 'test-rule', got %s", rule.ID)
	}
	if rule.Severity != "high" {
		t.Errorf("Expected severity to be 'high', got %s", rule.Severity)
	}
}

func TestLoadFromFile_NotExist(t *testing.T) {
	_, err := LoadFromFile("/non/existent/path.toml")
	if err == nil {
		t.Error("LoadFromFile() should return error for non-existent file")
	}
}

func TestLoadFromFile_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.toml")
	
	content := "invalid toml content {{{"
	os.WriteFile(configFile, []byte(content), 0644)

	_, err := LoadFromFile(configFile)
	if err == nil {
		t.Error("LoadFromFile() should return error for invalid TOML")
	}
}

func TestLoadDefault(t *testing.T) {
	cfg, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault() error = %v", err)
	}

	if cfg.Title != "SecretScanner Default Rules" {
		t.Errorf("Expected default title, got %s", cfg.Title)
	}

	// Should have default rules
	if len(cfg.Rules) == 0 {
		t.Error("LoadDefault() should have default rules")
	}

	// Should have default allowlist
	if len(cfg.Allowlist) == 0 {
		t.Error("LoadDefault() should have default allowlist")
	}
}

func TestSetDefaults(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{ID: "test-1", Severity: ""},
			{ID: "test-2", Severity: "critical", Entropy: 5.0},
			{ID: "test-3", Entropy: 0},
		},
	}

	setDefaults(cfg)

	if cfg.Rules[0].Severity != "medium" {
		t.Errorf("Expected default severity 'medium', got %s", cfg.Rules[0].Severity)
	}

	if cfg.Rules[1].Severity != "critical" {
		t.Errorf("Expected severity 'critical', got %s", cfg.Rules[1].Severity)
	}

	if cfg.Rules[1].Entropy != 5.0 {
		t.Errorf("Expected entropy 5.0, got %f", cfg.Rules[1].Entropy)
	}

	if cfg.Rules[2].Entropy != 3.0 {
		t.Errorf("Expected default entropy 3.0, got %f", cfg.Rules[2].Entropy)
	}
}

func TestAllowlistRule(t *testing.T) {
	allowlist := AllowlistRule{
		Description: "Test",
		Paths:       []string{`vendor/`, `node_modules/`},
		Regexes:     []string{`.*EXAMPLE.*`},
		Commits:     []string{"abc123"},
		Stopwords:   []string{"example", "test"},
	}

	if allowlist.Description != "Test" {
		t.Error("AllowlistRule.Description not set correctly")
	}

	if len(allowlist.Paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(allowlist.Paths))
	}
}

func TestRule(t *testing.T) {
	rule := Rule{
		ID:          "test-rule",
		Description: "Test Description",
		Regex:       `test_[a-z]+`,
		Entropy:     3.5,
		Keywords:    []string{"test_", "_key"},
		Severity:    "high",
		Tags:        []string{"test", "demo"},
		Validate:    "",
		Allowlist:   []AllowlistRule{},
		Required:    []RequiredRule{},
	}

	if rule.ID != "test-rule" {
		t.Error("Rule.ID not set correctly")
	}

	if len(rule.Keywords) != 2 {
		t.Errorf("Expected 2 keywords, got %d", len(rule.Keywords))
	}

	if len(rule.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(rule.Tags))
	}
}

func TestRequiredRule(t *testing.T) {
	required := RequiredRule{
		ID:          "companion-rule",
		Regex:       `secret_[a-z]+`,
		WithinLines: 5,
	}

	if required.WithinLines != 5 {
		t.Errorf("Expected WithinLines to be 5, got %d", required.WithinLines)
	}
}
