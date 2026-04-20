package config

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

//go:embed default.toml
var defaultConfig []byte

// Config represents the full configuration
type Config struct {
	Title     string     `toml:"title"`
	Extend    Extend     `toml:"extend"`
	Allowlist []AllowlistRule `toml:"allowlist"`
	Rules     []Rule     `toml:"rules"`
}

// Extend configuration for extending other config files
type Extend struct {
	Path       string `toml:"path"`
	URL        string `toml:"url"`
	UseDefault bool   `toml:"useDefault"`
	Description string `toml:"description"`
}

// AllowlistRule defines global allowlist patterns
type AllowlistRule struct {
	Description string   `toml:"description"`
	Paths       []string `toml:"paths"`
	Regexes     []string `toml:"regexes"`
	Commits     []string `toml:"commits"`
	Stopwords   []string `toml:"stopwords"`
}

// Rule defines a detection rule
type Rule struct {
	ID          string           `toml:"id"`
	Description string           `toml:"description"`
	Regex       string           `toml:"regex"`
	Entropy     float64          `toml:"entropy"`
	Keywords    []string         `toml:"keywords"`
	Severity    string           `toml:"severity"`
	Tags        []string         `toml:"tags"`
	Validate    string           `toml:"validate"`
	Allowlist   []AllowlistRule  `toml:"allowlist"`
	Required    []RequiredRule   `toml:"required"`
}

// RequiredRule defines required companion rules for composite detection
type RequiredRule struct {
	ID      string `toml:"id"`
	Regex   string `toml:"regex"`
	WithinLines int `toml:"withinLines"`
}

// LoadFromFile loads configuration from a TOML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	setDefaults(&cfg)

	return &cfg, nil
}

// LoadDefault loads the built-in default configuration
func LoadDefault() (*Config, error) {
	var cfg Config
	if err := toml.Unmarshal(defaultConfig, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse default config: %w", err)
	}

	setDefaults(&cfg)

	return &cfg, nil
}

func setDefaults(cfg *Config) {
	for i := range cfg.Rules {
		if cfg.Rules[i].Severity == "" {
			cfg.Rules[i].Severity = "medium"
		}
		if cfg.Rules[i].Entropy == 0 {
			cfg.Rules[i].Entropy = 3.0
		}
	}
}
