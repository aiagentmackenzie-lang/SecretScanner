# 🔐 SecretScanner

A high-performance, modern secret detection engine for SOC analysts and DevSecOps teams. Built in Go with signal-over-noise detection capabilities.

## Features

- ⚡ **Fast Scanning**: Multi-threaded file scanning with Aho-Corasick prefiltering
- 🎯 **High Signal-to-Noise**: Entropy-based filtering, contextual rule matching, and smart allowlists
- 🔍 **53 Detection Rules**: AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, Kubernetes, and more
- 🛡️ **Live Verification**: Verify GitHub, Slack, Stripe, OpenAI, Anthropic keys via API
- 📊 **Multiple Output Formats**: JSON, SARIF (GitHub Code Scanning), CSV, Terminal
- 🧠 **Smart Allowlists**: Path-based, regex-based, stopword, and inline comment exclusions
- 🔗 **Git Awareness**: Detects `.git/` directories (full git history scanning coming soon)
- 🚀 **CI/CD Ready**: Exit codes for pipeline integration, SARIF output for GitHub Security tab
- 🔒 **Safe by Default**: Secrets never leave local machine (verification is opt-in)

## Installation

```bash
# Clone the repository
git clone https://github.com/aiagentmackenzie-lang/SecretScanner.git
cd SecretScanner

# Build
go build ./cmd/secretscanner

# Or install directly
go install github.com/aiagentmackenzie-lang/SecretScanner/cmd/secretscanner@latest
```

## Usage

### Basic Scanning

```bash
# Scan current directory
./secretscanner scan .

# Scan specific files
./secretscanner scan file1.txt file2.go

# Output formats
./secretscanner scan . -f json           # JSON output (default)
./secretscanner scan . -f sarif          # SARIF for GitHub Code Scanning
./secretscanner scan . -f csv            # CSV format
./secretscanner scan . -f terminal       # Human-readable terminal output

# Save results to file
./secretscanner scan . -o results.json
```

### Filtering

```bash
# Filter by severity
./secretscanner scan . -s critical -s high

# Fail on findings (for CI/CD)
./secretscanner scan . --fail-on-findings

# Scan with baseline (only new findings)
./secretscanner scan . --baseline baseline.json

# Redact secrets in output
./secretscanner scan . --redact
```

### Verification (Opt-In)

```bash
# Verify secrets with live API calls (WARNING: makes real HTTP requests)
./secretscanner scan . --verify

# Verify a specific secret
./secretscanner verify ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Filter by verification status
./secretscanner scan . --verify --verify-status valid
```

⚠️ **Warning**: `--verify` makes real HTTP requests to provider APIs (GitHub, Slack, etc.). This can trigger rate limits or security alerts on the provider side. Use with caution on production secrets.

### Configuration

```bash
# Use custom config
./secretscanner scan . -c custom-rules.toml

# List available rules
./secretscanner rules list

# Max file size (skip larger files)
./secretscanner scan . --max-file-size 50MB
```

### Inline Ignores

Suppress false positives with inline comments:

```python
api_key = "real-key-value"  # secretscanner:allow
```

Supported comment styles: `#`, `//`, `/* */`, `<!-- -->`, `{% comment %}`

## Detection Rules

| Provider | Rules | Severity |
|----------|-------|----------|
| AWS | Access Key, Secret Key (context-scoped), MWS Key, AppSync Key | `critical`, `critical`, `high`, `high` |
| GitHub | PAT, Fine-grained PAT, OAuth, App Token, Refresh Token | `high` ×5 |
| Slack | Bot Token, User Token, Webhook | `high` ×3 |
| Stripe | Live Secret, Test Secret, Restricted Key | `critical`, `medium`, `critical` |
| OpenAI | API Key (proj/live/test) | `critical` |
| Anthropic | API Key | `critical` |
| Google Cloud | API Key | `high` |
| Azure | Storage Account Key | `high` |
| Discord | Bot Token | `high` |
| Twilio | API Key, Account SID | `high` ×2 |
| GitLab | PAT, Runner Token | `high`, `critical` |
| Telegram | Bot Token | `high` |
| SendGrid | API Key | `high` |
| HashiCorp Vault | Token | `critical` |
| Mailgun | API Key | `high` |
| Mailchimp | API Key | `high` |
| Pulumi | Access Token | `high` |
| NPM | Auth Token | `medium` |
| Docker | Hub Token, Swarm Token | `medium`, `critical` |
| Kubernetes | Client Certificate, Client Key | `high`, `critical` |
| Heroku | API Key | `high` |
| Cloudflare | API Key | `high` |
| Sentry | Auth Token | `high` |
| Segment | Write Key | `medium` |
| New Relic | License Key | `medium` |
| Terraform | Cloud API Token | `high` |
| Private Keys | RSA, EC, OpenSSH, PGP, Generic | `critical` ×5 |
| Generic | API Key, Secret/Password, JWT | `medium` ×3 |
| Database | PostgreSQL, MySQL, MongoDB, Redis connection strings | `high` ×4 |

**Total: 53 rules** across 25+ providers.

## Configuration (TOML)

Create a `.gitleaks.toml` or pass `-c config.toml`:

```toml
[extend]
useDefault = true  # Use built-in rules

# Global allowlist
[[allowlist]]
paths = ['''vendor/''', '''node_modules/''']
regexes = ['''.*EXAMPLE.*''']
stopwords = ["example", "placeholder"]

# Custom rule
[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''\b(custom_[a-zA-Z0-9]{32})\b'''
entropy = 3.5
keywords = ["custom_"]
severity = "high"
tags = ["custom", "api", "key"]
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Build SecretScanner
        run: go build ./cmd/secretscanner
      - name: Scan for secrets
        run: ./secretscanner scan . --fail-on-findings --severity high,critical
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found |
| 1 | Secrets found (with `--fail-on-findings`) |
| 2 | Configuration or runtime error |

## Architecture

```
Raw Content
    │
    ▼
┌─────────────────────────────────────┐
│ Stage 1: Pre-filtering              │
│ • Binary file detection (sampled)    │
│ • File extension filtering           │
│ • Global allowlist (paths)           │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ Stage 2: Aho-Corasick Matching      │
│ • Multi-pattern O(n) search         │
│ • Case-insensitive keyword match     │
│ • Keyword → Rule mapping             │
└─────────────────────────────────────┘
    │
    ▼ Candidate Rules
┌─────────────────────────────────────┐
│ Stage 3: Regex Validation            │
│ • Rule-specific regex matching       │
│ • Capture group extraction           │
│ • Path-based rule filtering           │
└─────────────────────────────────────┘
    │
    ▼ Potential Secrets
┌─────────────────────────────────────┐
│ Stage 4: Entropy Gate               │
│ • Shannon entropy calculation        │
│ • Per-rule thresholds                │
│ • Hex/sequential pattern penalties   │
└─────────────────────────────────────┘
    │
    ▼ Validated Finding
┌─────────────────────────────────────┐
│ Stage 5: Allowlist Filtering         │
│ • Global regex/stopword allowlists   │
│ • Rule-specific allowlists            │
│ • Inline comment ignores              │
└─────────────────────────────────────┘
    │
    ▼ Verified Finding
┌─────────────────────────────────────┐
│ Stage 6: Output                      │
│ • JSON / SARIF / CSV / Terminal       │
│ • Optional redaction                  │
│ • Optional live verification          │
└─────────────────────────────────────┘
```

## Performance

| Metric | Target | Status |
|--------|--------|--------|
| Scan Speed | >500 MB/s | ✅ Development |
| Memory | <2GB | ✅ Development |
| False Positive Rate | <10% | 🔄 Testing (context-scoped rules improve this) |
| Rules | 50+ | ⚠️ 53 current |
| Test Coverage | >80% | ✅ Passing |

## Current Limitations

- **Git history scanning**: `ScanGit`, `ScanStaged`, `ScanGitRange` currently fall back to filesystem scanning. Full git history scanning is planned.
- **Docker scanning**: Docker daemon integration is not yet implemented. Use `docker save` + filesystem scanning as a workaround.
- **CEL validation**: Rule-level `validate` expressions are parsed but not executed. Live verification uses dedicated provider code.
- **Composite rules**: `[[rules.required]]` is defined in config but not processed.

## Project Structure

```
.
├── cmd/secretscanner/       # CLI entrypoint
├── pkg/
│   ├── cmd/                 # Cobra commands (scan, verify, rules, version, docker)
│   ├── config/              # TOML config parsing + embedded default rules
│   ├── entropy/             # Shannon entropy calculator
│   ├── git/                 # Git repository scanning (stub)
│   ├── docker/              # Docker image scanning (stub)
│   ├── output/              # Output formatters (JSON, SARIF, CSV, Terminal)
│   ├── scanner/             # Core detection engine
│   └── verify/              # Live credential verification
├── go.mod
└── README.md
```

## Development

```bash
# Run tests
go test ./...

# Run with race detection
go test -race ./...

# Build release binary
go build -ldflags "-s -w" -o secretscanner ./cmd/secretscanner

# Run linter (requires golangci-lint)
golangci-lint run ./...
```

## Roadmap

### Phase 1: Core Foundation ✅
- [x] Project scaffold with Cobra CLI
- [x] 26 detection rules
- [x] Aho-Corasick prefiltering
- [x] Entropy-based validation
- [x] JSON / SARIF / CSV / Terminal formatters
- [x] Basic filesystem scanning

### Phase 2: Performance & Accuracy ✅
- [x] 49 total rules (context-scoped for broad patterns)
- [x] Advanced allowlist system (inline ignores, stopwords)
- [x] Baseline/diff mode
- [x] Pre-commit hook
- [x] GitHub Actions CI/CD

### Phase 3: Verification & Intelligence ✅
- [x] Live secret verification (GitHub, Slack, Stripe, OpenAI, Anthropic)
- [x] Docker image scanning foundation
- [x] SARIF output for GitHub Security tab

### Phase 4: Enterprise Features (Future)
- [ ] Full git history scanning (go-git commit diff parsing)
- [ ] Docker daemon integration (live image scanning)
- [ ] CEL-based validation framework
- [ ] Composite rule detection (AWS key+secret proximity)
- [ ] SecurityScarletAI webhook integration
- [ ] Historical trend analysis

## Security Considerations

- **Regex Safety**: Uses Go's RE2-based `regexp` engine (no catastrophic backtracking)
- **Memory Safety**: Bounded file sizes, sampled binary detection
- **No Credential Exposure**: Redaction options for output
- **Local Processing**: Secrets never leave local machine (by default; `--verify` makes opt-in API calls)
- **Verification Safety**: Rate-limited (500ms between checks), 10s timeout per request

## License

MIT License - See LICENSE file

## Credits

Lead Developer: Agent Mackenzie 🔍  
Built for: SOC Analyst Portfolio 

Special thanks to:
- TruffleHog (architecture inspiration)
- GitLeaks (config compatibility)
- scanner-rs (performance benchmarks)