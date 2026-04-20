# 🔐 SecretScanner - Technical Specification

## Project: SecretScanner - Modern Secret Detection Engine
**Version:** 1.0.0-PREVIEW  
**Status:** Specification Ready for Review  
**Created:** April 19, 2026  
**Lead Developer:** Agent Mackenzie

---

## Executive Summary

SecretScanner is a high-performance, modern secret detection engine designed for SOC analysts and DevSecOps teams. Built on lessons learned from analyzing TruffleHog, GitLeaks, Betterleaks, and scanner-rs, this tool prioritizes **signal over noise** while maintaining exceptional performance.

**Core Philosophy:** Detect secrets that matter, eliminate the noise that kills productivity.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECRETSCANNER ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌─────────────────┐    ┌──────────────────────────┐   │
│  │ Input Layer  │───▶│  Detection Core │───▶│      Analysis Engine     │   │
│  │              │    │                 │    │                          │   │
│  │ • Git repos  │    │ • Aho-Corasick  │    │ • Entropy Analysis       │   │
│  │ • Filesystem │    │ • Regex Engine  │    │ • CEL Validation         │   │
│  │ • GitHub API │    │ • Hybrid Match  │    │ • Context Scoring        │   │
│  │ • Docker Img │    │ • Decoder Chain │    │ • Severity Calculation   │   │
│  └──────────────┘    └─────────────────┘    └──────────────────────────┘   │
│         │                      │                         │                   │
│         ▼                      ▼                         ▼                   │
│  ┌──────────────┐    ┌─────────────────┐    ┌──────────────────────────┐   │
│  │   Sources    │    │    Findings     │    │      Output Layer        │   │
│  │              │    │   Pipeline      │    │                          │   │
│  │ • Git commit │    │                 │    │ • JSON / SARIF / CSV     │   │
│  │ • File scan  │    │ • Deduplication │    │ • CI/CD Integration      │   │
│  │ • GitHub PR  │    │ • Allowlist     │    │ • SecurityScarletAI      │   │
│  │ • S3 / GCS   │    │ • Verification  │    │ • GitHub Actions         │   │
│  └──────────────┘    └─────────────────┘    └──────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technology Stack Selection

| Component | Choice | Rationale |
|-----------|--------|-----------|
| **Language** | Go 1.22+ | Balance of speed (2-10x faster than Python), development velocity, and ecosystem maturity |
| **Regex Engine** | RE2 via `regexp` | O(n) worst-case time, no backtracking DoS |
| **Pattern Matcher** | Aho-Corasick | Multi-pattern matching in O(n) time, 90%+ CPU reduction |
| **Configuration** | TOML | Human-readable, community standard (.gitleaks compatible) |
| **Validation** | CEL (Common Expr) | Safe sandboxed expressions, no code injection risk |
| **CLI Framework** | Cobra | Industry standard, excellent help/documentation |
| **Concurrency** | Worker Pool | Bounded goroutines, backpressure handling |
| **Git Integration** | go-git (pure Go) | No external git dependency, faster than libgit2 |

### Why Go Over Rust/Python?

Based on benchmarks from scanner-rs research:

| Metric | Go (Target) | Rust (scanner-rs) | Python (gitleaks-ai) |
|--------|-------------|-------------------|----------------------|
| Lines/sec | 500M+ | 1.5B+ | 50M |
| Memory | Moderate | High (2-3x) | Low |
| Dev Speed | Fast | Medium | Fast |
| Binary Size | ~15MB | ~25MB | ~100MB* |
| Maintenance | Easy | Medium | Easy |
| Learning Curve | Low | High | Low |

**Decision:** Go provides the best balance for a 2-week MVP that must be maintainable by a single developer while achieving 10x+ performance over Python scanners.

---

## 3. Detection Engine Deep Dive

### 3.1 Hybrid Detection Pipeline

```
Raw Content
    │
    ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 1: Pre-filtering                                               │
│ • Remove comments that don't match patterns                           │
│ • Skip binary files (>5% non-printable)                               │
│ • Early allowlist exclusion                                           │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 2: Fast Pattern Matching (Aho-Corasick)                        │
│ • Build once from all rule keywords                                  │
│ • Single-pass SIMD scan identifies candidate locations              │
│ • Reduce regex workload by 90%+                                      │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼ Candidate Windows (10-50 char context)
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 3: Regex Validation                                            │
│ • Run only regexes for matched keywords                              │
│ • Capture groups extract actual secret                               │
│ • Path-based rule filters                                            │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼ Potential Secrets
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 4: Entropy Gate                                                │
│ • Shannon entropy calculation H = -Σp·log₂(p)                       │
│ • Filter < 3.5 for high-confidence patterns                          │
│ • Filter < 5.0 for generic patterns                                  │
│ • Token efficiency check (BPE-based, optional)                       │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼ High-Entropy Candidates
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 5: Allowlist Filtering                                         │
│ • Global allowlists (regex, paths, commits)                          │
│ • Rule-specific allowlists                                           │
│ • Inline ignore comments (# secretscanner:allow)                     │
└──────────────────────────────────────────────────────────────────────┘
    │
    ▼ Validated Findings
┌──────────────────────────────────────────────────────────────────────┐
│ Stage 6: Live Verification (Optional)                                  │
│ • CEL-defined HTTP requests                                           │
│ • Response-based status: valid/invalid/revoked/error              │
│ • Rate-limited, async execution                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Shannon Entropy Implementation

```go
// EntropyCalculator computes Shannon entropy for secret validation
type EntropyCalculator struct {
    charset string
}

// Calculate returns Shannon entropy H = -Σp·log₂(p)
// For a string to be considered a secret:
// - High-confidence patterns: H >= 3.5
// - Generic patterns: H >= 5.0
// - Maximum theoretical: 8.0 (for ASCII)
func (ec *EntropyCalculator) Calculate(data string) float64 {
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
    if ec.isHexString(data) {
        if _, err := strconv.ParseInt(data, 10, 64); err == nil {
            // All digits - likely not a secret
            entropy -= 1.2 / math.Log2(length)
        }
    }
    
    return entropy
}
```

**Entropy Thresholds (Based on Research):**

| Content Type | Entropy Range | Threshold |
|--------------|--------------|-----------|
| English Text | 3.5-4.5 | - |
| Source Code | 4.0-5.5 | - |
| Random Secret | 5.5-8.0 | 5.0 |
| Base64 Secret | 4.5-6.0 | 4.5 |
| Hex Secret | 3.5-5.0 | 3.5 |

### 3.3 Detection Rules Architecture

**Rule Structure (TOML):**

```toml
[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
entropy = 3.0  # Minimum Shannon entropy
keywords = ["AKIA", "ASIA", "ABIA", "ACCA", "A3T"]  # Aho-Corasick triggers
severity = "critical"

# Enhanced context validation
tags = ["aws", "cloud", "access-key"]

# Validation using Common Expression Language (CEL)
validate = '''
  secret.matches("^AKIA") ? {
    "result": http.get("https://sts.amazonaws.com/?Action=GetCallerIdentity", {
      "Authorization": "AWS4-HMAC-SHA256 Credential=" + secret + "/20260101/us-east-1/sts/aws4_request"
    }).status == 403 ? "valid" : "invalid"
  } : {"result": "unknown"}
'''

# Rule-specific allowlists
[[rules.allowlists]]
description = "AWS example keys"
regexes = ['''AKIAIOSFODNN7EXAMPLE''']
```

---

## 4. Detection Patterns (50+ Rules)

### 4.1 Cloud Providers

| Provider | Pattern | Regex Example | Entropy |
|-----------|---------|--------------|---------|
| **AWS** | Access Key | `AKIA[A-Z2-7]{16}` | 3.0 |
| **AWS** | Secret Key | `[A-Za-z0-9/+=]{40}` | 4.5 |
| **GCP** | API Key | `AIza[0-9A-Za-z_-]{35}` | 3.5 |
| **Azure** | Key | `[a-zA-Z0-9+/=]{88}` | 4.0 |
| **Azure** | Connection String | `DefaultEndpointsProtocol=https;AccountName=` | 3.0 |

### 4.2 Version Control

| Provider | Pattern | Regex | Confidence |
|-----------|---------|-------|------------|
| **GitHub** | Classic PAT | `ghp_[0-9a-zA-Z]{36}` | High |
| **GitHub** | Fine-grained PAT | `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` | High |
| **GitHub** | OAuth | `gho_[0-9a-zA-Z]{36}` | High |
| **GitHub** | App Token | `ghs_[0-9a-zA-Z]{36}` | High |
| **GitLab** | PAT | `glpat-[A-Za-z0-9-_]{20,}` | High |
| **Bitbucket** | App Pass | `[A-Za-z0-9]{24}` | Medium |

### 4.3 Communication & Collaboration

| Service | Pattern | Example |
|---------|---------|---------|
| **Slack** | Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` |
| **Slack** | User Token | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` |
| **Slack** | Webhook | `https://hooks.slack.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}` |
| **Discord** | Bot Token | `[MN][A-Za-z0-9]{23}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27}` |
| **Twilio** | API Key | `SK[a-f0-9]{32}` |

### 4.4 Payment & Financial

| Provider | Pattern | Example |
|-----------|---------|---------|
| **Stripe** | Live Secret | `sk_live_[0-9a-zA-Z]{24}` |
| **Stripe** | Restricted Key | `rk_live_[0-9a-zA-Z]{24}` |
| **Stripe** | Test Key | `sk_test_[0-9a-zA-Z]{24}` |
| **PayPal** | Braintree | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` |
| **Square** | App Token | `sq0atp-[0-9A-Za-z\-_]{22}` |

### 4.5 Cryptographic Keys

| Type | Pattern | Detection Method |
|------|---------|------------------|
| **RSA Private Key** | `-----BEGIN RSA PRIVATE KEY-----` | Header match + base64 content |
| **EC Private Key** | `-----BEGIN EC PRIVATE KEY-----` | Header match + base64 content |
| **OpenSSH Key** | `-----BEGIN OPENSSH PRIVATE KEY-----` | Header match |
| **PGP Private Key** | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | Header match |
| **Generic Private Key** | `-----BEGIN .*PRIVATE KEY.*-----` | Regex with entropy |

### 4.6 Database & Infrastructure

| Type | Pattern | Example |
|------|---------|---------|
| **PostgreSQL** | Connection String | `postgres://[^:]+:[^@]+@` |
| **MySQL** | Connection String | `mysql://[^:]+:[^@]+@` |
| **MongoDB** | Connection String | `mongodb(\+srv)?://[^:]+:[^@]+@` |
| **Redis** | Connection String | `redis://:[^@]+@` |
| **JWT** | Token | `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` |

---

## 5. Implementation Phases

### Phase 1: Core Foundation (Week 1)
**Goal:** Basic scanning functional with 20 high-confidence rules

**Deliverables:**
1. **Project scaffold** - Go module, Cobra CLI, logging
2. **Input layer** - File/directory scanning, git repository scanning
3. **Detection core** - Simple regex matching for 20 rules
4. **Output layer** - JSON and human-readable formats
5. **Configuration** - TOML rule format, basic allowlisting

**Key Tasks:**
- [ ] Set up Go project structure with proper linting (golangci-lint)
- [ ] Implement file walker with .gitignore respect
- [ ] Implement git history scanner using go-git
- [ ] Create rule registry system
- [ ] Implement 20 cloud provider rules (AWS, GitHub, Slack, Stripe)
- [ ] Add basic entropy calculation
- [ ] JSON/terminal output formatters
- [ ] CLI: `scan`, `version` commands

**Success Criteria:**
```bash
$ secretscanner scan ./test-repo
Found 3 secrets in 2 files
  - config/aws.go:15: AWS Access Key (AKIA...)
  - .env:8: GitHub Token (ghp_...)
  - docker-compose.yml:23: Database password
```

### Phase 2: Performance & Accuracy (Week 1.5)
**Goal:** Production-ready with enterprise features

**Deliverables:**
1. **Aho-Corasick integration** - Fast multi-pattern matching
2. **Advanced entropy analysis** - Per-rule thresholds, charset-specific
3. **Allowlist system** - File paths, regexes, commit SHAs, inline ignores
4. **50 total rules** - Cover top providers
5. **GitHub Actions** - CI/CD integration ready

**Key Tasks:**
- [ ] Integrate cloudflare/ahocorasick for keyword prefiltering
- [ ] Implement comprehensive allowlist system
- [ ] Add 30 additional rules (total 50)
- [ ] SARIF output format for GitHub Code Scanning
- [ ] GitHub Actions workflow
- [ ] Pre-commit hook support
- [ ] Baseline/diff mode (only new findings)

**Success Criteria:**
```bash
# Scan with baseline
$ secretscanner scan --baseline baseline.json --output sarif > results.sarif

# CI mode
$ secretscanner scan --staged --fail-on-findings
Found 0 new secrets (3 in baseline)
```

### Phase 3: Verification & Intelligence (Week 2)
**Goal:** Match TruffleHog's verification capabilities

**Deliverables:**
1. **CEL-based validation** - Safe credential verification
2. **Live verification** - For AWS, GitHub, Slack, Stripe
3. **Composite rules** - Multi-part secret detection (e.g., AWS key + secret)
4. **Docker image scanning** - Extract and scan container layers
5. **GitHub/GitLab API** - Platform-native scanning

**Key Tasks:**
- [ ] Integrate google/cel-go for validation expressions
- [ ] Implement verification for top 10 providers
- [ ] Composite rule engine (proximity matching)
- [ ] Docker layer extraction and scanning
- [ ] GitHub Issues/PR comment scanning via API
- [ ] GitLab API integration
- [ ] SecurityScarletAI webhook integration

**Success Criteria:**
```bash
# Verify a discovered secret
$ secretscanner verify AKIA...
Status: VALID
Account: 595918472158
ARN: arn:aws:iam::595918472158:user/test

# Docker scan
$ secretscanner scan --docker-image myapp:latest
Scanned 15 layers, found 2 secrets in layer sha256:abc...

# Output with verification
$ secretscanner scan --verify --results=verified
Showing only verified, active credentials
```

### Phase 4: Advanced Features (Post-MVP)
**Goal:** Competitive advantage features

- [ ] **ML-based false positive reduction** (local model, no API calls)
- [ ] **Custom detection rules** via web dashboard
- [ ] **Secret rotation playbooks** integration
- [ ] **Historical trend analysis**
- [ ] **Team collaboration features** (assign, track, resolve)
- [ ] **Policy-as-code** (OPA integration)

---

## 6. Detailed Implementation Plan

### Week 1: Days 1-3 - Core Infrastructure

**Day 1: Project Bootstrap**
```
tasks:
  - Initialize Go module (go mod init github.com/raphael/secretscanner)
  - Set up Cobra CLI framework
  - Configure golangci-lint, gofmt, pre-commit hooks
  - Create directory structure:
    /cmd/secretscanner      # CLI entrypoint
    /pkg/
      /scanner               # Core scanning logic
      /rules                 # Rule definitions
      /config                # Configuration parsing
      /output                # Output formatters
      /entropy               # Entropy calculation
    /config                  # Default rules
    /testdata                # Test fixtures
  - Implement basic logging (log/slog)
  - Create version command
```

**Day 2: Source Adaptation**
```
tasks:
  - Implement filesystem scanner
    - Walk directories with concurrency
    - Respect .gitignore
    - Skip binary files (>20% non-printable)
  - Implement git scanner
    - go-git integration for repo parsing
    - Scan commit patches (git log -p equivalent)
    - Branch/commit range filtering
  - File metadata extraction (lines, size)
  - Progress reporting for large repos
```

**Day 3: Rule Engine v1**
```
tasks:
  - TOML rule parser
  - Rule registry with keyword indexing
  - Simple regex matching per file
  - First 20 rules:
    * AWS (access key, secret key)
    * GitHub (4 token types)
    * Slack (3 token types)
    * Stripe (3 key types)
    * Generic API key
    * Generic password
    * Private key headers (RSA, EC, OpenSSH)
  - Basic allowlisting (paths)
  - Entropy calculation module
```

### Week 1: Days 4-7 - Performance Optimization

**Day 4: Detection Pipeline**
```
tasks:
  - Aho-Corasick keyword matcher
    - Build from all rule keywords
    - SIMD-accelerated scanning
    - Window extraction around matches
  - Regex-on-demand engine
    - Only run regexes for matched keywords
    - Compile and cache regexes
  - Performance benchmark vs baseline
```

**Day 5: Allowlist & Context**
```
tasks:
  - Comprehensive allowlists:
    * Global regex patterns
    * Per-rule regex patterns
    * Path-based exclusions
    * Commit-SHA exclusions
    * Inline comment ignores
  - Context extraction (lines before/after)
  - Severity scoring (critical/high/medium/low)
```

**Day 6: Output Formats**
```
tasks:
  - JSON format (machine-readable)
  - SARIF format (GitHub Code Scanning)
  - CSV format (spreadsheet friendly)
  - Terminal format with colors
  - Baseline/diff mode
  - Fingerprint generation for deduplication
```

**Day 7: CI/CD Integration**
```
tasks:
  - GitHub Actions workflow
  - Pre-commit hook
  - Exit code handling (0=clean, 1=findings)
  - GitLab CI example
  - Documentation
```

### Week 2: Days 8-10 - Verification

**Day 8: CEL Integration**
```
tasks:
  - Integrate google/cel-go
  - HTTP validation functions
  - Response parsing helpers
  - Safe sandbox configuration
  - Rate limiting for API calls
```

**Day 9: Provider Verification**
```
tasks:
  - AWS verification (STS GetCallerIdentity)
  - GitHub verification (GET /user)
  - Slack verification (auth.test)
  - Stripe verification (tokens retrieve)
  - Generic HTTP validation framework
```

**Day 10: Advanced Rules**
```
tasks:
  - Composite rule engine
    * Multi-part detection (AWS key + secret proximity)
    * WithinLines/WithinColumns constraints
  - 30 additional rules (total 50)
  - Docker image scanning
  - S3/GCS bucket scanning
```

### Week 2: Days 11-14 - Polish & Integration

**Days 11-12: Platform Scanning**
```
tasks:
  - GitHub API integration
    * Repository scanning
    * Issue/PR comment scanning
    * Webhook support
  - GitLab API integration
  - Paginated result handling
  - Token rotation support
```

**Days 13-14: Final Polish**
```
tasks:
  - SecurityScarletAI webhook integration
  - Performance optimization pass
  - Comprehensive test suite (>80% coverage)
  - Documentation (README, USAGE, CONTRIBUTING)
  - Benchmark vs GitLeaks/TruffleHog
  - Release v1.0.0
```

---

## 7. Configuration Specification

### 7.1 Default Configuration File

```toml
# SecretScanner Configuration
# Compatible with .gitleaks.toml format

title = "SecretScanner Configuration"

# Extend another config
[extend]
useDefault = true  # Use built-in rules
# path = "custom-rules.toml"  # Or extend custom file

# Global allowlist
[[allowlist]]
description = "Global exclusions"
paths = [
    '''vendor/''',
    '''node_modules/''',
    '''\.gitleaks\.toml$''',
    '''\.(jpg|gif|doc|pdf|bin)$''',
]
regexes = [
    '''AKIAIOSFODNN7EXAMPLE''',  # AWS example key
    '''.*EXAMPLE.*''',           # Generic example pattern
]
commits = [
    "abc123def456",  # Specific commits to ignore
]
stopwords = [
    "example",
    "test",
    "fake",
    "dummy",
]

# AWS Access Key Rule
[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = '''\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'''
entropy = 3.0
keywords = ["A3T", "AKIA", "ASIA", "ABIA", "ACCA"]
severity = "critical"
tags = ["aws", "cloud", "access-key"]

# Rule-specific allowlist
[[rules.allowlist]]
description = "Example AWS keys"
regexes = ['''.+EXAMPLE$''']

# GitHub Personal Access Token
[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
entropy = 3.5
keywords = ["ghp_"]
severity = "high"
tags = ["github", "token"]

[[rules]]
id = "github-fine-grained-pat"
description = "GitHub Fine-Grained PAT"
regex = '''github_pat_[0-9a-zA-Z_]{22}_[0-9a-zA-Z_]{59}'''
entropy = 4.0
keywords = ["github_pat_"]
severity = "high"
tags = ["github", "token"]

# Validation rule (CEL-based)
[[rules]]
id = "slack-bot-token"
description = "Slack Bot Token with verification"
regex = '''xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'''
keywords = ["xoxb-"]
severity = "high"
tags = ["slack", "token", "bot"]
validate = '''
  cel.bind(r,
    http.post("https://slack.com/api/auth.test", {}, {
      "Authorization": "Bearer " + secret
    }),
    r.json.?ok == true ? {
      "result": "valid",
      "team": r.json.?team.orValue(""),
      "user": r.json.?user.orValue("")
    } : r.json.?ok == false ? {
      "result": "invalid",
      "reason": r.json.?error.orValue("unknown")
    } : {"result": "error"}
  )
'''

# Composite rule (multi-part)
[[rules]]
id = "aws-credentials"
description = "AWS Access Key + Secret Key pair"
regex = '''\b((?:AKIA|ASIA)[A-Z2-7]{16})\b'''
keywords = ["AKIA", "ASIA"]
severity = "critical"
tags = ["aws", "credentials"]

[[rules.required]]
id = "aws-secret-key"
regex = '''[A-Za-z0-9/+=]{40}'''
withinLines = 5  # Must be within 5 lines
```

### 7.2 CLI Reference

```bash
# Scan commands
secretscanner scan [path]                    # Scan directory
secretscanner scan --git [repo]              # Scan git history
secretscanner scan --github-repo owner/repo  # Scan GitHub repo
secretscanner scan --staged                  # Scan staged changes
secretscanner scan --since-commit HEAD~10    # Scan last 10 commits

# Output options
secretscanner scan --format json             # JSON output
secretscanner scan --format sarif            # SARIF output
secretscanner scan --format csv              # CSV output
secretscanner scan -v                        # Verbose output
secretscanner scan --redact                  # Redact secrets in output

# Filtering
secretscanner scan --severity high,critical  # Only high severity
secretscanner scan --rules aws,github        # Only specific rules
secretscanner scan --exclude "test/*"        # Exclude paths
secretscanner scan --baseline baseline.json  # Show only new findings

# Verification
secretscanner scan --verify                  # Verify all secrets
secretscanner scan --verify-status valid     # Only verified secrets
secretscanner verify AKIA...                 # Verify specific secret

# Configuration
secretscanner scan --config custom.toml      # Use custom config
secretscanner scan --max-file-size 10MB      # Skip large files

# GitHub Actions
secretscanner --github-actions               # GitHub Actions format
```

### 7.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found, successful scan |
| 1 | Secrets found (with --fail-on-findings) |
| 2 | Configuration error |
| 126 | Permission denied |
| 127 | Required tool not found |

---

## 8. Testing Strategy

### 8.1 Test Data

**Repository: test-secrets-repo/**
```
test-secrets-repo/
├── aws/                    
│   ├── credentials         # AWS credentials file
│   └── config              # AWS config with keys
├── github/                 
│   ├── token.txt           # GitHub tokens
│   └── workflow.yml        # GitHub Actions with secrets
├── generic/                
│   ├── .env                # Environment variables
│   └── database.yml        # DB connection strings
├── allowed/                
│   └── example.txt         # Should be ignored (EXAMPLE pattern)
└── negative/               
    └── safe.txt            # Should not trigger
```

### 8.2 Test Categories

1. **Unit Tests** - Individual component testing
   - Entropy calculation
   - Regex matching
   - Allowlist filtering
   - Configuration parsing

2. **Integration Tests** - End-to-end scenarios
   - Full repository scan
   - Git history scanning
   - Verification API calls

3. **Performance Tests** - Benchmarking
   - Large repository (>10k files)
   - Deep git history (>1000 commits)
   - Comparison with GitLeaks

4. **Compatibility Tests**
   - TOML config compatibility with GitLeaks
   - SARIF output validation
   - GitHub Actions integration

### 8.3 Benchmark Suite

```go
// Benchmark scan performance
func BenchmarkScanLargeRepo(b *testing.B) {
    scanner := NewScanner(defaultConfig)
    for i := 0; i < b.N; i++ {
        scanner.Scan("testdata/linux-kernel")
    }
}

// Compare with GitLeaks
func BenchmarkComparison(b *testing.B) {
    // Run both scanners on same repo
    // Compare: files/sec, memory usage, true/false positives
}
```

---

## 9. Security Considerations

### 9.1 Safe Scanning

- **No credential exposure** - Secrets redacted in logs/output by default
- **Memory safety** - Bounded buffers, no unbounded string accumulation
- **Regex safety** - RE2 engine prevents catastrophic backtracking
- **Network safety** - Verification requests respect rate limits

### 9.2 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Malicious file names | Path traversal validation |
| Large files causing OOM | Max file size limits, streaming |
| Malicious regex in config | RE2 only, no user-supplied regex |
| Credential exfiltration | Local-only processing, opt-in cloud |
| Timing info leaks | Constant-time comparison where needed |

### 9.3 Compliance

- **GDPR** - No PII collection, local processing preferred
- **SOC 2** - Audit logging, access controls
- **PCI-DSS** - CCN detection, secure handling

---

## 10. Integration Points

### 10.1 SecurityScarletAI Integration

```yaml
# Webhook payload to SecurityScarletAI
{
  "event": "secret_scan_completed",
  "repository": "owner/repo",
  "timestamp": "2026-04-19T10:00:00Z",
  "summary": {
    "files_scanned": 347,
    "secrets_found": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1
    }
  },
  "findings": [
    {
      "rule": "aws-access-key",
      "file": "config/aws.go",
      "line": 15,
      "column": 23,
      "severity": "critical",
      "verified": true,
      "account": "595918472158"
    }
  ]
}
```

### 10.2 GitHub Advanced Security

SARIF output enables native integration:
- Appears in GitHub Security tab
- PR annotations
- Alert dismissal workflow

### 10.3 SIEM Integration

Structured JSON output compatible with:
- Splunk
- ELK Stack
- Datadog
- Custom webhooks

---

## 11. Deployment & Distribution

### 11.1 Release Artifacts

| Artifact | Platform | Size Target |
|----------|----------|-------------|
| Binary | Linux x64 | ~15MB |
| Binary | macOS x64/ARM | ~15MB |
| Binary | Windows x64 | ~15MB |
| Docker | Multi-platform | ~20MB |
| Homebrew | macOS/Linux | N/A |
| GitHub Action | N/A | N/A |

### 11.2 Installation Methods

```bash
# Homebrew
brew install raphael/secretscanner/secretscanner

# Docker
docker pull ghcr.io/raphael/secretscanner:latest

# Go install
go install github.com/raphael/secretscanner/cmd/secretscanner@latest

# Binary download (Linux example)
curl -sSfL https://github.com/raphael/secretscanner/releases/latest/download/secretscanner-linux-amd64 \
  -o /usr/local/bin/secretscanner
chmod +x /usr/local/bin/secretscanner
```

---

## 12. Success Metrics

### 12.1 Technical KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Scan Speed | >500 MB/s | Linux kernel scan time |
| Memory Usage | <2GB peak | RSS at peak |
| False Positive Rate | <10% | Manual review sample |
| True Positive Recall | >99% | Known secrets test set |
| Rule Coverage | 50+ providers | Count of unique services |
| Test Coverage | >80% | Go coverage report |

### 12.2 Adoption KPIs

| Metric | Target | Timeline |
|--------|--------|----------|
| GitHub Stars | 100 | Month 1 |
| CI/CD integrations | 10 repos | Month 1 |
| Active users | 50 | Month 3 |
| SecurityScarletAI integration | Live | Week 2 |

---

## 13. Risk Assessment

### 13.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| RE2 missing features | Low | Medium | Document limitations |
| Go-git limitations | Medium | Medium | Support git CLI fallback |
| API rate limits | Medium | Low | Caching, backoff strategies |
| False positive fatigue | Medium | High | Good defaults, clear docs |

### 13.2 Project Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Scope creep | High | Medium | Firm phase boundaries |
| Performance not competitive | Low | High | Early benchmarking |
| Integration complexity | Medium | Medium | Mock testing |

---

## 14. Decision Log

| Date | Decision | Alternatives | Rationale |
|------|----------|--------------|-----------|
| 2026-04-19 | Go as primary language | Rust, Python | Balance of speed and productivity |
| 2026-04-19 | RE2 regex engine | PCRE, standard lib | Security (no backtracking DoS) |
| 2026-04-19 | TOML configuration | YAML, JSON | Human readable, GitLeaks compat |
| 2026-04-19 | CEL for validation | Lua, JS | Security sandbox, type safety |
| 2026-04-19 | go-git over libgit2 | libgit2 bindings | Pure Go, easier deployment |
| 2026-04-19 | No ML initially | gitleaks-ai approach | Simpler MVP, add later |

---

## 15. Appendix

### 15.1 Glossary

- **Aho-Corasick**: Multi-pattern string matching algorithm
- **CEL**: Common Expression Language, sandboxed expression language
- **Entropy**: Shannon entropy, measure of randomness
- **Fingerprint**: Unique hash identifying a specific finding
- **SARIF**: Static Analysis Results Interchange Format (JSON)
- **RE2**: Google's regular expression engine (linear time)

### 15.2 References

- [TruffleHog Architecture](https://docs.trufflesecurity.com/architecture)
- [GitLeaks Configuration](https://github.com/gitleaks/gitleaks)
- [scanner-rs Benchmarks](https://github.com/ahrav/scratch-scanner-rs)
- [Shannon Entropy for Secrets](https://blog.miloslavhomer.cz/secret-detection-shannon-entropy/)
- [CEL Specification](https://github.com/google/cel-spec)

---

## Review Checklist

- [ ] Architecture reviewed and approved
- [ ] Technology choices justified
- [ ] Phase boundaries clear and achievable
- [ ] Security considerations addressed
- [ ] Integration points documented
- [ ] Success metrics defined
- [ ] Risk mitigations in place

**Status:** ✅ Ready for Implementation

---

*End of Specification*

**Next Steps:**
1. Review this document
2. Approve or request changes
3. Begin Phase 1 implementation (Core Foundation)
4. Weekly progress reviews

*Prepared by Agent Mackenzie, Lead Developer*
*For: Raphael - SOC Analyst Portfolio Build*
*Date: April 19, 2026*
