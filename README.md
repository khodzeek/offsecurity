# offsecurity

**Professional Web Vulnerability Analysis Tool**

A modern, fast, secure, and modular web application vulnerability scanner written in Rust. Designed for both offensive and defensive security auditing of authorized targets.

> **WARNING:** Esta ferramenta deve ser utilizada apenas em aplicacoes proprias ou mediante autorizacao explicita. O uso nao autorizado de scanners de vulnerabilidade e ilegal em muitas jurisdicoes.

---

## Features

- **Async scanning engine** — Built on Tokio for maximum concurrency and performance
- **Modular architecture** — Each check type is isolated for easy extension
- **Passive security checks** — Headers, cookies, forms, recon, info exposure
- **Active vulnerability detection** — XSS, SQLi, path traversal, SSRF, CMDi, XXE (3 intensity levels)
- **JWT analysis** — Algorithm none, jku/jwk injection, kid traversal, claims validation
- **OAuth2/OIDC analysis** — PKCE, state CSRF, implicit flow, open redirect, client secret exposure
- **GraphQL security** — Introspection, field suggestions, alias batching
- **WebSocket security** — Cross-origin checks, compression oracle detection
- **Software fingerprinting** — OS, web server, language, CMS detection with CVE correlation
- **Headless browser** — Chrome DevTools Protocol for DOM/JS analysis
- **WASM plugin system** — Extensible via WebAssembly plugins (Wasmtime)
- **Exploit PoC generation** — 12+ exploit types with interactive HTML/Python PoCs
- **Subdomain discovery** — DNS enumeration + TCP port scanning
- **Differential scanning** — Compare scans over time via SQLite
- **Multi-format reports** — JSON, HTML dashboard, TXT, SARIF, JUnit, NDJSON
- **Professional terminal UI** — Colored output, progress bars, formatted statistics

## Requirements

- **Rust** stable 1.75+
- **Cargo** (included with Rust)
- **Chrome/Edge** (optional, for headless browser analysis)

## Installation

### From Source

```bash
git clone https://github.com/khodzeek/offsecurity.git
cd offsecurity
cargo install --path .
```

After installation, `offsecurity` is available globally as a system command.

### Quick Start

```bash
# Build and run directly (no install)
cargo run -- scan --url https://example.com

# Or install globally
cargo install --path .
offsecurity scan --url https://example.com
```

## Usage

### Scan Command

```bash
# Basic scan
offsecurity scan --url https://example.com

# Multi-URL scan from file
offsecurity scan --file targets.txt

# Active scanning (intensity levels 1-3)
offsecurity scan --url https://example.com --intensity 2

# Full active scan with browser and exploit generation
offsecurity scan --url https://example.com --intensity 3 --browser --exploit

# With authentication
offsecurity scan --url https://example.com --auth-basic "user:pass"
offsecurity scan --url https://example.com --auth-bearer "token"

# With proxy
offsecurity scan --url https://example.com --proxy http://127.0.0.1:8080

# Skip specific checks
offsecurity scan --url https://example.com --skip headers,cookies,forms

# All report formats
offsecurity scan --url https://example.com --all-formats

# With screenshot (headless browser)
offsecurity scan --url https://example.com --browser --screenshot

# Run WASM plugins
offsecurity scan --url https://example.com --plugins-dir ./my-plugins

# Webhook callback on completion
offsecurity scan --url https://example.com --webhook https://hooks.example.com/scan-done
```

### Discover Command

```bash
# Basic subdomain discovery
offsecurity discover --domain example.com

# With custom wordlist
offsecurity discover --domain example.com --wordlist subdomains.txt

# Skip port scanning
offsecurity discover --domain example.com --no-ports

# Custom port profile and timeout
offsecurity discover --domain example.com --port-profile common --port-timeout 2000
```

### Diff Command

```bash
# List all scans for a target
offsecurity diff --target https://example.com

# Compare two scans
offsecurity diff --scan-a abc123 --scan-b def456

# Custom database path
offsecurity diff --target https://example.com --db my-scans.db
```

### Configuration File (offsecurity.toml)

```toml
[scan]
timeout_secs = 15
max_threads = 50
rate_limit_ms = 0
max_retries = 2
follow_redirects = true
max_redirects = 10
max_body_size = 5242880
delay_between_requests_ms = 0
intensity_level = 1
allow_insecure_tls = false

[output]
verbose = false
color = true
output_dir = "reports"
json_report = true
html_report = true
txt_report = true
sarif_report = false
junit_report = false
ndjson_report = false

[http]
user_agent = "offsecurity/1.0 (Security Audit Tool)"
accept = "*/*"
accept_language = "en-US,en;q=0.9"
max_connections_per_host = 20
pool_idle_timeout_secs = 90

[browser]
enabled = false
browser_path = ""
timeout_secs = 30
screenshot = false

[plugins]
plugins_dir = "./plugins"
timeout_secs = 30

[crawler]
enabled = false
max_pages = 100
same_origin_only = true
```

## Security Checks Performed

### 1. Security Headers (`--skip headers`)
- Content-Security-Policy (missing, unsafe-inline, unsafe-eval, data: URIs, bypass vectors)
- X-Frame-Options (missing, weak values; considers CSP frame-ancestors)
- X-Content-Type-Options (missing)
- Strict-Transport-Security (missing on HTTPS, missing max-age/includeSubDomains)
- Referrer-Policy (missing)
- Permissions-Policy / Feature-Policy (missing)
- Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy / Cross-Origin-Resource-Policy
- Server header exposure / X-Powered-By leakage
- CORS misconfigurations (wildcard with credentials, origin reflection)

### 2. Cookies (`--skip cookies`)
- Missing Secure / HttpOnly / SameSite flags
- SameSite=None without Secure
- Default session cookie names (sessionid, JSESSIONID, PHPSESSID, ASPSESSIONID)
- Short/weak session values
- __Host-/__Secure- prefix validation

### 3. Forms (`--skip forms`)
- GET method on login forms (credentials in URL/Referer)
- Missing CSRF tokens (hidden fields, meta tags)
- Hidden field abuse potential (price, role, admin, level, discount)
- Login forms on non-HTTPS pages (Critical)
- Missing autocomplete=off on password forms
- Insecure form actions (http:// action on https:// page)

### 4. Passive Reconnaissance (`--skip passive`)
- Sensitive file detection (/.env, /.git, backups, configs, Dockerfiles, wp-config, etc.)
- Directory listing detection (Apache, IIS)
- Dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT, PATCH)
- HTTP vs HTTPS enforcement

### 5. Information Exposure (`--skip sensitive`)
- Email address harvesting / Internal IP disclosure
- Stack traces / SQL errors / exceptions / path disclosure
- Debug mode indicators (Symfony, Laravel, Xdebug, Whoops)
- Source map references in production

### 6. Active Vulnerability Checks (`--intensity 2+`)
- **Level 2:** CORS preflight, XSS reflection, SQLi error-based, path traversal
- **Level 3:** Advanced XSS, blind SQLi timing, SSRF (AWS/GCP/Azure metadata), command injection, XXE

### 7. JWT Analysis (`--skip jwt`)
- Algorithm: none (Critical) / HS256 symmetric
- jku/jwk header injection (key injection / SSRF)
- kid path traversal / Missing exp claim / Excessive lifespan

### 8. OAuth2 Analysis (`--skip oauth2`)
- PKCE absence / Missing state parameter (CSRF)
- Implicit flow detection / Token endpoint in client-side code
- Open redirect via redirect_uri / Exposed client_secret

### 9. GraphQL Security (`--skip graphql`)
- Introspection query exposure
- Field suggestion info leak ("Did you mean?")
- Alias-based batching (resource exhaustion)

### 10. IDOR/BOLA Detection (`--skip idor`)
- Sequential/resource ID patterns in URLs and parameters
- UUID/GUID-based resource detection
- User ID enumeration vectors

### 11. SSTI Detection (`--skip ssti`)
- Jinja2, Twig, Freemarker, ERB, Velocity, Smarty template injection
- Mathematical expression evaluation markers
- Error-based template engine identification

### 12. NoSQL Injection (`--skip nosql`)
- MongoDB $where, $regex, $ne, $gt operator injection
- JSON-based query parameter injection
- Error-based NoSQL fingerprinting

### 13. WebSocket Security (`--skip ws`)
- Cross-origin WebSocket hijacking (ACAO: *)
- Missing Sec-WebSocket-Accept validation
- Permessage-deflate compression (CRIME/BREACH risk)

### 14. Rate Limiting (`--skip rate-limit`)
- RateLimit-* header analysis
- Retry-After header presence
- Throttling behavior testing

### 15. API Discovery (`--skip api`)
- OpenAPI/Swagger specification detection
- Common API paths (/api, /v1, /v2, /graphql, /rest)
- Exposed API documentation endpoints

## Report Formats

### JSON
Machine-readable format suitable for CI/CD integration and custom tooling.

### HTML
Professional dashboard with executive summary, risk score, severity cards, finding details, responsive dark theme.

### TXT
Human-readable text format for quick review and archival.

### SARIF v2.1.0
Static Analysis Results Interchange Format — GitHub Code Scanning, Azure DevOps, VS Code integration.

### JUnit XML
Standard test result format — Jenkins, GitLab CI, TeamCity, and most CI/CD platforms.

### NDJSON
Newline-delimited JSON — one JSON object per line, ideal for log processors (ELK, Splunk, Datadog).

## Architecture

```
├── main.rs                 # Entry point, tracing setup, CLI dispatch
├── cli/mod.rs              # CLI argument parsing (Clap derive)
├── core/
│   ├── engine.rs           # Scan orchestration engine
│   ├── http_client.rs      # Reqwest-based async HTTP client
│   ├── tls.rs              # TLS certificate inspection (rustls + x509-parser)
│   ├── ws_client.rs        # WebSocket client (tokio-tungstenite)
│   ├── browser.rs          # Headless browser via Chrome DevTools Protocol
│   └── crawler.rs          # Web crawler / spider for page discovery
├── scanner/mod.rs          # Concurrent scan worker pool, rate limiting
├── checks/
│   ├── headers.rs          # Security header analysis (CSP, HSTS, CORS, etc.)
│   ├── cookies.rs          # Cookie security audit
│   ├── forms.rs            # Form vulnerability scanner
│   ├── passive.rs          # Passive recon (sensitive files, dir listing, HTTP methods)
│   ├── sensitive.rs        # Info exposure (emails, IPs, stack traces, debug mode)
│   ├── active.rs           # Active checks: XSS, SQLi, path traversal, SSRF, CMDi, XXE
│   ├── jwt.rs              # JWT analysis: alg none, jku/jwk injection, kid traversal
│   ├── oauth2.rs           # OAuth2/OIDC: PKCE, state, implicit flow, open redirect
│   ├── ws.rs               # WebSocket endpoint discovery
│   ├── graphql.rs          # GraphQL: introspection, field suggestions, batching
│   ├── idor.rs             # IDOR/BOLA detection
│   ├── ssti.rs             # Server-Side Template Injection detection
│   ├── nosql.rs            # NoSQL injection detection (MongoDB)
│   ├── api.rs              # API endpoint discovery (OpenAPI/Swagger)
│   ├── rate_limit.rs       # Rate limiting detection
│   └── fingerprint.rs      # OS/software fingerprinting + CVE correlation
├── models/
│   ├── config.rs           # Configuration model (AppConfig, ScanConfig, etc.)
│   ├── finding.rs          # Vulnerability finding
│   ├── scan_result.rs      # Scan result with statistics
│   ├── http_data.rs        # HTTP response data structures
│   └── severity.rs         # Risk severity enum (Critical..Info)
├── reports/
│   ├── json.rs             # JSON report
│   ├── html.rs             # HTML dashboard report (dark theme, responsive)
│   ├── txt.rs              # Plain text report
│   ├── sarif.rs            # SARIF v2.1.0 for CI/CD integration
│   ├── junit.rs            # JUnit XML for CI/CD
│   └── ndjson.rs           # Newline-delimited JSON for log processors
├── discovery/
│   ├── subdomains.rs       # Subdomain enumeration via DNS resolution
│   └── ports.rs            # TCP port scanning with service banner grabbing
├── db/
│   ├── store.rs            # SQLite scan storage with deduplication
│   └── diff.rs             # Scan comparison (new/fixed/unchanged findings)
├── plugins/
│   ├── mod.rs              # WASM plugin discovery and orchestration
│   └── wasm_runtime.rs     # Wasmtime runtime, memory management
├── exploits/mod.rs         # Exploit PoC generation (13+ exploit types)
├── utils/
│   ├── error.rs            # Error types (thiserror)
│   ├── helpers.rs          # String utilities, regex patterns
│   └── url_utils.rs        # URL validation & normalization
└── output/
    ├── banner.rs           # ASCII banner & formatted output
    └── stats.rs            # Statistics display
```

## Performance

- Fully async I/O via Tokio runtime
- Connection pooling with configurable limits
- HTTP/2 support via reqwest
- Release builds with LTO, single codegen unit, and symbol stripping
- Supports hundreds of concurrent URL scans

## Build Optimization

The release profile is configured for maximum performance:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

## Security Philosophy

This tool supports both passive analysis and configurable active testing:

- **Intensity 1 (default):** Passive GET-only analysis, no payload injection
- **Intensity 2:** Basic active checks (XSS reflection, SQLi errors, path traversal, CORS)
- **Intensity 3:** Advanced active checks (blind SQLi timing, SSRF, command injection, XXE)
- Configurable rate limiting to avoid overwhelming targets
- All active payloads use safe markers — no destructive testing

## License

MIT License — See LICENSE file for details.

## Disclaimer

**IMPORTANT:** Esta ferramenta deve ser utilizada apenas em sistemas proprios ou com autorizacao explicita por escrito do proprietario. O uso nao autorizado de scanners de vulnerabilidade contra sistemas de terceiros e:

- Ilegal em muitas jurisdicoes
- Violacao dos termos de servico da maioria dos provedores
- Potencialmente considerado crime cibernetico

Os autores nao se responsabilizam pelo uso indevido desta ferramenta.
