use clap::{Parser, Subcommand, ValueHint};

#[derive(Parser)]
#[command(
    name = "offsecurity",
    version = env!("CARGO_PKG_VERSION"),
    about = "Professional Web Vulnerability Analysis Tool",
    long_about = r#"
  ██████╗  ███████╗ ███████╗ ███████╗ ███████╗  ██████╗ ██╗   ██╗ ██████╗  ██╗ ████████╗ ██╗   ██╗
  ██╔═══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██╔════╝ ██╔════╝ ██║   ██║ ██╔══██╗ ██║ ╚══██╔══╝ ╚██╗ ██╔╝
  ██║   ██║ █████╗   █████╗   ███████╗ █████╗   ██║      ██║   ██║ ██████╔╝ ██║    ██║     ╚████╔╝
  ██║   ██║ ██╔══╝   ██╔══╝   ╚════██║ ██╔══╝   ██║      ██║   ██║ ██╔══██╗ ██║    ██║      ╚██╔╝
  ╚██████╔╝ ██║      ██║      ███████║ ███████╗ ╚██████╗ ╚██████╔╝ ██║  ██║ ██║    ██║       ██║
   ╚═════╝  ╚═╝      ╚═╝      ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝    ╚═╝       ╚═╝

  Professional Web Vulnerability Analysis — Offensive & Defensive Security Tool
  Authorized use only. Scan your own assets or obtain explicit permission.
"#,
    after_help = "Examples:\n  \
      offsecurity scan --url https://example.com\n  \
      offsecurity scan --file targets.txt --threads 50 --verbose\n  \
      offsecurity scan --url https://example.com --output reports/ --timeout 15"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan URLs for vulnerabilities
    Scan(ScanArgs),

    /// Discover subdomains and open ports
    Discover(DiscoverArgs),

    /// Crawl a website to discover pages
    Crawl(CrawlArgs),

    /// Compare two scans or show scan history
    Diff(DiffArgs),

    /// Show version information
    Version,
}

#[derive(Parser, Debug, Clone)]
pub struct DiscoverArgs {
    /// Target domain for discovery
    #[arg(short = 'd', long = "domain")]
    pub domain: String,

    /// Skip port scanning (subdomains only)
    #[arg(long = "no-ports")]
    pub no_ports: bool,

    /// Port scan profile: quick, common
    #[arg(long = "ports", default_value = "common")]
    pub port_profile: Option<String>,

    /// Timeout per port in milliseconds
    #[arg(long = "port-timeout", default_value = "1000")]
    pub port_timeout: u64,

    /// Custom subdomain wordlist file
    #[arg(long = "wordlist", value_hint = ValueHint::FilePath)]
    pub wordlist: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CrawlArgs {
    /// Target URL to start crawling from
    #[arg(short = 'u', long = "url")]
    pub url: String,

    /// Maximum pages to crawl
    #[arg(long = "max-pages", default_value = "100")]
    pub max_pages: usize,

    /// Crawl external domains as well
    #[arg(long = "all")]
    pub all_origins: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct DiffArgs {
    /// First scan ID to compare
    #[arg(long = "scan-a")]
    pub scan_a: Option<String>,

    /// Second scan ID to compare
    #[arg(long = "scan-b")]
    pub scan_b: Option<String>,

    /// Show scan history for a target URL
    #[arg(long = "target")]
    pub target: Option<String>,

    /// Database file path
    #[arg(long = "db", default_value = "offsecurity.db")]
    pub db: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ScanArgs {
    /// Target URL to scan (single URL mode)
    #[arg(short = 'u', long = "url", conflicts_with = "file", group = "target")]
    pub url: Option<String>,

    /// File with list of URLs to scan (one per line)
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath, group = "target")]
    pub file: Option<String>,

    /// Aggressive mode: max intensity, no rate limit, all checks, crawl, browser, exploits, all formats
    #[arg(short = 'A', long = "aggressive")]
    pub aggressive: bool,

    /// Request timeout in seconds
    #[arg(short = 't', long = "timeout", default_value = "15")]
    pub timeout: u64,

    /// Number of concurrent threads
    #[arg(short = 'T', long = "threads", default_value = "50")]
    pub threads: usize,

    /// Output directory for reports
    #[arg(short = 'o', long = "output", default_value = "reports")]
    pub output: String,

    /// Enable verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Custom User-Agent string
    #[arg(long = "user-agent")]
    pub user_agent: Option<String>,

    /// Scanning intensity level: 1=passive, 2=light active, 3=full active
    #[arg(short = 'L', long = "level", visible_alias = "intensity", default_value = "1", value_parser = clap::value_parser!(u8).range(1..=3))]
    pub intensity_level: u8,

    /// Rate limit delay in milliseconds between requests
    #[arg(short = 'd', long = "delay", default_value = "0")]
    pub delay: u64,

    /// Max retries per request
    #[arg(short = 'r', long = "retries", default_value = "2")]
    pub retries: u32,

    /// Configuration file path (TOML)
    #[arg(short = 'c', long = "config", value_hint = ValueHint::FilePath)]
    pub config: Option<String>,

    /// Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)
    #[arg(long = "proxy", value_name = "URL")]
    pub proxy: Option<String>,

    /// Route all traffic through Tor SOCKS5 proxy (127.0.0.1:9050) for anonymous scanning
    #[arg(long = "tor")]
    pub tor: bool,

    /// Tor SOCKS5 proxy port (default: 9050)
    #[arg(long = "tor-port", default_value = "9050")]
    pub tor_port: u16,

    /// Custom request header (e.g., -H "Authorization: Bearer token")
    #[arg(short = 'H', long = "header", value_name = "KEY:VALUE")]
    pub custom_headers: Vec<String>,

    /// Authentication credentials (e.g., --auth basic:user:pass or --auth bearer:token)
    #[arg(long = "auth", value_name = "TYPE:CREDENTIALS")]
    pub auth: Option<String>,

    /// Basic authentication: --auth-basic "user:pass"
    #[arg(long = "auth-basic", value_name = "USER:PASS")]
    pub auth_basic: Option<String>,

    /// Bearer token authentication: --auth-bearer "token"
    #[arg(long = "auth-bearer", value_name = "TOKEN")]
    pub auth_bearer: Option<String>,

    /// Allow insecure TLS connections (self-signed certificates)
    #[arg(long = "insecure")]
    pub insecure: bool,

    /// Generate only JSON report
    #[arg(long = "json", conflicts_with_all = ["html_only", "txt_only"])]
    pub json_only: bool,

    /// Generate only HTML report
    #[arg(long = "html", conflicts_with_all = ["json_only", "txt_only"])]
    pub html_only: bool,

    /// Generate only TXT report
    #[arg(long = "txt", conflicts_with_all = ["json_only", "html_only"])]
    pub txt_only: bool,

    /// Store scan results in SQLite database for diff comparison
    #[arg(long = "db")]
    pub save_to_db: bool,

    /// Database file path (default: offsecurity.db)
    #[arg(long = "db-path", default_value = "offsecurity.db")]
    pub db_path: String,

    /// Generate SARIF v2.1.0 report
    #[arg(long = "sarif", conflicts_with_all = ["json_only", "html_only", "txt_only", "junit_only", "ndjson_only"])]
    pub sarif: bool,

    /// Generate JUnit XML report
    #[arg(long = "junit", conflicts_with_all = ["json_only", "html_only", "txt_only", "sarif", "ndjson_only"])]
    pub junit: bool,

    /// Generate ndjson report
    #[arg(long = "ndjson", conflicts_with_all = ["json_only", "html_only", "txt_only", "sarif", "junit_only"])]
    pub ndjson: bool,

    /// Generate all report formats
    #[arg(long = "all-formats")]
    pub all_formats: bool,

    /// Enable headless browser analysis (DOM XSS, storage, frameworks)
    #[cfg(feature = "browser")]
    #[arg(long = "browser")]
    pub browser: bool,

    /// Path to Chrome/Edge/Chromium executable for browser analysis
    #[cfg(feature = "browser")]
    #[arg(long = "browser-path")]
    pub browser_path: Option<String>,

    /// Browser page load timeout in seconds
    #[cfg(feature = "browser")]
    #[arg(long = "browser-timeout", default_value = "15")]
    pub browser_timeout: u64,

    /// Save screenshots of analyzed pages
    #[cfg(feature = "browser")]
    #[arg(long = "screenshot")]
    pub screenshot: bool,

    /// Directory for WASM plugins
    #[cfg(feature = "plugins")]
    #[arg(long = "plugins-dir")]
    pub plugins_dir: Option<String>,

    /// Timeout per plugin in seconds
    #[cfg(feature = "plugins")]
    #[arg(long = "plugin-timeout", default_value = "5")]
    pub plugin_timeout: u64,

    /// Generate exploit PoC files for each vulnerability found
    #[arg(long = "exploit")]
    pub exploit: bool,

    /// Webhook URL for scan completion notification (POST with JSON results)
    #[arg(long = "webhook", value_name = "URL")]
    pub webhook: Option<String>,

    /// Enable web crawler to discover additional pages from the target
    #[arg(long = "crawl")]
    pub crawl: bool,

    /// Maximum pages to crawl (default: 100)
    #[arg(long = "crawl-max-pages")]
    pub crawl_max_pages: Option<usize>,

    /// Crawl all origins, not just same-origin
    #[arg(long = "crawl-all")]
    pub crawl_all_origins: bool,

    /// Disable specific check categories (comma-separated: headers,cookies,forms,passive,sensitive,active,ws,graphql,jwt,oauth2,idor,api,ssti,nosql,rate-limit,fingerprint)
    #[arg(long = "skip", value_delimiter = ',')]
    pub skip_checks: Option<Vec<String>>,
}
