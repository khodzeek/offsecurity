use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub scan: ScanConfig,
    pub output: OutputConfig,
    pub http: HttpConfig,
    pub crawler: Option<CrawlerConfigData>,
    pub webhook: Option<WebhookConfig>,
    pub oauth2: Option<OAuth2ConfigData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout_secs: u64,
    pub max_threads: usize,
    pub rate_limit_ms: u64,
    pub max_retries: u32,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub max_body_size: usize,
    pub delay_between_requests_ms: u64,
    pub intensity_level: u8,
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub verbose: bool,
    pub color: bool,
    pub output_dir: String,
    pub json_report: bool,
    pub html_report: bool,
    pub txt_report: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub user_agent: String,
    pub accept: String,
    pub accept_language: String,
    pub max_connections_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub proxy_url: Option<String>,
    pub custom_headers: Vec<(String, String)>,
    pub auth_type: Option<String>,
    pub auth_credentials: Option<String>,
    pub tor_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerConfigData {
    pub enabled: bool,
    pub max_pages: usize,
    pub same_origin_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub on_complete: bool,
    pub on_finding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ConfigData {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                timeout_secs: 15,
                max_threads: 50,
                rate_limit_ms: 0,
                max_retries: 2,
                follow_redirects: true,
                max_redirects: 10,
                max_body_size: 5 * 1024 * 1024, // 5MB
                delay_between_requests_ms: 0,
                intensity_level: 1,
                insecure: false,
            },
            output: OutputConfig {
                verbose: false,
                color: true,
                output_dir: "reports".to_string(),
                json_report: true,
                html_report: true,
                txt_report: true,
            },
            http: HttpConfig {
                user_agent: "offsecurity/1.0 (Security Audit Tool)".to_string(),
                accept: "*/*".to_string(),
                accept_language: "en-US,en;q=0.9".to_string(),
                max_connections_per_host: 20,
                pool_idle_timeout_secs: 90,
                proxy_url: None,
                custom_headers: vec![],
                auth_type: None,
                auth_credentials: None,
                tor_enabled: false,
            },
            crawler: None,
            webhook: None,
            oauth2: None,
        }
    }
}

impl AppConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn merge_with_default(path: Option<&str>) -> anyhow::Result<Self> {
        match path {
            Some(p) if std::path::Path::new(p).exists() => Self::from_file(p),
            _ => Ok(Self::default()),
        }
    }
}
