use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ScanError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("HTTP request failed for {url}: {reason}")]
    HttpRequestFailed { url: String, reason: String },

    #[error("Timeout reached for {url} after {timeout}s")]
    Timeout { url: String, timeout: u64 },

    #[error("Connection error for {url}: {reason}")]
    ConnectionError { url: String, reason: String },

    #[error("TLS error for {url}: {reason}")]
    TlsError { url: String, reason: String },

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Report generation error: {0}")]
    ReportError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}
