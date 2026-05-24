use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpData {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    pub is_https: bool,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_size: usize,
    pub response_time_ms: u64,
    pub redirect_chain: Vec<RedirectHop>,
    pub server_info: ServerInfo,
    pub cookies: Vec<CookieInfo>,
    pub forms: Vec<FormInfo>,
    pub technologies: Vec<String>,
    pub tls_info: Option<TlsInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub from: String,
    pub to: String,
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub server_header: Option<String>,
    pub powered_by: Option<String>,
    pub detected_server: Option<String>,
    pub detected_language: Option<String>,
    pub detected_framework: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value_preview: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInfo {
    pub action: Option<String>,
    pub method: String,
    pub has_password_field: bool,
    pub hidden_fields: Vec<String>,
    pub has_csrf_token: bool,
    pub visible_fields: Vec<FormField>,
    pub html_snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub is_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub valid: bool,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub errors: Vec<String>,
}
