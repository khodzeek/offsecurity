use crate::models::{AppConfig, HttpData, RedirectHop, ServerInfo, CookieInfo, FormInfo, FormField};
use crate::utils::ScanError;
use reqwest::header::{HeaderMap, HeaderValue};
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::time::Instant;
use tracing::debug;

pub struct HttpClient {
    client: reqwest::Client,
    config: AppConfig,
}

/// Map reqwest errors to our ScanError type
fn map_reqwest_error(e: reqwest::Error, url: &str) -> ScanError {
    if e.is_timeout() {
        ScanError::Timeout { url: url.to_string(), timeout: 0 }
    } else if e.is_connect() {
        ScanError::ConnectionError { url: url.to_string(), reason: e.to_string() }
    } else {
        ScanError::HttpRequestFailed { url: url.to_string(), reason: e.to_string() }
    }
}

impl HttpClient {
    pub fn new(config: AppConfig) -> Result<Self, ScanError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&config.http.user_agent)
                .map_err(|e| ScanError::ConfigError(e.to_string()))?,
        );
        headers.insert(
            "Accept",
            HeaderValue::from_str(&config.http.accept)
                .map_err(|e| ScanError::ConfigError(e.to_string()))?,
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_str(&config.http.accept_language)
                .map_err(|e| ScanError::ConfigError(e.to_string()))?,
        );

        // Custom headers
        for (name, value) in &config.http.custom_headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| ScanError::ConfigError(format!("Invalid header name '{}': {}", name, e)))?,
                HeaderValue::from_str(value)
                    .map_err(|e| ScanError::ConfigError(format!("Invalid header value '{}': {}", value, e)))?,
            );
        }

        let mut client_builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(config.scan.timeout_secs))
            .pool_max_idle_per_host(config.http.max_connections_per_host)
            .pool_idle_timeout(std::time::Duration::from_secs(config.http.pool_idle_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(config.scan.insecure)
            .gzip(true)
            .brotli(true)
            .deflate(true);

        // Proxy support
        if let Some(ref proxy_url) = config.http.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ScanError::ConfigError(format!("Invalid proxy URL '{}': {}", proxy_url, e)))?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder
            .build()
            .map_err(|e| ScanError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Build a request with authentication if configured
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);

        if let (Some(auth_type), Some(creds)) = (&self.config.http.auth_type, &self.config.http.auth_credentials) {
            if auth_type == "basic" {
                let parts: Vec<&str> = creds.splitn(2, ':').collect();
                if parts.len() == 2 {
                    req = req.basic_auth(parts[0].to_string(), Some(parts[1].to_string()));
                }
            } else if auth_type == "bearer" {
                req = req.bearer_auth(creds);
            }
        }

        req
    }

    pub async fn fetch_url(&self, url: &str) -> Result<HttpData, ScanError> {
        let start = Instant::now();

        debug!("Fetching URL: {}", url);

        let request = self.build_request(url);
        let response = self.send_with_retry(request).await?;

        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let is_https = response.url().scheme() == "https";

        // Collect headers
        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        // Extract cookies before consuming the body (extract owned data immediately)
        let cookies: Vec<CookieInfo> = response.cookies().map(|c| {
            let value = c.value().to_string();
            CookieInfo {
                name: c.name().to_string(),
                value_preview: if value.len() > 30 { format!("{}...", &value[..27]) } else { value },
                secure: c.secure(),
                http_only: c.http_only(),
                same_site: {
                    if c.same_site_strict() { Some("Strict".to_string()) }
                    else if c.same_site_lax() { Some("Lax".to_string()) }
                    else { None }
                },
                domain: c.domain().map(|d| d.to_string()),
                path: c.path().map(|p| p.to_string()),
                expires: c.expires().map(|e| format!("{:?}", e)),
            }
        }).collect();

        // Capture TLS info before consuming the body
        let tls_host = if is_https { response.url().host_str().map(|h| h.to_string()) } else { None };
        let tls_port = if is_https { response.url().port().unwrap_or(443) } else { 0 };

        // Get body
        let body_bytes = response.bytes().await.unwrap_or_default();
        let body_size = body_bytes.len();
        let body = if body_size <= self.config.scan.max_body_size {
            String::from_utf8_lossy(&body_bytes).to_string()
        } else {
            String::from_utf8_lossy(&body_bytes[..self.config.scan.max_body_size]).to_string()
        };

        let response_time = start.elapsed().as_millis() as u64;

        // Detect technologies
        let technologies = Self::detect_technologies(&headers_map, &body);

        // Parse server info
        let server_info = Self::parse_server_info(&headers_map, &body);

        // Parse forms
        let forms = Self::parse_forms(&body, url);

        // Real TLS certificate info
        let tls_info = if let Some(ref host) = tls_host {
            Some(crate::core::tls::fetch_tls_info(host, tls_port).await)
        } else {
            None
        };

        Ok(HttpData {
            url: url.to_string(),
            final_url,
            status_code,
            is_https,
            headers: headers_map,
            body: Some(body),
            body_size,
            response_time_ms: response_time,
            redirect_chain: vec![],
            server_info,
            cookies,
            forms,
            technologies,
            tls_info,
        })
    }

    pub async fn fetch_with_redirects(&self, url: &str) -> Result<HttpData, ScanError> {
        let mut current_url = url.to_string();
        let mut redirect_chain = Vec::new();

        for _ in 0..self.config.scan.max_redirects {
            let start = Instant::now();

            let request = self.build_request(&current_url);
            let response = match self.send_with_retry(request).await {
                Ok(r) => r,
                Err(e) => {
                    if redirect_chain.is_empty() {
                        return Err(e);
                    }
                    // Return last successful response with what we have
                    break;
                }
            };

            let status = response.status().as_u16();

            // Check for redirect if follow_redirects is enabled
            if self.config.scan.follow_redirects
                && ((300..400).contains(&status) || status == 301 || status == 302 || status == 303 || status == 307 || status == 308)
            {
                if let Some(location) = response.headers().get("location") {
                    if let Ok(loc) = location.to_str() {
                        let next_url = if loc.starts_with("http") {
                            loc.to_string()
                        } else {
                            let base = url::Url::parse(&current_url).unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
                            base.join(loc).map(|u| u.to_string()).unwrap_or(loc.to_string())
                        };

                        redirect_chain.push(RedirectHop {
                            from: current_url.clone(),
                            to: next_url.clone(),
                            status_code: status,
                        });

                        current_url = next_url;
                        continue;
                    }
                }
            }

            // Not a redirect — process response
            let final_url = response.url().to_string();
            let is_https = response.url().scheme() == "https";
            let status_code = status;

            let mut headers_map: HashMap<String, String> = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    headers_map.insert(name.as_str().to_lowercase(), v.to_string());
                }
            }

            // Capture TLS info before consuming body
            let tls_host_redirect = if is_https { response.url().host_str().map(|h| h.to_string()) } else { None };
            let tls_port_redirect = if is_https { response.url().port().unwrap_or(443) } else { 0 };

            let body_bytes = response.bytes().await.unwrap_or_default();
            let body_size = body_bytes.len();
            let body = if body_size <= self.config.scan.max_body_size {
                String::from_utf8_lossy(&body_bytes).to_string()
            } else {
                String::from_utf8_lossy(&body_bytes[..self.config.scan.max_body_size]).to_string()
            };

            let response_time = start.elapsed().as_millis() as u64;

            let technologies = Self::detect_technologies(&headers_map, &body);
            let server_info = Self::parse_server_info(&headers_map, &body);

            let tls_info = if let Some(ref host) = tls_host_redirect {
                Some(crate::core::tls::fetch_tls_info(host, tls_port_redirect).await)
            } else {
                None
            };

            let cookies = Self::parse_cookies_from_headers(&headers_map);
            let forms = Self::parse_forms(&body, &final_url);

            return Ok(HttpData {
                url: url.to_string(),
                final_url,
                status_code,
                is_https,
                headers: headers_map,
                body: Some(body),
                body_size,
                response_time_ms: response_time,
                redirect_chain,
                server_info,
                cookies,
                forms,
                technologies,
                tls_info,
            });
        }

        Err(ScanError::Unknown(format!(
            "Too many redirects for {}",
            url
        )))
    }

    /// Send a request with retry and exponential backoff
    async fn send_with_retry(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response, ScanError> {
        let max_retries = self.config.scan.max_retries;
        let mut last_error = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let backoff_ms = 500u64 * 2u64.pow((attempt - 1).min(4));
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                debug!("Retry attempt {} after {}ms backoff", attempt, backoff_ms);
            }

            match request.try_clone() {
                Some(cloned) => {
                    match cloned.send().await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            if e.is_timeout() || e.is_connect() {
                                last_error = Some(e);
                                continue;
                            }
                            return Err(map_reqwest_error(e, "unknown"));
                        }
                    }
                }
                None => {
                    return request.send().await.map_err(|e| map_reqwest_error(e, "unknown"));
                }
            }
        }

        Err(last_error.map(|e| map_reqwest_error(e, "unknown")).unwrap_or_else(|| {
            ScanError::Unknown("Retry exhausted with no error".into())
        }))
    }

    /// Send a custom HTTP method request (e.g., OPTIONS for CORS testing)
    pub async fn send_custom_request(&self, method: &str, url: &str) -> Result<HttpData, ScanError> {
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ScanError::ConfigError(format!("Invalid HTTP method '{}': {}", method, e)))?;

        let mut req = self.client.request(http_method, url);
        req = self.apply_auth(req);

        let response = self.send_with_retry(req).await?;

        let final_url = response.url().to_string();
        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        Ok(HttpData {
            url: url.to_string(),
            final_url,
            status_code: response.status().as_u16(),
            is_https: response.url().scheme() == "https",
            headers: headers_map,
            body: None,
            body_size: 0,
            response_time_ms: 0,
            redirect_chain: vec![],
            server_info: ServerInfo {
                server_header: None, powered_by: None,
                detected_server: None, detected_language: None, detected_framework: None,
            },
            cookies: vec![],
            forms: vec![],
            technologies: vec![],
            tls_info: None,
        })
    }

    /// Send a POST request with a JSON body (e.g., GraphQL queries)
    pub async fn send_custom_request_body(&self, method: &str, url: &str, body: &str) -> Result<HttpData, ScanError> {
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ScanError::ConfigError(format!("Invalid HTTP method '{}': {}", method, e)))?;

        let mut req = self.client.request(http_method, url)
            .header("Content-Type", "application/json")
            .body(body.to_string());
        req = self.apply_auth(req);

        let response = self.send_with_retry(req).await?;

        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let is_https = response.url().scheme() == "https";
        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body_bytes).to_string();

        Ok(HttpData {
            url: url.to_string(),
            final_url,
            status_code,
            is_https,
            headers: headers_map,
            body: Some(body_str),
            body_size: 0,
            response_time_ms: 0,
            redirect_chain: vec![],
            server_info: ServerInfo {
                server_header: None, powered_by: None,
                detected_server: None, detected_language: None, detected_framework: None,
            },
            cookies: vec![],
            forms: vec![],
            technologies: vec![],
            tls_info: None,
        })
    }

    /// Send a request with a custom header (for CORS origin reflection testing)
    pub async fn send_custom_request_with_header(
        &self, method: &str, url: &str, header_name: &str, header_value: &str,
    ) -> Result<HttpData, ScanError> {
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ScanError::ConfigError(format!("Invalid HTTP method: {}", e)))?;

        let mut req = self.client.request(http_method, url)
            .header(header_name, header_value);
        req = self.apply_auth(req);

        let response = self.send_with_retry(req).await?;
        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        Ok(HttpData {
            url: url.to_string(),
            final_url: response.url().to_string(),
            status_code: response.status().as_u16(),
            is_https: response.url().scheme() == "https",
            headers: headers_map,
            body: None,
            body_size: 0,
            response_time_ms: 0,
            redirect_chain: vec![],
            server_info: ServerInfo { server_header: None, powered_by: None, detected_server: None, detected_language: None, detected_framework: None },
            cookies: vec![],
            forms: vec![],
            technologies: vec![],
            tls_info: None,
        })
    }

    /// Send form-encoded POST with key-value params (for POST body injection)
    pub async fn send_custom_request_form(
        &self, method: &str, url: &str, params: &[(String, String)],
    ) -> Result<HttpData, ScanError> {
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ScanError::ConfigError(format!("Invalid HTTP method: {}", e)))?;

        let mut req = self.client.request(http_method, url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(params);
        req = self.apply_auth(req);

        let response = self.send_with_retry(req).await?;
        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body_bytes).to_string();

        Ok(HttpData {
            url: url.to_string(),
            final_url: String::new(),
            status_code: 0,
            is_https: url.starts_with("https://"),
            headers: headers_map,
            body: Some(body_str),
            body_size: 0,
            response_time_ms: 0,
            redirect_chain: vec![],
            server_info: ServerInfo { server_header: None, powered_by: None, detected_server: None, detected_language: None, detected_framework: None },
            cookies: vec![],
            forms: vec![],
            technologies: vec![],
            tls_info: None,
        })
    }

    /// Fetch URL with a custom User-Agent header (for log poisoning)
    pub async fn fetch_url_with_ua(&self, url: &str, user_agent: &str) -> Result<HttpData, ScanError> {
        let mut req = self.client.get(url).header("User-Agent", user_agent);
        req = self.apply_auth(req);
        let response = self.send_with_retry(req).await?;
        Ok(HttpData {
            url: url.to_string(),
            final_url: response.url().to_string(),
            status_code: response.status().as_u16(),
            is_https: response.url().scheme() == "https",
            headers: HashMap::new(),
            body: None,
            body_size: 0,
            response_time_ms: 0,
            redirect_chain: vec![],
            server_info: ServerInfo { server_header: None, powered_by: None, detected_server: None, detected_language: None, detected_framework: None },
            cookies: vec![],
            forms: vec![],
            technologies: vec![],
            tls_info: None,
        })
    }

    /// OAuth2 client credentials flow — obtain access token
    pub async fn oauth2_client_credentials(
        &self, token_url: &str, client_id: &str, client_secret: &str, scope: Option<&str>,
    ) -> Result<String, ScanError> {
        let mut params = vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("client_secret".to_string(), client_secret.to_string()),
        ];
        if let Some(s) = scope {
            params.push(("scope".to_string(), s.to_string()));
        }

        let http_method = reqwest::Method::POST;
        let req = self.client.request(http_method, token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params);

        let response = self.send_with_retry(req).await?;
        let body = response.text().await.unwrap_or_default();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(token) = json["access_token"].as_str() {
                return Ok(token.to_string());
            }
        }

        Err(ScanError::ConfigError(format!("OAuth2 token request failed: {}", body)))
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let (Some(auth_type), Some(creds)) = (&self.config.http.auth_type, &self.config.http.auth_credentials) {
            if auth_type == "basic" {
                let parts: Vec<&str> = creds.splitn(2, ':').collect();
                if parts.len() == 2 {
                    return req.basic_auth(parts[0].to_string(), Some(parts[1].to_string()));
                }
            } else if auth_type == "bearer" {
                return req.bearer_auth(creds);
            } else if auth_type == "oauth2" {
                return req.bearer_auth(creds);
            }
        }
        req
    }

    fn detect_technologies(headers: &HashMap<String, String>, body: &str) -> Vec<String> {
        let mut techs = Vec::new();

        // Server header detection
        if let Some(server) = headers.get("server") {
            let s = server.to_lowercase();
            if s.contains("nginx") { techs.push("Nginx".into()); }
            if s.contains("apache") { techs.push("Apache".into()); }
            if s.contains("iis") || s.contains("microsoft") { techs.push("IIS".into()); }
            if s.contains("cloudflare") { techs.push("Cloudflare".into()); }
            if s.contains("caddy") { techs.push("Caddy".into()); }
            if s.contains("liteSpeed") { techs.push("LiteSpeed".into()); }
        }

        // Powered-By
        if let Some(powered) = headers.get("x-powered-by") {
            let p = powered.to_lowercase();
            if p.contains("php") { techs.push("PHP".into()); }
            if p.contains("asp.net") { techs.push("ASP.NET".into()); }
            if p.contains("express") { techs.push("Express.js".into()); }
            if p.contains("flask") || p.contains("werkzeug") { techs.push("Flask".into()); }
            if p.contains("django") { techs.push("Django".into()); }
        }

        // Body-based detection
        let body_lower = body.to_lowercase();
        if body_lower.contains("wp-content") || body_lower.contains("wp-includes") { techs.push("WordPress".into()); }
        if body_lower.contains("jquery") { techs.push("jQuery".into()); }
        if body_lower.contains("bootstrap") { techs.push("Bootstrap".into()); }
        if body_lower.contains("react") || body_lower.contains("_react") { techs.push("React".into()); }
        if body_lower.contains("vue") { techs.push("Vue.js".into()); }
        if body_lower.contains("angular") { techs.push("Angular".into()); }

        techs.sort();
        techs.dedup();
        techs
    }

    fn parse_server_info(headers: &HashMap<String, String>, _body: &str) -> ServerInfo {
        let server_header = headers.get("server").cloned();
        let powered_by = headers.get("x-powered-by").cloned();

        let detected_server = server_header.as_ref().map(|s| {
            let lower = s.to_lowercase();
            if lower.contains("nginx") { "Nginx".to_string() }
            else if lower.contains("apache") { "Apache".to_string() }
            else if lower.contains("iis") { "IIS".to_string() }
            else if lower.contains("cloudflare") { "Cloudflare".to_string() }
            else { s.clone() }
        });

        let detected_language = powered_by.as_ref().map(|p| {
            let lower = p.to_lowercase();
            if lower.contains("php") { "PHP".to_string() }
            else if lower.contains("asp.net") { "ASP.NET".to_string() }
            else if lower.contains("node") { "Node.js".to_string() }
            else { p.clone() }
        });

        ServerInfo {
            server_header,
            powered_by,
            detected_server,
            detected_language,
            detected_framework: None,
        }
    }

    /// Split a potentially concatenated Set-Cookie header value into individual cookies
    fn split_set_cookie(raw: &str) -> Vec<String> {
        let mut cookies = Vec::new();
        let mut current = String::new();
        let comma_parts: Vec<&str> = raw.split(',').collect();

        for part in comma_parts {
            let trimmed = part.trim();
            // Heuristic: if the part starts with a known cookie name pattern (contains '=' before any attribute),
            // it's a new cookie. Otherwise it's a continuation (e.g., an expires date with comma)
            if !current.is_empty() {
                let test = trimmed.to_lowercase();
                if test.contains("=") && !test.starts_with("expires=") {
                    // New cookie starting
                    cookies.push(current.trim().to_string());
                    current = trimmed.to_string();
                } else {
                    // Continuation of expires date
                    current.push_str(", ");
                    current.push_str(trimmed);
                }
            } else {
                current = trimmed.to_string();
            }
        }

        if !current.is_empty() {
            cookies.push(current.trim().to_string());
        }

        cookies
    }

    fn parse_cookies_from_headers(headers: &HashMap<String, String>) -> Vec<CookieInfo> {
        let mut cookies = Vec::new();

        if let Some(set_cookie) = headers.get("set-cookie") {
            for cookie_str in Self::split_set_cookie(set_cookie) {
                if let Some(cookie) = Self::parse_single_set_cookie(&cookie_str) {
                    cookies.push(cookie);
                }
            }
        }

        cookies
    }

    fn parse_single_set_cookie(raw: &str) -> Option<CookieInfo> {
        let parts: Vec<&str> = raw.split(';').collect();
        if parts.is_empty() { return None; }

        let first = parts[0].trim();
        let eq_pos = first.find('=')?;

        let name = first[..eq_pos].trim().to_string();
        let value = first[eq_pos + 1..].trim().to_string();

        let raw_lower = raw.to_lowercase();
        let secure = raw_lower.contains("secure");
        let http_only = raw_lower.contains("httponly");

        let mut same_site = None;
        let mut domain = None;
        let mut path = None;
        let mut expires = None;

        for attr in &parts[1..] {
            let attr = attr.trim();
            let attr_lower = attr.to_lowercase();

            if attr_lower.starts_with("domain=") {
                domain = Some(attr[7..].trim().to_string());
            } else if attr_lower.starts_with("path=") {
                path = Some(attr[5..].trim().to_string());
            } else if attr_lower.starts_with("expires=") {
                expires = Some(attr[8..].trim().to_string());
            } else if attr_lower.starts_with("samesite=") {
                same_site = Some(attr[9..].trim().to_string());
            }
        }

        Some(CookieInfo {
            name,
            value_preview: if value.len() > 30 { format!("{}...", &value[..27]) } else { value },
            secure,
            http_only,
            same_site,
            domain,
            path,
            expires,
        })
    }

    fn parse_forms(body: &str, base_url: &str) -> Vec<FormInfo> {
        let mut forms = Vec::new();

        let document = Html::parse_document(body);

        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input").unwrap();

        for form_elem in document.select(&form_selector) {
            let action = form_elem
                .value()
                .attr("action")
                .map(|a| {
                    if a.starts_with("http") {
                        a.to_string()
                    } else if a.starts_with('/') {
                        let base = url::Url::parse(base_url).unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
                        format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), a)
                    } else {
                        a.to_string()
                    }
                });

            let method = form_elem
                .value()
                .attr("method")
                .map(|m| m.to_uppercase())
                .unwrap_or_else(|| "GET".to_string());

            let mut has_password = false;
            let mut hidden_fields = Vec::new();
            let mut visible_fields = Vec::new();
            let mut has_csrf = false;

            for input in form_elem.select(&input_selector) {
                let field_type = input.value().attr("type").unwrap_or("text").to_lowercase();
                let name = input.value().attr("name").unwrap_or("").to_string();
                let is_required = input.value().attr("required").is_some();

                if field_type == "password" {
                    has_password = true;
                }

                if field_type == "hidden" {
                    hidden_fields.push(name.clone());
                    // Check for CSRF-like token names
                    if name.to_lowercase().contains("csrf")
                        || name.to_lowercase().contains("token")
                        || name.to_lowercase().contains("nonce")
                    {
                        has_csrf = true;
                    }
                }

                if !name.is_empty() && field_type != "hidden" && field_type != "submit" && field_type != "button" {
                    visible_fields.push(FormField {
                        name,
                        field_type,
                        is_required,
                    });
                }
            }

            // Also check the entire page for CSRF tokens in meta tags
            if !has_csrf {
                let meta_selector = Selector::parse("meta[name='csrf-token'], meta[name='csrf_token'], meta[name='_csrf']").unwrap();
                if document.select(&meta_selector).next().is_some() {
                    has_csrf = true;
                }
            }

            let html_snippet = {
                let html = form_elem.html();
                if html.len() > 300 {
                    format!("{}...", &html[..297])
                } else {
                    html
                }
            };

            forms.push(FormInfo {
                action,
                method,
                has_password_field: has_password,
                hidden_fields,
                has_csrf_token: has_csrf,
                visible_fields,
                html_snippet,
            });
        }

        forms
    }
}
