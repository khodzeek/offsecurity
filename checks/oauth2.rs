use crate::models::{Finding, HttpData, Severity};

/// Check for OAuth2/OIDC security issues
pub fn check_oauth2(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    let body = match &data.body {
        Some(b) => b,
        None => return findings,
    };

    // Detect OAuth2 endpoints referenced in page source
    let oauth_patterns = detect_oauth_urls(body);

    if oauth_patterns.is_empty() {
        return findings;
    }

    for (auth_url, pattern_type) in &oauth_patterns {
        match pattern_type.as_str() {
            "authorize" => check_authorize_endpoint(auth_url, body, &data.final_url, &mut findings),
            "token" => check_token_endpoint_exposure(auth_url, &data.final_url, &mut findings),
            "redirect_uri" => check_redirect_uri(body, &data.final_url, &mut findings),
            "client_id" => check_client_id_exposure(body, &data.final_url, &mut findings),
            _ => {}
        }
    }

    findings
}

fn detect_oauth_urls(body: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();

    // Common OAuth2/OIDC URL patterns
    let patterns = [
        ("/authorize", "authorize"),
        ("/oauth2/authorize", "authorize"),
        ("/oauth/authorize", "authorize"),
        ("/oidc/auth", "authorize"),
        ("response_type=code", "authorize"),
        ("response_type=token", "token"),
        ("grant_type=authorization_code", "token"),
        ("grant_type=implicit", "token"),
        ("redirect_uri=", "redirect_uri"),
        ("client_id=", "client_id"),
    ];

    let body_lower = body.to_lowercase();

    for (pattern, ptype) in &patterns {
        if body_lower.contains(pattern) {
            // Extract the full URL if possible
            if let Some(full_url) = extract_url_around(body, pattern) {
                if !results.iter().any(|(u, _)| u == &full_url) {
                    results.push((full_url, ptype.to_string()));
                }
            }
        }
    }

    results
}

fn extract_url_around(body: &str, pattern: &str) -> Option<String> {
    if let Some(pos) = body.find(pattern) {
        let start = body[..pos].rfind(|c: char| c == '"' || c == '\'' || c == ' ').map(|p| p + 1).unwrap_or(0);
        let end = body[pos..].find(|c: char| c == '"' || c == '\'' || c == ' ' || c == '&').map(|p| pos + p).unwrap_or_else(|| body.len());
        let fragment = body[start..end].to_string();
        if fragment.len() > 10 {
            return Some(fragment);
        }
    }
    None
}

fn check_authorize_endpoint(url: &str, body: &str, page_url: &str, findings: &mut Vec<Finding>) {
    // Check for PKCE
    if !body.to_lowercase().contains("code_challenge") && !body.to_lowercase().contains("pkce") {
        findings.push(Finding::new(
            "oauth2",
            "OAuth2 authorization code flow without PKCE",
            Severity::Medium,
            "The authorization code flow is used without PKCE (Proof Key for Code Exchange), making it vulnerable to authorization code interception attacks.",
            format!("URL: {}\nNo code_challenge parameter found.", url),
            "Implement PKCE (S256) for all authorization code flows, especially for SPAs and mobile apps.",
            page_url,
        ));
    }

    // Check for state parameter
    if !url.to_lowercase().contains("state=") {
        findings.push(Finding::new(
            "oauth2",
            "OAuth2 missing state parameter (CSRF risk)",
            Severity::High,
            "The authorization request lacks a 'state' parameter, making the flow vulnerable to CSRF attacks. An attacker can bind the victim's authorization code to their own session.",
            format!("URL: {}\nNo state parameter found.", url),
            "Always include a random 'state' parameter in authorization requests and validate it in the callback.",
            page_url,
        ));
    }

    // Check for implicit flow
    if url.contains("response_type=token") || url.contains("response_type=id_token") {
        findings.push(Finding::new(
            "oauth2",
            "OAuth2 implicit flow detected (deprecated)",
            Severity::Medium,
            "The implicit flow (response_type=token) is deprecated per OAuth 2.1. Access tokens are exposed in the URL fragment, making them vulnerable to leakage via Referer headers and browser history.",
            format!("URL: {}", url),
            "Migrate to the authorization code flow with PKCE. Never use implicit flow for new applications.",
            page_url,
        ));
    }

    // Check scope
    if let Some(scope_start) = url.to_lowercase().find("scope=") {
        let scope_str = &url[scope_start + 6..];
        let scope_end = scope_str.find('&').unwrap_or(scope_str.len());
        let scope = &scope_str[..scope_end];

        if scope.contains("openid") && scope.contains("email") && scope.contains("profile") {
            findings.push(Finding::new(
                "oauth2",
                "OAuth2 requests broad scopes (openid email profile)",
                Severity::Info,
                "The authorization request asks for multiple scopes. While common for OIDC, ensure no unnecessary scopes are requested.",
                format!("Scopes: {}", scope),
                "Follow the principle of least privilege — only request scopes that are strictly necessary.",
                page_url,
            ));
        }
    }
}

fn check_token_endpoint_exposure(url: &str, page_url: &str, findings: &mut Vec<Finding>) {
    findings.push(Finding::new(
        "oauth2",
        "OAuth2 token/grant endpoint referenced in client-side code",
        Severity::Low,
        format!("An OAuth2 token or grant endpoint is referenced in client-side code: {}. Ensure client secrets are not exposed.", url),
        format!("URL: {}", url),
        "Never expose token endpoints with client secrets in client-side code. Use BFF (Backend for Frontend) pattern.",
        page_url,
    ));
}

fn check_redirect_uri(body: &str, page_url: &str, findings: &mut Vec<Finding>) {
    if let Some(uri_start) = body.to_lowercase().find("redirect_uri=") {
        let rest = &body[uri_start + 13..];
        let uri_end = rest.find('&').unwrap_or(rest.len());
        let redirect_uri = &rest[..uri_end];

        // Check for open redirect: redirect_uri pointing to a different domain
        if redirect_uri.starts_with("http://") || redirect_uri.starts_with("https://") {
            if let Ok(parsed) = url::Url::parse(page_url) {
                if let Ok(redirect_parsed) = url::Url::parse(redirect_uri) {
                    if parsed.host_str() != redirect_parsed.host_str() {
                        findings.push(Finding::new(
                            "oauth2",
                            "OAuth2 open redirect in redirect_uri",
                            Severity::High,
                            format!("The redirect_uri parameter '{}' points to a different domain than the page origin. This could allow authorization code theft if not validated server-side.", redirect_uri),
                            format!("redirect_uri: {}\nPage origin: {}", redirect_uri, page_url),
                            "Always validate redirect_uri on the server side against a whitelist of allowed URIs.",
                            page_url,
                        ));
                    }
                }
            }
        }
    }
}

fn check_client_id_exposure(body: &str, page_url: &str, findings: &mut Vec<Finding>) {
    // client_id in client-side code is normal (it's public), but check for suspicious patterns
    if body.contains("client_secret") {
        findings.push(Finding::new(
            "oauth2",
            "OAuth2 client_secret exposed in client-side code",
            Severity::Critical,
            "A client_secret was found in the page source. Client secrets must NEVER be in client-side code — only on a backend server.",
            format!("Found 'client_secret' in page source at {}", page_url),
            "Move the client_secret to server-side code immediately and rotate the compromised secret.",
            page_url,
        ));
    }
}
