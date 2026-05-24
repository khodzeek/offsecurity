use crate::models::Finding;
use crate::models::Severity;
use std::time::Duration;
use tokio_tungstenite::connect_async;
// use tokio_tungstenite::tungstenite::Message; // reserved for frame inspection

/// Test a WebSocket connection and run security checks
pub async fn check_websocket(
    ws_url: &str,
    origin: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let request = match tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(ws_url)
        .header("Origin", origin)
        .body(())
    {
        Ok(req) => req,
        Err(e) => {
            findings.push(Finding::new(
                "ws",
                "WebSocket request building failed",
                Severity::Info,
                format!("Could not build WebSocket request for {}: {}", ws_url, e),
                format!("URL: {}", ws_url),
                "Verify the WebSocket URL format.",
                ws_url,
            ));
            return findings;
        }
    };

    match tokio::time::timeout(Duration::from_secs(10), connect_async(request)).await {
        Ok(Ok((_ws_stream, response))) => {
            // Check response headers for security issues
            let headers = response.headers();

            // Missing Origin validation
            if let Some(acao) = headers.get("access-control-allow-origin") {
                if acao == "*" {
                    findings.push(Finding::new(
                        "ws",
                        "WebSocket allows any origin",
                        Severity::High,
                        "The WebSocket server allows connections from any origin (*), enabling Cross-Site WebSocket Hijacking.",
                        format!("Access-Control-Allow-Origin: * on {}", ws_url),
                        "Validate the Origin header on the server side. Only allow specific, trusted origins.",
                        ws_url,
                    ));
                }
            }

            // Check for missing Sec-WebSocket-Accept
            if !headers.contains_key("sec-websocket-accept") {
                findings.push(Finding::new(
                    "ws",
                    "WebSocket handshake missing Sec-WebSocket-Accept",
                    Severity::Medium,
                    "The WebSocket handshake response lacks the Sec-WebSocket-Accept header, indicating a non-compliant or misconfigured server.",
                    format!("Missing Sec-WebSocket-Accept on {}", ws_url),
                    "Ensure the WebSocket server properly implements the RFC 6455 handshake.",
                    ws_url,
                ));
            }

            // Check if permessage-deflate compression is enabled (CRIME-like risk)
            if let Some(extensions) = headers.get("sec-websocket-extensions") {
                if let Ok(ext_str) = extensions.to_str() {
                    if ext_str.contains("permessage-deflate") {
                        findings.push(Finding::new(
                            "ws",
                            "WebSocket compression enabled (CRIME risk)",
                            Severity::Medium,
                            "Per-message compression (permessage-deflate) is enabled, which may be vulnerable to compression oracle attacks (CRIME/BREACH-style).",
                            format!("Sec-WebSocket-Extensions: {}", ext_str),
                            "Disable permessage-deflate if the WebSocket transmits secret data alongside attacker-controlled data.",
                            ws_url,
                        ));
                    }
                }
            }

            // Success info
            findings.push(Finding::new(
                "ws",
                "WebSocket endpoint accessible",
                Severity::Info,
                format!("WebSocket endpoint {} accepted the connection.", ws_url),
                format!("Connected successfully to {}", ws_url),
                "Ensure the WebSocket endpoint requires authentication for sensitive operations.",
                ws_url,
            ));
        }
        Ok(Err(e)) => {
            findings.push(Finding::new(
                "ws",
                "WebSocket connection failed",
                Severity::Info,
                format!("Could not connect to WebSocket {}: {}", ws_url, e),
                format!("Error: {}", e),
                "Verify the WebSocket endpoint is accessible.",
                ws_url,
            ));
        }
        Err(_) => {
            findings.push(Finding::new(
                "ws",
                "WebSocket connection timeout",
                Severity::Info,
                format!("Timeout connecting to WebSocket {}", ws_url),
                format!("Timeout after 10s for {}", ws_url),
                "Check network connectivity and server availability.",
                ws_url,
            ));
        }
    }

    findings
}

/// Extract WebSocket URLs from page content
pub fn extract_ws_urls(body: &str, base_url: &str) -> Vec<String> {
    let mut urls = Vec::new();

    // Look for ws:// and wss:// URLs in page source
    for prefix in &["ws://", "wss://"] {
        let mut start = 0;
        while let Some(pos) = body[start..].find(prefix) {
            let abs_pos = start + pos;
            let end = body[abs_pos..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == ')')
                .map(|p| abs_pos + p)
                .unwrap_or_else(|| body.len());
            let ws_url = body[abs_pos..end].trim_end_matches(&['"', '\'', ')', ',', ';'] as &[_]).to_string();
            if ws_url.len() > 6 && !urls.contains(&ws_url) {
                urls.push(ws_url);
            }
            start = abs_pos + prefix.len();
        }
    }

    // Also look for relative WebSocket paths in JS (new WebSocket("/ws"))
    let re = regex::Regex::new(r#"new\s+WebSocket\s*\(\s*["']([^"']+)["']"#).unwrap();
    for cap in re.captures_iter(body) {
        let path = &cap[1];
        let resolved = if path.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_url) {
                let scheme = if parsed.scheme() == "https" { "wss" } else { "ws" };
                format!("{}://{}{}", scheme, parsed.host_str().unwrap_or("localhost"), path)
            } else {
                path.to_string()
            }
        } else if path.starts_with("ws") {
            path.to_string()
        } else {
            // Relative path
            format!("{}/{}", base_url.trim_end_matches('/'), path)
        };
        if !urls.contains(&resolved) {
            urls.push(resolved);
        }
    }

    urls
}
