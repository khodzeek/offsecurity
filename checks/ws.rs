use crate::core::ws_client;
use crate::models::{Finding, HttpData};

/// Check for WebSocket endpoints and run WebSocket security checks
pub async fn check_websockets(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    let body = match &data.body {
        Some(b) => b,
        None => return findings,
    };

    // Detect WebSocket URLs in page source
    let ws_urls = ws_client::extract_ws_urls(body, &data.final_url);

    if ws_urls.is_empty() {
        return findings;
    }

    for ws_url in &ws_urls {
        // Connect to each WebSocket and run checks
        let ws_findings = ws_client::check_websocket(ws_url, &data.final_url).await;
        findings.extend(ws_findings);
    }

    findings
}
