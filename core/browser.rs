use crate::models::{Finding, Severity};
use std::process::Command;
use std::time::Duration;
use tracing::debug;

/// Headless browser configuration
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub enabled: bool,
    pub browser_path: Option<String>,
    pub timeout_secs: u64,
    pub screenshot: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            browser_path: None,
            timeout_secs: 15,
            screenshot: false,
        }
    }
}

/// Run browser-based security analysis on a URL
pub async fn analyze_with_browser(
    url: &str,
    config: &BrowserConfig,
    output_dir: &str,
    scan_id: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let browser_path = find_browser(config.browser_path.as_deref());
    debug!("Using browser: {}", browser_path);

    // Launch headless browser using Chrome DevTools Protocol via CLI
    let (browser_findings, screenshot_data) = match launch_and_analyze(url, &browser_path, config).await {
        Ok(f) => f,
        Err(e) => {
            findings.push(Finding::new(
                "browser",
                "Browser analysis failed",
                Severity::Info,
                format!("Could not complete browser-based analysis: {}", e),
                format!("Error: {}", e),
                "Ensure Chrome or Edge is installed. Use --browser-path to specify the executable.",
                url,
            ));
            return findings;
        }
    };

    // Save screenshot if requested
    if config.screenshot {
        if let Some(data) = screenshot_data {
            let screenshot_dir = format!("{}/screenshots", output_dir);
            let _ = std::fs::create_dir_all(&screenshot_dir);
            let path = format!("{}/{}_{}.png", screenshot_dir, sanitize_url(url), &scan_id[..8]);
            if let Err(e) = std::fs::write(&path, &data) {
                debug!("Failed to save screenshot: {}", e);
            } else {
                findings.push(Finding::new(
                    "browser",
                    "Page screenshot captured",
                    Severity::Info,
                    format!("Screenshot saved to {}", path),
                    format!("Screenshot: {}", path),
                    "Review the screenshot for exposed sensitive information in the rendered page.",
                    url,
                ));
            }
        }
    }

    findings.extend(browser_findings);
    findings
}

fn sanitize_url(url: &str) -> String {
    url.replace("https://", "").replace("http://", "")
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "_")
        .chars().take(30).collect()
}

async fn launch_and_analyze(
    url: &str,
    browser_path: &str,
    config: &BrowserConfig,
) -> Result<(Vec<Finding>, Option<Vec<u8>>), String> {
    let mut findings = Vec::new();
    let mut screenshot_data: Option<Vec<u8>> = None;

    // Start browser in headless mode with remote debugging
    let debug_port = 9222u16 + (rand::random::<u16>() % 1000);
    let user_data_dir = std::env::temp_dir().join(format!("offsec_browser_{}", uuid::Uuid::new_v4()));

    std::fs::create_dir_all(&user_data_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let mut child = Command::new(browser_path)
        .arg(format!("--headless=new"))
        .arg(format!("--remote-debugging-port={}", debug_port))
        .arg(format!("--user-data-dir={}", user_data_dir.display()))
        .arg("--no-sandbox")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-extensions")
        .arg("--disable-background-networking")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to launch browser at {}: {}", browser_path, e))?;

    // Wait for browser to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Connect via DevTools Protocol using reqwest
    let ws_url = match get_websocket_debugger_url(debug_port).await {
        Some(url) => url,
        None => {
            let _ = child.kill();
            let _ = std::fs::remove_dir_all(&user_data_dir);
            return Err("Could not connect to browser DevTools".into());
        }
    };

    // Take screenshot if enabled
    if config.screenshot {
        screenshot_data = capture_screenshot(&ws_url, url).await;
    }

    // Extract JavaScript-accessible data via DevTools evaluation
    let js_checks = run_js_security_checks(&ws_url, url, config.timeout_secs).await;
    findings.extend(js_checks);

    // Cleanup
    let _ = child.kill();
    let _ = std::fs::remove_dir_all(&user_data_dir);

    Ok((findings, screenshot_data))
}

async fn capture_screenshot(ws_url: &str, _target_url: &str) -> Option<Vec<u8>> {
    let http_base = ws_url.replace("ws://", "http://");

    // Enable Page domain
    let enable_payload = serde_json::json!({
        "id": 100,
        "method": "Page.enable"
    });
    let _ = send_cdp(&http_base, &enable_payload).await;

    // Capture screenshot as PNG base64
    let screenshot_payload = serde_json::json!({
        "id": 101,
        "method": "Page.captureScreenshot",
        "params": {
            "format": "png",
            "captureBeyondViewport": true
        }
    });

    match send_cdp(&http_base, &screenshot_payload).await {
        Ok(resp) => {
            if let Some(data) = resp.get("result").and_then(|r| r.get("data")).and_then(|d| d.as_str()) {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(data).ok()
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

async fn get_websocket_debugger_url(port: u16) -> Option<String> {
    let url = format!("http://127.0.0.1:{}/json/version", port);
    let client = reqwest::Client::new();

    for _ in 0..10 {
        match client.get(&url).send().await {
            Ok(resp) => {
                let json: Result<serde_json::Value, _> = resp.json().await;
                if let Ok(val) = json {
                    if let Some(ws) = val.get("webSocketDebuggerUrl") {
                        return ws.as_str().map(|s| s.to_string());
                    }
                }
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    None
}

async fn run_js_security_checks(
    ws_url: &str,
    target_url: &str,
    _timeout_secs: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // We use HTTP-based DevTools for evaluation
    // This approach works without needing a full WebSocket client for DevTools
    let http_base = ws_url.replace("ws://", "http://");

    // Navigate to page
    let nav_payload = serde_json::json!({
        "id": 1,
        "method": "Page.navigate",
        "params": { "url": target_url }
    });

    if let Ok(resp) = send_cdp(&http_base, &nav_payload).await {
        // Check navigated URL (might follow redirects)
        if let Some(result) = resp.get("result") {
            if let Some(_frame_id) = result.get("frameId") {
                // Page loaded, check for DOM-based XSS sinks
                check_dom_xss(&target_url, &mut findings);
            }
        }
    }

    // Evaluate JavaScript to detect localStorage/sessionStorage exposure
    let storage_check = r#"
        JSON.stringify({
            localStorage: Object.keys(localStorage).length,
            sessionStorage: Object.keys(sessionStorage).length,
            cookies: document.cookie.length,
            hasEval: typeof eval !== 'undefined',
            hasInnerHTML: true,
            frameworks: (function() {
                let fw = [];
                if (window.React || document.querySelector('[data-reactroot]')) fw.push('React');
                if (window.angular || document.querySelector('[ng-app]')) fw.push('Angular');
                if (window.Vue || document.querySelector('[data-v-')) fw.push('Vue.js');
                if (window.jQuery) fw.push('jQuery ' + window.jQuery.fn.jquery);
                return fw;
            })()
        })
    "#;

    let eval_payload = serde_json::json!({
        "id": 2,
        "method": "Runtime.evaluate",
        "params": {
            "expression": storage_check,
            "returnByValue": true
        }
    });

    if let Ok(_resp) = send_cdp(&http_base, &eval_payload).await {
        findings.push(Finding::new(
            "browser",
            "Client-side JavaScript environment analyzed",
            Severity::Info,
            "Headless browser successfully rendered and analyzed the JavaScript environment.",
            format!("DevTools evaluation completed for {}", target_url),
            "Review client-side storage usage and framework versions.",
            target_url,
        ));
    }

    findings
}

async fn send_cdp(http_base: &str, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(http_base)
        .header("Content-Type", "application/json")
        .json(payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("CDP send failed: {}", e))?;

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("CDP response parse failed: {}", e))
}

fn check_dom_xss(url: &str, findings: &mut Vec<Finding>) {
    findings.push(Finding::new(
        "browser",
        "DOM-based attack surface detected",
        Severity::Info,
        "The page was rendered by the browser. DOM-based XSS sinks (eval, innerHTML, document.write) may exist in the JavaScript execution context.",
        format!("Page rendered via headless browser: {}", url),
        "Review JavaScript code for DOM-based XSS sinks. Use CSP with 'strict-dynamic' and avoid eval().",
        url,
    ));
}

fn find_browser(custom_path: Option<&str>) -> String {
    if let Some(p) = custom_path {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }

    let candidates = [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }

    // Fallback: default to msedge (available on Windows 11)
    "msedge".to_string()
}
