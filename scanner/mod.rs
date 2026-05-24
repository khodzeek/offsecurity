use crate::checks;
use crate::core::HttpClient;
use crate::models::{AppConfig, Finding, ScanResult, ScanStatistics};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

pub struct Scanner {
    client: Arc<HttpClient>,
    config: AppConfig,
    skip_checks: Vec<String>,
    browser_config: crate::core::browser::BrowserConfig,
    plugin_config: crate::plugins::PluginConfig,
    aggressive: bool,
}

impl Scanner {
    pub fn new(
        client: Arc<HttpClient>,
        config: AppConfig,
        skip_checks: Vec<String>,
        browser_config: crate::core::browser::BrowserConfig,
        plugin_config: crate::plugins::PluginConfig,
        aggressive: bool,
    ) -> Self {
        Self {
            client,
            config,
            skip_checks,
            browser_config,
            plugin_config,
            aggressive,
        }
    }

    pub async fn scan_urls(&self, urls: Vec<String>) -> Vec<ScanResult> {
        let total = urls.len();
        let pb = if self.config.output.color && total > 1 {
            let bar = ProgressBar::new(total as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            bar.set_message("Scanning targets...");
            Some(bar)
        } else {
            None
        };

        let max_concurrent = self.config.scan.max_threads;
        let delay = std::time::Duration::from_millis(self.config.scan.delay_between_requests_ms);
        let client = Arc::clone(&self.client);
        let config = self.config.clone();
        let skip = self.skip_checks.clone();
        let browser_config = self.browser_config.clone();
        let plugin_config = self.plugin_config.clone();
        let aggressive = self.aggressive;

        let results = stream::iter(urls)
            .map(|url| {
                let client = Arc::clone(&client);
                let config = config.clone();
                let skip = skip.clone();
                let browser_config = browser_config.clone();
                let plugin_config = plugin_config.clone();
                let aggressive = aggressive;
                let pb = pb.as_ref();

                async move {
                    if delay.as_millis() > 0 {
                        tokio::time::sleep(delay).await;
                    }

                    let result = scan_single_url(&client, &config, &url, &skip, &browser_config, &plugin_config, aggressive).await;

                    if let Some(ref bar) = pb {
                        bar.inc(1);
                        bar.set_message(format!("Completed: {}", url));
                    }

                    result
                }
            })
            .buffer_unordered(max_concurrent)
            .collect::<Vec<_>>()
            .await;

        if let Some(ref bar) = pb {
            bar.finish_with_message("All targets scanned");
        }

        results
    }
}

async fn scan_single_url(
    client: &HttpClient,
    config: &AppConfig,
    url: &str,
    skip_checks: &[String],
    browser_config: &crate::core::browser::BrowserConfig,
    plugin_config: &crate::plugins::PluginConfig,
    aggressive: bool,
) -> ScanResult {
    let start = Instant::now();
    let scan_start_time = chrono::Utc::now().to_rfc3339();
    let mut findings: Vec<Finding> = Vec::new();

    info!("Scanning: {}", url);

    // Fetch URL
    let http_data = match client.fetch_with_redirects(url).await {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to fetch {}: {}", url, e);
            return ScanResult {
                target_url: url.to_string(),
                scan_id: uuid::Uuid::new_v4().to_string(),
                start_time: scan_start_time,
                end_time: chrono::Utc::now().to_rfc3339(),
                duration_secs: start.elapsed().as_secs_f64(),
                findings: vec![Finding::new(
                    "connectivity",
                    "Failed to connect",
                    crate::models::Severity::High,
                    &format!("Could not connect to target: {}", e),
                    &e.to_string(),
                    "Verify the URL is correct and the server is reachable",
                    url,
                )],
                total_urls_scanned: 1,
                statistics: ScanStatistics {
                    critical: 0,
                    high: 1,
                    medium: 0,
                    low: 0,
                    info: 0,
                    total: 1,
                },
                scan_version: env!("CARGO_PKG_VERSION").to_string(),
                intensity_level: config.scan.intensity_level,
            };
        }
    };

    // Run all check modules
    if !skip_checks.contains(&"headers".to_string()) {
        findings.extend(checks::headers::check_security_headers(&http_data));
    }

    if !skip_checks.contains(&"cookies".to_string()) {
        findings.extend(checks::cookies::check_cookies(&http_data));
    }

    if !skip_checks.contains(&"forms".to_string()) {
        findings.extend(checks::forms::check_forms(&http_data));
    }

    if !skip_checks.contains(&"passive".to_string()) {
        findings.extend(checks::passive::check_passive(&http_data));
        findings.extend(checks::passive::check_sensitive_files(client, url).await);
    }

    if !skip_checks.contains(&"sensitive".to_string()) {
        findings.extend(checks::sensitive::check_info_exposure(&http_data));
    }

    // JWT + OAuth2 checks
    if !skip_checks.contains(&"jwt".to_string()) {
        findings.extend(checks::jwt::check_jwt(&http_data));
    }
    if !skip_checks.contains(&"oauth2".to_string()) {
        findings.extend(checks::oauth2::check_oauth2(&http_data));
    }

    // WebSocket checks
    if !skip_checks.contains(&"ws".to_string()) {
        findings.extend(checks::ws::check_websockets(&http_data).await);
    }

    // GraphQL checks
    if !skip_checks.contains(&"graphql".to_string()) {
        findings.extend(checks::graphql::check_graphql(client, &http_data).await);
    }

    // IDOR/BOLA checks
    if !skip_checks.contains(&"idor".to_string()) {
        findings.extend(checks::idor::check_idor(client, &http_data, url).await);
    }

    // API discovery
    if !skip_checks.contains(&"api".to_string()) {
        findings.extend(checks::api::check_api_endpoints(client, &http_data, url).await);
    }

    // SSTI checks
    if !skip_checks.contains(&"ssti".to_string()) && config.scan.intensity_level >= 2 {
        findings.extend(checks::ssti::check_ssti(client, url, &http_data, config.scan.intensity_level).await);
    }

    // NoSQL injection checks
    if !skip_checks.contains(&"nosql".to_string()) && config.scan.intensity_level >= 2 {
        findings.extend(checks::nosql::check_nosql(client, &http_data, url, config.scan.intensity_level).await);
    }

    // Rate limiting checks
    if !skip_checks.contains(&"rate-limit".to_string()) {
        findings.extend(checks::rate_limit::check_rate_limiting(client, &http_data, url, config.scan.intensity_level).await);
    }

    // OS/Software fingerprint
    if !skip_checks.contains(&"fingerprint".to_string()) {
        findings.extend(checks::fingerprint::fingerprint(client, &http_data).await);
        if config.output.verbose {
            let report = checks::fingerprint::generate_exploit_report(&http_data);
            if !report.is_empty() {
                println!("{}", report);
            }
        }
    }

    // Active checks based on intensity level
    if config.scan.intensity_level >= 2 {
        findings.extend(
            checks::active::run_active_checks(
                client,
                url,
                &http_data,
                config.scan.intensity_level,
                skip_checks,
            ).await,
        );
    }

    // Aggressive fuzzing (HPP, CRLF, Host header, polyglots, hidden params)
    if aggressive && !skip_checks.contains(&"fuzzer".to_string()) {
        let baseline_body = http_data.body.as_deref().unwrap_or("");
        let baseline_headers = &http_data.headers;
        findings.extend(
            checks::fuzzer::run_aggressive_fuzzing(
                client, url, baseline_body, baseline_headers,
            ).await,
        );
    }

    // Headless browser analysis
    if browser_config.enabled && !skip_checks.contains(&"browser".to_string()) {
        findings.extend(
            crate::core::browser::analyze_with_browser(
                url,
                browser_config,
                &config.output.output_dir,
                &uuid::Uuid::new_v4().to_string(),
            ).await,
        );
    }

    // WASM plugin execution
    if !skip_checks.contains(&"plugins".to_string()) {
        findings.extend(
            crate::plugins::run_plugins(plugin_config, &http_data).await,
        );
    }

    let statistics = ScanStatistics::from_findings(&findings);
    let duration = start.elapsed().as_secs_f64();

    debug!(
        "Scan complete for {} — {} findings in {:.2}s",
        url,
        findings.len(),
        duration
    );

    ScanResult {
        target_url: url.to_string(),
        scan_id: uuid::Uuid::new_v4().to_string(),
        start_time: scan_start_time,
        end_time: chrono::Utc::now().to_rfc3339(),
        duration_secs: duration,
        findings,
        total_urls_scanned: 1,
        statistics,
        scan_version: env!("CARGO_PKG_VERSION").to_string(),
        intensity_level: config.scan.intensity_level,
    }
}
