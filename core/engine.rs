use crate::cli::ScanArgs;
use crate::core::HttpClient;
use crate::models::AppConfig;
use crate::scanner::Scanner;
use crate::utils::ScanError;
use crate::output;
use std::sync::Arc;
use tracing::{info, error};

pub struct ScanEngine {
    config: AppConfig,
    args: ScanArgs,
    pub browser_config: crate::core::browser::BrowserConfig,
    pub plugin_config: crate::plugins::PluginConfig,
    pub crawler_config: crate::core::crawler::CrawlerConfig,
    pub webhook_url: Option<String>,
}

impl ScanEngine {
    pub fn new(mut config: AppConfig, args: ScanArgs) -> Self {
        // ═══ Aggressive mode override ═══
        if args.aggressive {
            config.scan.intensity_level = 3;
            config.scan.delay_between_requests_ms = 0;
            config.scan.max_threads = 100;
            config.scan.timeout_secs = 10;
            config.scan.max_retries = 5;
            config.scan.insecure = true;
            config.scan.max_body_size = 0; // unlimited
            config.output.json_report = true;
            config.output.html_report = true;
            config.output.txt_report = true;
        }

        // Merge CLI args into config (may override aggressive defaults)
        config.scan.timeout_secs = if args.aggressive { config.scan.timeout_secs } else { args.timeout };
        config.scan.max_threads = if args.aggressive { config.scan.max_threads } else { args.threads };
        config.scan.delay_between_requests_ms = if args.aggressive { config.scan.delay_between_requests_ms } else { args.delay };
        config.scan.max_retries = if args.aggressive { config.scan.max_retries } else { args.retries };
        config.output.verbose = args.verbose || args.aggressive;
        config.output.color = !args.no_color;
        config.output.output_dir = args.output.clone();

        if let Some(ref ua) = args.user_agent {
            config.http.user_agent = ua.clone();
        } else if args.aggressive {
            config.http.user_agent = "offsecurity/1.0 (Aggressive Scan)".into();
        }

        // Intensity level
        config.scan.intensity_level = if args.aggressive { 3 } else { args.intensity_level };
        config.scan.insecure = args.insecure || args.aggressive;

        // Tor proxy (overrides --proxy)
        if args.tor {
            let tor_proxy = format!("socks5h://127.0.0.1:{}", args.tor_port);
            config.http.proxy_url = Some(tor_proxy);
            config.http.tor_enabled = true;
            // Force generic UA for anonymity
            if args.user_agent.is_none() {
                config.http.user_agent = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0".into();
            }
            // Accept self-signed certs (Tor exit nodes may intercept)
            config.scan.insecure = true;
        } else if let Some(ref proxy) = args.proxy {
            config.http.proxy_url = Some(proxy.clone());
        }

        // Custom headers
        config.http.custom_headers = args.custom_headers.iter().map(|h| {
            let mut parts = h.splitn(2, ':');
            let name = parts.next().unwrap_or("").trim().to_string();
            let value = parts.next().unwrap_or("").trim().to_string();
            (name, value)
        }).collect();

        // Authentication
        if let Some(ref auth) = args.auth {
            if let Some(creds) = auth.strip_prefix("basic:") {
                config.http.auth_type = Some("basic".into());
                config.http.auth_credentials = Some(creds.to_string());
            } else if let Some(token) = auth.strip_prefix("bearer:") {
                config.http.auth_type = Some("bearer".into());
                config.http.auth_credentials = Some(token.to_string());
            } else if let Some(oauth2_creds) = auth.strip_prefix("oauth2:") {
                config.http.auth_type = Some("oauth2".into());
                config.http.auth_credentials = Some(oauth2_creds.to_string());
            }
        }

        let webhook_url = args.webhook.clone();

        // Merge rate_limit_ms into delay
        config.scan.delay_between_requests_ms = std::cmp::max(config.scan.rate_limit_ms, args.delay);

        // Report format overrides
        if args.json_only {
            config.output.json_report = true;
            config.output.html_report = false;
            config.output.txt_report = false;
        }
        if args.html_only {
            config.output.json_report = false;
            config.output.html_report = true;
            config.output.txt_report = false;
        }
        if args.txt_only {
            config.output.json_report = false;
            config.output.html_report = false;
            config.output.txt_report = true;
        }

        let browser_config = crate::core::browser::BrowserConfig {
            enabled: args.browser || args.aggressive,
            browser_path: args.browser_path.clone(),
            timeout_secs: if args.aggressive { 10 } else { args.browser_timeout },
            screenshot: args.screenshot || args.aggressive,
        };

        let plugin_config = crate::plugins::PluginConfig {
            plugins_dir: args.plugins_dir.clone(),
            timeout_secs: args.plugin_timeout,
        };

        let crawler_config = crate::core::crawler::CrawlerConfig {
            enabled: args.crawl || args.aggressive,
            max_pages: if args.aggressive { 500 } else { args.crawl_max_pages.unwrap_or(100) },
            same_origin_only: if args.aggressive { false } else { !args.crawl_all_origins },
        };

        Self { config, args, browser_config, plugin_config, crawler_config, webhook_url }
    }

    pub async fn run(&self) -> Result<(), ScanError> {
        output::banner::print_banner();

        // Tor connectivity check
        if self.config.http.tor_enabled {
            let tor_check = self.verify_tor_connection().await;
            if tor_check {
                output::banner::print_info("Tor connection verified — scanning anonymously");
            } else {
                output::banner::print_error("Tor proxy not reachable. Ensure Tor is running (tor --socksport 9050)");
                return Err(ScanError::ConnectionError {
                    url: "tor://127.0.0.1".into(),
                    reason: "Tor SOCKS5 proxy not accessible".into(),
                });
            }
        }

        // OAuth2 flow
        let mut http_config = self.config.http.clone();
        if let Some(ref oauth2_cfg) = self.config.oauth2 {
            if http_config.auth_type.as_deref() == Some("oauth2") {
                let creds = http_config.auth_credentials.as_deref().unwrap_or("");
                let parts: Vec<&str> = creds.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let temp_client = HttpClient::new(self.config.clone())?;
                    match temp_client.oauth2_client_credentials(
                        &oauth2_cfg.token_url,
                        parts[0],
                        parts[1],
                        oauth2_cfg.scope.as_deref(),
                    ).await {
                        Ok(token) => {
                            http_config.auth_type = Some("bearer".into());
                            http_config.auth_credentials = Some(token);
                            output::banner::print_info("OAuth2 token obtained successfully");
                        }
                        Err(e) => {
                            output::banner::print_warning(&format!("OAuth2 token request failed: {}", e));
                        }
                    }
                }
            }
        }

        // Collect target URLs
        let urls = self.collect_urls()?;

        if urls.is_empty() {
            error!("No valid URLs to scan");
            output::banner::print_error("No valid URLs provided. Use --url or --file to specify targets.");
            return Ok(());
        }

        // Crawl if enabled — expand URL list
        let expanded_urls = if self.crawler_config.enabled {
            let crawl_client = Arc::new(HttpClient::new(self.config.clone())?);
            let mut all_urls = urls.clone();
            for url in &urls {
                let discovered = crate::core::crawler::crawl(&crawl_client, url, &self.crawler_config).await;
                for d in discovered {
                    if !all_urls.contains(&d) {
                        all_urls.push(d);
                    }
                }
            }
            output::banner::print_info(&format!("Crawler expanded {} URLs to {} pages", urls.len(), all_urls.len()));
            all_urls
        } else {
            urls
        };

        info!("Starting scan — {} target(s)", expanded_urls.len());
        output::banner::print_scan_start(&expanded_urls, &self.config, self.args.aggressive);

        // Build HTTP client with potentially OAuth2-authenticated config
        let mut final_config = self.config.clone();
        final_config.http = http_config;
        let client = Arc::new(HttpClient::new(final_config)?);

        // Build scanner
        let skip_checks: Vec<String> = self
            .args
            .skip_checks
            .as_ref()
            .map(|v| v.iter().map(|s| s.trim().to_lowercase()).collect())
            .unwrap_or_default();

        let scanner = Scanner::new(
            client,
            self.config.clone(),
            skip_checks,
            self.browser_config.clone(),
            self.plugin_config.clone(),
            self.args.aggressive,
        );

        // Run scan
        let scan_uuid = uuid::Uuid::new_v4().to_string();
        let results = scanner.scan_urls(expanded_urls).await;

        // Generate reports
        self.generate_reports(&results, &scan_uuid)?;

        // Generate exploits if requested (always in aggressive mode)
        if self.args.exploit || self.args.aggressive {
            match crate::exploits::generate_exploits(&results, &self.config.output.output_dir) {
                Ok(count) => {
                    output::banner::print_report_saved("EXPLOITS", &format!("{}/exploits/ ({} files)", self.config.output.output_dir, count));
                }
                Err(e) => {
                    output::banner::print_warning(&format!("Failed to generate exploits: {}", e));
                }
            }
        }

        // Save to DB if requested (always in aggressive mode)
        if self.args.save_to_db || self.args.aggressive {
            match crate::db::store::init_db(&self.args.db_path) {
                Ok(conn) => {
                    for result in &results {
                        if let Err(e) = crate::db::store::save_scan(&conn, result) {
                            output::banner::print_warning(&format!("Failed to save scan to DB: {}", e));
                        }
                    }
                    output::banner::print_info(&format!("Scan saved to database: {}", self.args.db_path));
                }
                Err(e) => {
                    output::banner::print_warning(&format!("Failed to initialize database: {}", e));
                }
            }
        }

        // Send webhook notification if configured
        if let Some(ref webhook_url) = self.webhook_url {
            self.send_webhook(webhook_url, &results, &scan_uuid).await;
        } else if let Some(ref wh_cfg) = self.config.webhook {
            self.send_webhook(&wh_cfg.url, &results, &scan_uuid).await;
        }

        // Print final statistics
        output::stats::print_statistics(
            &results,
            self.config.scan.timeout_secs,
            self.config.scan.max_threads,
        );

        info!("Scan completed successfully");
        Ok(())
    }

    async fn send_webhook(&self, url: &str, results: &[crate::models::ScanResult], scan_id: &str) {
        let payload = serde_json::json!({
            "scan_id": scan_id,
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "total_targets": results.len(),
            "total_findings": results.iter().map(|r| r.statistics.total).sum::<usize>(),
            "critical": results.iter().map(|r| r.statistics.critical).sum::<usize>(),
            "high": results.iter().map(|r| r.statistics.high).sum::<usize>(),
            "medium": results.iter().map(|r| r.statistics.medium).sum::<usize>(),
            "low": results.iter().map(|r| r.statistics.low).sum::<usize>(),
            "info": results.iter().map(|r| r.statistics.info).sum::<usize>(),
        });

        match reqwest::Client::new()
            .post(url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(_) => output::banner::print_info(&format!("Webhook sent to {}", url)),
            Err(e) => output::banner::print_warning(&format!("Webhook failed: {}", e)),
        }
    }

    fn collect_urls(&self) -> Result<Vec<String>, ScanError> {
        match (&self.args.url, &self.args.file) {
            (Some(url), _) => {
                let normalized = crate::utils::url_utils::normalize_url(url);
                if !crate::utils::url_utils::is_valid_url(&normalized) {
                    return Err(ScanError::InvalidUrl(format!(
                        "'{}' is not a valid URL",
                        url
                    )));
                }
                Ok(vec![normalized])
            }
            (_, Some(file)) => {
                crate::utils::url_utils::read_urls_from_file(file).map_err(|e| {
                    ScanError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to read URLs file '{}': {}", file, e),
                    ))
                })
            }
            (None, None) => {
                Err(ScanError::InvalidUrl(
                    "No target specified. Use --url or --file.".into(),
                ))
            }
        }
    }

    fn generate_reports(&self, results: &[crate::models::ScanResult], scan_id: &str) -> Result<(), ScanError> {
        use crate::reports;

        // Ensure output directory exists
        std::fs::create_dir_all(&self.config.output.output_dir).map_err(|e| {
            ScanError::ReportError(format!("Cannot create output directory: {}", e))
        })?;

        if self.config.output.json_report {
            let path = format!("{}/scan_{}.json", self.config.output.output_dir, &scan_id[..8]);
            reports::json::generate(results, &path)?;
            output::banner::print_report_saved("JSON", &path);
        }

        if self.config.output.html_report {
            let path = format!("{}/scan_{}.html", self.config.output.output_dir, &scan_id[..8]);
            reports::html::generate(results, &path)?;
            output::banner::print_report_saved("HTML", &path);
        }

        if self.config.output.txt_report {
            let path = format!("{}/scan_{}.txt", self.config.output.output_dir, &scan_id[..8]);
            reports::txt::generate(results, &path)?;
            output::banner::print_report_saved("TXT", &path);
        }

        // Enterprise formats (always all in aggressive mode)
        let gen_all = self.args.all_formats || self.args.aggressive;

        if gen_all || self.args.sarif {
            let path = format!("{}/scan_{}.sarif", self.config.output.output_dir, &scan_id[..8]);
            reports::sarif::generate(results, &path)?;
            output::banner::print_report_saved("SARIF", &path);
        }

        if gen_all || self.args.junit {
            let path = format!("{}/scan_{}.xml", self.config.output.output_dir, &scan_id[..8]);
            reports::junit::generate(results, &path)?;
            output::banner::print_report_saved("JUnit", &path);
        }

        if gen_all || self.args.ndjson {
            let path = format!("{}/scan_{}.ndjson", self.config.output.output_dir, &scan_id[..8]);
            reports::ndjson::generate(results, &path)?;
            output::banner::print_report_saved("ndjson", &path);
        }

        Ok(())
    }

    /// Verify Tor SOCKS5 proxy is reachable
    async fn verify_tor_connection(&self) -> bool {
        let proxy_url = format!("socks5h://127.0.0.1:{}", self.args.tor_port);
        let client = match reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
            .timeout(std::time::Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Check Tor by connecting to check.torproject.org
        match client
            .get("https://check.torproject.org/api/ip")
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(is_tor) = json["IsTor"].as_bool() {
                        return is_tor;
                    }
                }
                status.is_success()
            }
            Err(_) => false,
        }
    }
}
