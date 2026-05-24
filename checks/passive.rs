use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};

pub fn check_passive(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_comments(data, &mut findings);
    check_directory_listing(data, &mut findings);
    check_http_methods(data, &mut findings);
    check_http_vs_https(data, &mut findings);

    findings
}

fn check_comments(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    // Find HTML comments
    let comment_pattern = regex::Regex::new(r"<!--(.*?)-->").unwrap();
    let sensitive_patterns = [
        ("TODO", Severity::Info, "TODO comment found", "TODO comments may reveal planned features or incomplete security measures."),
        ("FIXME", Severity::Info, "FIXME comment found", "FIXME comments may indicate known issues that haven't been addressed."),
        ("password", Severity::Medium, "Sensitive comment mentioning 'password'", "Comments referencing passwords may reveal authentication details."),
        ("secret", Severity::Medium, "Sensitive comment mentioning 'secret'", "Comments referencing secrets may reveal sensitive information."),
        ("token", Severity::Low, "Comment referencing 'token'", "Comments about tokens may contain sensitive implementation details."),
        ("api key", Severity::High, "API key reference in comments", "API keys in HTML comments would be exposed to any page visitor."),
        ("admin", Severity::Info, "Admin reference in comments", "Comments referencing admin functionality may reveal privileged endpoints."),
        ("user:", Severity::Low, "Potential credential in comment", "Comments containing 'user:' may indicate leaked test credentials."),
        ("debug", Severity::Info, "Debug comment found", "Debug comments may reveal debugging functionality left in production."),
    ];

    for cap in comment_pattern.captures_iter(body) {
        let comment = &cap[1];
        let comment_lower = comment.to_lowercase();

        for (keyword, severity, title, description) in &sensitive_patterns {
            if comment_lower.contains(keyword) {
                let truncated = if comment.len() > 200 {
                    format!("{}...", &comment[..197])
                } else {
                    comment.to_string()
                };

                findings.push(Finding::new(
                    "passive-comments",
                    *title,
                    *severity,
                    *description,
                    format!("Comment: {}", truncated),
                    "Remove sensitive information from HTML comments before deploying to production.",
                    &data.final_url,
                ));

                break; // One finding per comment
            }
        }
    }
}

fn check_directory_listing(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    let body_lower = body.to_lowercase();

    // Apache directory listing
    if body_lower.contains("index of /") && body_lower.contains("parent directory") {
        findings.push(Finding::new(
            "passive",
            "Directory listing enabled",
            Severity::Medium,
            "Directory listing is enabled on the web server, exposing file structure to attackers.",
            "Page contains directory listing markers ('Index of /', 'Parent Directory')",
            "Disable directory listing: Apache: 'Options -Indexes', Nginx: 'autoindex off', IIS: disable 'Directory Browsing'",
            &data.final_url,
        ));
    }

    // IIS directory listing
    if body_lower.contains("iis") && body_lower.contains("[to parent directory]") {
        findings.push(Finding::new(
            "passive",
            "IIS Directory listing enabled",
            Severity::Medium,
            "Directory listing is enabled on IIS, exposing file structure to attackers.",
            "IIS directory listing detected",
            "Disable directory browsing in IIS Manager or web.config.",
            &data.final_url,
        ));
    }
}

fn check_http_methods(data: &HttpData, findings: &mut Vec<Finding>) {
    if let Some(allow) = data.headers.get("allow") {
        let dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];
        let found_dangerous: Vec<&str> = dangerous_methods
            .iter()
            .filter(|m| allow.to_uppercase().contains(*m))
            .cloned()
            .collect();

        if !found_dangerous.is_empty() {
            findings.push(Finding::new(
                "passive",
                "Dangerous HTTP methods allowed",
                Severity::Medium,
                &format!(
                    "The server allows HTTP methods that may pose security risks: {}. These methods could be exploited for file upload, resource modification, or Cross-Site Tracing (XST) attacks.",
                    found_dangerous.join(", ")
                ),
                format!("Allow header: {}", allow),
                "Disable unnecessary HTTP methods at the web server level. Only allow GET, POST, HEAD, and OPTIONS for most applications.",
                &data.final_url,
            ));
        }

        if allow.to_uppercase().contains("TRACE") {
            findings.push(Finding::new(
                "passive",
                "HTTP TRACE method enabled",
                Severity::Medium,
                "The TRACE method is enabled, which can be exploited in Cross-Site Tracing (XST) attacks to steal cookies and credentials.",
                format!("Allow header includes TRACE: {}", allow),
                "Disable the TRACE method in your web server configuration.",
                &data.final_url,
            ));
        }
    }
}

fn check_http_vs_https(data: &HttpData, findings: &mut Vec<Finding>) {
    if !data.is_https {
        findings.push(Finding::new(
            "passive",
            "Site served over HTTP (not HTTPS)",
            Severity::High,
            "The site is served over unencrypted HTTP. All data transmitted between client and server is in plaintext and can be intercepted.",
            format!("URL scheme: HTTP, status: {}", data.status_code),
            "Enable HTTPS and configure automatic HTTP-to-HTTPS redirects (301). Obtain a TLS certificate from Let's Encrypt or a commercial CA.",
            &data.final_url,
        ));
    }
}

/// Check for common sensitive files (low-intrusion path probing)
pub async fn check_sensitive_files(client: &HttpClient, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut responses_200: Vec<(String, usize, String)> = Vec::new(); // (url, body_len, body_preview)
    let mut responses_403: Vec<String> = Vec::new(); // urls that returned 403

    let sensitive_paths = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/backup.zip",
        "/backup.sql",
        "/wp-config.php",
        "/phpinfo.php",
        "/info.php",
        "/server-status",
        "/server-info",
        "/.htaccess",
        "/.htpasswd",
        "/config.php",
        "/config.yml",
        "/config.json",
        "/credentials.json",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/web.config",
        "/package.json",
        "/composer.json",
        "/Gemfile",
        "/Dockerfile",
        "/docker-compose.yml",
    ];

    let base = url::Url::parse(base_url).unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
    let base_prefix = format!("{}://{}", base.scheme(), base.host_str().unwrap_or(""));

    for path in &sensitive_paths {
        let test_url = format!("{}{}", base_prefix, path);

        match client.fetch_url(&test_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    // Collect response metadata for SPA detection
                    let body_len = response.body_size;
                    let body_preview = response.body.as_ref()
                        .map(|b| b.chars().take(200).collect::<String>())
                        .unwrap_or_default();
                    responses_200.push((test_url.clone(), body_len, body_preview.clone()));

                    let (title, severity, description) = match *path {
                        "/.env" => ("Environment file (.env) exposed", Severity::Critical,
                            "The .env file is publicly accessible, potentially exposing database credentials, API keys, and other secrets."),
                        "/.git/config" => ("Git repository config exposed", Severity::Critical,
                            "Git configuration is publicly accessible, potentially revealing repository details and credentials."),
                        "/.git/HEAD" => ("Git repository exposed", Severity::Critical,
                            "The .git directory is publicly accessible. Source code can be downloaded using tools like git-dumper."),
                        "/backup.zip" | "/backup.sql" => ("Backup file publicly accessible", Severity::Critical,
                            "A backup file is accessible, potentially exposing the entire application codebase or database."),
                        "/wp-config.php" => ("WordPress config file exposed", Severity::Critical,
                            "The WordPress configuration file is accessible (though PHP should execute it). This indicates a server misconfiguration."),
                        "/phpinfo.php" | "/info.php" => ("PHP info page exposed", Severity::High,
                            "A PHP info page reveals detailed server configuration including paths, modules, and environment variables."),
                        "/server-status" | "/server-info" => ("Server status page exposed", Severity::Medium,
                            "Server status/info pages are publicly accessible, revealing server performance and configuration details."),
                        "/.htaccess" | "/.htpasswd" => ("Apache config file exposed", Severity::Critical,
                            "Apache configuration/htpasswd files are publicly accessible, potentially revealing authentication credentials."),
                        "/config.php" | "/config.yml" | "/config.json" => ("Configuration file exposed", Severity::High,
                            "A configuration file is publicly accessible, potentially containing sensitive settings and credentials."),
                        "/credentials.json" => ("Credentials file exposed", Severity::Critical,
                            "A credentials file is publicly accessible. This likely contains authentication secrets."),
                        "/web.config" => ("ASP.NET web.config exposed", Severity::High,
                            "The web.config file is accessible, potentially revealing connection strings and application secrets."),
                        "/package.json" => ("package.json exposed", Severity::Low,
                            "package.json is accessible, revealing JavaScript dependencies and their versions."),
                        "/Dockerfile" | "/docker-compose.yml" => ("Docker configuration exposed", Severity::Medium,
                            "Docker configuration files are accessible, revealing infrastructure and deployment details."),
                        "/robots.txt" => ("robots.txt accessible", Severity::Info,
                            "robots.txt reveals paths the site owner wants to hide from search engines, which may be interesting to attackers."),
                        _ => ("Sensitive file exposed", Severity::Medium,
                            "A potentially sensitive file is publicly accessible."),
                    };

                    findings.push(Finding::new(
                        "passive-files",
                        title,
                        severity,
                        description,
                        format!("URL: {} returned HTTP {}", test_url, response.status_code),
                        "Restrict public access to sensitive files via web server configuration. Add deny rules for sensitive file patterns.",
                        &test_url,
                    ));
                }

                if response.status_code == 403 {
                    responses_403.push(test_url.clone());
                    // Only report if it's likely a real file, not a generic block
                    // We'll filter generic blocks after the loop
                }
            }
            Err(_) => {
                // File doesn't exist or timeout — expected for most checks
            }
        }
    }

    // Generic 403 detection: if too many unrelated paths return 403, it's a server rule
    if responses_403.len() >= 4 {
        // Check diversity — if different file types (.php, .env, .git, .zip) all return 403,
        // it's almost certainly a generic security rule, not individual protected files
        let mut has_php = false;
        let mut has_env = false;
        let mut has_git = false;
        let mut has_backup = false;
        for url in &responses_403 {
            if url.contains(".php") { has_php = true; }
            if url.contains(".env") { has_env = true; }
            if url.contains(".git") { has_git = true; }
            if url.contains("backup") { has_backup = true; }
        }
        let diversity = [has_php, has_env, has_git, has_backup].iter().filter(|&&x| x).count();

        if diversity >= 3 {
            // Generic 403 block detected — skip individual 403 findings
            findings.push(Finding::new(
                "passive-files",
                "Generic 403 block detected on sensitive paths",
                Severity::Info,
                format!(
                    "{} sensitive paths returned HTTP 403 with diverse file types (.php, .env, .git, backup). This likely means a generic security rule blocks access to these paths, not that the actual files exist. WordPress/CMS detection cannot be confirmed.",
                    responses_403.len()
                ),
                format!("403 paths: {}", responses_403.iter().take(5).map(|u| u.as_str()).collect::<Vec<_>>().join(", ")),
                "Review server rules to ensure sensitive files are not actually present. The 403 response alone does not confirm file existence.",
                base_url,
            ));
        }
    }

    // SPA detection: if multiple paths return identical content, filter false positives
    if responses_200.len() >= 3 {
        let mut spa_detected = false;
        let mut spa_signature = (0usize, String::new()); // (body_len, body_preview)

        // Find content that appears for >= 3 different paths
        for (_i, (_, len1, preview1)) in responses_200.iter().enumerate() {
            let count = responses_200.iter()
                .filter(|(_, len2, preview2)| len1 == len2 && preview1 == preview2)
                .count();
            if count >= 3 {
                spa_detected = true;
                spa_signature = (*len1, preview1.clone());
                break;
            }
        }

        if spa_detected {
            let (spa_len, spa_preview) = &spa_signature;

            // Filter out findings where the response matches the SPA shell
            findings.retain(|f| {
                let is_spa_false_positive = responses_200.iter()
                    .any(|(url, len, preview)| {
                        f.affected_url == *url && *len == *spa_len && preview == spa_preview
                    });

                if is_spa_false_positive {
                    // Downgrade to INFO with SPA false positive annotation
                    // Actually we just remove it and add a single info finding
                    false // remove
                } else {
                    true // keep
                }
            });

            // Add a single SPA detection finding
            if responses_200.len() >= 5 {
                findings.push(Finding::new(
                    "passive-files",
                    "SPA detected: sensitive file check results may be false positives",
                    Severity::Info,
                    format!(
                        "{} of {} sensitive paths returned identical content ({} bytes). This is a Single Page Application where all routes serve the same HTML shell. The critical findings above are likely false positives — the files are not actually exposed.",
                        responses_200.len(), sensitive_paths.len(), spa_len
                    ),
                    format!(
                        "SPA signature: {} bytes, starts with: {}",
                        spa_len,
                        &spa_preview[..100.min(spa_preview.len())]
                    ),
                    "The SPA pattern is normal. Ensure the web server does not serve real sensitive files at these paths.",
                    base_url,
                ));
            }
        }
    }

    findings
}
