use crate::models::{Finding, HttpData, Severity};
use crate::utils::helpers;

pub fn check_info_exposure(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_email_exposure(data, &mut findings);
    check_internal_ip_exposure(data, &mut findings);
    check_error_messages(data, &mut findings);
    check_debug_info(data, &mut findings);
    check_source_maps(data, &mut findings);

    findings
}

fn check_email_exposure(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    let emails = helpers::find_emails(body);
    if emails.len() > 10 {
        findings.push(Finding::new(
            "sensitive-info",
            "Multiple email addresses exposed in HTML",
            Severity::Low,
            format!(
                "Found {} email addresses in the HTML response. Exposed emails can be harvested by spammers and used for social engineering.",
                emails.len()
            ),
            format!("First few emails: {}", emails.iter().take(3).cloned().collect::<Vec<_>>().join(", ")),
            "Consider using contact forms instead of displaying email addresses directly, or obfuscate email addresses.",
            &data.final_url,
        ));
    } else if !emails.is_empty() {
        findings.push(Finding::new(
            "sensitive-info",
            "Email addresses exposed in HTML",
            Severity::Info,
            format!(
                "Found {} email address(es) in the HTML response: {}",
                emails.len(),
                emails.join(", ")
            ),
            format!("Emails: {}", emails.join(", ")),
            "Consider obfuscating email addresses to prevent harvesting.",
            &data.final_url,
        ));
    }
}

fn check_internal_ip_exposure(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    let ip_pattern = regex::Regex::new(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    ).unwrap();

    let found_ips: Vec<String> = ip_pattern
        .find_iter(body)
        .map(|m| m.as_str().to_string())
        .take(5)
        .collect();

    if !found_ips.is_empty() {
        findings.push(Finding::new(
            "sensitive-info",
            "Internal IP addresses exposed",
            Severity::Medium,
            format!(
                "Internal/private IP addresses were found in the response body: {}. This reveals internal network architecture.",
                found_ips.join(", ")
            ),
            format!("Found internal IPs: {}", found_ips.join(", ")),
            "Remove internal IP addresses from production HTML responses. Use relative URLs or environment-specific configuration.",
            &data.final_url,
        ));
    }
}

fn check_error_messages(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    let body_lower = body.to_lowercase();

    // Stack traces
    if body_lower.contains("stack trace") || body_lower.contains("stacktrace") {
        findings.push(Finding::new(
            "sensitive-info",
            "Stack trace exposed in response",
            Severity::High,
            "A stack trace is visible in the HTTP response, revealing internal code paths, file names, and potential vulnerabilities.",
            "Response body contains stack trace information",
            "Disable debug/error output in production. Configure custom error pages that don't leak internal details.",
            &data.final_url,
        ));
    }

    // SQL errors
    let sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "postgresql",
        "sqlite3::",
        "pdoexception",
        "sqlsrv",
        "odbc_exec",
        "invalid query",
        "unclosed quotation mark",
        "warning: mysql",
        "warning: pg_",
        "division by zero",
        "call to undefined function",
        "class not found",
    ];

    for err in &sql_errors {
        if body_lower.contains(err) {
            findings.push(Finding::new(
                "sensitive-info",
                "SQL error message exposed",
                Severity::High,
                format!(
                    "A SQL/database error message was found in the response ('{}'). This reveals database details and may indicate SQL injection vulnerability.",
                    err
                ),
                format!("Found pattern: '{}' in response body", err),
                "Configure the application to not display database errors to users. Use generic error pages and log details server-side.",
                &data.final_url,
            ));
            break;
        }
    }

    // Generic exception
    if body_lower.contains("exception:") || body_lower.contains("throwable") {
        findings.push(Finding::new(
            "sensitive-info",
            "Exception details exposed",
            Severity::Medium,
            "Exception details are visible in the response, including error types that reveal technology stack and internal logic.",
            "Response body contains exception/throwable details",
            "Implement proper exception handling and display only user-friendly error messages in production.",
            &data.final_url,
        ));
    }

    // Path disclosure
    let path_patterns = [
        "c:\\inetpub",
        "c:\\windows",
        "/var/www",
        "/usr/share",
        "/home/",
        "webapps/",
        "htdocs/",
    ];

    for pp in &path_patterns {
        if body_lower.contains(pp) {
            findings.push(Finding::new(
                "sensitive-info",
                "Server path disclosed in response",
                Severity::Medium,
                format!(
                    "A server file path pattern ('{}') was found in the response, revealing the internal directory structure.",
                    pp
                ),
                format!("Found path: '{}' in response", pp),
                "Remove absolute file paths from error messages and production output.",
                &data.final_url,
            ));
            break;
        }
    }
}

fn check_debug_info(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    let body_lower = body.to_lowercase();

    // Debug mode indicators
    let debug_indicators = [
        ("debug mode", "Debug mode enabled", Severity::High,
         "The application appears to be running in debug mode, which may expose sensitive configuration and internal state."),
        ("x-debug-token", "Symfony debug toolbar detected", Severity::High,
         "The Symfony debug toolbar/profile is visible, exposing detailed request data including queries and configuration."),
        ("xdebug", "Xdebug enabled", Severity::High,
         "Xdebug appears to be enabled in production, which can expose detailed debugging information."),
        ("laravel-debugbar", "Laravel debug bar detected", Severity::High,
         "The Laravel debug bar is visible, exposing queries, configuration, and request data."),
        ("whoops", "Whoops error handler detected", Severity::High,
         "The Whoops error handler for PHP is active in production, displaying detailed stack traces and environment details."),
    ];

    for (pattern, title, severity, description) in &debug_indicators {
        if body_lower.contains(pattern) {
            findings.push(Finding::new(
                "sensitive-info",
                *title,
                *severity,
                *description,
                format!("Found indicator: '{}' in response", pattern),
                "Disable debug mode and development tools in production environments.",
                &data.final_url,
            ));
            break;
        }
    }
}

fn check_source_maps(data: &HttpData, findings: &mut Vec<Finding>) {
    let body = match &data.body {
        Some(b) => b,
        None => return,
    };

    // Check for source map references
    if body.contains("sourceMappingURL") || body.contains("//# sourceMap") {
        findings.push(Finding::new(
            "sensitive-info",
            "Source maps referenced in production",
            Severity::Medium,
            "JavaScript source maps are referenced in production, which can expose the original source code to attackers.",
            "Response contains sourceMappingURL or sourceMap reference",
            "Remove source map references from production builds. Configure your bundler to not emit source maps for production.",
            &data.final_url,
        ));
    }
}
