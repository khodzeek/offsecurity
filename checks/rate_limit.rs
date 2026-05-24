use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};

/// Rate limiting detection — check for rate limit headers and test throttling behavior
pub async fn check_rate_limiting(client: &HttpClient, data: &HttpData, url: &str, intensity_level: u8) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for rate limit headers in the response
    let rate_limit_headers = [
        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
        "retry-after",
    ];

    let mut found_headers = Vec::new();
    let mut has_retry_after = false;

    for header in &rate_limit_headers {
        if let Some(value) = data.headers.get(*header) {
            found_headers.push((header.to_string(), value.to_string()));
            if *header == "retry-after" {
                has_retry_after = true;
            }
        }
    }

    if !found_headers.is_empty() {
        findings.push(Finding::new(
            "rate-limit",
            "Rate limiting headers detected",
            Severity::Info,
            format!(
                "The server includes rate limiting headers ({}). This is good for DoS protection but the limits should be reviewed.",
                found_headers.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>().join(", ")
            ),
            format!("Rate limit headers: {:?}", found_headers),
            "Ensure rate limits are appropriate for your use case and that legitimate traffic isn't blocked.",
            url,
        ));
    }

    // Check for missing rate limiting (potential DoS surface)
    if found_headers.is_empty() && !has_retry_after {
        findings.push(Finding::new(
            "rate-limit",
            "No rate limiting detected",
            Severity::Low,
            "The server does not expose rate limiting headers. Without rate limiting, the application may be vulnerable to brute-force attacks, credential stuffing, or DoS.",
            "No rate limit or Retry-After headers found in response",
            "Implement rate limiting (token bucket, sliding window). Add RateLimit-* headers per RFC draft. Use Retry-After for 429 responses.",
            url,
        ));
    }

    // Level 2+: Test actual throttling behavior
    if intensity_level >= 2 && found_headers.is_empty() {
        findings.extend(test_throttling(client, url).await);
    }

    // Check for missing security-related headers that help with DoS
    check_dos_headers(data, url, &mut findings);

    findings
}

async fn test_throttling(client: &HttpClient, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let burst_size = 15;
    let mut response_times = Vec::new();
    let mut status_codes = Vec::new();

    for _ in 0..burst_size {
        let start = std::time::Instant::now();
        match client.fetch_url(url).await {
            Ok(response) => {
                response_times.push(start.elapsed().as_millis());
                status_codes.push(response.status_code);
                if response.status_code == 429 {
                    findings.push(Finding::new(
                        "rate-limit",
                        "Rate limiting enforced (HTTP 429 received)",
                        Severity::Info,
                        format!(
                            "After {} rapid requests, the server returned HTTP 429 Too Many Requests. Rate limiting is active.",
                            status_codes.len()
                        ),
                        format!("Response: HTTP 429 after {} requests", status_codes.len()),
                        "Good. Ensure rate limits are tuned to prevent abuse without impacting legitimate users.",
                        url,
                    ));
                    return findings;
                }
            }
            Err(_) => {
                status_codes.push(0);
            }
        }
    }

    // Analyze timing for evidence of server-side throttling
    if response_times.len() >= 10 {
        let avg_first_5: f64 = response_times[..5].iter().sum::<u128>() as f64 / 5.0;
        let avg_last_5: f64 = response_times[response_times.len()-5..].iter().sum::<u128>() as f64 / 5.0;

        if avg_last_5 > avg_first_5 * 3.0 {
            findings.push(Finding::new(
                "rate-limit",
                "Possible silent rate limiting (response time degradation)",
                Severity::Info,
                format!(
                    "Response times increased from {:.0}ms (first 5) to {:.0}ms (last 5), suggesting server-side throttling without explicit 429 responses.",
                    avg_first_5, avg_last_5
                ),
                format!("First 5 avg: {:.0}ms, Last 5 avg: {:.0}ms", avg_first_5, avg_last_5),
                "Explicit rate limiting with 429 + Retry-After is better than silent degradation.",
                url,
            ));
        } else if status_codes.iter().all(|&s| s == 200) {
            findings.push(Finding::new(
                "rate-limit",
                "No rate limiting enforcement detected",
                Severity::Medium,
                format!(
                    "{} rapid requests all returned HTTP 200 with stable response times. The application appears to have no rate limiting, making it vulnerable to brute-force and DoS attacks.",
                    burst_size
                ),
                format!("All {} requests returned 200 OK", burst_size),
                "Implement rate limiting with exponential backoff. Return HTTP 429 with Retry-After header when limits are exceeded.",
                url,
            ));
        }
    }

    findings
}

fn check_dos_headers(data: &HttpData, url: &str, findings: &mut Vec<Finding>) {
    // Check for missing headers that help prevent DoS
    let missing_headers: Vec<&str> = [
        ("strict-transport-security", "HSTS"),
        ("x-content-type-options", "X-Content-Type-Options"),
    ]
    .iter()
    .filter(|(h, _)| !data.headers.contains_key(*h))
    .map(|(_, name)| *name)
    .collect();

    if !missing_headers.is_empty() {
        findings.push(Finding::new(
            "rate-limit",
            "Missing DoS-resilience headers",
            Severity::Low,
            format!(
                "Missing security headers that contribute to DoS resilience: {}.",
                missing_headers.join(", ")
            ),
            format!("Missing: {}", missing_headers.join(", ")),
            "Add the missing headers to improve overall security posture against DoS attacks.",
            url,
        ));
    }
}
