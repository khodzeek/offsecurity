use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};
use regex::Regex;

/// Check for IDOR/BOLA vulnerabilities by detecting resource ID patterns
pub async fn check_idor(client: &HttpClient, data: &HttpData, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Detect sequential/resource IDs in URL paths and query params
    let patterns = [
        ("Numeric ID", r#"/\d{2,6}[/\?#]"#, Severity::Medium),
        ("UUID", r#"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#, Severity::Low),
        ("Username param", r#"[/?&](user|username|account|profile|uid|id|user_id)="#, Severity::Medium),
        ("Resource ID", r#"[/?&](order|invoice|payment|ticket|document|file|report|record)_?(id|num)="#, Severity::High),
    ];

    for (label, pattern, sev) in &patterns {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(url) {
            findings.push(Finding::new(
                "idor",
                format!("Potential IDOR: {} in URL", label),
                sev.clone(),
                format!(
                    "A {} pattern was detected in the URL. If the application doesn't verify object-level access, attackers may access other users' resources.",
                    label.to_lowercase()
                ),
                format!("URL: {}\nPattern: {}", url, pattern),
                "Implement object-level authorization checks. Use random/unguessable IDs (UUID v4) instead of sequential IDs, and verify ownership on every request.",
                url,
            ));
        }
    }

    // Check for predictable IDs in response body (JSON API responses)
    if let Some(ref body) = data.body {
        let id_re = Regex::new(r#""id"\s*:\s*(\d+)"#).unwrap();
        let ids: Vec<u32> = id_re.captures_iter(body)
            .filter_map(|c| c[1].parse::<u32>().ok())
            .collect();

        if ids.len() >= 2 {
            // Check if IDs are sequential
            let mut sequential = true;
            for window in ids.windows(2) {
                if window[1] != window[0] + 1 {
                    sequential = false;
                    break;
                }
            }
            if sequential && ids.len() >= 3 {
                findings.push(Finding::new(
                    "idor",
                    "Sequential resource IDs exposed in API response",
                    Severity::High,
                    format!("The API response contains sequential resource IDs ({} IDs found). An attacker can enumerate all resources by incrementing the ID.", ids.len()),
                    format!("Sequential IDs: {:?}...", &ids[..10.min(ids.len())]),
                    "Use UUIDs instead of sequential integers. Add authorization checks for every resource access.",
                    url,
                ));
            }
        }

        // Check for user_id exposure patterns
        for keyword in &["user_id", "userId", "owner_id", "account_id", "tenant_id"] {
            if body.contains(keyword) {
                let re = Regex::new(&format!(r#""{}"\s*:\s*(\d+)"#, keyword)).unwrap();
                if let Some(cap) = re.captures(body) {
                    findings.push(Finding::new(
                        "idor",
                        format!("User identifier '{}' exposed in response", keyword),
                        Severity::Medium,
                        format!("The response body exposes '{}' with value {}. If this is used for access control, it may be manipulable.", keyword, &cap[1]),
                        format!("Found: \"{}\": {}", keyword, &cap[1]),
                        "Avoid exposing internal user/resource identifiers. Implement server-side authorization.",
                        url,
                    ));
                }
            }
        }
    }

    // Test ID manipulation if intensity level >= 2
    let intensity = 1u8; // Check is passive by default
    if intensity >= 2 {
        findings.extend(test_id_manipulation(client, url).await);
    }

    findings
}

async fn test_id_manipulation(client: &HttpClient, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try incrementing numeric IDs in the URL
    let id_re = Regex::new(r#"/(\d{2,6})([/\?#]|$)"#).unwrap();
    for cap in id_re.captures_iter(url).take(3) {
        if let Ok(current_id) = cap[1].parse::<u32>() {
            let test_ids = [current_id + 1, current_id.wrapping_sub(1), 1];

            for test_id in &test_ids {
                let test_url = url.replace(
                    &format!("/{}/", current_id),
                    &format!("/{}/", test_id),
                );

                if test_url == *url {
                    continue;
                }

                match client.fetch_url(&test_url).await {
                    Ok(response) => {
                        if response.status_code == 200 {
                            // Check if response is similar to original (suggesting unauthorized access)
                            if response.body_size > 100 {
                                findings.push(Finding::new(
                                    "idor",
                                    "Possible IDOR: Modified resource ID returns data",
                                    Severity::High,
                                    format!(
                                        "Changing resource ID from {} to {} returned HTTP 200 with {} bytes. The application may not verify resource ownership.",
                                        current_id, test_id, response.body_size
                                    ),
                                    format!("Test URL: {}\nResponse: HTTP {}", test_url, response.status_code),
                                    "Implement proper authorization checks for all object accesses.",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        break; // Only test first ID pattern
    }

    findings
}
