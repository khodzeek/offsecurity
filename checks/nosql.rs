use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};

/// NoSQL injection detection (MongoDB-focused)
pub async fn check_nosql(client: &HttpClient, data: &HttpData, url: &str, intensity_level: u8) -> Vec<Finding> {
    let mut findings = Vec::new();

    let injection_points = extract_nosql_points(url, data);
    if injection_points.is_empty() {
        return findings;
    }

    // Level 2: Error-based detection
    if intensity_level >= 2 {
        findings.extend(check_nosql_error_based(client, &injection_points).await);
    }

    // Level 3: Blind/operator-based detection
    if intensity_level >= 3 {
        findings.extend(check_nosql_blind(client, &injection_points).await);
    }

    findings
}

#[derive(Debug, Clone)]
struct InjectionPoint {
    param: String,
    url: String,
}

fn extract_nosql_points(url: &str, data: &HttpData) -> Vec<InjectionPoint> {
    let mut points = Vec::new();

    if let Ok(parsed) = url::Url::parse(url) {
        for (key, _value) in parsed.query_pairs() {
            if !key.is_empty() {
                points.push(InjectionPoint {
                    param: key.to_string(),
                    url: url.to_string(),
                });
            }
        }
    }

    for form in &data.forms {
        let base_url = form.action.as_deref().unwrap_or(url);
        for field in &form.visible_fields {
            points.push(InjectionPoint {
                param: field.name.clone(),
                url: base_url.to_string(),
            });
        }
    }

    points
}

fn inject_param(base_url: &str, param: &str, value: &str) -> String {
    let encoded = url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    if let Ok(mut parsed) = url::Url::parse(base_url) {
        let mut pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        let mut found = false;
        for (k, v) in pairs.iter_mut() {
            if *k == param {
                *v = value.to_string();
                found = true;
                break;
            }
        }
        if !found {
            pairs.push((param.to_string(), value.to_string()));
        }

        let query: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", k, encode_val(v))).collect();
        parsed.set_query(Some(&query.join("&")));
        parsed.to_string()
    } else {
        if base_url.contains('?') {
            format!("{}&{}={}", base_url, param, encoded)
        } else {
            format!("{}?{}={}", base_url, param, encoded)
        }
    }
}

fn encode_val(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Level 2: Error-based NoSQL injection
async fn check_nosql_error_based(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let error_payloads = [
        ("'\"", "quotation"),
        ("{\"$gt\":\"\"}", "mongo"),
        ("[$ne]", "array injection"),
        ("{\"$where\":\"1==1\"}", "$where operator"),
    ];

    let nosql_error_patterns = [
        "mongo", "mongodb", "bson", "ObjectId", "$where",
        "unterminated", "MongoError", "MongoServerError",
        "cannot read property", "undefined is not",
        "syntax error, unexpected",
    ];

    for point in points.iter().take(5) {
        for (payload, label) in &error_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        let body_lower = body.to_lowercase();
                        for pattern in &nosql_error_patterns {
                            if body_lower.contains(pattern) {
                                findings.push(Finding::new(
                                    "nosql",
                                    "Potential NoSQL injection (error-based)",
                                    Severity::High,
                                    format!(
                                        "Parameter '{}' with {} payload triggered a NoSQL error pattern ('{}').",
                                        point.param, label, pattern
                                    ),
                                    format!("URL: {}\nPayload: {}\nFound: {}", test_url, payload, pattern),
                                    "Sanitize all user input. Use an ODM/ORM with built-in injection protection. Avoid passing raw user input to MongoDB queries.",
                                    &test_url,
                                ));
                                break;
                            }
                        }

                        // Status 500 suggests query failure
                        if response.status_code == 500 && body_lower.contains("error") {
                            findings.push(Finding::new(
                                "nosql",
                                "Possible NoSQL injection (server error on injection)",
                                Severity::Medium,
                                format!(
                                    "Parameter '{}' with {} payload caused HTTP 500 error, suggesting query failure.",
                                    point.param, label
                                ),
                                format!("URL: {}\nPayload: {}\nStatus: 500", test_url, payload),
                                "Investigate the 500 error. It may indicate unhandled NoSQL injection.",
                                &test_url,
                            ));
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}

/// Level 3: Blind/operator-based NoSQL injection
async fn check_nosql_blind(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let operator_payloads = [
        // $ne — not equal (always true for non-empty)
        ("{\"$ne\":\"\"}", "$ne bypass"),
        // $regex — regex matching (always matches .*)
        ("{\"$regex\":\".*\"}", "$regex bypass"),
        // $gt — greater than
        ("{\"$gt\":\"\"}", "$gt bypass"),
        // $where — JavaScript evaluation
        ("{\"$where\":\"sleep(3000)\"}", "$where timing"),
        ("{\"$where\":\"1\"}", "$where true"),
    ];

    for point in points.iter().take(3) {
        // Baseline
        let baseline_url = inject_param(&point.url, &point.param, "normal");
        let baseline_start = std::time::Instant::now();
        if let Ok(baseline) = client.fetch_url(&baseline_url).await {
            let baseline_time = baseline_start.elapsed().as_millis();
            let baseline_size = baseline.body_size;

            for (payload, label) in &operator_payloads {
                let test_url = inject_param(&point.url, &point.param, payload);
                let test_start = std::time::Instant::now();

                match client.fetch_url(&test_url).await {
                    Ok(response) => {
                        let test_time = test_start.elapsed().as_millis();

                        // Timing-based detection (for $where sleep)
                        if test_time >= baseline_time + 2500 {
                            findings.push(Finding::new(
                                "nosql",
                                "NoSQL injection: timing-based detection",
                                Severity::Critical,
                                format!(
                                    "Parameter '{}' with {} caused a {}ms delay (baseline: {}ms). The $where operator is executing server-side JavaScript.",
                                    point.param, label, test_time, baseline_time
                                ),
                                format!("URL: {}\nPayload: {}\nBaseline: {}ms, Test: {}ms, Delta: {}ms", test_url, payload, baseline_time, test_time, test_time - baseline_time),
                                "Disable $where operator. Use strict input validation and parameterized queries.",
                                &test_url,
                            ));
                        }

                        // Response size difference (suggesting different query results)
                        let size_diff = if baseline_size > 0 {
                            ((response.body_size as i64 - baseline_size as i64).abs() as f64 / baseline_size as f64) * 100.0
                        } else {
                            0.0
                        };

                        if size_diff > 30.0 && response.status_code == 200 {
                            findings.push(Finding::new(
                                "nosql",
                                "NoSQL injection: response size anomaly",
                                Severity::High,
                                format!(
                                    "Parameter '{}' with {} caused {:.0}% response size change ({} vs {} bytes). The injection may be bypassing authentication or filters.",
                                    point.param, label, size_diff, baseline_size, response.body_size
                                ),
                                format!("URL: {}\nPayload: {}\nBaseline size: {} bytes, Test size: {} bytes", test_url, payload, baseline_size, response.body_size),
                                "Validate and sanitize all query parameters. Use Mongoose schema validation or equivalent.",
                                &test_url,
                            ));
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    findings
}
