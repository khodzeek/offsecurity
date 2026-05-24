use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};

/// OpenAPI/Swagger specification detection with SPA false-positive filtering
pub async fn check_api_endpoints(client: &HttpClient, data: &HttpData, base_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let api_paths = [
        ("/swagger.json", "Swagger/OpenAPI v2 JSON"),
        ("/swagger/v1/swagger.json", "Swagger/OpenAPI v2 (versioned)"),
        ("/api/swagger.json", "Swagger JSON (api prefix)"),
        ("/openapi.json", "OpenAPI v3 JSON"),
        ("/api/openapi.json", "OpenAPI v3 JSON (api prefix)"),
        ("/v2/api-docs", "Springfox Swagger v2"),
        ("/v3/api-docs", "Springdoc OpenAPI v3"),
        ("/api/v2/api-docs", "Springfox (api prefix)"),
        ("/api/v3/api-docs", "Springdoc (api prefix)"),
        ("/swagger.yaml", "Swagger YAML"),
        ("/openapi.yaml", "OpenAPI v3 YAML"),
        ("/api-docs", "Generic API docs"),
        ("/docs/api", "Generic API docs (docs prefix)"),
        ("/api/docs", "Generic API docs (api prefix)"),
        ("/api", "API root"),
        ("/api/v1", "API v1"),
        ("/api/v2", "API v2"),
        ("/graphql", "GraphQL endpoint"),
        ("/rest", "REST API root"),
        ("/REST", "REST API root (uppercase)"),
        ("/_ah/api", "Google Cloud Endpoints"),
        ("/.well-known/openid-configuration", "OIDC Discovery"),
        ("/.well-known/oauth-authorization-server", "OAuth2 Authorization Server"),
    ];

    let base = if base_url.ends_with('/') {
        base_url.trim_end_matches('/').to_string()
    } else {
        base_url.to_string()
    };

    // ── Phase 1: collect all responses ──
    let mut responses_200: Vec<(String, usize, String, Option<String>)> = Vec::new();
    // (url, body_size, body_preview, full_body)

    for (path, _label) in &api_paths {
        let full_url = format!("{}{}", base, path);
        match client.fetch_url(&full_url).await {
            Ok(response) => {
                if response.status_code == 200 {
                    let preview = response.body.as_deref()
                        .map(|b| b.chars().take(160).collect::<String>())
                        .unwrap_or_default();
                    responses_200.push((full_url, response.body_size, preview, response.body.clone()));
                }
            }
            Err(_) => continue,
        }
    }

    // ── Phase 2: SPA detection ──
    let mut spa_detected = false;
    let mut spa_len = 0usize;
    let mut spa_preview = String::new();

    if responses_200.len() >= 3 {
        for (_, len1, preview1, _) in &responses_200 {
            let count = responses_200.iter()
                .filter(|(_, len2, preview2, _)| len1 == len2 && preview1 == preview2)
                .count();
            if count >= 3 {
                spa_detected = true;
                spa_len = *len1;
                spa_preview = preview1.clone();
                break;
            }
        }
    }

    // ── Phase 3: report findings with SPA filtering ──
    let total_200 = responses_200.len();

    for (full_url, body_size, _preview, body) in &responses_200 {
        // Skip if this response matches the SPA shell pattern
        if spa_detected && *body_size == spa_len {
            let body_preview = body.as_deref()
                .map(|b| b.chars().take(160).collect::<String>())
                .unwrap_or_default();
            if body_preview == spa_preview {
                continue; // False positive from SPA
            }
        }

        // Find the matching label
        let label = api_paths.iter()
            .find(|(p, _)| {
                let fu = format!("{}{}", base, p);
                fu == *full_url
            })
            .map(|(_, l)| *l)
            .unwrap_or("Unknown");

        // Genuinely different response — could be real API docs
        let is_real_openapi = body.as_deref()
            .map(|b| b.contains("\"paths\"") || b.contains("\"swagger\"") || b.contains("\"openapi\""))
            .unwrap_or(false);

        let severity = if is_real_openapi {
            Severity::Medium
        } else {
            Severity::Info
        };

        let description = if is_real_openapi {
            format!(
                "{} specification found at {} ({} bytes). Response differs from SPA shell — this exposes the real API surface.",
                label, full_url, body_size
            )
        } else {
            format!("{} endpoint responds with unique content ({} bytes).", label, body_size)
        };

        findings.push(Finding::new(
            "api-discovery",
            format!("API endpoint found: {}", label),
            severity,
            description,
            format!("URL: {}\nStatus: 200\nSize: {} bytes", full_url, body_size),
            "Restrict access to API documentation in production. Use authentication for API docs or disable them entirely.",
            full_url,
        ));

        // Parse OpenAPI spec for endpoint enumeration
        if is_real_openapi {
            if let Some(ref b) = body {
                if let Ok(spec) = serde_json::from_str::<serde_json::Value>(b) {
                    if let Some(paths) = spec.get("paths") {
                        if let Some(obj) = paths.as_object() {
                            let endpoint_count = obj.len();
                            findings.push(Finding::new(
                                "api-discovery",
                                format!("{} API endpoints exposed in specification", endpoint_count),
                                Severity::Medium,
                                format!("The API specification at {} exposes {} endpoints.", full_url, endpoint_count),
                                format!("Endpoints: {:?}", obj.keys().take(20).collect::<Vec<_>>()),
                                "Disable API documentation in production or restrict access to authorized users only.",
                                full_url,
                            ));
                        }
                    }
                }
            }
        }
    }

    // ── Phase 4: SPA info finding ──
    if spa_detected && total_200 >= 5 {
        findings.push(Finding::new(
            "api-discovery",
            "SPA detected: API endpoint results may be false positives",
            Severity::Info,
            format!(
                "{} of {} API paths returned identical content ({} bytes). This is a Single Page Application where all routes serve the same HTML shell. API findings matching this pattern have been filtered out.",
                total_200, api_paths.len(), spa_len
            ),
            format!("SPA signature: {} bytes, starts with: {}", spa_len, &spa_preview[..100.min(spa_preview.len())]),
            "SPA pattern is normal. Verify any remaining API findings are not also served by the SPA catch-all route.",
            base_url,
        ));
    }

    // ── Phase 5: page content check ──
    if let Some(ref body) = data.body {
        if body.contains("swagger") || body.contains("openapi") || body.contains("api-docs") {
            findings.push(Finding::new(
                "api-discovery",
                "API documentation references found in page",
                Severity::Info,
                "The page contains references to API documentation.",
                "Page contains swagger/openapi/api-docs references",
                "Ensure API documentation is not linked from public pages in production.",
                base_url,
            ));
        }
    }

    findings
}
