use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};
/// Check for GraphQL endpoints and audit them
pub async fn check_graphql(client: &HttpClient, data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Detect GraphQL endpoints from the page
    let endpoints = detect_graphql_endpoints(data);
    if endpoints.is_empty() {
        return findings;
    }

    for endpoint in &endpoints {
        findings.extend(check_introspection(client, endpoint).await);
        findings.extend(check_field_suggestions(client, endpoint).await);
        findings.extend(check_batching(client, endpoint).await);
    }

    findings
}

/// Detect GraphQL endpoints from page content and HTTP response
fn detect_graphql_endpoints(data: &HttpData) -> Vec<String> {
    let mut endpoints = Vec::new();

    // Common GraphQL paths
    let common_paths = ["/graphql", "/gql", "/api/graphql", "/query", "/graphiql"];

    let base = url::Url::parse(&data.final_url)
        .ok()
        .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")))
        .unwrap_or_default();

    if base.is_empty() {
        return endpoints;
    }

    let body = data.body.as_ref().map(|b| b.as_str()).unwrap_or("");

    // Check if the page itself returns GraphQL-like content
    if let Some(ct) = data.headers.get("content-type") {
        if ct.contains("application/graphql") || ct.contains("application/json") {
            if body.contains("__schema") || body.contains("__typename") || body.contains("mutation") {
                if !endpoints.contains(&data.final_url) {
                    endpoints.push(data.final_url.clone());
                }
            }
        }
    }

    // Check body for GraphQL endpoint references
    for path in &common_paths {
        if body.contains(path) {
            let url = format!("{}{}", base, path);
            if !endpoints.contains(&url) {
                endpoints.push(url);
            }
        }
    }

    // Always try the standard /graphql path
    let standard = format!("{}/graphql", base);
    if !endpoints.contains(&standard) {
        endpoints.push(standard);
    }

    // Deduplicate
    endpoints.sort();
    endpoints.dedup();
    endpoints.truncate(5); // Limit number of endpoints to probe

    endpoints
}

/// Check if GraphQL introspection is enabled (potential info leak)
async fn check_introspection(client: &HttpClient, endpoint: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let introspection_query = r#"{"query":"{ __schema { types { name fields { name } } } }"}"#;

    let response = client
        .send_custom_request_body("POST", endpoint, introspection_query)
        .await;

    match response {
        Ok(resp) => {
            if let Some(ref body) = resp.body {
                if body.contains("__schema") && body.contains("\"data\"") {
                    let type_count = body.matches("\"name\"").count();

                    findings.push(Finding::new(
                        "graphql",
                        "GraphQL introspection enabled",
                        Severity::Medium,
                        format!(
                            "GraphQL introspection is enabled at {}, exposing the full API schema (approx. {} types). Attackers can enumerate all queries, mutations, and fields.",
                            endpoint, type_count
                        ),
                        format!("URL: {}\nResponse contains full schema introspection data. {} type name references found.", endpoint, type_count),
                        "Disable introspection in production. For Apollo: set introspection: false. For GraphQL.js: use the NoSchemaIntrospectionCustomRule validation rule.",
                        endpoint,
                    ));
                }
            }
        }
        Err(_) => {
            // Might not be a GraphQL endpoint — that's fine
        }
    }

    findings
}

/// Check for field suggestions (Did you mean?) info leak
async fn check_field_suggestions(client: &HttpClient, endpoint: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let typo_query = r#"{"query":"{ __typenam { name } }"}"#;

    match client.send_custom_request_body("POST", endpoint, typo_query).await {
        Ok(resp) => {
            if let Some(ref body) = resp.body {
                let body_lower = body.to_lowercase();
                if body_lower.contains("did you mean") || body_lower.contains("cannot query field") {
                    findings.push(Finding::new(
                        "graphql",
                        "GraphQL field suggestions enabled",
                        Severity::Low,
                        format!(
                            "GraphQL at {} provides field name suggestions (Did you mean?), leaking schema information even without introspection.",
                            endpoint
                        ),
                        format!("URL: {}\nResponse: {}", endpoint, &body[..200.min(body.len())]),
                        "Disable field suggestions in production. In GraphQL.js: use a custom formatError that strips suggestion info.",
                        endpoint,
                    ));
                }
            }
        }
        Err(_) => {}
    }

    findings
}

/// Check for query batching vulnerability (DoS via alias-based resource exhaustion)
async fn check_batching(client: &HttpClient, endpoint: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Alias-based attack: same query executed 10 times in one request
    let alias_query = format!(
        r#"{{"query":"query {{{} __typename}}"}}"#,
        (0..10).map(|i| format!(" q{}: __typename", i)).collect::<Vec<_>>().join("")
    );

    match client.send_custom_request_body("POST", endpoint, &alias_query).await {
        Ok(resp) => {
            if resp.status_code == 200 {
                if let Some(ref body) = resp.body {
                    if body.contains("q0") && body.contains("q9") {
                        findings.push(Finding::new(
                            "graphql",
                            "GraphQL alias-based batching enabled",
                            Severity::Medium,
                            "The GraphQL endpoint accepts alias-based query batching, enabling resource exhaustion attacks by multiplying query cost.",
                            format!("URL: {}\nSent 10 aliased __typename queries in one request — all 10 resolved successfully.", endpoint),
                            "Implement query cost analysis, depth limiting, and rate limiting. Consider restricting aliases or maximum alias count per request.",
                            endpoint,
                        ));
                    }
                }
            }
        }
        Err(_) => {}
    }

    findings
}
