use crate::models::{Finding, HttpData, Severity};

pub fn check_security_headers(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_csp(data, &mut findings);
    check_x_frame_options(data, &mut findings);
    check_x_content_type_options(data, &mut findings);
    check_hsts(data, &mut findings);
    check_referrer_policy(data, &mut findings);
    check_permissions_policy(data, &mut findings);
    check_server_info_exposure(data, &mut findings);
    check_xss_protection(data, &mut findings);
    check_cross_origin_policies(data, &mut findings);

    findings
}

fn check_csp(data: &HttpData, findings: &mut Vec<Finding>) {
    let header = data.headers.get("content-security-policy");

    match header {
        None => {
            findings.push(Finding::new(
                "security-headers",
                "Missing Content-Security-Policy header",
                Severity::High,
                "Content-Security-Policy (CSP) helps prevent XSS and data injection attacks by controlling which resources can be loaded.",
                "CSP header is not present in the response",
                "Add a Content-Security-Policy header with appropriate directives. Example: default-src 'self'; script-src 'self'",
                &data.final_url,
            ));
        }
        Some(csp) => {
            // Basic CSP quality checks
            if csp.contains("unsafe-inline") {
                findings.push(Finding::new(
                    "security-headers",
                    "CSP contains 'unsafe-inline'",
                    Severity::Medium,
                    "The 'unsafe-inline' directive allows inline scripts/styles, weakening CSP protection against XSS attacks.",
                    format!("CSP header: {}", csp),
                    "Use nonces or hashes instead of 'unsafe-inline' for inline scripts/styles.",
                    &data.final_url,
                ));
            }

            if csp.contains("unsafe-eval") {
                findings.push(Finding::new(
                    "security-headers",
                    "CSP contains 'unsafe-eval'",
                    Severity::Medium,
                    "The 'unsafe-eval' directive allows JavaScript eval(), weakening CSP protection.",
                    format!("CSP header: {}", csp),
                    "Remove 'unsafe-eval' and refactor code to avoid eval() usage.",
                    &data.final_url,
                ));
            }

            if csp.contains("data:") {
                findings.push(Finding::new(
                    "security-headers",
                    "CSP allows 'data:' URIs",
                    Severity::Low,
                    "Allowing data: URIs can enable data exfiltration in some attack scenarios.",
                    format!("CSP header: {}", csp),
                    "Avoid allowing data: URIs in CSP unless necessary.",
                    &data.final_url,
                ));
            }

            if !csp.contains("default-src") && !csp.contains("script-src") {
                findings.push(Finding::new(
                    "security-headers",
                    "CSP missing script-src directive",
                    Severity::Medium,
                    "Without script-src, CSP cannot effectively prevent XSS.",
                    format!("CSP header: {}", csp),
                    "Add 'script-src' directive to explicitly control JavaScript sources.",
                    &data.final_url,
                ));
            }

            // CSP bypass analysis
            analyze_csp_bypass(csp, data, findings);
        }
    }
}

/// Deep CSP bypass analysis
fn analyze_csp_bypass(csp: &str, data: &HttpData, findings: &mut Vec<Finding>) {
    let csp_lower = csp.to_lowercase();

    // Check for JSONP endpoints on CDN allowlists
    let cdn_domains = [
        "ajax.googleapis.com", "cdnjs.cloudflare.com", "*.bootstrapcdn.com",
        "code.jquery.com", "unpkg.com", "cdn.jsdelivr.net",
    ];
    for domain in &cdn_domains {
        if csp_lower.contains(domain) {
            findings.push(Finding::new(
                "security-headers",
                "CSP allows scripts from CDN with known JSONP endpoints",
                Severity::Low,
                format!("CSP allows scripts from '{}', which hosts JSONP endpoints that can be abused to bypass CSP.", domain),
                format!("CSP allows: {}", domain),
                "Use Subresource Integrity (SRI) hashes for CDN scripts, or host scripts on your own origin.",
                &data.final_url,
            ));
        }
    }

    // Check for missing object-src (can allow plugin-based bypass)
    if !csp_lower.contains("object-src") {
        findings.push(Finding::new(
            "security-headers",
            "CSP missing object-src directive",
            Severity::Low,
            "Without 'object-src', plugins like Flash/Java could be used to bypass CSP in legacy browsers. CSP defaults to '*' for object-src when not specified.",
            format!("CSP: {}", csp),
            "Add 'object-src: none' to your CSP to block plugin-based content.",
            &data.final_url,
        ));
    }

    // Check for missing base-uri (can allow base tag injection)
    if !csp_lower.contains("base-uri") {
        findings.push(Finding::new(
            "security-headers",
            "CSP missing base-uri directive",
            Severity::Medium,
            "Without 'base-uri', attackers can inject a <base> tag to hijack relative script URLs and bypass CSP.",
            format!("CSP: {}", csp),
            "Add 'base-uri: self' or 'base-uri: none' to prevent base tag injection.",
            &data.final_url,
        ));
    }

    // Check for wildcard in script-src
    if csp_lower.contains("script-src *") || csp_lower.contains("script-src '*'") {
        findings.push(Finding::new(
            "security-headers",
            "CSP script-src allows all sources (wildcard)",
            Severity::Critical,
            "CSP script-src is set to '*', allowing scripts from any origin. This completely defeats CSP script protection.",
            format!("CSP: {}", csp),
            "Restrict script-src to specific origins. Never use wildcard for script-src.",
            &data.final_url,
        ));
    }

    // Check for https: scheme (allows any HTTPS host)
    if csp_lower.contains("script-src https:") && !csp_lower.contains("'strict-dynamic'") {
        findings.push(Finding::new(
            "security-headers",
            "CSP allows scripts from any HTTPS origin",
            Severity::Medium,
            "script-src allows 'https:' which permits scripts from any HTTPS host, including attacker-controlled domains with valid certificates.",
            format!("CSP: {}", csp),
            "Use 'strict-dynamic' with a nonce/hash-based approach instead of scheme-based allowlisting.",
            &data.final_url,
        ));
    }

    // Check for missing frame-ancestors
    if !csp_lower.contains("frame-ancestors") {
        if data.headers.get("x-frame-options").is_none() {
            findings.push(Finding::new(
                "security-headers",
                "CSP missing frame-ancestors and no X-Frame-Options",
                Severity::Medium,
                "Without frame-ancestors in CSP and no X-Frame-Options header, the page is vulnerable to clickjacking.",
                format!("CSP: {}", csp),
                "Add 'frame-ancestors: self' or 'frame-ancestors: none' to CSP.",
                &data.final_url,
            ));
        }
    }

    // Check for missing form-action
    if !csp_lower.contains("form-action") {
        findings.push(Finding::new(
            "security-headers",
            "CSP missing form-action directive",
            Severity::Low,
            "Without 'form-action', an XSS can redirect form submissions to attacker-controlled endpoints.",
            format!("CSP: {}", csp),
            "Add 'form-action: self' to prevent form hijacking via XSS.",
            &data.final_url,
        ));
    }
}

fn check_x_frame_options(data: &HttpData, findings: &mut Vec<Finding>) {
    match data.headers.get("x-frame-options") {
        None => {
            findings.push(Finding::new(
                "security-headers",
                "Missing X-Frame-Options header",
                Severity::Medium,
                "X-Frame-Options prevents clickjacking attacks by controlling whether the page can be embedded in iframes.",
                "X-Frame-Options header is not present",
                "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
                &data.final_url,
            ));
        }
        Some(value) => {
            let v = value.to_lowercase();
            if v != "deny" && v != "sameorigin" {
                findings.push(Finding::new(
                    "security-headers",
                    "Weak X-Frame-Options value",
                    Severity::Low,
                    &format!("X-Frame-Options is set to '{}' which may not provide strong protection.", value),
                    format!("X-Frame-Options: {}", value),
                    "Set X-Frame-Options to 'DENY' for maximum protection.",
                    &data.final_url,
                ));
            }
        }
    }

    // Also check frame-ancestors in CSP
    if let Some(csp) = data.headers.get("content-security-policy") {
        if csp.contains("frame-ancestors") {
            // frame-ancestors in CSP supersedes X-Frame-Options — remove the info
            if data.headers.get("x-frame-options").is_none() {
                // CSP frame-ancestors is present and is the modern alternative
                return; // Don't report missing X-Frame-Options if CSP has frame-ancestors
            }
        }
    }
}

fn check_x_content_type_options(data: &HttpData, findings: &mut Vec<Finding>) {
    if !data.headers.contains_key("x-content-type-options") {
        findings.push(Finding::new(
            "security-headers",
            "Missing X-Content-Type-Options header",
            Severity::Medium,
            "X-Content-Type-Options prevents MIME type sniffing, which can lead to XSS attacks.",
            "X-Content-Type-Options header is not present",
            "Add 'X-Content-Type-Options: nosniff' header.",
            &data.final_url,
        ));
    }
}

fn check_hsts(data: &HttpData, findings: &mut Vec<Finding>) {
    if !data.is_https {
        return;
    }

    match data.headers.get("strict-transport-security") {
        None => {
            findings.push(Finding::new(
                "security-headers",
                "Missing Strict-Transport-Security header",
                Severity::High,
                "HSTS enforces HTTPS connections and prevents SSL stripping attacks.",
                "Strict-Transport-Security header is not present on HTTPS site",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                &data.final_url,
            ));
        }
        Some(hsts) => {
            if !hsts.to_lowercase().contains("max-age") {
                findings.push(Finding::new(
                    "security-headers",
                    "Invalid HSTS header",
                    Severity::Low,
                    "The HSTS header is present but missing the required max-age directive.",
                    format!("Strict-Transport-Security: {}", hsts),
                    "Ensure HSTS includes 'max-age' with a value of at least 31536000 (1 year).",
                    &data.final_url,
                ));
            } else {
                // Check for includeSubDomains
                if !hsts.to_lowercase().contains("includesubdomains") {
                    findings.push(Finding::new(
                        "security-headers",
                        "HSTS missing includeSubDomains",
                        Severity::Low,
                        "Without includeSubDomains, subdomains remain vulnerable to SSL stripping.",
                        format!("Strict-Transport-Security: {}", hsts),
                        "Add 'includeSubDomains' directive to HSTS header.",
                        &data.final_url,
                    ));
                }
            }
        }
    }
}

fn check_referrer_policy(data: &HttpData, findings: &mut Vec<Finding>) {
    if !data.headers.contains_key("referrer-policy") {
        findings.push(Finding::new(
            "security-headers",
            "Missing Referrer-Policy header",
            Severity::Low,
            "Referrer-Policy controls what referrer information is sent with requests, affecting privacy and security.",
            "Referrer-Policy header is not present",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
            &data.final_url,
        ));
    }
}

fn check_permissions_policy(data: &HttpData, findings: &mut Vec<Finding>) {
    if !data.headers.contains_key("permissions-policy") {
        // Also check legacy Feature-Policy
        if !data.headers.contains_key("feature-policy") {
            findings.push(Finding::new(
                "security-headers",
                "Missing Permissions-Policy header",
                Severity::Low,
                "Permissions-Policy controls which browser features and APIs can be used.",
                "Neither Permissions-Policy nor Feature-Policy header is present",
                "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' as a starting point.",
                &data.final_url,
            ));
        }
    }
}

fn check_server_info_exposure(data: &HttpData, findings: &mut Vec<Finding>) {
    if let Some(ref server) = data.server_info.server_header {
        if server.len() > 3 && !server.to_lowercase().contains("cloudflare") {
            findings.push(Finding::new(
                "security-headers",
                "Server header exposes version information",
                Severity::Info,
                "Revealing server software and version helps attackers target known vulnerabilities.",
                format!("Server header: {}", server),
                "Configure the web server to suppress or mask the Server header.",
                &data.final_url,
            ));
        }
    }

    if data.headers.contains_key("x-powered-by") {
        findings.push(Finding::new(
            "security-headers",
            "X-Powered-By header leaks technology stack",
            Severity::Info,
            "This header reveals the underlying technology stack to potential attackers.",
            format!("X-Powered-By: {}", data.headers.get("x-powered-by").unwrap()),
            "Remove or suppress the X-Powered-By header.",
            &data.final_url,
        ));
    }

    if data.headers.contains_key("x-aspnet-version") || data.headers.contains_key("x-aspnetmvc-version") {
        findings.push(Finding::new(
            "security-headers",
            "ASP.NET version information exposed",
            Severity::Medium,
            "Version-specific headers help attackers identify vulnerable ASP.NET installations.",
            "ASP.NET version headers are present",
            "Disable version headers in web.config: <httpRuntime enableVersionHeader=\"false\"/>",
            &data.final_url,
        ));
    }
}

fn check_xss_protection(data: &HttpData, findings: &mut Vec<Finding>) {
    if let Some(xss) = data.headers.get("x-xss-protection") {
        if xss == "0" {
            findings.push(Finding::new(
                "security-headers",
                "X-XSS-Protection disabled",
                Severity::Info,
                "The X-XSS-Protection header is set to 0, disabling the browser's built-in XSS filter.",
                format!("X-XSS-Protection: {}", xss),
                "Consider using CSP instead, which provides stronger XSS protection than the legacy X-XSS-Protection header.",
                &data.final_url,
            ));
        }
    }
}

fn check_cross_origin_policies(data: &HttpData, findings: &mut Vec<Finding>) {
    if data.headers.contains_key("access-control-allow-origin") {
        let acao = data.headers.get("access-control-allow-origin").unwrap();

        if acao == "*" {
            findings.push(Finding::new(
                "security-headers",
                "Wildcard CORS Access-Control-Allow-Origin",
                Severity::Medium,
                "Allowing all origins (*) in CORS can expose the application to cross-origin attacks.",
                format!("Access-Control-Allow-Origin: {}", acao),
                "Restrict Access-Control-Allow-Origin to specific trusted domains.",
                &data.final_url,
            ));
        }
    }

    if data.headers.contains_key("access-control-allow-credentials") {
        let acac = data.headers.get("access-control-allow-credentials").unwrap();
        if acac == "true" {
            if let Some(acao) = data.headers.get("access-control-allow-origin") {
                if acao == "*" {
                    findings.push(Finding::new(
                        "security-headers",
                        "Dangerous CORS configuration",
                        Severity::High,
                        "Access-Control-Allow-Credentials: true combined with wildcard origin is insecure and blocked by browsers, but indicates misconfiguration.",
                        format!("Access-Control-Allow-Origin: {}, Access-Control-Allow-Credentials: true", acao),
                        "Never use wildcard origin with credentialed requests.",
                        &data.final_url,
                    ));
                }
            }
        }
    }

    // Check for Cross-Origin isolation headers
    if !data.headers.contains_key("cross-origin-opener-policy") {
        findings.push(Finding::new(
            "security-headers",
            "Missing Cross-Origin-Opener-Policy header",
            Severity::Low,
            "COOP prevents cross-origin interactions that can enable Spectre/XS-Leaks attacks.",
            "Cross-Origin-Opener-Policy header is not present",
            "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
            &data.final_url,
        ));
    }

    if !data.headers.contains_key("cross-origin-embedder-policy") {
        findings.push(Finding::new(
            "security-headers",
            "Missing Cross-Origin-Embedder-Policy header",
            Severity::Low,
            "COEP controls which cross-origin resources can be loaded, enabling cross-origin isolation.",
            "Cross-Origin-Embedder-Policy header is not present",
            "Consider 'Cross-Origin-Embedder-Policy: require-corp' for sensitive applications.",
            &data.final_url,
        ));
    }

    if !data.headers.contains_key("cross-origin-resource-policy") {
        findings.push(Finding::new(
            "security-headers",
            "Missing Cross-Origin-Resource-Policy header",
            Severity::Low,
            "CORP prevents Spectre-style attacks by restricting cross-origin resource loading.",
            "Cross-Origin-Resource-Policy header is not present",
            "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' header.",
            &data.final_url,
        ));
    }
}
