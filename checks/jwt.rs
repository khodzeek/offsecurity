use crate::models::{Finding, HttpData, Severity};
use serde_json::Value;

/// Find and analyze JWTs in the HTTP response
pub fn check_jwt(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look in Authorization header
    if let Some(auth) = data.headers.get("authorization") {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            analyze_token(token, "Authorization header", &data.final_url, &mut findings);
        }
    }

    // Look in Set-Cookie header
    if let Some(cookies) = data.headers.get("set-cookie") {
        for part in cookies.split(';') {
            let part = part.trim();
            if let Some(eq) = part.find('=') {
                let value = part[eq+1..].trim();
                if is_jwt(value) {
                    analyze_token(value, &format!("Set-Cookie: {}", &part[..eq]), &data.final_url, &mut findings);
                }
            }
        }
    }

    // Look in response body (e.g., id_token, access_token in JSON responses)
    if let Some(ref body) = data.body {
        // Regex for JWT pattern in body
        let jwt_re = regex::Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();
        for (i, m) in jwt_re.find_iter(body).enumerate().take(5) {
            analyze_token(m.as_str(), &format!("response body (match #{})", i+1), &data.final_url, &mut findings);
        }

        // Check for JWTs exposed in JavaScript variables
        for pattern in &["access_token", "id_token", "jwt", "token"] {
            let re = regex::Regex::new(&format!(r#""{}"\s*:\s*"([^"]+)""#, pattern)).unwrap();
            for cap in re.captures_iter(body).take(3) {
                let val = &cap[1];
                if is_jwt(val) {
                    findings.push(Finding::new(
                        "jwt",
                        "JWT exposed in client-side code",
                        Severity::Medium,
                        format!("A JWT '{}' was found exposed in JavaScript/JSON in the page body. This token can be extracted by any XSS attack.", pattern),
                        format!("Found in body: \"{}\" = \"{}...\"", pattern, &val[..30.min(val.len())]),
                        "Never expose tokens in client-side code. Use HttpOnly cookies for storage.",
                        &data.final_url,
                    ));
                }
            }
        }
    }

    findings
}

fn is_jwt(s: &str) -> bool {
    s.matches('.').count() == 2
        && s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        && s.len() > 20
}

fn analyze_token(token: &str, source: &str, url: &str, findings: &mut Vec<Finding>) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    // Decode header
    let header = base64_url_decode(parts[0]);
    let payload = base64_url_decode(parts[1]);

    let header_json: Option<Value> = serde_json::from_str(&header).ok();
    let payload_json: Option<Value> = serde_json::from_str(&payload).ok();

    // === Algorithm checks ===
    if let Some(ref header_obj) = header_json {
        let alg = header_obj["alg"].as_str().unwrap_or("unknown");

        // alg: none — CRITICAL
        if alg == "none" {
            findings.push(Finding::new(
                "jwt",
                "JWT 'none' algorithm attack possible",
                Severity::Critical,
                format!("JWT in {} uses algorithm 'none', allowing attackers to bypass signature verification by removing the signature entirely.", source),
                format!("Header: {}\nToken: {}...", header, &token[..50]),
                "Never accept 'none' algorithm. Explicitly whitelist allowed algorithms (RS256, ES256).",
                url,
            ));
        }

        // HS256 with RSA key confusion
        if alg == "HS256" {
            findings.push(Finding::new(
                "jwt",
                "JWT uses symmetric algorithm (HS256)",
                Severity::Low,
                format!("JWT in {} uses HS256 symmetric signing. If the server also accepts RS256, the public key can be used to forge HS256 tokens.", source),
                format!("Algorithm: {}\nHeader: {}", alg, header),
                "Prefer asymmetric algorithms (RS256, ES256, EdDSA). If HS256 is required, ensure the secret is strong and not exposed.",
                url,
            ));
        }

        // Algorithm confusion: RS256→HS256 (if public key is accessible)
        if alg == "RS256" || alg == "RS384" || alg == "RS512" || alg == "ES256" || alg == "ES384" || alg == "ES512" {
            findings.push(Finding::new(
                "jwt",
                format!("JWT uses asymmetric algorithm — verify key confusion is not possible ({})", alg),
                Severity::Low,
                format!(
                    "JWT in {} uses {} asymmetric signing. Ensure the server does NOT also accept HS256/HS384/HS512, as an attacker could use the public key as an HMAC secret to forge tokens (algorithm confusion attack).",
                    source, alg
                ),
                format!("Algorithm: {}\nToken: {}...", alg, &token[..50]),
                "Explicitly whitelist only asymmetric algorithms on the server. Reject tokens with symmetric algorithms when expecting asymmetric ones.",
                url,
            ));
        }

        // alg: none-like variants
        let alg_lower = alg.to_lowercase();
        if alg_lower == "none" || alg_lower == "none" || alg_lower.starts_with("non") {
            // covered above
        }

        // Check for jku/jwk header injection
        if header_obj.get("jku").is_some() {
            findings.push(Finding::new(
                "jwt",
                "JWT contains jku (JWK Set URL) header",
                Severity::Critical,
                format!("JWT in {} uses 'jku' header, which tells the server to fetch public keys from an external URL. This can be exploited for SSRF or key injection.", source),
                format!("Header: {}", header),
                "Do not trust jku/jwk headers in tokens. Use a pre-configured set of trusted keys.",
                url,
            ));
        }

        if header_obj.get("jwk").is_some() {
            findings.push(Finding::new(
                "jwt",
                "JWT contains embedded jwk (JSON Web Key)",
                Severity::Critical,
                format!("JWT in {} embeds a public key via 'jwk' header, allowing attackers to sign tokens with their own key pair.", source),
                format!("Header: {}", header),
                "Never accept embedded JWKs. Always use server-side key storage.",
                url,
            ));
        }

        // Check kid injection potential
        if let Some(kid) = header_obj.get("kid") {
            let kid_str = kid.as_str().unwrap_or("");
            if kid_str.contains("../") || kid_str.contains("..\\") || kid_str.contains('/') {
                findings.push(Finding::new(
                    "jwt",
                    "JWT kid parameter contains path traversal",
                    Severity::High,
                    format!("JWT in {} has a 'kid' parameter with a file path: '{}'. This could be exploited for key confusion or file read if the server uses kid for key lookup.", source, kid_str),
                    format!("kid: {}", kid_str),
                    "Sanitize kid parameter. Do not use it directly for file system operations.",
                    url,
                ));
            }
        }
    }

    // === Claims checks ===
    if let Some(ref payload_obj) = payload_json {
        // Missing expiration
        if payload_obj.get("exp").is_none() {
            findings.push(Finding::new(
                "jwt",
                "JWT missing expiration (exp claim)",
                Severity::High,
                format!("JWT in {} has no expiration time, meaning it remains valid indefinitely if stolen.", source),
                format!("Payload: {}", &payload[..200.min(payload.len())]),
                "Always set an 'exp' (expiration) claim with a reasonable lifetime (e.g., 15 minutes for access tokens).",
                url,
            ));
        }

        // Long-lived token
        if let (Some(iat), Some(exp)) = (
            payload_obj.get("iat").and_then(|v| v.as_i64()),
            payload_obj.get("exp").and_then(|v| v.as_i64()),
        ) {
            let lifespan_days = (exp - iat) / 86400;
            if lifespan_days > 30 {
                findings.push(Finding::new(
                    "jwt",
                    "JWT has excessively long lifespan",
                    Severity::Medium,
                    format!("JWT in {} is valid for {} days (iat={}, exp={}). Long-lived tokens increase the window for token theft and reuse.", source, lifespan_days, iat, exp),
                    format!("iat: {}, exp: {}, lifespan: {} days", iat, exp, lifespan_days),
                    "Use short-lived access tokens (15-60 minutes) with refresh tokens for longer sessions.",
                    url,
                ));
            }
        }

        // Missing issuer
        if payload_obj.get("iss").is_none() && payload_obj.get("sub").is_some() {
            findings.push(Finding::new(
                "jwt",
                "JWT missing issuer (iss claim)",
                Severity::Low,
                format!("JWT in {} has no 'iss' (issuer) claim. The token could have been issued by any authority.", source),
                format!("Payload: {}", &payload[..200]),
                "Include an 'iss' claim to identify the token issuer.",
                url,
            ));
        }
    }
}

fn base64_url_decode(input: &str) -> String {
    use base64::Engine;
    let mut b64 = input.replace('-', "+").replace('_', "/");
    while b64.len() % 4 != 0 {
        b64.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}
