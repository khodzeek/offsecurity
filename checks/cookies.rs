use crate::models::{Finding, HttpData, Severity};

pub fn check_cookies(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    if data.cookies.is_empty() {
        return findings;
    }

    for cookie in &data.cookies {
        let cookie_desc = format!("Cookie '{}' (value: {})", cookie.name, cookie.value_preview);

        // Check Secure flag
        if !cookie.secure && data.is_https {
            findings.push(Finding::new(
                "cookies",
                "Cookie missing Secure flag",
                Severity::High,
                &format!(
                    "Cookie '{}' is served over HTTPS but lacks the Secure flag. It could be transmitted over unencrypted connections.",
                    cookie.name
                ),
                cookie_desc.clone(),
                "Set the Secure flag on all cookies. Set-Cookie: <name>=<value>; Secure",
                &data.final_url,
            ));
        }

        // Check HttpOnly flag
        if !cookie.http_only {
            let sev = if cookie.name.to_lowercase().contains("session")
                || cookie.name.to_lowercase().contains("auth")
                || cookie.name.to_lowercase().contains("token")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(Finding::new(
                "cookies",
                "Cookie missing HttpOnly flag",
                sev,
                &format!(
                    "Cookie '{}' lacks the HttpOnly flag, making it accessible to JavaScript via document.cookie. This enables cookie theft via XSS.",
                    cookie.name
                ),
                cookie_desc.clone(),
                "Set the HttpOnly flag on all cookies: Set-Cookie: <name>=<value>; HttpOnly",
                &data.final_url,
            ));
        }

        // Check SameSite
        if cookie.same_site.is_none() {
            findings.push(Finding::new(
                "cookies",
                "Cookie missing SameSite attribute",
                Severity::Medium,
                &format!(
                    "Cookie '{}' does not have a SameSite attribute, which can make it vulnerable to CSRF attacks.",
                    cookie.name
                ),
                cookie_desc.clone(),
                "Set SameSite=Lax or SameSite=Strict on cookies: Set-Cookie: <name>=<value>; SameSite=Lax",
                &data.final_url,
            ));
        } else if let Some(ref ss) = cookie.same_site {
            if ss.to_lowercase() == "none" && !cookie.secure {
                findings.push(Finding::new(
                    "cookies",
                    "SameSite=None without Secure flag",
                    Severity::High,
                    &format!(
                        "Cookie '{}' has SameSite=None without the Secure flag. Browsers will reject this cookie.",
                        cookie.name
                    ),
                    format!("SameSite=None, Secure={}", cookie.secure),
                    "When using SameSite=None, the Secure flag must also be set.",
                    &data.final_url,
                ));
            }
        }

        // Check for session cookie names (potentially guessable)
        if cookie.name.to_lowercase() == "sessionid"
            || cookie.name.to_lowercase() == "jsessionid"
            || cookie.name.to_lowercase() == "phpsessid"
            || cookie.name.to_lowercase() == "aspsessionid"
        {
            findings.push(Finding::new(
                "cookies",
                "Default session cookie name detected",
                Severity::Info,
                &format!(
                    "Cookie '{}' uses a default framework session name. This reveals the technology stack.",
                    cookie.name
                ),
                cookie_desc,
                "Consider customizing the session cookie name in your framework configuration.",
                &data.final_url,
            ));
        }

        // Check for short/suspicious values
        if cookie.value_preview.len() < 8 && cookie.name.to_lowercase().contains("session") {
            findings.push(Finding::new(
                "cookies",
                "Session cookie has a short value",
                Severity::Info,
                &format!(
                    "Session cookie '{}' has a very short value, which may indicate weak session identifiers.",
                    cookie.name
                ),
                format!("Value length: {} bytes", cookie.value_preview.len()),
                "Ensure session identifiers are at least 128 bits of entropy (32+ hex characters).",
                &data.final_url,
            ));
        }
    }

    // Check: no cookies at all on sensitive pages
    let url_lower = data.final_url.to_lowercase();
    if (url_lower.contains("login") || url_lower.contains("admin") || url_lower.contains("dashboard"))
        && data.cookies.is_empty()
    {
        // Might not be an issue, but worth noting
    }

    // Check Set-Cookie header parsing issues
    if let Some(set_cookie) = data.headers.get("set-cookie") {
        if set_cookie.contains("__Host-") || set_cookie.contains("__Secure-") {
            // Cookie prefixes are good — these require Secure and correct Path
        }
    }

    findings
}
