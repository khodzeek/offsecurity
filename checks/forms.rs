use crate::models::{Finding, HttpData, Severity};

pub fn check_forms(data: &HttpData) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (i, form) in data.forms.iter().enumerate() {
        let form_id = format!("form #{} on {}", i + 1, data.final_url);

        // Check for GET method on forms with password fields
        if form.has_password_field && form.method == "GET" {
            findings.push(Finding::new(
                "forms",
                "Login form uses GET method",
                Severity::High,
                "A login form uses the GET method, which means credentials will be sent in the URL query string and logged in server logs, browser history, and referrer headers.",
                format!("Form action: {:?}, method: {}", form.action, form.method),
                "Change the login form method to POST to prevent credential leakage.",
                &data.final_url,
            ));
        }

        // Check for missing CSRF token
        if form.method == "POST" && !form.has_csrf_token {
            let sev = if form.has_password_field {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(Finding::new(
                "forms",
                "Form missing CSRF token",
                sev,
                &format!(
                    "A POST form{} does not have a detectable CSRF token, making it potentially vulnerable to Cross-Site Request Forgery attacks.",
                    if form.has_password_field { " with password fields" } else { "" }
                ),
                format!(
                    "Form action: {:?}, method: {}, hidden fields: {:?}",
                    form.action, form.method, form.hidden_fields
                ),
                "Implement CSRF protection by adding a unique token as a hidden form field or via a custom request header.",
                &data.final_url,
            ));
        }

        // Check for password fields without HTTPS
        if form.has_password_field && !data.is_https {
            findings.push(Finding::new(
                "forms",
                "Login form on non-HTTPS page",
                Severity::Critical,
                "A form containing password fields is served over HTTP. Credentials will be transmitted in plaintext over the network.",
                format!("URL: {}", data.final_url),
                "Serve the entire page over HTTPS and redirect all HTTP traffic to HTTPS.",
                &data.final_url,
            ));
        }

        // Check for hidden fields that may contain sensitive-looking names
        for hidden in &form.hidden_fields {
            let hidden_lower = hidden.to_lowercase();
            if hidden_lower.contains("price")
                || hidden_lower.contains("role")
                || hidden_lower.contains("admin")
                || hidden_lower.contains("level")
                || hidden_lower.contains("discount")
            {
                findings.push(Finding::new(
                    "forms",
                    "Potentially dangerous hidden field",
                    Severity::Medium,
                    &format!(
                        "Hidden form field '{}' may be used for client-side state that could be tampered with. Values in hidden fields can be modified by users.",
                        hidden
                    ),
                    format!("Hidden field: {} in {}", hidden, form_id),
                    "Never trust client-side data. Move sensitive logic to server-side validation.",
                    &data.final_url,
                ));
            }
        }

        // Check for autocomplete on sensitive fields
        if form.has_password_field {
            let form_html = form.html_snippet.to_lowercase();
            if !form_html.contains("autocomplete=\"off\"")
                && !form_html.contains("autocomplete=\"new-password\"")
            {
                findings.push(Finding::new(
                    "forms",
                    "Login form does not disable autocomplete",
                    Severity::Low,
                    "The login form does not set autocomplete='off' or autocomplete='new-password', which may cause browsers to cache credentials.",
                    &form.html_snippet,
                    "Add autocomplete='off' on the form or autocomplete='new-password' on password fields.",
                    &data.final_url,
                ));
            }
        }
    }

    // Check for missing Content-Type
    if data.body.as_ref().map(|b| b.to_lowercase().contains("<form")).unwrap_or(false) {
        if !data.headers.contains_key("content-type") {
            findings.push(Finding::new(
                "forms",
                "Missing Content-Type header",
                Severity::Info,
                "The response contains an HTML form but does not specify a Content-Type header, which could lead to MIME sniffing attacks.",
                "Content-Type header is missing from a page with forms",
                "Add 'Content-Type: text/html; charset=UTF-8' to all HTML responses.",
                &data.final_url,
            ));
        }
    }

    findings
}
