use std::collections::HashMap;

/// Response diff result — compares baseline vs injected response
#[derive(Debug, Clone)]
pub struct ResponseDiff {
    /// Whether the injected payload appears in the response
    pub payload_reflected: bool,
    /// Exact position(s) where payload was found
    pub reflection_points: Vec<ReflectionPoint>,
    /// Difference in response size
    pub size_delta: i64,
    /// Difference in response time (ms)
    pub time_delta_ms: i128,
    /// New headers in injected response
    pub new_headers: Vec<String>,
    /// Whether error patterns appeared
    pub error_markers: Vec<String>,
    /// Content similarity score (0.0-1.0)
    pub similarity: f64,
    /// Number of new/removed lines
    pub line_delta: i64,
}

#[derive(Debug, Clone)]
pub struct ReflectionPoint {
    pub offset: usize,
    pub context: String,
    pub context_type: ReflectionContext,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReflectionContext {
    HtmlBody,
    AttributeValue,
    JavaScript,
    JsonValue,
    HttpHeader,
    UrlPath,
    Comment,
}

impl ReflectionPoint {
    pub fn risk(&self) -> &str {
        match self.context_type {
            ReflectionContext::JavaScript => "Critical — unsanitized JS injection",
            ReflectionContext::HtmlBody => "High — HTML tag injection possible",
            ReflectionContext::AttributeValue => "High — attribute breakout possible",
            ReflectionContext::JsonValue => "Medium — JSON context, XSS unlikely but data injection possible",
            ReflectionContext::HttpHeader => "Medium — header injection risk",
            ReflectionContext::UrlPath => "Low — URL context",
            ReflectionContext::Comment => "Info — inside HTML comment",
        }
    }
}

/// Diff two responses to find injection evidence
pub fn diff_responses(
    baseline_body: &str,
    injected_body: &str,
    baseline_time_ms: u128,
    injected_time_ms: u128,
    baseline_headers: &HashMap<String, String>,
    injected_headers: &HashMap<String, String>,
    payload_marker: &str,
) -> ResponseDiff {
    let payload_reflected = injected_body.contains(payload_marker);

    let reflection_points = if payload_reflected {
        find_reflection_points(injected_body, payload_marker)
    } else {
        vec![]
    };

    let size_delta = injected_body.len() as i64 - baseline_body.len() as i64;
    let time_delta_ms = injected_time_ms as i128 - baseline_time_ms as i128;

    let new_headers: Vec<String> = injected_headers
        .keys()
        .filter(|k| !baseline_headers.contains_key(*k))
        .cloned()
        .collect();

    let error_markers = find_error_markers(injected_body);

    let line_delta = injected_body.lines().count() as i64 - baseline_body.lines().count() as i64;

    let similarity = if size_delta.abs() < 50 {
        0.99
    } else {
        let max_len = baseline_body.len().max(injected_body.len()) as f64;
        if max_len > 0.0 {
            1.0 - (size_delta.abs() as f64 / max_len)
        } else {
            1.0
        }
    };

    ResponseDiff {
        payload_reflected,
        reflection_points,
        size_delta,
        time_delta_ms,
        new_headers,
        error_markers,
        similarity,
        line_delta,
    }
}

fn find_reflection_points(body: &str, marker: &str) -> Vec<ReflectionPoint> {
    let mut points = Vec::new();
    let body_lower = body.to_lowercase();

    for (offset, _) in body.match_indices(marker) {
        let start = if offset > 80 { offset - 80 } else { 0 };
        let end = (offset + marker.len() + 80).min(body.len());
        let context = body[start..end].to_string();

        let context_type = if body[..offset].rfind("<script").map_or(true, |s| {
            body[s..offset].contains("</script>")
        }) && body[offset..].find("</script>").map_or(false, |_| true) {
            ReflectionContext::JavaScript
        } else if offset > 0 && body.as_bytes()[offset - 1] == b'"' {
            ReflectionContext::AttributeValue
        } else if body[..offset].rfind('>').map_or(false, |g| {
            body[g..offset].find('<').is_none()
        }) {
            ReflectionContext::HtmlBody
        } else if body_lower[..offset].contains("content-type") {
            ReflectionContext::HttpHeader
        } else if body[..offset].rfind("//").is_some() || body[..offset].rfind("<!--").is_some() {
            ReflectionContext::Comment
        } else {
            ReflectionContext::JsonValue
        };

        points.push(ReflectionPoint {
            offset,
            context,
            context_type,
        });
    }

    points
}

fn find_error_markers(body: &str) -> Vec<String> {
    let patterns = [
        ("sql syntax", "MySQL syntax error"),
        ("mysql_fetch", "MySQL fetch error"),
        ("unclosed quotation mark", "MSSQL quotation error"),
        ("ora-", "Oracle error"),
        ("postgresql", "PostgreSQL error"),
        ("sqlite3::", "SQLite error"),
        ("pdoexception", "PDO exception"),
        ("stack trace", "Stack trace exposed"),
        ("fatal error", "PHP fatal error"),
        ("exception:", "Exception message"),
        ("warning:", "Warning message"),
        ("mongoerror", "MongoDB error"),
        ("bson", "BSON error"),
        ("objectid", "MongoDB ObjectId"),
    ];

    let body_lower = body.to_lowercase();
    patterns
        .iter()
        .filter(|(p, _)| body_lower.contains(p))
        .map(|(_, label)| label.to_string())
        .collect()
}

/// Calculate detection confidence based on response diff
pub fn confidence_from_diff(diff: &ResponseDiff) -> crate::models::Confidence {
    if diff.payload_reflected && !diff.reflection_points.is_empty() {
        // Check if in dangerous context
        let has_dangerous = diff.reflection_points.iter().any(|p| {
            p.context_type == ReflectionContext::JavaScript
                || p.context_type == ReflectionContext::HtmlBody
                || p.context_type == ReflectionContext::AttributeValue
        });
        if has_dangerous {
            crate::models::Confidence::Confirmed
        } else {
            crate::models::Confidence::High
        }
    } else if !diff.error_markers.is_empty() {
        crate::models::Confidence::Medium
    } else if diff.time_delta_ms > 2000 {
        crate::models::Confidence::Low
    } else if diff.size_delta.abs() > 100 && diff.similarity < 0.8 {
        crate::models::Confidence::Low
    } else {
        crate::models::Confidence::Heuristic
    }
}
