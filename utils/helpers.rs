use regex::Regex;

#[allow(dead_code)]
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[allow(dead_code)]
pub fn mask_sensitive_value(value: &str) -> String {
    if value.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &value[..4], &value[value.len()-4..])
}

lazy_static::lazy_static! {
    static ref SENSITIVE_KEYWORDS: Regex =
        Regex::new(r"(?i)(password|secret|token|api[_-]?key|auth|credential|private[_-]?key|access[_-]?key|session)").unwrap();

    static ref CREDIT_CARD_PATTERN: Regex =
        Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();

    static ref EMAIL_PATTERN: Regex =
        Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
}

#[allow(dead_code)]
pub fn is_sensitive_keyword(key: &str) -> bool {
    SENSITIVE_KEYWORDS.is_match(key)
}

#[allow(dead_code)]
pub fn find_credit_card_numbers(text: &str) -> Vec<String> {
    CREDIT_CARD_PATTERN
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn find_emails(text: &str) -> Vec<String> {
    EMAIL_PATTERN
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{}ms", (secs * 1000.0) as u64)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else {
        let minutes = (secs / 60.0) as u64;
        let remaining_secs = secs % 60.0;
        format!("{}m {:.0}s", minutes, remaining_secs)
    }
}
