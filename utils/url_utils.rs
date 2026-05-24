use url::Url;

pub fn is_valid_url(input: &str) -> bool {
    let normalized = normalize_url(input);
    Url::parse(&normalized).is_ok()
}

pub fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return format!("https://{}", trimmed);
    }

    trimmed.to_string()
}

#[allow(dead_code)]
pub fn parse_url(input: &str) -> Result<Url, String> {
    let normalized = normalize_url(input);
    Url::parse(&normalized).map_err(|e| format!("Invalid URL '{}': {}", input, e))
}

#[allow(dead_code)]
pub fn extract_domain(input: &str) -> Option<String> {
    parse_url(input).ok().and_then(|u| u.host_str().map(|h| h.to_string()))
}

#[allow(dead_code)]
pub fn is_https(input: &str) -> bool {
    input.trim().starts_with("https://")
}

pub fn read_urls_from_file(path: &str) -> Result<Vec<String>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let urls: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| is_valid_url(l))
        .collect();
    Ok(urls)
}
