use crate::core::HttpClient;
use std::collections::{HashSet, VecDeque};
use regex::Regex;
use tracing::{debug, info};

/// Web crawler configuration
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    pub enabled: bool,
    pub max_pages: usize,
    pub same_origin_only: bool,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pages: 100,
            same_origin_only: true,
        }
    }
}

/// Crawl a URL and discover additional pages
pub async fn crawl(
    client: &HttpClient,
    start_url: &str,
    config: &CrawlerConfig,
) -> Vec<String> {
    let mut discovered = HashSet::new();
    let mut queue = VecDeque::new();
    let mut result_urls = Vec::new();

    let base_origin = get_origin(start_url);

    discovered.insert(start_url.to_string());
    queue.push_back(start_url.to_string());
    result_urls.push(start_url.to_string());

    info!("Starting crawl from {} (max {} pages)", start_url, config.max_pages);

    while let Some(current_url) = queue.pop_front() {
        if result_urls.len() >= config.max_pages {
            debug!("Crawl limit reached ({} pages)", config.max_pages);
            break;
        }

        match client.fetch_url(&current_url).await {
            Ok(response) => {
                if let Some(ref body) = response.body {
                    let links = extract_links(body, &current_url);

                    for link in links {
                        if result_urls.len() >= config.max_pages {
                            break;
                        }

                        // Skip non-HTTP URLs
                        if !link.starts_with("http://") && !link.starts_with("https://") {
                            continue;
                        }

                        // Same-origin check
                        if config.same_origin_only {
                            if let Some(ref origin) = base_origin {
                                let link_origin = get_origin(&link);
                                if link_origin.as_deref() != Some(origin.as_str()) {
                                    continue;
                                }
                            }
                        }

                        // Skip fragments and anchors
                        let clean_url = strip_fragment(&link);

                        // Skip already-seen URLs
                        if discovered.contains(&clean_url) {
                            continue;
                        }

                        // Skip non-page resources
                        if is_static_resource(&clean_url) {
                            continue;
                        }

                        debug!("Discovered: {}", clean_url);
                        discovered.insert(clean_url.clone());
                        queue.push_back(clean_url.clone());
                        result_urls.push(clean_url);
                    }
                }
            }
            Err(e) => {
                debug!("Crawl error for {}: {}", current_url, e);
                continue;
            }
        }
    }

    info!("Crawl complete: {} pages discovered", result_urls.len());
    result_urls
}

fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();

    // Extract href attributes from <a> tags
    let href_re = Regex::new(r#"<a\s[^>]*href\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in href_re.captures_iter(html) {
        let href = &cap[1];
        if !href.starts_with('#') && !href.starts_with("javascript:") && !href.starts_with("mailto:") && !href.starts_with("tel:") {
            let resolved = resolve_url(href, base_url);
            links.push(resolved);
        }
    }

    // Extract src from iframes
    let iframe_re = Regex::new(r#"<iframe\s[^>]*src\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in iframe_re.captures_iter(html) {
        let src = &cap[1];
        if !src.starts_with('#') && !src.starts_with("javascript:") {
            links.push(resolve_url(src, base_url));
        }
    }

    // Extract form actions
    let form_re = Regex::new(r#"<form\s[^>]*action\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in form_re.captures_iter(html) {
        let action = &cap[1];
        links.push(resolve_url(action, base_url));
    }

    links
}

fn resolve_url(href: &str, base_url: &str) -> String {
    // Absolute URL
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }

    // Protocol-relative
    if href.starts_with("//") {
        let proto = if base_url.starts_with("https://") { "https:" } else { "http:" };
        return format!("{}{}", proto, href);
    }

    // Root-relative
    if href.starts_with('/') {
        if let Some(origin) = get_origin(base_url) {
            return format!("{}{}", origin, href);
        }
    }

    // Path-relative
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else if let Some(last_slash) = base_url.rfind('/') {
        if last_slash > 7 {
            format!("{}/", &base_url[..last_slash + 1])
        } else {
            format!("{}/", base_url)
        }
    } else {
        format!("{}/", base_url)
    };
    format!("{}{}", base, href.trim_start_matches('/'))
}

fn get_origin(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        Some(format!("{}://{}", parsed.scheme(), parsed.host_str()?).to_string())
    } else {
        None
    }
}

fn strip_fragment(url: &str) -> String {
    if let Some(pos) = url.find('#') {
        url[..pos].to_string()
    } else {
        url.to_string()
    }
}

fn is_static_resource(url: &str) -> bool {
    let extensions = [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
        ".mp4", ".mp3", ".webm", ".ogg", ".avi",
    ];
    let url_lower = url.to_lowercase();
    extensions.iter().any(|ext| url_lower.contains(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_absolute() {
        assert_eq!(
            resolve_url("https://example.com/page", "https://site.com"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_resolve_root_relative() {
        assert_eq!(
            resolve_url("/about", "https://example.com/page"),
            "https://example.com/about"
        );
    }

    #[test]
    fn test_strip_fragment() {
        assert_eq!(
            strip_fragment("https://example.com/page#section"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_is_static() {
        assert!(is_static_resource("https://example.com/style.css"));
        assert!(is_static_resource("https://example.com/logo.png"));
        assert!(!is_static_resource("https://example.com/about"));
    }
}
