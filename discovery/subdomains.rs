use super::DiscoveredHost;
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Built-in top subdomains wordlist (abbreviated — top ~200)
const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "download", "dns", "api", "cdn",
    "staging", "app", "git", "svn", "assets", "portal", "video", "sip", "dns2",
    "dns1", "proxy", "chat", "stats", "status", "help", "host", "owa", "remote",
    "jobs", "monitor", "mon", "search", "stage", "store", "wpad", "bbs", "web01",
    "web1", "gateway", "intranet", "data", "backup", "db", "crm", "erp", "ldap",
    "jenkins", "jira", "confluence", "grafana", "kibana", "prometheus", "alertmanager",
];

/// Detect if a domain has wildcard DNS by resolving a random non-existent subdomain
async fn detect_wildcard_dns(domain: &str) -> Option<HashSet<String>> {
    let random_sub = format!("thisdoesnotexist{}.{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>(), domain);

    // Try multiple random subdomains to be sure
    let mut wildcard_ips = HashSet::new();
    for _ in 0..3 {
        let probe = format!("_wildcard_probe_{}.{}", uuid::Uuid::new_v4().to_string().chars().take(6).collect::<String>(), domain);
        if let Some(ip) = resolve_host(&probe).await {
            wildcard_ips.insert(ip);
        }
    }

    if !wildcard_ips.is_empty() {
        // Also include the base domain IPs (they may be behind the same CDN)
        if let Some(ip) = resolve_host(domain).await {
            wildcard_ips.insert(ip);
        }
    }

    // Silence unused warning for random_sub
    let _ = random_sub;

    if wildcard_ips.is_empty() { None } else { Some(wildcard_ips) }
}

/// Verify a subdomain via HTTP HEAD request — returns true if it serves real content
async fn verify_subdomain_http(fqdn: &str, wildcard_baseline: Option<&str>) -> bool {
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, fqdn);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        let resp = match client.head(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        // If we have a wildcard baseline, compare against it
        if let Some(baseline) = wildcard_baseline {
            // If the response differs from the wildcard baseline, it's a real subdomain
            if body != baseline || status >= 400 {
                return body != baseline;
            }
            return false;
        }

        // Without baseline, consider any successful HTTP response as a real subdomain
        return status < 500;
    }
    false
}

/// Get a baseline HTTP response from the wildcard domain
async fn get_wildcard_baseline(domain: &str) -> Option<String> {
    let probe = format!("_{}.{}", uuid::Uuid::new_v4().to_string().chars().take(6).collect::<String>(), domain);
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, probe);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;

        if let Ok(resp) = client.head(&url).send().await {
            return resp.text().await.ok();
        }
    }
    None
}

/// Enumerate subdomains for a given domain
#[allow(dead_code)]
pub async fn enumerate(domain: &str, concurrency: usize) -> (Vec<DiscoveredHost>, f64) {
    enumerate_with_wordlist(domain, concurrency, None).await
}

/// Enumerate subdomains with an optional custom wordlist
pub async fn enumerate_with_wordlist(
    domain: &str,
    concurrency: usize,
    custom_wordlist: Option<&str>,
) -> (Vec<DiscoveredHost>, f64) {
    let start = Instant::now();
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();

    // Detect wildcard DNS
    let wildcard_ips = detect_wildcard_dns(domain).await;
    let has_wildcard = wildcard_ips.is_some();
    if has_wildcard {
        println!("  ⚠ Wildcard DNS detected — verifying via HTTP");
    }

    // Get wildcard HTTP baseline for filtering
    let wildcard_baseline = if has_wildcard {
        get_wildcard_baseline(domain).await
    } else {
        None
    };

    // Always check the base domain first
    if let Some(ip) = resolve_host(domain).await {
        seen.insert(domain.to_string());
        hosts.push(DiscoveredHost {
            hostname: domain.to_string(),
            ip: Some(ip),
            open_ports: vec![],
            services: vec![],
        });
    }

    // Load wordlist: custom file first, then fall back to built-in
    let wordlist: Vec<String> = if let Some(path) = custom_wordlist {
        match std::fs::read_to_string(path) {
            Ok(content) => content.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(e) => {
                tracing::warn!("Failed to read custom wordlist '{}': {}. Falling back to built-in.", path, e);
                SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect()
            }
        }
    } else {
        SUBDOMAIN_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    // Enumerate subdomains concurrently
    let results: Vec<_> = stream::iter(wordlist)
        .map(|sub| {
            let fqdn = format!("{}.{}", sub, domain);
            let wildcard_ips = wildcard_ips.clone();
            let wc_baseline = wildcard_baseline.clone();
            let has_wc = has_wildcard;
            async move {
                match resolve_host(&fqdn).await {
                    Some(ip) => {
                        // If wildcard DNS and this IP is only a wildcard IP, verify via HTTP
                        if has_wc {
                            if let Some(ref wc_ips) = wildcard_ips {
                                if wc_ips.contains(&ip) {
                                    // IP matches wildcard — verify via HTTP
                                    if !verify_subdomain_http(&fqdn, wc_baseline.as_deref()).await {
                                        return None;
                                    }
                                }
                            }
                        }
                        Some(DiscoveredHost {
                            hostname: fqdn,
                            ip: Some(ip),
                            open_ports: vec![],
                            services: vec![],
                        })
                    },
                    None => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    for result in results {
        if let Some(host) = result {
            if !seen.contains(&host.hostname) {
                seen.insert(host.hostname.clone());
                hosts.push(host);
            }
        }
    }

    // Show summary
    let real = hosts.len();
    let total_resolved = if has_wildcard { format!("{} filtered", real) } else { format!("{}", real) };
    println!("  Resolved {} subdomains in {:.2}s", total_resolved, start.elapsed().as_secs_f64());

    hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let duration = start.elapsed().as_secs_f64();
    (hosts, duration)
}

async fn resolve_host(hostname: &str) -> Option<String> {
    match tokio::net::lookup_host((hostname, 80)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
        Err(_) => None,
    }
}
