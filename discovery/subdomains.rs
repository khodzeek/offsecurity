use super::DiscoveredHost;
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::time::Instant;

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
            async move {
                match resolve_host(&fqdn).await {
                    Some(ip) => Some(DiscoveredHost {
                        hostname: fqdn,
                        ip: Some(ip),
                        open_ports: vec![],
                        services: vec![],
                    }),
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

    let duration = start.elapsed().as_secs_f64();
    (hosts, duration)
}

async fn resolve_host(hostname: &str) -> Option<String> {
    match tokio::net::lookup_host((hostname, 80)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
        Err(_) => None,
    }
}
