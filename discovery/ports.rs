use super::DiscoveredHost;
use futures::stream::{self, StreamExt};
use std::time::Duration;

const QUICK_PORTS: &[u16] = &[80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379, 27017];

const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
    3389, 5432, 5900, 6379, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 27017, 50000,
];

fn get_ports(profile: &str) -> &'static [u16] {
    match profile {
        "quick" => QUICK_PORTS,
        "full" => &[], // Full would use all 65535 but that's too slow
        _ => COMMON_PORTS,
    }
}

/// Scan common ports on discovered hosts
pub async fn scan_hosts(
    hosts: &mut [DiscoveredHost],
    port_profile: &str,
    timeout_ms: u64,
    concurrency: usize,
) -> usize {
    let ports = get_ports(port_profile);
    let total_ports = ports.len();

    // Collect valid host IPs first (avoids borrow conflict with hosts slice)
    let host_targets: Vec<(usize, String)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| h.ip.as_ref().map(|ip| (i, ip.clone())))
        .collect();

    let host_count = host_targets.len();

    println!("  Port scanning {} hosts x {} ports (profile: {})...",
        host_count, total_ports, port_profile);

    let results: Vec<(usize, Vec<Option<(u16, String)>>)> = stream::iter(host_targets)
        .map(|(i, ip)| {
            async move {
                let host_results: Vec<Option<(u16, String)>> = stream::iter(ports.iter().copied())
                    .map(|port| {
                        let ip = ip.clone();
                        async move {
                            match tokio::time::timeout(
                                Duration::from_millis(timeout_ms),
                                tokio::net::TcpStream::connect((ip.as_str(), port)),
                            ).await {
                                Ok(Ok(stream)) => {
                                    let mut service = guess_service(port);
                                    if let Ok(banner) = grab_banner(&stream, port, timeout_ms).await {
                                        if !banner.is_empty() {
                                            service = format!("{} — {}", service, banner);
                                        }
                                    }
                                    Some((port, service))
                                }
                                _ => None,
                            }
                        }
                    })
                    .buffer_unordered(concurrency)
                    .collect()
                    .await;

                (i, host_results)
            }
        })
        .buffer_unordered(concurrency.min(host_count.max(1)))
        .collect()
        .await;

    let mut total_scanned = 0;

    for (i, host_results) in results {
        for result in host_results {
            if let Some((port, service)) = result {
                hosts[i].open_ports.push(port);
                hosts[i].services.push((port, service));
                total_scanned += 1;
            }
        }
        hosts[i].open_ports.sort();
        hosts[i].services.sort_by_key(|(p, _)| *p);
    }

    total_scanned
}

fn guess_service(port: u16) -> String {
    match port {
        21 => "FTP".into(),
        22 => "SSH".into(),
        23 => "Telnet".into(),
        25 => "SMTP".into(),
        53 => "DNS".into(),
        80 => "HTTP".into(),
        110 => "POP3".into(),
        143 => "IMAP".into(),
        443 => "HTTPS".into(),
        445 => "SMB".into(),
        993 => "IMAPS".into(),
        995 => "POP3S".into(),
        1723 => "PPTP".into(),
        3306 => "MySQL".into(),
        3389 => "RDP".into(),
        5432 => "PostgreSQL".into(),
        5900 => "VNC".into(),
        6379 => "Redis".into(),
        8080 => "HTTP-Alt".into(),
        8443 => "HTTPS-Alt".into(),
        8888 => "HTTP-Alt".into(),
        9000 => "PHP-FPM/Dev".into(),
        9090 => "Prometheus/Cockpit".into(),
        9200 => "Elasticsearch".into(),
        27017 => "MongoDB".into(),
        50000 => "DB2/SAP".into(),
        _ => "Unknown".into(),
    }
}

async fn grab_banner(stream: &tokio::net::TcpStream, port: u16, timeout_ms: u64) -> Result<String, ()> {
    // Only grab banners for common text-protocol ports
    let banner_ports = [21, 22, 25, 80, 110, 143, 3306, 5432, 6379, 8080, 27017];
    if !banner_ports.contains(&port) {
        return Ok(String::new());
    }

    let mut buf = [0u8; 256];
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms.min(2000)),
        stream.readable(),
    ).await {
        Ok(Ok(())) => {
            match stream.try_read(&mut buf) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .chars()
                        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                        .take(80)
                        .collect::<String>();
                    Ok(banner)
                }
                _ => Ok(String::new()),
            }
        }
        _ => Ok(String::new()),
    }
}
