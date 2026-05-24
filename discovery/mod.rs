pub mod subdomains;
pub mod ports;

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub hostname: String,
    pub ip: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<(u16, String)>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DiscoveryResult {
    pub domain: String,
    pub subdomains: Vec<DiscoveredHost>,
    pub duration_secs: f64,
    pub total_resolved: usize,
    pub total_ports_scanned: usize,
}
