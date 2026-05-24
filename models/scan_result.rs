use serde::{Deserialize, Serialize};
use super::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target_url: String,
    pub scan_id: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_secs: f64,
    pub findings: Vec<Finding>,
    pub total_urls_scanned: usize,
    pub statistics: ScanStatistics,
    #[serde(default)]
    pub scan_version: String,
    #[serde(default)]
    pub intensity_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl ScanStatistics {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut stats = Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: findings.len(),
        };

        for f in findings {
            match f.severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
        }

        stats
    }
}
