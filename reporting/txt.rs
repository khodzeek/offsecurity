use crate::models::ScanResult;
use crate::utils::ScanError;

pub fn generate(results: &[ScanResult], path: &str) -> Result<(), ScanError> {
    let mut report = String::new();

    report.push_str("╔══════════════════════════════════════════════╗\n");
    report.push_str("║   OFFSECURITY — Vulnerability Scan Report    ║\n");
    report.push_str("╚══════════════════════════════════════════════╝\n\n");

    for result in results {
        report.push_str(&format!("Target: {}\n", result.target_url));
        report.push_str(&format!("Scan ID: {}\n", &result.scan_id[..8.min(result.scan_id.len())]));
        report.push_str(&format!("Duration: {:.2}s\n", result.duration_secs));
        report.push_str(&format!("Intensity: Level {}\n", result.intensity_level));
        report.push_str("\n── Statistics ──\n");
        report.push_str(&format!(
            "  Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}  Total: {}\n\n",
            result.statistics.critical,
            result.statistics.high,
            result.statistics.medium,
            result.statistics.low,
            result.statistics.info,
            result.statistics.total,
        ));

        if result.findings.is_empty() {
            report.push_str("  No findings.\n\n");
        } else {
            report.push_str("── Findings ──\n");
            for (i, finding) in result.findings.iter().enumerate() {
                report.push_str(&format!(
                    "\n{}. [{}] {}\n   Confidence: {:.0}%\n   URL: {}\n   Description: {}\n   Evidence: {}\n   Recommendation: {}\n",
                    i + 1,
                    finding.severity,
                    finding.title,
                    finding.confidence * 100.0,
                    finding.affected_url,
                    finding.description,
                    finding.evidence,
                    finding.recommendation,
                ));
            }
        }
        report.push_str("──────────────────────────────────────────────\n\n");
    }

    std::fs::write(path, &report).map_err(|e| {
        ScanError::ReportError(format!("Failed to write TXT report: {}", e))
    })?;
    Ok(())
}
