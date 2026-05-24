use crate::models::ScanResult;
use crate::utils::ScanError;

pub fn generate(results: &[ScanResult], path: &str) -> Result<(), ScanError> {
    let mut lines = String::new();

    for result in results {
        for finding in &result.findings {
            let entry = serde_json::json!({
                "scan_id": result.scan_id,
                "target_url": result.target_url,
                "timestamp": finding.timestamp,
                "check_type": finding.check_type,
                "title": finding.title,
                "severity": finding.severity.to_string(),
                "confidence": finding.confidence,
                "description": finding.description,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "affected_url": finding.affected_url,
            });
            lines.push_str(&serde_json::to_string(&entry).unwrap_or_default());
            lines.push('\n');
        }
    }

    std::fs::write(path, &lines).map_err(|e| {
        ScanError::ReportError(format!("Failed to write ndjson report: {}", e))
    })?;
    Ok(())
}
