use crate::models::ScanResult;
use crate::utils::ScanError;

pub fn generate(results: &[ScanResult], path: &str) -> Result<(), ScanError> {
    let json = serde_json::to_string_pretty(results).map_err(|e| {
        ScanError::ReportError(format!("JSON serialization failed: {}", e))
    })?;
    std::fs::write(path, json).map_err(|e| {
        ScanError::ReportError(format!("Failed to write JSON report: {}", e))
    })?;
    Ok(())
}
