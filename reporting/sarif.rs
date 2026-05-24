use crate::models::{ScanResult, Severity};
use crate::utils::ScanError;

pub fn generate(results: &[ScanResult], path: &str) -> Result<(), ScanError> {
    let mut runs = Vec::new();

    for result in results {
        let mut rules = Vec::new();
        let mut rule_indices = serde_json::Map::new();
        let mut rule_idx = 0u32;

        let mut sarif_results = Vec::new();

        for finding in &result.findings {
            let rule_id = format!("offsecurity/{}", finding.check_type);
            if !rule_indices.contains_key(&rule_id) {
                rule_indices.insert(rule_id.clone(), serde_json::Value::from(rule_idx));
                rules.push(serde_json::json!({
                    "id": rule_id,
                    "shortDescription": { "text": finding.title },
                    "fullDescription": { "text": finding.description },
                    "help": { "text": finding.recommendation },
                    "properties": {
                        "security-severity": severity_to_score(finding.severity),
                    },
                }));
                rule_idx += 1;
            }

            sarif_results.push(serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[&rule_id],
                "message": { "text": finding.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": &finding.affected_url },
                    },
                }],
                "level": severity_to_level(finding.severity),
                "properties": {
                    "evidence": finding.evidence,
                    "confidence": finding.confidence,
                },
            }));
        }

        runs.push(serde_json::json!({
            "tool": {
                "driver": {
                    "name": "offsecurity",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/khodzeek/offsecurity",
                    "rules": rules,
                },
            },
            "results": sarif_results,
        }));
    }

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    });

    let json = serde_json::to_string_pretty(&sarif).map_err(|e| {
        ScanError::ReportError(format!("SARIF serialization failed: {}", e))
    })?;
    std::fs::write(path, json).map_err(|e| {
        ScanError::ReportError(format!("Failed to write SARIF report: {}", e))
    })?;
    Ok(())
}

fn severity_to_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".into(),
        Severity::Medium => "warning".into(),
        Severity::Low => "note".into(),
        Severity::Info => "none".into(),
    }
}

fn severity_to_score(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
        Severity::Info => 0.5,
    }
}
