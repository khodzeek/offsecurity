use crate::models::{ScanResult, Severity};
use crate::utils::ScanError;

pub fn generate(results: &[ScanResult], path: &str) -> Result<(), ScanError> {
    let total_findings: usize = results.iter().map(|r| r.statistics.total).sum();
    let total_errors: usize = results.iter().map(|r| r.statistics.critical + r.statistics.high).sum();

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuite name=\"offsecurity\" tests=\"{}\" errors=\"0\" failures=\"{}\" hostname=\"\" time=\"{:.3}\">\n",
        total_findings,
        total_errors,
        results.iter().map(|r| r.duration_secs).sum::<f64>(),
    ));

    for result in results {
        for finding in &result.findings {
            let sev = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            let is_failure = matches!(finding.severity, Severity::Critical | Severity::High);

            xml.push_str(&format!(
                "  <testcase classname=\"offsecurity.{}\" name=\"{}\" time=\"0.000\">\n",
                xml_escape(&finding.check_type),
                xml_escape(&finding.title),
            ));
            if is_failure {
                xml.push_str(&format!(
                    "    <failure message=\"{}\" type=\"{}\">\n{}",
                    xml_escape(&finding.title),
                    sev,
                    xml_escape(&finding.description),
                ));
                if !finding.evidence.is_empty() {
                    xml.push_str(&format!("\nEvidence: {}", xml_escape(&finding.evidence)));
                }
                xml.push_str(&format!("\nRecommendation: {}\n    </failure>\n",
                    xml_escape(&finding.recommendation)));
            }
            xml.push_str("  </testcase>\n");
        }
    }

    xml.push_str("</testsuite>\n");

    std::fs::write(path, &xml).map_err(|e| {
        ScanError::ReportError(format!("Failed to write JUnit report: {}", e))
    })?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&apos;")
}
