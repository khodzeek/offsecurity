use serde::{Deserialize, Serialize};
use super::Severity;

/// Confidence level for a finding
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Confidence {
    /// Confirmed — exact payload reflection or content match (0.95)
    Confirmed = 95,
    /// High confidence — direct evidence match (0.85)
    High = 85,
    /// Medium — error-based or pattern detection (0.70)
    Medium = 70,
    /// Low — timing-based or indirect detection (0.50)
    Low = 50,
    /// Heuristic — pattern/header only (0.30)
    Heuristic = 30,
    /// Info — informational finding (0.20)
    Info = 20,
    /// Uncertain — possible false positive (0.10)
    Uncertain = 10,
}

impl Confidence {
    pub fn value(&self) -> f64 {
        *self as u8 as f64 / 100.0
    }

    pub fn label(&self) -> &str {
        match self {
            Confidence::Confirmed => "Confirmed",
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
            Confidence::Heuristic => "Heuristic",
            Confidence::Info => "Info",
            Confidence::Uncertain => "Uncertain",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: f64,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
    pub affected_url: String,
    pub check_type: String,
    pub timestamp: String,
}

impl Finding {
    pub fn new(
        check_type: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
        evidence: impl Into<String>,
        recommendation: impl Into<String>,
        affected_url: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            severity,
            confidence: Confidence::Medium.value(),
            description: description.into(),
            evidence: evidence.into(),
            recommendation: recommendation.into(),
            affected_url: affected_url.into(),
            check_type: check_type.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence.value();
        self
    }
}
