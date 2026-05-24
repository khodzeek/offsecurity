use serde::{Deserialize, Serialize};
use std::fmt;
use colored::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn color(&self) -> Color {
        match self {
            Severity::Critical => Color::Red,
            Severity::High => Color::BrightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::BrightBlue,
            Severity::Info => Color::Cyan,
        }
    }

    pub fn weight(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Critical => "[CRIT]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MED ]",
            Severity::Low => "[LOW ]",
            Severity::Info => "[INFO]",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}
