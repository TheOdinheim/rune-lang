// ═══════════════════════════════════════════════════════════════════════
// SecuritySeverity — Common severity vocabulary for all security libs
//
// Every Tier 2+ security library speaks in this type: rune-detection
// raises alerts, rune-shield applies responses, rune-monitoring tracks
// metrics — all using SecuritySeverity.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum SecuritySeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Emergency = 5,
}

impl SecuritySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
            Self::Emergency => "Emergency",
        }
    }

    /// Maps a 0.0–10.0 CVSS-style score to a severity level.
    pub fn from_score(score: f64) -> Self {
        if score <= 0.0 {
            Self::Info
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else if score < 10.0 {
            Self::Critical
        } else {
            Self::Emergency
        }
    }

    /// Recommended response time in hours. None means no action needed.
    pub fn response_time_hours(&self) -> Option<u64> {
        match self {
            Self::Info => None,
            Self::Low => Some(720),    // 30 days
            Self::Medium => Some(168), // 7 days
            Self::High => Some(24),
            Self::Critical => Some(4),
            Self::Emergency => Some(0),
        }
    }

    /// True for severities that require escalation to senior responders.
    pub fn requires_escalation(&self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }

    /// Stoplight color for dashboards.
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Info => "green",
            Self::Low => "blue",
            Self::Medium => "yellow",
            Self::High => "orange",
            Self::Critical => "red",
            Self::Emergency => "black",
        }
    }
}

impl fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── SeverityChange ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SeverityChange {
    pub from: SecuritySeverity,
    pub to: SecuritySeverity,
    pub reason: String,
    pub changed_at: i64,
    pub changed_by: String,
}

impl SeverityChange {
    pub fn is_escalation(&self) -> bool {
        self.to > self.from
    }

    pub fn is_deescalation(&self) -> bool {
        self.to < self.from
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(SecuritySeverity::Info < SecuritySeverity::Low);
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
        assert!(SecuritySeverity::Critical < SecuritySeverity::Emergency);
    }

    #[test]
    fn test_from_score_ranges() {
        assert_eq!(SecuritySeverity::from_score(0.0), SecuritySeverity::Info);
        assert_eq!(SecuritySeverity::from_score(0.1), SecuritySeverity::Low);
        assert_eq!(SecuritySeverity::from_score(3.9), SecuritySeverity::Low);
        assert_eq!(SecuritySeverity::from_score(4.0), SecuritySeverity::Medium);
        assert_eq!(SecuritySeverity::from_score(6.9), SecuritySeverity::Medium);
        assert_eq!(SecuritySeverity::from_score(7.0), SecuritySeverity::High);
        assert_eq!(SecuritySeverity::from_score(8.9), SecuritySeverity::High);
        assert_eq!(SecuritySeverity::from_score(9.0), SecuritySeverity::Critical);
        assert_eq!(SecuritySeverity::from_score(9.9), SecuritySeverity::Critical);
        assert_eq!(SecuritySeverity::from_score(10.0), SecuritySeverity::Emergency);
    }

    #[test]
    fn test_response_time_hours() {
        assert_eq!(SecuritySeverity::Info.response_time_hours(), None);
        assert_eq!(SecuritySeverity::Low.response_time_hours(), Some(720));
        assert_eq!(SecuritySeverity::Medium.response_time_hours(), Some(168));
        assert_eq!(SecuritySeverity::High.response_time_hours(), Some(24));
        assert_eq!(SecuritySeverity::Critical.response_time_hours(), Some(4));
        assert_eq!(SecuritySeverity::Emergency.response_time_hours(), Some(0));
    }

    #[test]
    fn test_requires_escalation() {
        assert!(!SecuritySeverity::Info.requires_escalation());
        assert!(!SecuritySeverity::Low.requires_escalation());
        assert!(!SecuritySeverity::Medium.requires_escalation());
        assert!(!SecuritySeverity::High.requires_escalation());
        assert!(SecuritySeverity::Critical.requires_escalation());
        assert!(SecuritySeverity::Emergency.requires_escalation());
    }

    #[test]
    fn test_color_code() {
        assert_eq!(SecuritySeverity::Info.color_code(), "green");
        assert_eq!(SecuritySeverity::Low.color_code(), "blue");
        assert_eq!(SecuritySeverity::Medium.color_code(), "yellow");
        assert_eq!(SecuritySeverity::High.color_code(), "orange");
        assert_eq!(SecuritySeverity::Critical.color_code(), "red");
        assert_eq!(SecuritySeverity::Emergency.color_code(), "black");
    }

    #[test]
    fn test_display_and_as_str() {
        assert_eq!(SecuritySeverity::Critical.as_str(), "Critical");
        assert_eq!(SecuritySeverity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_severity_change_escalation() {
        let c = SeverityChange {
            from: SecuritySeverity::Low,
            to: SecuritySeverity::High,
            reason: "new evidence".into(),
            changed_at: 1000,
            changed_by: "analyst".into(),
        };
        assert!(c.is_escalation());
        assert!(!c.is_deescalation());
    }

    #[test]
    fn test_severity_change_deescalation() {
        let c = SeverityChange {
            from: SecuritySeverity::High,
            to: SecuritySeverity::Low,
            reason: "false positive".into(),
            changed_at: 1000,
            changed_by: "analyst".into(),
        };
        assert!(c.is_deescalation());
        assert!(!c.is_escalation());
    }
}
