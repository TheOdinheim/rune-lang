// ═══════════════════════════════════════════════════════════════════════
// Integrity — Safety Integrity Levels (IEC 61508 SIL, DO-178C DAL,
// ISO 26262 ASIL) and cross-standard classification.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── SafetyIntegrityLevel (IEC 61508) ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyIntegrityLevel {
    Sil0 = 0,
    Sil1 = 1,
    Sil2 = 2,
    Sil3 = 3,
    Sil4 = 4,
}

impl SafetyIntegrityLevel {
    /// Target dangerous failure rate per hour (upper bound).
    /// Returns None for SIL 0 (no safety requirement).
    pub fn failure_rate_target(&self) -> Option<f64> {
        match self {
            Self::Sil0 => None,
            Self::Sil1 => Some(1e-6),
            Self::Sil2 => Some(1e-7),
            Self::Sil3 => Some(1e-8),
            Self::Sil4 => Some(1e-9),
        }
    }

    pub fn requires_independent_verification(&self) -> bool {
        matches!(self, Self::Sil3 | Self::Sil4)
    }

    /// Minimum required test coverage percentage.
    pub fn min_test_coverage(&self) -> f64 {
        match self {
            Self::Sil0 => 0.0,
            Self::Sil1 => 0.90,
            Self::Sil2 => 0.95,
            Self::Sil3 => 0.99,
            Self::Sil4 => 0.999,
        }
    }
}

impl fmt::Display for SafetyIntegrityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sil0 => write!(f, "SIL 0"),
            Self::Sil1 => write!(f, "SIL 1"),
            Self::Sil2 => write!(f, "SIL 2"),
            Self::Sil3 => write!(f, "SIL 3"),
            Self::Sil4 => write!(f, "SIL 4"),
        }
    }
}

// ── DesignAssuranceLevel (DO-178C) ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DesignAssuranceLevel {
    DalE = 0,
    DalD = 1,
    DalC = 2,
    DalB = 3,
    DalA = 4,
}

impl DesignAssuranceLevel {
    pub fn structural_coverage_required(&self) -> &'static str {
        match self {
            Self::DalE => "none",
            Self::DalD => "statement",
            Self::DalC => "decision",
            Self::DalB => "MC/DC",
            Self::DalA => "MC/DC + object code",
        }
    }

    pub fn independence_required(&self) -> bool {
        matches!(self, Self::DalA | Self::DalB)
    }
}

impl fmt::Display for DesignAssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DalE => write!(f, "DAL E"),
            Self::DalD => write!(f, "DAL D"),
            Self::DalC => write!(f, "DAL C"),
            Self::DalB => write!(f, "DAL B"),
            Self::DalA => write!(f, "DAL A"),
        }
    }
}

// ── AutomotiveSafetyLevel (ISO 26262) ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutomotiveSafetyLevel {
    QM = 0,
    AsilA = 1,
    AsilB = 2,
    AsilC = 3,
    AsilD = 4,
}

impl fmt::Display for AutomotiveSafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QM => write!(f, "QM"),
            Self::AsilA => write!(f, "ASIL A"),
            Self::AsilB => write!(f, "ASIL B"),
            Self::AsilC => write!(f, "ASIL C"),
            Self::AsilD => write!(f, "ASIL D"),
        }
    }
}

// ── SafetyClassification ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyClassification {
    pub sil: Option<SafetyIntegrityLevel>,
    pub dal: Option<DesignAssuranceLevel>,
    pub asil: Option<AutomotiveSafetyLevel>,
    pub custom_level: Option<String>,
    pub justification: String,
    pub classified_by: String,
    pub classified_at: i64,
}

impl SafetyClassification {
    pub fn new() -> Self {
        Self {
            sil: None,
            dal: None,
            asil: None,
            custom_level: None,
            justification: String::new(),
            classified_by: String::new(),
            classified_at: 0,
        }
    }

    pub fn with_sil(mut self, sil: SafetyIntegrityLevel) -> Self {
        self.sil = Some(sil);
        self
    }

    pub fn with_dal(mut self, dal: DesignAssuranceLevel) -> Self {
        self.dal = Some(dal);
        self
    }

    pub fn with_asil(mut self, asil: AutomotiveSafetyLevel) -> Self {
        self.asil = Some(asil);
        self
    }

    pub fn with_justification(mut self, justification: impl Into<String>) -> Self {
        self.justification = justification.into();
        self
    }

    pub fn with_classified_by(mut self, by: impl Into<String>, at: i64) -> Self {
        self.classified_by = by.into();
        self.classified_at = at;
        self
    }

    /// Returns the name of the most restrictive level across all standards.
    pub fn highest_level_name(&self) -> String {
        let mut parts = Vec::new();
        if let Some(sil) = &self.sil {
            parts.push(sil.to_string());
        }
        if let Some(dal) = &self.dal {
            parts.push(dal.to_string());
        }
        if let Some(asil) = &self.asil {
            parts.push(asil.to_string());
        }
        if let Some(custom) = &self.custom_level {
            parts.push(custom.clone());
        }
        if parts.is_empty() {
            "Unclassified".into()
        } else {
            parts.join(" / ")
        }
    }

    /// True if any standard requires formal verification
    /// (SIL 4, DAL A, or ASIL D).
    pub fn requires_formal_verification(&self) -> bool {
        self.sil == Some(SafetyIntegrityLevel::Sil4)
            || self.dal == Some(DesignAssuranceLevel::DalA)
            || self.asil == Some(AutomotiveSafetyLevel::AsilD)
    }
}

impl Default for SafetyClassification {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sil_ordering() {
        assert!(SafetyIntegrityLevel::Sil0 < SafetyIntegrityLevel::Sil1);
        assert!(SafetyIntegrityLevel::Sil1 < SafetyIntegrityLevel::Sil2);
        assert!(SafetyIntegrityLevel::Sil2 < SafetyIntegrityLevel::Sil3);
        assert!(SafetyIntegrityLevel::Sil3 < SafetyIntegrityLevel::Sil4);
    }

    #[test]
    fn test_sil_failure_rate() {
        assert!(SafetyIntegrityLevel::Sil0.failure_rate_target().is_none());
        assert!((SafetyIntegrityLevel::Sil1.failure_rate_target().unwrap() - 1e-6).abs() < 1e-12);
        assert!((SafetyIntegrityLevel::Sil4.failure_rate_target().unwrap() - 1e-9).abs() < 1e-15);
    }

    #[test]
    fn test_sil_independent_verification() {
        assert!(!SafetyIntegrityLevel::Sil0.requires_independent_verification());
        assert!(!SafetyIntegrityLevel::Sil1.requires_independent_verification());
        assert!(!SafetyIntegrityLevel::Sil2.requires_independent_verification());
        assert!(SafetyIntegrityLevel::Sil3.requires_independent_verification());
        assert!(SafetyIntegrityLevel::Sil4.requires_independent_verification());
    }

    #[test]
    fn test_sil_test_coverage() {
        assert!((SafetyIntegrityLevel::Sil0.min_test_coverage() - 0.0).abs() < f64::EPSILON);
        assert!((SafetyIntegrityLevel::Sil1.min_test_coverage() - 0.90).abs() < f64::EPSILON);
        assert!((SafetyIntegrityLevel::Sil2.min_test_coverage() - 0.95).abs() < f64::EPSILON);
        assert!((SafetyIntegrityLevel::Sil3.min_test_coverage() - 0.99).abs() < f64::EPSILON);
        assert!((SafetyIntegrityLevel::Sil4.min_test_coverage() - 0.999).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dal_ordering() {
        assert!(DesignAssuranceLevel::DalE < DesignAssuranceLevel::DalD);
        assert!(DesignAssuranceLevel::DalD < DesignAssuranceLevel::DalC);
        assert!(DesignAssuranceLevel::DalC < DesignAssuranceLevel::DalB);
        assert!(DesignAssuranceLevel::DalB < DesignAssuranceLevel::DalA);
    }

    #[test]
    fn test_dal_structural_coverage() {
        assert_eq!(DesignAssuranceLevel::DalE.structural_coverage_required(), "none");
        assert_eq!(DesignAssuranceLevel::DalD.structural_coverage_required(), "statement");
        assert_eq!(DesignAssuranceLevel::DalC.structural_coverage_required(), "decision");
        assert_eq!(DesignAssuranceLevel::DalB.structural_coverage_required(), "MC/DC");
        assert_eq!(DesignAssuranceLevel::DalA.structural_coverage_required(), "MC/DC + object code");
    }

    #[test]
    fn test_dal_independence() {
        assert!(!DesignAssuranceLevel::DalE.independence_required());
        assert!(!DesignAssuranceLevel::DalC.independence_required());
        assert!(DesignAssuranceLevel::DalB.independence_required());
        assert!(DesignAssuranceLevel::DalA.independence_required());
    }

    #[test]
    fn test_asil_ordering() {
        assert!(AutomotiveSafetyLevel::QM < AutomotiveSafetyLevel::AsilA);
        assert!(AutomotiveSafetyLevel::AsilA < AutomotiveSafetyLevel::AsilB);
        assert!(AutomotiveSafetyLevel::AsilB < AutomotiveSafetyLevel::AsilC);
        assert!(AutomotiveSafetyLevel::AsilC < AutomotiveSafetyLevel::AsilD);
    }

    #[test]
    fn test_classification_with_sil_and_dal() {
        let c = SafetyClassification::new()
            .with_sil(SafetyIntegrityLevel::Sil3)
            .with_dal(DesignAssuranceLevel::DalB)
            .with_justification("avionics subsystem")
            .with_classified_by("engineer", 1000);
        assert_eq!(c.sil, Some(SafetyIntegrityLevel::Sil3));
        assert_eq!(c.dal, Some(DesignAssuranceLevel::DalB));
        assert_eq!(c.classified_by, "engineer");
    }

    #[test]
    fn test_classification_requires_formal_verification() {
        assert!(SafetyClassification::new()
            .with_sil(SafetyIntegrityLevel::Sil4)
            .requires_formal_verification());
        assert!(SafetyClassification::new()
            .with_dal(DesignAssuranceLevel::DalA)
            .requires_formal_verification());
        assert!(SafetyClassification::new()
            .with_asil(AutomotiveSafetyLevel::AsilD)
            .requires_formal_verification());
        assert!(!SafetyClassification::new()
            .with_sil(SafetyIntegrityLevel::Sil2)
            .requires_formal_verification());
    }

    #[test]
    fn test_classification_highest_level_name() {
        let c = SafetyClassification::new()
            .with_sil(SafetyIntegrityLevel::Sil3)
            .with_dal(DesignAssuranceLevel::DalB);
        assert_eq!(c.highest_level_name(), "SIL 3 / DAL B");

        let empty = SafetyClassification::new();
        assert_eq!(empty.highest_level_name(), "Unclassified");
    }
}
