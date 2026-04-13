// ═══════════════════════════════════════════════════════════════════════
// Hazard — Systematic hazard identification and risk analysis.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::constraint::{ConstraintId, ConstraintSeverity};
use crate::error::SafetyError;
use crate::failsafe::FailsafeId;

// ── HazardId ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HazardId(pub String);

impl HazardId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for HazardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── HazardType ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HazardType {
    SystemFailure,
    DesignFlaw,
    OperationalError,
    EnvironmentalHazard,
    SecurityThreat,
    AiSpecific,
    DataIntegrity,
    IntegrationFailure,
}

impl fmt::Display for HazardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SystemFailure => "SystemFailure",
            Self::DesignFlaw => "DesignFlaw",
            Self::OperationalError => "OperationalError",
            Self::EnvironmentalHazard => "EnvironmentalHazard",
            Self::SecurityThreat => "SecurityThreat",
            Self::AiSpecific => "AiSpecific",
            Self::DataIntegrity => "DataIntegrity",
            Self::IntegrationFailure => "IntegrationFailure",
        };
        f.write_str(s)
    }
}

// ── HazardLikelihood ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HazardLikelihood {
    Incredible = 0,
    Improbable = 1,
    Remote = 2,
    Occasional = 3,
    Probable = 4,
    Frequent = 5,
}

impl fmt::Display for HazardLikelihood {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Incredible => "Incredible",
            Self::Improbable => "Improbable",
            Self::Remote => "Remote",
            Self::Occasional => "Occasional",
            Self::Probable => "Probable",
            Self::Frequent => "Frequent",
        };
        f.write_str(s)
    }
}

// ── RiskLevel ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Negligible = 0,
    Tolerable = 1,
    Undesirable = 2,
    Intolerable = 3,
}

impl RiskLevel {
    /// Risk matrix: severity × likelihood.
    pub fn from_severity_likelihood(
        severity: ConstraintSeverity,
        likelihood: HazardLikelihood,
    ) -> Self {
        if severity >= ConstraintSeverity::Critical && likelihood >= HazardLikelihood::Occasional {
            return Self::Intolerable;
        }
        if severity >= ConstraintSeverity::Critical || likelihood >= HazardLikelihood::Probable {
            return Self::Undesirable;
        }
        if severity >= ConstraintSeverity::Warning || likelihood >= HazardLikelihood::Occasional {
            return Self::Tolerable;
        }
        Self::Negligible
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Negligible => "Negligible",
            Self::Tolerable => "Tolerable",
            Self::Undesirable => "Undesirable",
            Self::Intolerable => "Intolerable",
        };
        f.write_str(s)
    }
}

// ── MitigationType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationType {
    Elimination,
    Reduction,
    Isolation,
    DesignControl,
    ProceduralControl,
    Warning,
    PersonalProtection,
}

impl fmt::Display for MitigationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Elimination => "Elimination",
            Self::Reduction => "Reduction",
            Self::Isolation => "Isolation",
            Self::DesignControl => "DesignControl",
            Self::ProceduralControl => "ProceduralControl",
            Self::Warning => "Warning",
            Self::PersonalProtection => "PersonalProtection",
        };
        f.write_str(s)
    }
}

// ── MitigationEffectiveness ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MitigationEffectiveness {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl fmt::Display for MitigationEffectiveness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "Unknown",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        };
        f.write_str(s)
    }
}

// ── HazardMitigation ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazardMitigation {
    pub id: String,
    pub description: String,
    pub mitigation_type: MitigationType,
    pub implemented: bool,
    pub effectiveness: MitigationEffectiveness,
    pub residual_risk: Option<RiskLevel>,
    pub related_failsafe: Option<FailsafeId>,
}

// ── HazardStatus ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HazardStatus {
    Identified,
    Analyzed,
    Mitigated,
    Accepted,
    Closed,
}

impl fmt::Display for HazardStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Identified => "Identified",
            Self::Analyzed => "Analyzed",
            Self::Mitigated => "Mitigated",
            Self::Accepted => "Accepted",
            Self::Closed => "Closed",
        };
        f.write_str(s)
    }
}

// ── Hazard ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hazard {
    pub id: HazardId,
    pub name: String,
    pub description: String,
    pub hazard_type: HazardType,
    pub severity: ConstraintSeverity,
    pub likelihood: HazardLikelihood,
    pub risk_level: RiskLevel,
    pub causes: Vec<String>,
    pub consequences: Vec<String>,
    pub affected_components: Vec<String>,
    pub mitigations: Vec<HazardMitigation>,
    pub related_constraints: Vec<ConstraintId>,
    pub status: HazardStatus,
    pub identified_at: i64,
    pub identified_by: String,
}

impl Hazard {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        hazard_type: HazardType,
        severity: ConstraintSeverity,
        likelihood: HazardLikelihood,
    ) -> Self {
        let risk_level = RiskLevel::from_severity_likelihood(severity, likelihood);
        Self {
            id: HazardId::new(id),
            name: name.into(),
            description: String::new(),
            hazard_type,
            severity,
            likelihood,
            risk_level,
            causes: Vec::new(),
            consequences: Vec::new(),
            affected_components: Vec::new(),
            mitigations: Vec::new(),
            related_constraints: Vec::new(),
            status: HazardStatus::Identified,
            identified_at: 0,
            identified_by: String::new(),
        }
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.causes.push(cause.into());
        self
    }

    pub fn with_consequence(mut self, consequence: impl Into<String>) -> Self {
        self.consequences.push(consequence.into());
        self
    }

    pub fn with_mitigation(mut self, mitigation: HazardMitigation) -> Self {
        self.mitigations.push(mitigation);
        self.status = HazardStatus::Mitigated;
        self
    }

    pub fn with_status(mut self, status: HazardStatus) -> Self {
        self.status = status;
        self
    }
}

// ── HazardRegistry ────────────────────────────────────────────────────

pub struct HazardRegistry {
    hazards: HashMap<HazardId, Hazard>,
}

impl HazardRegistry {
    pub fn new() -> Self {
        Self {
            hazards: HashMap::new(),
        }
    }

    pub fn register(&mut self, hazard: Hazard) -> Result<(), SafetyError> {
        if self.hazards.contains_key(&hazard.id) {
            return Err(SafetyError::HazardAlreadyExists(hazard.id.0.clone()));
        }
        self.hazards.insert(hazard.id.clone(), hazard);
        Ok(())
    }

    pub fn get(&self, id: &HazardId) -> Option<&Hazard> {
        self.hazards.get(id)
    }

    pub fn by_type(&self, hazard_type: &HazardType) -> Vec<&Hazard> {
        self.hazards
            .values()
            .filter(|h| &h.hazard_type == hazard_type)
            .collect()
    }

    pub fn by_risk_level(&self, level: RiskLevel) -> Vec<&Hazard> {
        self.hazards
            .values()
            .filter(|h| h.risk_level == level)
            .collect()
    }

    pub fn by_status(&self, status: &HazardStatus) -> Vec<&Hazard> {
        self.hazards
            .values()
            .filter(|h| &h.status == status)
            .collect()
    }

    pub fn intolerable_hazards(&self) -> Vec<&Hazard> {
        self.hazards
            .values()
            .filter(|h| h.risk_level == RiskLevel::Intolerable)
            .collect()
    }

    pub fn unmitigated_hazards(&self) -> Vec<&Hazard> {
        self.hazards
            .values()
            .filter(|h| {
                matches!(h.status, HazardStatus::Identified | HazardStatus::Analyzed)
            })
            .collect()
    }

    pub fn risk_matrix(&self) -> Vec<(HazardId, ConstraintSeverity, HazardLikelihood, RiskLevel)> {
        self.hazards
            .values()
            .map(|h| (h.id.clone(), h.severity, h.likelihood, h.risk_level))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.hazards.len()
    }
}

impl Default for HazardRegistry {
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

    fn sample_hazard(
        id: &str,
        severity: ConstraintSeverity,
        likelihood: HazardLikelihood,
    ) -> Hazard {
        Hazard::new(id, format!("Hazard {id}"), HazardType::AiSpecific, severity, likelihood)
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Critical, HazardLikelihood::Occasional))
            .unwrap();
        assert!(reg.get(&HazardId::new("h1")).is_some());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_by_type() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Warning, HazardLikelihood::Remote))
            .unwrap();
        assert_eq!(reg.by_type(&HazardType::AiSpecific).len(), 1);
        assert_eq!(reg.by_type(&HazardType::DesignFlaw).len(), 0);
    }

    #[test]
    fn test_by_risk_level() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Critical, HazardLikelihood::Probable))
            .unwrap();
        assert_eq!(reg.by_risk_level(RiskLevel::Intolerable).len(), 1);
        assert_eq!(reg.by_risk_level(RiskLevel::Negligible).len(), 0);
    }

    #[test]
    fn test_by_status() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Warning, HazardLikelihood::Remote))
            .unwrap();
        assert_eq!(reg.by_status(&HazardStatus::Identified).len(), 1);
        assert_eq!(reg.by_status(&HazardStatus::Mitigated).len(), 0);
    }

    #[test]
    fn test_intolerable_hazards() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Critical, HazardLikelihood::Occasional))
            .unwrap();
        reg.register(sample_hazard("h2", ConstraintSeverity::Advisory, HazardLikelihood::Improbable))
            .unwrap();
        assert_eq!(reg.intolerable_hazards().len(), 1);
    }

    #[test]
    fn test_unmitigated_hazards() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Warning, HazardLikelihood::Remote))
            .unwrap();
        reg.register(
            sample_hazard("h2", ConstraintSeverity::Warning, HazardLikelihood::Remote)
                .with_mitigation(HazardMitigation {
                    id: "m1".into(),
                    description: "Fix it".into(),
                    mitigation_type: MitigationType::Reduction,
                    implemented: true,
                    effectiveness: MitigationEffectiveness::High,
                    residual_risk: Some(RiskLevel::Negligible),
                    related_failsafe: None,
                }),
        )
        .unwrap();
        assert_eq!(reg.unmitigated_hazards().len(), 1);
    }

    #[test]
    fn test_risk_matrix() {
        let mut reg = HazardRegistry::new();
        reg.register(sample_hazard("h1", ConstraintSeverity::Critical, HazardLikelihood::Probable))
            .unwrap();
        reg.register(sample_hazard("h2", ConstraintSeverity::Advisory, HazardLikelihood::Improbable))
            .unwrap();
        let matrix = reg.risk_matrix();
        assert_eq!(matrix.len(), 2);
    }

    #[test]
    fn test_risk_level_from_severity_likelihood() {
        // Catastrophic + Probable = Intolerable
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Catastrophic,
                HazardLikelihood::Probable,
            ),
            RiskLevel::Intolerable,
        );
        // Critical + Occasional = Intolerable
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Critical,
                HazardLikelihood::Occasional,
            ),
            RiskLevel::Intolerable,
        );
        // Critical + Remote = Undesirable (Critical but likelihood < Occasional)
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Critical,
                HazardLikelihood::Remote,
            ),
            RiskLevel::Undesirable,
        );
        // Warning + Probable = Undesirable (Probable triggers >= Undesirable)
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Warning,
                HazardLikelihood::Probable,
            ),
            RiskLevel::Undesirable,
        );
        // Warning + Occasional = Tolerable
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Warning,
                HazardLikelihood::Occasional,
            ),
            RiskLevel::Tolerable,
        );
        // Advisory + Improbable = Negligible
        assert_eq!(
            RiskLevel::from_severity_likelihood(
                ConstraintSeverity::Advisory,
                HazardLikelihood::Improbable,
            ),
            RiskLevel::Negligible,
        );
    }

    #[test]
    fn test_hazard_type_display() {
        let types = vec![
            HazardType::SystemFailure,
            HazardType::DesignFlaw,
            HazardType::OperationalError,
            HazardType::EnvironmentalHazard,
            HazardType::SecurityThreat,
            HazardType::AiSpecific,
            HazardType::DataIntegrity,
            HazardType::IntegrationFailure,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_hazard_likelihood_ordering() {
        assert!(HazardLikelihood::Incredible < HazardLikelihood::Improbable);
        assert!(HazardLikelihood::Improbable < HazardLikelihood::Remote);
        assert!(HazardLikelihood::Remote < HazardLikelihood::Occasional);
        assert!(HazardLikelihood::Occasional < HazardLikelihood::Probable);
        assert!(HazardLikelihood::Probable < HazardLikelihood::Frequent);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Negligible < RiskLevel::Tolerable);
        assert!(RiskLevel::Tolerable < RiskLevel::Undesirable);
        assert!(RiskLevel::Undesirable < RiskLevel::Intolerable);
    }

    #[test]
    fn test_mitigation_type_display() {
        let types = vec![
            MitigationType::Elimination,
            MitigationType::Reduction,
            MitigationType::Isolation,
            MitigationType::DesignControl,
            MitigationType::ProceduralControl,
            MitigationType::Warning,
            MitigationType::PersonalProtection,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_mitigation_effectiveness_ordering() {
        assert!(MitigationEffectiveness::Unknown < MitigationEffectiveness::Low);
        assert!(MitigationEffectiveness::Low < MitigationEffectiveness::Medium);
        assert!(MitigationEffectiveness::Medium < MitigationEffectiveness::High);
    }

    #[test]
    fn test_hazard_status_display() {
        let statuses = vec![
            HazardStatus::Identified,
            HazardStatus::Analyzed,
            HazardStatus::Mitigated,
            HazardStatus::Accepted,
            HazardStatus::Closed,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }
}
