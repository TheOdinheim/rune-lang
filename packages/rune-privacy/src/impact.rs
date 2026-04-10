// ═══════════════════════════════════════════════════════════════════════
// Privacy Impact Assessment (PIA / DPIA)
//
// Structured assessment of privacy risks in data flows, with mitigations
// and overall risk rating. Builder pattern for incremental assessment.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::pii::PiiCategory;
use crate::purpose::LegalBasis;

// ── RiskRating ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskRating {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl RiskRating {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl fmt::Display for RiskRating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── RiskCategory ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskCategory {
    UnauthorizedAccess,
    DataBreach,
    PurposeDrift,
    ExcessiveCollection,
    InsufficientAnonymization,
    CrossBorderTransfer,
    ThirdPartySharing,
    AutomatedDecisionMaking,
}

impl fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RiskStatus ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskStatus {
    Identified,
    Mitigated,
    Accepted,
    Transferred,
}

impl fmt::Display for RiskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── DataFlow ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub source: String,
    pub destination: String,
    pub data_categories: Vec<PiiCategory>,
    pub purpose: String,
    pub legal_basis: LegalBasis,
    pub cross_border: bool,
    pub encrypted_in_transit: bool,
}

// ── PrivacyRisk ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivacyRisk {
    pub id: String,
    pub description: String,
    pub category: RiskCategory,
    pub likelihood: RiskRating,
    pub impact: RiskRating,
    pub overall: RiskRating,
    pub status: RiskStatus,
}

// ── Mitigation ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Mitigation {
    pub risk_id: String,
    pub description: String,
    pub implemented: bool,
    pub effectiveness: RiskRating,
}

// ── PrivacyImpactAssessment ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivacyImpactAssessment {
    pub id: String,
    pub name: String,
    pub description: String,
    pub assessed_at: i64,
    pub assessor: String,
    pub data_flows: Vec<DataFlow>,
    pub risk_items: Vec<PrivacyRisk>,
    pub mitigations: Vec<Mitigation>,
    pub overall_risk: RiskRating,
    pub recommendations: Vec<String>,
}

// ── PiaBuilder ────────────────────────────────────────────────────────

pub struct PiaBuilder {
    name: String,
    assessor: String,
    description: String,
    data_flows: Vec<DataFlow>,
    risk_items: Vec<PrivacyRisk>,
    mitigations: Vec<Mitigation>,
}

impl PiaBuilder {
    pub fn new(name: &str, assessor: &str) -> Self {
        Self {
            name: name.into(),
            assessor: assessor.into(),
            description: String::new(),
            data_flows: Vec::new(),
            risk_items: Vec::new(),
            mitigations: Vec::new(),
        }
    }

    pub fn description(&mut self, d: &str) -> &mut Self {
        self.description = d.into();
        self
    }

    pub fn add_data_flow(&mut self, flow: DataFlow) -> &mut Self {
        self.data_flows.push(flow);
        self
    }

    pub fn add_risk(&mut self, risk: PrivacyRisk) -> &mut Self {
        self.risk_items.push(risk);
        self
    }

    pub fn add_mitigation(&mut self, mitigation: Mitigation) -> &mut Self {
        self.mitigations.push(mitigation);
        self
    }

    pub fn build(&self) -> PrivacyImpactAssessment {
        let overall = Self::overall_risk(&self.risk_items, &self.mitigations);
        let recommendations = Self::generate_recommendations(&self.risk_items, &self.mitigations);
        PrivacyImpactAssessment {
            id: format!("pia-{}", self.name.to_lowercase().replace(' ', "-")),
            name: self.name.clone(),
            description: self.description.clone(),
            assessed_at: 0,
            assessor: self.assessor.clone(),
            data_flows: self.data_flows.clone(),
            risk_items: self.risk_items.clone(),
            mitigations: self.mitigations.clone(),
            overall_risk: overall,
            recommendations,
        }
    }

    fn overall_risk(risks: &[PrivacyRisk], mitigations: &[Mitigation]) -> RiskRating {
        let mut highest = RiskRating::Low;
        for risk in risks {
            let mitigated = mitigations
                .iter()
                .any(|m| m.risk_id == risk.id && m.implemented);
            if mitigated {
                continue;
            }
            if risk.overall > highest {
                highest = risk.overall.clone();
            }
        }
        highest
    }

    pub fn generate_recommendations(
        risks: &[PrivacyRisk],
        mitigations: &[Mitigation],
    ) -> Vec<String> {
        let mut recs = Vec::new();
        for risk in risks {
            let mitigated = mitigations.iter().any(|m| m.risk_id == risk.id && m.implemented);
            if mitigated {
                continue;
            }
            let rec = match risk.category {
                RiskCategory::UnauthorizedAccess => {
                    "Strengthen access controls (RBAC, MFA, principle of least privilege)"
                }
                RiskCategory::DataBreach => {
                    "Implement encryption at rest and in transit; add breach detection"
                }
                RiskCategory::PurposeDrift => {
                    "Tag data with collection purpose; enforce purpose limitation checks"
                }
                RiskCategory::ExcessiveCollection => {
                    "Apply data minimization: collect only fields required by stated purpose"
                }
                RiskCategory::InsufficientAnonymization => {
                    "Apply k-anonymity / l-diversity / differential privacy where feasible"
                }
                RiskCategory::CrossBorderTransfer => {
                    "Ensure SCCs, adequacy decisions, or binding corporate rules are in place"
                }
                RiskCategory::ThirdPartySharing => {
                    "Establish data processing agreements; verify third-party compliance"
                }
                RiskCategory::AutomatedDecisionMaking => {
                    "Provide human review path; document logic per GDPR Art. 22"
                }
            };
            recs.push(format!("[{}] {}", risk.id, rec));
        }
        recs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_risk(id: &str, category: RiskCategory, overall: RiskRating) -> PrivacyRisk {
        PrivacyRisk {
            id: id.into(),
            description: "test".into(),
            category,
            likelihood: RiskRating::Medium,
            impact: RiskRating::Medium,
            overall,
            status: RiskStatus::Identified,
        }
    }

    #[test]
    fn test_builder_constructs_assessment() {
        let pia = PiaBuilder::new("Signup Flow", "privacy-officer").build();
        assert_eq!(pia.name, "Signup Flow");
        assert_eq!(pia.overall_risk, RiskRating::Low);
    }

    #[test]
    fn test_builder_calculates_highest_risk() {
        let mut builder = PiaBuilder::new("Test", "assessor");
        builder.add_risk(test_risk("r1", RiskCategory::DataBreach, RiskRating::Medium));
        builder.add_risk(test_risk("r2", RiskCategory::UnauthorizedAccess, RiskRating::Critical));
        builder.add_risk(test_risk("r3", RiskCategory::PurposeDrift, RiskRating::Low));
        let pia = builder.build();
        assert_eq!(pia.overall_risk, RiskRating::Critical);
    }

    #[test]
    fn test_mitigated_risk_excluded_from_overall() {
        let mut builder = PiaBuilder::new("Test", "assessor");
        builder.add_risk(test_risk("r1", RiskCategory::DataBreach, RiskRating::Critical));
        builder.add_mitigation(Mitigation {
            risk_id: "r1".into(),
            description: "encrypt everything".into(),
            implemented: true,
            effectiveness: RiskRating::High,
        });
        let pia = builder.build();
        assert_eq!(pia.overall_risk, RiskRating::Low);
    }

    #[test]
    fn test_generate_recommendations() {
        let risks = vec![
            test_risk("r1", RiskCategory::DataBreach, RiskRating::High),
            test_risk("r2", RiskCategory::ExcessiveCollection, RiskRating::Medium),
        ];
        let recs = PiaBuilder::generate_recommendations(&risks, &[]);
        assert_eq!(recs.len(), 2);
        assert!(recs[0].contains("encryption"));
        assert!(recs[1].contains("minimization"));
    }

    #[test]
    fn test_data_flow_construction() {
        let flow = DataFlow {
            source: "app".into(),
            destination: "warehouse".into(),
            data_categories: vec![PiiCategory::Email],
            purpose: "analytics".into(),
            legal_basis: LegalBasis::LegitimateInterest,
            cross_border: true,
            encrypted_in_transit: true,
        };
        assert!(flow.cross_border);
    }

    #[test]
    fn test_privacy_risk_construction() {
        let risk = test_risk("r1", RiskCategory::DataBreach, RiskRating::High);
        assert_eq!(risk.overall, RiskRating::High);
    }

    #[test]
    fn test_risk_rating_ordering() {
        assert!(RiskRating::Critical > RiskRating::High);
        assert!(RiskRating::High > RiskRating::Medium);
        assert!(RiskRating::Medium > RiskRating::Low);
    }

    #[test]
    fn test_risk_rating_as_str() {
        assert_eq!(RiskRating::Low.as_str(), "Low");
        assert_eq!(RiskRating::Critical.as_str(), "Critical");
    }
}
