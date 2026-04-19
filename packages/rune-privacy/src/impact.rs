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
// Layer 2: Privacy Impact Assessment Enhancement
// ═══════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

/// Weighted PIA score with component breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiaScore {
    pub data_sensitivity: f64,
    pub processing_risk: f64,
    pub cross_border: f64,
    pub volume: f64,
    pub overall: f64,
    pub risk_level: String,
}

/// Calculate a weighted PIA score from component values (each 0.0–1.0).
/// Weights: data_sensitivity=0.35, processing_risk=0.25, cross_border=0.20, volume=0.20
pub fn calculate_pia_score(
    data_sensitivity: f64,
    processing_risk: f64,
    cross_border: f64,
    volume: f64,
) -> PiaScore {
    let overall = data_sensitivity * 0.35
        + processing_risk * 0.25
        + cross_border * 0.20
        + volume * 0.20;
    let risk_level = if overall < 0.25 {
        "Low"
    } else if overall < 0.50 {
        "Medium"
    } else if overall < 0.75 {
        "High"
    } else {
        "Critical"
    };
    PiaScore {
        data_sensitivity,
        processing_risk,
        cross_border,
        volume,
        overall,
        risk_level: risk_level.to_string(),
    }
}

/// Priority level for PIA recommendations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A structured PIA recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiaRecommendation {
    pub category: String,
    pub priority: RecommendationPriority,
    pub description: String,
    pub regulatory_reference: String,
}

/// Generate recommendations based on PIA score.
pub fn generate_pia_recommendations(score: &PiaScore) -> Vec<PiaRecommendation> {
    let mut recs = Vec::new();
    if score.data_sensitivity >= 0.5 {
        recs.push(PiaRecommendation {
            category: "Data Protection".into(),
            priority: if score.data_sensitivity >= 0.75 {
                RecommendationPriority::Critical
            } else {
                RecommendationPriority::High
            },
            description: "Implement encryption at rest and pseudonymization for sensitive data".into(),
            regulatory_reference: "GDPR Art. 32".into(),
        });
    }
    if score.processing_risk >= 0.5 {
        recs.push(PiaRecommendation {
            category: "Processing Controls".into(),
            priority: RecommendationPriority::High,
            description: "Add purpose limitation checks and data minimization controls".into(),
            regulatory_reference: "GDPR Art. 5(1)(b),(c)".into(),
        });
    }
    if score.cross_border >= 0.5 {
        recs.push(PiaRecommendation {
            category: "Cross-Border Transfer".into(),
            priority: RecommendationPriority::High,
            description: "Ensure adequate safeguards for international data transfers (SCCs, adequacy decisions)".into(),
            regulatory_reference: "GDPR Art. 46".into(),
        });
    }
    if score.volume >= 0.5 {
        recs.push(PiaRecommendation {
            category: "Data Minimization".into(),
            priority: RecommendationPriority::Medium,
            description: "Review data collection scope; apply retention limits and aggregation".into(),
            regulatory_reference: "GDPR Art. 5(1)(e)".into(),
        });
    }
    if score.overall >= 0.75 {
        recs.push(PiaRecommendation {
            category: "DPO Consultation".into(),
            priority: RecommendationPriority::Critical,
            description: "Consult supervisory authority before processing (high-risk DPIA)".into(),
            regulatory_reference: "GDPR Art. 36".into(),
        });
    }
    recs
}

/// A regulatory requirement mapped from a PIA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryRequirement {
    pub regulation: String,
    pub article: String,
    pub description: String,
    pub applicable: bool,
}

/// Map a PIA to applicable regulatory requirements.
pub fn map_to_regulations(pia: &PrivacyImpactAssessment) -> Vec<RegulatoryRequirement> {
    let mut reqs = Vec::new();
    let has_cross_border = pia.data_flows.iter().any(|f| f.cross_border);
    let has_sensitive = pia.data_flows.iter().any(|f| {
        f.data_categories.iter().any(|c| {
            matches!(
                c,
                PiiCategory::Biometric | PiiCategory::HealthInfo | PiiCategory::GeneticData
            )
        })
    });
    let has_automated = pia.risk_items.iter().any(|r| {
        matches!(r.category, RiskCategory::AutomatedDecisionMaking)
    });

    reqs.push(RegulatoryRequirement {
        regulation: "GDPR".into(),
        article: "Art. 35".into(),
        description: "Data Protection Impact Assessment required for high-risk processing".into(),
        applicable: pia.overall_risk >= RiskRating::High,
    });
    reqs.push(RegulatoryRequirement {
        regulation: "GDPR".into(),
        article: "Art. 46".into(),
        description: "Appropriate safeguards for cross-border transfers".into(),
        applicable: has_cross_border,
    });
    reqs.push(RegulatoryRequirement {
        regulation: "GDPR".into(),
        article: "Art. 9".into(),
        description: "Special category data processing restrictions".into(),
        applicable: has_sensitive,
    });
    reqs.push(RegulatoryRequirement {
        regulation: "GDPR".into(),
        article: "Art. 22".into(),
        description: "Automated individual decision-making safeguards".into(),
        applicable: has_automated,
    });
    reqs.push(RegulatoryRequirement {
        regulation: "GDPR".into(),
        article: "Art. 32".into(),
        description: "Security of processing".into(),
        applicable: true,
    });
    reqs
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_pia_score_low() {
        let score = calculate_pia_score(0.1, 0.1, 0.1, 0.1);
        assert!(score.overall < 0.25);
        assert_eq!(score.risk_level, "Low");
    }

    #[test]
    fn test_pia_score_critical() {
        let score = calculate_pia_score(1.0, 1.0, 1.0, 1.0);
        assert!((score.overall - 1.0).abs() < 1e-9);
        assert_eq!(score.risk_level, "Critical");
    }

    #[test]
    fn test_pia_score_weights() {
        let score = calculate_pia_score(1.0, 0.0, 0.0, 0.0);
        assert!((score.overall - 0.35).abs() < 1e-9);
        let score2 = calculate_pia_score(0.0, 1.0, 0.0, 0.0);
        assert!((score2.overall - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_generate_recommendations_high_sensitivity() {
        let score = calculate_pia_score(0.8, 0.3, 0.2, 0.1);
        let recs = generate_pia_recommendations(&score);
        assert!(!recs.is_empty());
        assert!(recs.iter().any(|r| r.category == "Data Protection"));
    }

    #[test]
    fn test_generate_recommendations_critical_overall() {
        let score = calculate_pia_score(0.9, 0.9, 0.9, 0.9);
        let recs = generate_pia_recommendations(&score);
        assert!(recs.iter().any(|r| r.category == "DPO Consultation"));
    }

    #[test]
    fn test_generate_recommendations_low_score_empty() {
        let score = calculate_pia_score(0.1, 0.1, 0.1, 0.1);
        let recs = generate_pia_recommendations(&score);
        assert!(recs.is_empty());
    }

    #[test]
    fn test_map_to_regulations() {
        let mut builder = PiaBuilder::new("Test", "assessor");
        builder.add_data_flow(DataFlow {
            source: "app".into(),
            destination: "eu-warehouse".into(),
            data_categories: vec![PiiCategory::HealthInfo],
            purpose: "treatment".into(),
            legal_basis: LegalBasis::LegalObligation,
            cross_border: true,
            encrypted_in_transit: true,
        });
        builder.add_risk(test_risk("r1", RiskCategory::AutomatedDecisionMaking, RiskRating::High));
        let pia = builder.build();
        let regs = map_to_regulations(&pia);
        assert!(regs.iter().any(|r| r.article == "Art. 46" && r.applicable));
        assert!(regs.iter().any(|r| r.article == "Art. 9" && r.applicable));
        assert!(regs.iter().any(|r| r.article == "Art. 22" && r.applicable));
        assert!(regs.iter().any(|r| r.article == "Art. 35" && r.applicable));
    }

    #[test]
    fn test_recommendation_priority_ordering() {
        assert!(RecommendationPriority::Critical > RecommendationPriority::High);
        assert!(RecommendationPriority::High > RecommendationPriority::Medium);
        assert!(RecommendationPriority::Medium > RecommendationPriority::Low);
    }
}
