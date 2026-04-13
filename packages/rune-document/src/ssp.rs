// ═══════════════════════════════════════════════════════════════════════
// SSP — System Security Plan generation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::document::*;

// ── SystemType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemType {
    General,
    Major,
    Minor,
    Cloud,
}

impl fmt::Display for SystemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::General => f.write_str("general-support-system"),
            Self::Major => f.write_str("major-application"),
            Self::Minor => f.write_str("minor-application"),
            Self::Cloud => f.write_str("cloud-service"),
        }
    }
}

// ── ImpactLevel ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low = 0,
    Moderate = 1,
    High = 2,
}

impl fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Moderate => f.write_str("moderate"),
            Self::High => f.write_str("high"),
        }
    }
}

// ── ImplementationStatus ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImplementationStatus {
    Implemented,
    PartiallyImplemented,
    Planned,
    Alternative,
    NotApplicable,
}

impl fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented => f.write_str("implemented"),
            Self::PartiallyImplemented => f.write_str("partially-implemented"),
            Self::Planned => f.write_str("planned"),
            Self::Alternative => f.write_str("alternative"),
            Self::NotApplicable => f.write_str("not-applicable"),
        }
    }
}

// ── SecurityControlEntry ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityControlEntry {
    pub control_id: String,
    pub control_family: String,
    pub title: String,
    pub description: String,
    pub implementation_status: ImplementationStatus,
    pub implementation_description: String,
    pub responsible_party: String,
    pub evidence: Vec<String>,
}

impl SecurityControlEntry {
    pub fn new(
        control_id: impl Into<String>,
        control_family: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            control_family: control_family.into(),
            title: title.into(),
            description: String::new(),
            implementation_status: ImplementationStatus::Planned,
            implementation_description: String::new(),
            responsible_party: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn with_status(mut self, status: ImplementationStatus) -> Self {
        self.implementation_status = status;
        self
    }

    pub fn with_responsible(mut self, party: impl Into<String>) -> Self {
        self.responsible_party = party.into();
        self
    }
}

// ── SystemSecurityPlan ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemSecurityPlan {
    pub system_name: String,
    pub system_description: String,
    pub system_owner: String,
    pub authorization_boundary: String,
    pub security_controls: Vec<SecurityControlEntry>,
    pub system_type: SystemType,
    pub impact_level: ImpactLevel,
    pub operational_status: String,
    pub generated_at: i64,
}

// ── SspBuilder ──────────────────────────────────────────────────────

pub struct SspBuilder {
    system_name: String,
    system_description: String,
    owner: String,
    system_type: SystemType,
    impact_level: ImpactLevel,
    authorization_boundary: String,
    controls: Vec<SecurityControlEntry>,
}

impl SspBuilder {
    pub fn new(system_name: &str, owner: &str) -> Self {
        Self {
            system_name: system_name.into(),
            system_description: String::new(),
            owner: owner.into(),
            system_type: SystemType::General,
            impact_level: ImpactLevel::Low,
            authorization_boundary: String::new(),
            controls: Vec::new(),
        }
    }

    pub fn description(&mut self, desc: &str) -> &mut Self {
        self.system_description = desc.into();
        self
    }

    pub fn system_type(&mut self, st: SystemType) -> &mut Self {
        self.system_type = st;
        self
    }

    pub fn impact_level(&mut self, level: ImpactLevel) -> &mut Self {
        self.impact_level = level;
        self
    }

    pub fn authorization_boundary(&mut self, boundary: &str) -> &mut Self {
        self.authorization_boundary = boundary.into();
        self
    }

    pub fn add_control(&mut self, control: SecurityControlEntry) -> &mut Self {
        self.controls.push(control);
        self
    }

    pub fn implementation_rate(&self) -> f64 {
        if self.controls.is_empty() {
            return 0.0;
        }
        let implemented = self
            .controls
            .iter()
            .filter(|c| c.implementation_status == ImplementationStatus::Implemented)
            .count();
        implemented as f64 / self.controls.len() as f64
    }

    pub fn unimplemented_controls(&self) -> Vec<&SecurityControlEntry> {
        self.controls
            .iter()
            .filter(|c| c.implementation_status != ImplementationStatus::Implemented)
            .collect()
    }

    pub fn controls_by_family(&self) -> HashMap<String, Vec<&SecurityControlEntry>> {
        let mut map: HashMap<String, Vec<&SecurityControlEntry>> = HashMap::new();
        for ctrl in &self.controls {
            map.entry(ctrl.control_family.clone())
                .or_default()
                .push(ctrl);
        }
        map
    }

    pub fn build(&self, now: i64) -> Document {
        let mut doc = Document::new(
            DocumentId::new(format!("ssp-{now}")),
            format!("System Security Plan — {}", self.system_name),
            DocumentType::SystemSecurityPlan,
            ComplianceFramework::FedRamp,
            &self.owner,
            now,
        );

        // Section 1: System identification
        doc.sections.push(
            DocumentSection::new("system-id", "System Identification and Description")
                .with_content(format!(
                    "System: {}. Owner: {}. Description: {}.",
                    self.system_name, self.owner, self.system_description
                ))
                .with_field(
                    DocumentField::new("system_name", FieldType::Text, true)
                        .with_value(&self.system_name),
                )
                .with_field(
                    DocumentField::new("system_owner", FieldType::Text, true)
                        .with_value(&self.owner),
                ),
        );

        // Section 2: System categorization
        doc.sections.push(
            DocumentSection::new("categorization", "System Categorization")
                .with_content(format!(
                    "Type: {}. Impact level: {}.",
                    self.system_type, self.impact_level
                )),
        );

        // Section 3: Authorization boundary
        doc.sections.push(
            DocumentSection::new("boundary", "Authorization Boundary")
                .with_content(if self.authorization_boundary.is_empty() {
                    "Not defined.".to_string()
                } else {
                    self.authorization_boundary.clone()
                }),
        );

        // Section 4: Security controls by family
        let by_family = self.controls_by_family();
        let mut families: Vec<&String> = by_family.keys().collect();
        families.sort();
        let mut s4 = DocumentSection::new("controls", "Security Controls");
        for family in families {
            let controls = &by_family[family];
            let mut family_section = DocumentSection::new(
                format!("family-{family}"),
                family,
            );
            for ctrl in controls {
                family_section = family_section.with_subsection(
                    DocumentSection::new(&ctrl.control_id, &ctrl.title)
                        .with_content(format!(
                            "Status: {}. Responsible: {}.",
                            ctrl.implementation_status, ctrl.responsible_party
                        ))
                        .with_status(match &ctrl.implementation_status {
                            ImplementationStatus::Implemented => ComplianceStatus::Compliant,
                            ImplementationStatus::PartiallyImplemented => {
                                ComplianceStatus::PartiallyCompliant {
                                    gaps: vec!["partial implementation".into()],
                                }
                            }
                            ImplementationStatus::NotApplicable => ComplianceStatus::NotApplicable,
                            _ => ComplianceStatus::NonCompliant {
                                reason: ctrl.implementation_status.to_string(),
                            },
                        }),
                );
            }
            s4 = s4.with_subsection(family_section);
        }
        doc.sections.push(s4);

        // Section 5: Implementation summary
        doc.sections.push(
            DocumentSection::new("summary", "Implementation Status Summary")
                .with_content(format!(
                    "Total controls: {}. Implementation rate: {:.1}%.",
                    self.controls.len(),
                    self.implementation_rate() * 100.0
                )),
        );

        doc
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_builder() -> SspBuilder {
        let mut builder = SspBuilder::new("RUNE Platform", "security-team");
        builder.description("Core governance platform");
        builder.system_type(SystemType::Major);
        builder.impact_level(ImpactLevel::Moderate);
        builder.authorization_boundary("VPC boundary");
        builder.add_control(
            SecurityControlEntry::new("AC-1", "Access Control", "Access Control Policy")
                .with_status(ImplementationStatus::Implemented)
                .with_responsible("security-team"),
        );
        builder.add_control(
            SecurityControlEntry::new("AU-2", "Audit", "Audit Events")
                .with_status(ImplementationStatus::PartiallyImplemented)
                .with_responsible("ops-team"),
        );
        builder.add_control(
            SecurityControlEntry::new("SC-7", "System and Communications Protection", "Boundary Protection")
                .with_status(ImplementationStatus::Planned),
        );
        builder
    }

    #[test]
    fn test_builder_constructs_valid_plan() {
        let builder = sample_builder();
        let doc = builder.build(1000);
        assert_eq!(doc.document_type, DocumentType::SystemSecurityPlan);
        assert_eq!(doc.framework, ComplianceFramework::FedRamp);
    }

    #[test]
    fn test_build_produces_control_sections() {
        let builder = sample_builder();
        let doc = builder.build(1000);
        // system-id + categorization + boundary + controls + summary = 5
        assert_eq!(doc.sections.len(), 5);
    }

    #[test]
    fn test_impact_level_ordering() {
        assert!(ImpactLevel::Low < ImpactLevel::Moderate);
        assert!(ImpactLevel::Moderate < ImpactLevel::High);
    }

    #[test]
    fn test_implementation_rate() {
        let builder = sample_builder();
        // 1 of 3 implemented
        assert!((builder.implementation_rate() - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_unimplemented_controls() {
        let builder = sample_builder();
        assert_eq!(builder.unimplemented_controls().len(), 2);
    }

    #[test]
    fn test_controls_by_family() {
        let builder = sample_builder();
        let by_family = builder.controls_by_family();
        assert_eq!(by_family["Access Control"].len(), 1);
        assert_eq!(by_family["Audit"].len(), 1);
    }

    #[test]
    fn test_system_type_display() {
        assert_eq!(SystemType::General.to_string(), "general-support-system");
        assert_eq!(SystemType::Major.to_string(), "major-application");
        assert_eq!(SystemType::Minor.to_string(), "minor-application");
        assert_eq!(SystemType::Cloud.to_string(), "cloud-service");
    }

    #[test]
    fn test_implementation_status_display() {
        assert_eq!(ImplementationStatus::Implemented.to_string(), "implemented");
        assert_eq!(ImplementationStatus::PartiallyImplemented.to_string(), "partially-implemented");
        assert_eq!(ImplementationStatus::Planned.to_string(), "planned");
        assert_eq!(ImplementationStatus::Alternative.to_string(), "alternative");
        assert_eq!(ImplementationStatus::NotApplicable.to_string(), "not-applicable");
    }

    #[test]
    fn test_empty_controls_valid_document() {
        let builder = SspBuilder::new("Empty System", "owner");
        let doc = builder.build(1000);
        assert_eq!(doc.sections.len(), 5);
    }
}
