// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Cross-framework control equivalence mapping.
//
// Maps controls between different compliance frameworks, enabling
// organisations to reuse evidence and assessments across frameworks.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── EquivalenceLevel ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EquivalenceLevel {
    None = 0,
    Partial = 1,
    Substantial = 2,
    Full = 3,
}

impl fmt::Display for EquivalenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::Partial => "Partial",
            Self::Substantial => "Substantial",
            Self::Full => "Full",
        };
        f.write_str(s)
    }
}

// ── ControlMapping ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ControlMapping {
    pub source_framework: String,
    pub source_control_id: String,
    pub target_framework: String,
    pub target_control_id: String,
    pub equivalence: EquivalenceLevel,
    pub notes: String,
}

impl ControlMapping {
    pub fn new(
        source_framework: impl Into<String>,
        source_control_id: impl Into<String>,
        target_framework: impl Into<String>,
        target_control_id: impl Into<String>,
        equivalence: EquivalenceLevel,
    ) -> Self {
        Self {
            source_framework: source_framework.into(),
            source_control_id: source_control_id.into(),
            target_framework: target_framework.into(),
            target_control_id: target_control_id.into(),
            equivalence,
            notes: String::new(),
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }
}

// ── ControlMappingStore ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ControlMappingStore {
    mappings: Vec<ControlMapping>,
}

impl ControlMappingStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_mapping(&mut self, mapping: ControlMapping) {
        self.mappings.push(mapping);
    }

    pub fn mappings_from(
        &self,
        source_framework: &str,
        source_control_id: &str,
    ) -> Vec<&ControlMapping> {
        self.mappings
            .iter()
            .filter(|m| {
                m.source_framework == source_framework
                    && m.source_control_id == source_control_id
            })
            .collect()
    }

    pub fn mappings_between(
        &self,
        source_framework: &str,
        target_framework: &str,
    ) -> Vec<&ControlMapping> {
        self.mappings
            .iter()
            .filter(|m| {
                m.source_framework == source_framework
                    && m.target_framework == target_framework
            })
            .collect()
    }

    pub fn coverage_from_framework(
        &self,
        source_framework: &str,
        target_framework: &str,
    ) -> f64 {
        let between = self.mappings_between(source_framework, target_framework);
        if between.is_empty() {
            return 0.0;
        }
        let mapped = between
            .iter()
            .filter(|m| m.equivalence != EquivalenceLevel::None)
            .count();
        mapped as f64 / between.len() as f64
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

// ── Built-in mappings ─────────────────────────────────────────────

pub fn nist_to_soc2_mappings() -> Vec<ControlMapping> {
    vec![
        ControlMapping::new("nist-ai-rmf", "GOV-1", "soc2", "CC-1", EquivalenceLevel::Partial)
            .with_notes("NIST governance maps partially to SOC 2 access controls"),
        ControlMapping::new("nist-ai-rmf", "GOV-2", "soc2", "CC-1", EquivalenceLevel::Partial)
            .with_notes("Risk management policies overlap with SOC 2 security controls"),
        ControlMapping::new("nist-ai-rmf", "MEA-1", "soc2", "CC-2", EquivalenceLevel::Substantial)
            .with_notes("Performance measurement substantially maps to system monitoring"),
        ControlMapping::new("nist-ai-rmf", "MAN-2", "soc2", "CC-2", EquivalenceLevel::Full)
            .with_notes("Continuous monitoring fully maps to SOC 2 system monitoring"),
        ControlMapping::new("nist-ai-rmf", "MAP-1", "soc2", "PI-1", EquivalenceLevel::Partial)
            .with_notes("Context mapping partially relates to processing integrity"),
    ]
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_mapping_store_add_and_retrieve() {
        let mut store = ControlMappingStore::new();
        store.add_mapping(ControlMapping::new(
            "nist-ai-rmf", "GOV-1", "soc2", "CC-1", EquivalenceLevel::Partial,
        ));
        assert_eq!(store.mapping_count(), 1);
        let found = store.mappings_from("nist-ai-rmf", "GOV-1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target_control_id, "CC-1");
    }

    #[test]
    fn test_mappings_between_filters_correctly() {
        let mut store = ControlMappingStore::new();
        for m in nist_to_soc2_mappings() {
            store.add_mapping(m);
        }
        store.add_mapping(ControlMapping::new(
            "eu-ai-act", "ART-6", "soc2", "CC-1", EquivalenceLevel::Partial,
        ));
        let nist_soc2 = store.mappings_between("nist-ai-rmf", "soc2");
        assert_eq!(nist_soc2.len(), 5);
        let eu_soc2 = store.mappings_between("eu-ai-act", "soc2");
        assert_eq!(eu_soc2.len(), 1);
    }

    #[test]
    fn test_equivalence_level_ordering() {
        assert!(EquivalenceLevel::None < EquivalenceLevel::Partial);
        assert!(EquivalenceLevel::Partial < EquivalenceLevel::Substantial);
        assert!(EquivalenceLevel::Substantial < EquivalenceLevel::Full);
    }

    #[test]
    fn test_coverage_from_framework() {
        let mut store = ControlMappingStore::new();
        for m in nist_to_soc2_mappings() {
            store.add_mapping(m);
        }
        // All 5 built-in mappings have equivalence != None
        let coverage = store.coverage_from_framework("nist-ai-rmf", "soc2");
        assert!((coverage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_with_none_equivalence() {
        let mut store = ControlMappingStore::new();
        store.add_mapping(ControlMapping::new(
            "fw-a", "C-1", "fw-b", "C-1", EquivalenceLevel::Full,
        ));
        store.add_mapping(ControlMapping::new(
            "fw-a", "C-2", "fw-b", "C-2", EquivalenceLevel::None,
        ));
        let coverage = store.coverage_from_framework("fw-a", "fw-b");
        assert!((coverage - 0.5).abs() < f64::EPSILON);
    }
}
