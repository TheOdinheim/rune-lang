// ═══════════════════════════════════════════════════════════════════════
// Control Framework Mapper — cross-framework security control mapping.
//
// Security controls are defined in multiple overlapping frameworks.
// This module defines how cross-framework mappings are expressed and
// queried. MappingConfidence is a five-level enum because cross-
// framework mappings are rarely exact.
//
// No automatic inference — mappings are pre-computed and loaded at
// construction time.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::SecurityError;

// ── MappingConfidence ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MappingConfidence {
    Exact,
    Substantial,
    Partial,
    Related,
    Disputed,
}

impl fmt::Display for MappingConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ControlEquivalence ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEquivalence {
    pub source_framework: String,
    pub source_control_id: String,
    pub target_framework: String,
    pub target_control_id: String,
    pub confidence: MappingConfidence,
    pub rationale: String,
}

// ── ControlFrameworkMapper trait ───────────────────────────────────

pub trait ControlFrameworkMapper {
    fn map_control(
        &self,
        source_framework: &str,
        control_identifier: &str,
    ) -> Result<Vec<ControlEquivalence>, SecurityError>;

    fn list_supported_frameworks(&self) -> Vec<String>;

    fn frameworks_mapping_to(&self, target_framework: &str) -> Vec<String>;

    fn confidence_of_mapping(
        &self,
        source_framework: &str,
        source_control_id: &str,
        target_framework: &str,
    ) -> Result<MappingConfidence, SecurityError>;

    fn mapper_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryControlFrameworkMapper ────────────────────────────────

pub struct InMemoryControlFrameworkMapper {
    id: String,
    mappings: Vec<ControlEquivalence>,
}

impl InMemoryControlFrameworkMapper {
    pub fn new(id: &str, mappings: Vec<ControlEquivalence>) -> Self {
        Self {
            id: id.to_string(),
            mappings,
        }
    }
}

impl ControlFrameworkMapper for InMemoryControlFrameworkMapper {
    fn map_control(
        &self,
        source_framework: &str,
        control_identifier: &str,
    ) -> Result<Vec<ControlEquivalence>, SecurityError> {
        Ok(self.mappings.iter()
            .filter(|m| m.source_framework == source_framework && m.source_control_id == control_identifier)
            .cloned()
            .collect())
    }

    fn list_supported_frameworks(&self) -> Vec<String> {
        let mut frameworks: Vec<String> = self.mappings.iter()
            .flat_map(|m| [m.source_framework.clone(), m.target_framework.clone()])
            .collect();
        frameworks.sort();
        frameworks.dedup();
        frameworks
    }

    fn frameworks_mapping_to(&self, target_framework: &str) -> Vec<String> {
        let mut sources: Vec<String> = self.mappings.iter()
            .filter(|m| m.target_framework == target_framework)
            .map(|m| m.source_framework.clone())
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }

    fn confidence_of_mapping(
        &self,
        source_framework: &str,
        source_control_id: &str,
        target_framework: &str,
    ) -> Result<MappingConfidence, SecurityError> {
        self.mappings.iter()
            .find(|m| {
                m.source_framework == source_framework
                    && m.source_control_id == source_control_id
                    && m.target_framework == target_framework
            })
            .map(|m| m.confidence)
            .ok_or_else(|| SecurityError::InvalidOperation(
                format!("no mapping from {source_framework}/{source_control_id} to {target_framework}")
            ))
    }

    fn mapper_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── TableLookupControlFrameworkMapper ─────────────────────────────

pub struct TableLookupControlFrameworkMapper {
    id: String,
    table: HashMap<(String, String), Vec<ControlEquivalence>>,
}

impl TableLookupControlFrameworkMapper {
    pub fn new(id: &str, mappings: Vec<ControlEquivalence>) -> Self {
        let mut table: HashMap<(String, String), Vec<ControlEquivalence>> = HashMap::new();
        for m in mappings {
            table.entry((m.source_framework.clone(), m.source_control_id.clone()))
                .or_default()
                .push(m);
        }
        Self {
            id: id.to_string(),
            table,
        }
    }
}

impl ControlFrameworkMapper for TableLookupControlFrameworkMapper {
    fn map_control(
        &self,
        source_framework: &str,
        control_identifier: &str,
    ) -> Result<Vec<ControlEquivalence>, SecurityError> {
        Ok(self.table
            .get(&(source_framework.to_string(), control_identifier.to_string()))
            .cloned()
            .unwrap_or_default())
    }

    fn list_supported_frameworks(&self) -> Vec<String> {
        let mut frameworks: Vec<String> = self.table.iter()
            .flat_map(|((src, _), equivs)| {
                let mut fws = vec![src.clone()];
                fws.extend(equivs.iter().map(|e| e.target_framework.clone()));
                fws
            })
            .collect();
        frameworks.sort();
        frameworks.dedup();
        frameworks
    }

    fn frameworks_mapping_to(&self, target_framework: &str) -> Vec<String> {
        let mut sources: Vec<String> = self.table.iter()
            .filter(|(_, equivs)| equivs.iter().any(|e| e.target_framework == target_framework))
            .map(|((src, _), _)| src.clone())
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }

    fn confidence_of_mapping(
        &self,
        source_framework: &str,
        source_control_id: &str,
        target_framework: &str,
    ) -> Result<MappingConfidence, SecurityError> {
        self.table
            .get(&(source_framework.to_string(), source_control_id.to_string()))
            .and_then(|equivs| equivs.iter().find(|e| e.target_framework == target_framework))
            .map(|e| e.confidence)
            .ok_or_else(|| SecurityError::InvalidOperation(
                format!("no mapping from {source_framework}/{source_control_id} to {target_framework}")
            ))
    }

    fn mapper_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_mappings() -> Vec<ControlEquivalence> {
        vec![
            ControlEquivalence {
                source_framework: "NIST-CSF".to_string(),
                source_control_id: "ID.AM-1".to_string(),
                target_framework: "CIS".to_string(),
                target_control_id: "CIS-1.1".to_string(),
                confidence: MappingConfidence::Exact,
                rationale: "Direct asset inventory mapping".to_string(),
            },
            ControlEquivalence {
                source_framework: "NIST-CSF".to_string(),
                source_control_id: "ID.AM-1".to_string(),
                target_framework: "ISO-27001".to_string(),
                target_control_id: "A.8.1".to_string(),
                confidence: MappingConfidence::Substantial,
                rationale: "Asset management scope overlap".to_string(),
            },
            ControlEquivalence {
                source_framework: "CIS".to_string(),
                source_control_id: "CIS-1.1".to_string(),
                target_framework: "NIST-800-53".to_string(),
                target_control_id: "CM-8".to_string(),
                confidence: MappingConfidence::Partial,
                rationale: "Partial overlap in inventory scope".to_string(),
            },
        ]
    }

    #[test]
    fn test_in_memory_map_control() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        let equivs = mapper.map_control("NIST-CSF", "ID.AM-1").unwrap();
        assert_eq!(equivs.len(), 2);
    }

    #[test]
    fn test_in_memory_map_control_no_match() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        let equivs = mapper.map_control("NIST-CSF", "PR.AC-1").unwrap();
        assert!(equivs.is_empty());
    }

    #[test]
    fn test_list_supported_frameworks() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        let frameworks = mapper.list_supported_frameworks();
        assert!(frameworks.contains(&"NIST-CSF".to_string()));
        assert!(frameworks.contains(&"CIS".to_string()));
        assert!(frameworks.contains(&"ISO-27001".to_string()));
    }

    #[test]
    fn test_frameworks_mapping_to() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        let sources = mapper.frameworks_mapping_to("CIS");
        assert!(sources.contains(&"NIST-CSF".to_string()));
    }

    #[test]
    fn test_confidence_of_mapping() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        let conf = mapper.confidence_of_mapping("NIST-CSF", "ID.AM-1", "CIS").unwrap();
        assert_eq!(conf, MappingConfidence::Exact);
    }

    #[test]
    fn test_confidence_no_match() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", sample_mappings());
        assert!(mapper.confidence_of_mapping("NIST-CSF", "ID.AM-1", "PCI-DSS").is_err());
    }

    #[test]
    fn test_table_lookup_mapper() {
        let mapper = TableLookupControlFrameworkMapper::new("t1", sample_mappings());
        let equivs = mapper.map_control("CIS", "CIS-1.1").unwrap();
        assert_eq!(equivs.len(), 1);
        assert_eq!(equivs[0].target_control_id, "CM-8");
    }

    #[test]
    fn test_table_lookup_supported_frameworks() {
        let mapper = TableLookupControlFrameworkMapper::new("t1", sample_mappings());
        let frameworks = mapper.list_supported_frameworks();
        assert!(frameworks.len() >= 3);
    }

    #[test]
    fn test_mapping_confidence_display() {
        assert_eq!(MappingConfidence::Exact.to_string(), "Exact");
        assert_eq!(MappingConfidence::Disputed.to_string(), "Disputed");
    }

    #[test]
    fn test_mapper_metadata() {
        let mapper = InMemoryControlFrameworkMapper::new("m1", vec![]);
        assert_eq!(mapper.mapper_id(), "m1");
        assert!(mapper.is_active());
    }
}
