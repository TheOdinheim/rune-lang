// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — CrossFrameworkMapper trait for cross-framework requirement
// mapping, traceability, cycle detection, and gap suggestion.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};

use crate::backend::{MappingConfidence, StoredCrossFrameworkMapping};
use crate::error::FrameworkError;

// ── CrossFrameworkMapper trait ────────────────────────────────────────

pub trait CrossFrameworkMapper {
    fn register_mapping(
        &mut self,
        mapping: StoredCrossFrameworkMapping,
    ) -> Result<(), FrameworkError>;

    fn query_equivalents(
        &self,
        source_requirement_id: &str,
        min_confidence: &MappingConfidence,
    ) -> Vec<&StoredCrossFrameworkMapping>;

    fn query_traceability(
        &self,
        target_requirement_id: &str,
    ) -> Vec<&StoredCrossFrameworkMapping>;

    fn detect_mapping_cycles(&self) -> Vec<Vec<String>>;

    fn suggest_gaps(
        &self,
        framework_a_requirement_ids: &[String],
        framework_b_requirement_ids: &[String],
    ) -> Vec<String>;

    fn mapper_id(&self) -> &str;

    fn is_active(&self) -> bool;
}

// ── InMemoryCrossFrameworkMapper ─────────────────────────────────────

pub struct InMemoryCrossFrameworkMapper {
    id: String,
    mappings: Vec<StoredCrossFrameworkMapping>,
}

impl InMemoryCrossFrameworkMapper {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            mappings: Vec::new(),
        }
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

impl CrossFrameworkMapper for InMemoryCrossFrameworkMapper {
    fn register_mapping(
        &mut self,
        mapping: StoredCrossFrameworkMapping,
    ) -> Result<(), FrameworkError> {
        self.mappings.push(mapping);
        Ok(())
    }

    fn query_equivalents(
        &self,
        source_requirement_id: &str,
        min_confidence: &MappingConfidence,
    ) -> Vec<&StoredCrossFrameworkMapping> {
        self.mappings
            .iter()
            .filter(|m| {
                m.source_requirement_id == source_requirement_id
                    && &m.confidence >= min_confidence
            })
            .collect()
    }

    fn query_traceability(
        &self,
        target_requirement_id: &str,
    ) -> Vec<&StoredCrossFrameworkMapping> {
        self.mappings
            .iter()
            .filter(|m| m.target_requirement_id == target_requirement_id)
            .collect()
    }

    fn detect_mapping_cycles(&self) -> Vec<Vec<String>> {
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for m in &self.mappings {
            adjacency
                .entry(m.source_requirement_id.as_str())
                .or_default()
                .push(m.target_requirement_id.as_str());
        }

        let mut cycles = Vec::new();
        let mut visited: HashSet<&str> = HashSet::new();
        let mut in_stack: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = Vec::new();

        for &node in adjacency.keys() {
            if !visited.contains(node) {
                Self::dfs_cycles(
                    node,
                    &adjacency,
                    &mut visited,
                    &mut in_stack,
                    &mut stack,
                    &mut cycles,
                );
            }
        }
        cycles
    }

    fn suggest_gaps(
        &self,
        framework_a_requirement_ids: &[String],
        framework_b_requirement_ids: &[String],
    ) -> Vec<String> {
        let mapped_to_b: HashSet<&str> = self
            .mappings
            .iter()
            .filter(|m| framework_a_requirement_ids.contains(&m.source_requirement_id))
            .map(|m| m.target_requirement_id.as_str())
            .collect();

        framework_b_requirement_ids
            .iter()
            .filter(|id| !mapped_to_b.contains(id.as_str()))
            .cloned()
            .collect()
    }

    fn mapper_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

impl InMemoryCrossFrameworkMapper {
    fn dfs_cycles<'a>(
        node: &'a str,
        adjacency: &HashMap<&'a str, Vec<&'a str>>,
        visited: &mut HashSet<&'a str>,
        in_stack: &mut HashSet<&'a str>,
        stack: &mut Vec<&'a str>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node);
        in_stack.insert(node);
        stack.push(node);

        if let Some(neighbors) = adjacency.get(node) {
            for &neighbor in neighbors {
                if !visited.contains(neighbor) {
                    Self::dfs_cycles(neighbor, adjacency, visited, in_stack, stack, cycles);
                } else if in_stack.contains(neighbor) {
                    // found cycle
                    let cycle_start = stack.iter().position(|&n| n == neighbor).unwrap();
                    let cycle: Vec<String> =
                        stack[cycle_start..].iter().map(|s| s.to_string()).collect();
                    cycles.push(cycle);
                }
            }
        }

        stack.pop();
        in_stack.remove(node);
    }
}

// ── AuthoritativeCrossFrameworkMapper ─────────────────────────────────

pub struct AuthoritativeCrossFrameworkMapper<M: CrossFrameworkMapper> {
    inner: M,
}

impl<M: CrossFrameworkMapper> AuthoritativeCrossFrameworkMapper<M> {
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<M: CrossFrameworkMapper> CrossFrameworkMapper for AuthoritativeCrossFrameworkMapper<M> {
    fn register_mapping(
        &mut self,
        mapping: StoredCrossFrameworkMapping,
    ) -> Result<(), FrameworkError> {
        if mapping.confidence != MappingConfidence::Authoritative {
            return Err(FrameworkError::InvalidConfiguration {
                field: "confidence".to_string(),
                reason: "authoritative mapper requires Authoritative confidence".to_string(),
            });
        }
        self.inner.register_mapping(mapping)
    }

    fn query_equivalents(
        &self,
        source_requirement_id: &str,
        min_confidence: &MappingConfidence,
    ) -> Vec<&StoredCrossFrameworkMapping> {
        self.inner
            .query_equivalents(source_requirement_id, min_confidence)
    }

    fn query_traceability(
        &self,
        target_requirement_id: &str,
    ) -> Vec<&StoredCrossFrameworkMapping> {
        self.inner.query_traceability(target_requirement_id)
    }

    fn detect_mapping_cycles(&self) -> Vec<Vec<String>> {
        self.inner.detect_mapping_cycles()
    }

    fn suggest_gaps(
        &self,
        framework_a_requirement_ids: &[String],
        framework_b_requirement_ids: &[String],
    ) -> Vec<String> {
        self.inner
            .suggest_gaps(framework_a_requirement_ids, framework_b_requirement_ids)
    }

    fn mapper_id(&self) -> &str {
        self.inner.mapper_id()
    }

    fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NullCrossFrameworkMapper ─────────────────────────────────────────

pub struct NullCrossFrameworkMapper;

impl NullCrossFrameworkMapper {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullCrossFrameworkMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFrameworkMapper for NullCrossFrameworkMapper {
    fn register_mapping(&mut self, _: StoredCrossFrameworkMapping) -> Result<(), FrameworkError> {
        Ok(())
    }
    fn query_equivalents(&self, _: &str, _: &MappingConfidence) -> Vec<&StoredCrossFrameworkMapping> {
        vec![]
    }
    fn query_traceability(&self, _: &str) -> Vec<&StoredCrossFrameworkMapping> {
        vec![]
    }
    fn detect_mapping_cycles(&self) -> Vec<Vec<String>> {
        vec![]
    }
    fn suggest_gaps(&self, _: &[String], _: &[String]) -> Vec<String> {
        vec![]
    }
    fn mapper_id(&self) -> &str {
        "null"
    }
    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MappingType;

    fn test_mapping(id: &str, src: &str, tgt: &str, confidence: MappingConfidence) -> StoredCrossFrameworkMapping {
        StoredCrossFrameworkMapping {
            mapping_id: id.to_string(),
            source_requirement_id: src.to_string(),
            target_requirement_id: tgt.to_string(),
            mapping_type: MappingType::Equivalent,
            confidence,
            justification: "test".to_string(),
            mapped_by: "tester".to_string(),
            mapped_at: 1000,
        }
    }

    #[test]
    fn test_register_and_query_equivalents() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper
            .register_mapping(test_mapping("m-1", "cjis-5.6", "nist-ia-2", MappingConfidence::Authoritative))
            .unwrap();
        mapper
            .register_mapping(test_mapping("m-2", "cjis-5.6", "pci-req-8", MappingConfidence::ProvisionalMapping))
            .unwrap();
        let auth = mapper.query_equivalents("cjis-5.6", &MappingConfidence::Authoritative);
        assert_eq!(auth.len(), 1);
        let all = mapper.query_equivalents("cjis-5.6", &MappingConfidence::ProvisionalMapping);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_query_traceability() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper
            .register_mapping(test_mapping("m-1", "cjis-5.6", "nist-ia-2", MappingConfidence::Authoritative))
            .unwrap();
        mapper
            .register_mapping(test_mapping("m-2", "pci-req-8", "nist-ia-2", MappingConfidence::HighConfidence))
            .unwrap();
        let trace = mapper.query_traceability("nist-ia-2");
        assert_eq!(trace.len(), 2);
    }

    #[test]
    fn test_detect_no_cycles() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper
            .register_mapping(test_mapping("m-1", "a", "b", MappingConfidence::Authoritative))
            .unwrap();
        mapper
            .register_mapping(test_mapping("m-2", "b", "c", MappingConfidence::Authoritative))
            .unwrap();
        let cycles = mapper.detect_mapping_cycles();
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_detect_cycles() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper
            .register_mapping(test_mapping("m-1", "a", "b", MappingConfidence::Authoritative))
            .unwrap();
        mapper
            .register_mapping(test_mapping("m-2", "b", "c", MappingConfidence::Authoritative))
            .unwrap();
        mapper
            .register_mapping(test_mapping("m-3", "c", "a", MappingConfidence::Authoritative))
            .unwrap();
        let cycles = mapper.detect_mapping_cycles();
        assert!(!cycles.is_empty());
    }

    #[test]
    fn test_suggest_gaps() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper
            .register_mapping(test_mapping("m-1", "cjis-5.6", "nist-ia-2", MappingConfidence::Authoritative))
            .unwrap();
        let fw_b_reqs = vec!["nist-ia-2".to_string(), "nist-au-2".to_string(), "nist-sc-7".to_string()];
        let gaps = mapper.suggest_gaps(&["cjis-5.6".to_string()], &fw_b_reqs);
        assert_eq!(gaps.len(), 2); // nist-au-2, nist-sc-7 unmapped
        assert!(gaps.contains(&"nist-au-2".to_string()));
    }

    #[test]
    fn test_authoritative_rejects_provisional() {
        let inner = InMemoryCrossFrameworkMapper::new("test");
        let mut auth = AuthoritativeCrossFrameworkMapper::new(inner);
        assert!(auth
            .register_mapping(test_mapping("m-1", "a", "b", MappingConfidence::ProvisionalMapping))
            .is_err());
        assert!(auth
            .register_mapping(test_mapping("m-2", "a", "b", MappingConfidence::Authoritative))
            .is_ok());
    }

    #[test]
    fn test_null_mapper() {
        let mut mapper = NullCrossFrameworkMapper::new();
        assert!(!mapper.is_active());
        assert!(mapper.register_mapping(test_mapping("m-1", "a", "b", MappingConfidence::Authoritative)).is_ok());
        assert!(mapper.query_equivalents("a", &MappingConfidence::Authoritative).is_empty());
    }

    #[test]
    fn test_mapping_count() {
        let mut mapper = InMemoryCrossFrameworkMapper::new("test");
        mapper.register_mapping(test_mapping("m-1", "a", "b", MappingConfidence::Authoritative)).unwrap();
        mapper.register_mapping(test_mapping("m-2", "c", "d", MappingConfidence::Authoritative)).unwrap();
        assert_eq!(mapper.mapping_count(), 2);
    }
}
