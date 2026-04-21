// ═══════════════════════════════════════════════════════════════════════
// Policy Package Backend — Layer 3 trait boundary for pluggable
// storage of policy packages, rule sets, evaluation records, and
// package signatures.
//
// Concrete backends (database-backed, S3, OPA bundle registries)
// belong in adapter crates.  Only InMemoryPolicyPackageBackend is
// shipped as a reference implementation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::PolicyExtError;

// ── StoredPolicyPackage ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicyPackage {
    pub package_id: String,
    pub name: String,
    pub namespace: String,
    pub version: String,
    pub description: String,
    pub tags: Vec<String>,
    pub rule_set_refs: Vec<String>,
    pub dependencies: Vec<PackageDependency>,
    pub signature_ref: Option<String>,
    pub created_at: String,
    pub metadata: HashMap<String, String>,
}

// ── PackageDependency ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDependency {
    pub name: String,
    pub version_constraint: String,
    pub optional: bool,
    pub purpose: String,
}

// ── StoredRuleSet ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuleSet {
    pub rule_set_id: String,
    pub package_id: String,
    pub rule_definitions_bytes: Vec<u8>,
    pub rule_count: usize,
    pub precedence_level: usize,
    pub metadata: HashMap<String, String>,
}

// ── StoredPolicyEvaluationRecord ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicyEvaluationRecord {
    pub record_id: String,
    pub package_id: String,
    pub package_version: String,
    pub request_digest: String,
    pub decision_outcome: String,
    pub evaluated_at: String,
    pub evaluation_duration_microseconds: String,
}

// ── StoredPackageSignature ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPackageSignature {
    pub signature_id: String,
    pub package_id: String,
    pub package_version: String,
    pub signer_identity: String,
    pub signature_bytes: Vec<u8>,
    pub signed_at: String,
    pub signature_algorithm: String,
}

// ── PolicyPackageBackendInfo ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPackageBackendInfo {
    pub backend_name: String,
    pub backend_version: String,
    pub supports_signatures: bool,
    pub supports_versioning: bool,
}

impl fmt::Display for PolicyPackageBackendInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.backend_name, self.backend_version)
    }
}

// ── PolicyPackageBackend trait ────────────────────────────────────

pub trait PolicyPackageBackend {
    fn store_package(&mut self, package: StoredPolicyPackage) -> Result<(), PolicyExtError>;
    fn retrieve_package(&self, package_id: &str) -> Result<StoredPolicyPackage, PolicyExtError>;
    fn delete_package(&mut self, package_id: &str) -> Result<(), PolicyExtError>;
    fn list_packages_by_namespace(&self, namespace: &str) -> Vec<StoredPolicyPackage>;
    fn list_packages_by_tag(&self, tag: &str) -> Vec<StoredPolicyPackage>;
    fn list_package_versions(&self, name: &str, namespace: &str) -> Vec<StoredPolicyPackage>;
    fn resolve_package_version(
        &self,
        name: &str,
        namespace: &str,
        version_constraint: &str,
    ) -> Result<StoredPolicyPackage, PolicyExtError>;
    fn package_count(&self) -> usize;

    fn store_rule_set(&mut self, rule_set: StoredRuleSet) -> Result<(), PolicyExtError>;
    fn retrieve_rule_set(&self, rule_set_id: &str) -> Result<StoredRuleSet, PolicyExtError>;
    fn list_rule_sets_for_package(&self, package_id: &str) -> Vec<StoredRuleSet>;

    fn store_evaluation_record(
        &mut self,
        record: StoredPolicyEvaluationRecord,
    ) -> Result<(), PolicyExtError>;
    fn retrieve_evaluation_record(
        &self,
        record_id: &str,
    ) -> Result<StoredPolicyEvaluationRecord, PolicyExtError>;
    fn list_evaluation_records_for_package(
        &self,
        package_id: &str,
    ) -> Vec<StoredPolicyEvaluationRecord>;

    fn store_package_signature(
        &mut self,
        signature: StoredPackageSignature,
    ) -> Result<(), PolicyExtError>;
    fn retrieve_package_signature(
        &self,
        signature_id: &str,
    ) -> Result<StoredPackageSignature, PolicyExtError>;

    fn flush(&mut self);
    fn backend_info(&self) -> PolicyPackageBackendInfo;
}

// ── InMemoryPolicyPackageBackend ──────────────────────────────────

pub struct InMemoryPolicyPackageBackend {
    packages: HashMap<String, StoredPolicyPackage>,
    rule_sets: HashMap<String, StoredRuleSet>,
    evaluation_records: HashMap<String, StoredPolicyEvaluationRecord>,
    signatures: HashMap<String, StoredPackageSignature>,
}

impl Default for InMemoryPolicyPackageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryPolicyPackageBackend {
    pub fn new() -> Self {
        Self {
            packages: HashMap::new(),
            rule_sets: HashMap::new(),
            evaluation_records: HashMap::new(),
            signatures: HashMap::new(),
        }
    }
}

impl PolicyPackageBackend for InMemoryPolicyPackageBackend {
    fn store_package(&mut self, package: StoredPolicyPackage) -> Result<(), PolicyExtError> {
        self.packages.insert(package.package_id.clone(), package);
        Ok(())
    }

    fn retrieve_package(&self, package_id: &str) -> Result<StoredPolicyPackage, PolicyExtError> {
        self.packages
            .get(package_id)
            .cloned()
            .ok_or_else(|| PolicyExtError::PolicyNotFound(package_id.to_string()))
    }

    fn delete_package(&mut self, package_id: &str) -> Result<(), PolicyExtError> {
        self.packages
            .remove(package_id)
            .map(|_| ())
            .ok_or_else(|| PolicyExtError::PolicyNotFound(package_id.to_string()))
    }

    fn list_packages_by_namespace(&self, namespace: &str) -> Vec<StoredPolicyPackage> {
        self.packages
            .values()
            .filter(|p| p.namespace == namespace)
            .cloned()
            .collect()
    }

    fn list_packages_by_tag(&self, tag: &str) -> Vec<StoredPolicyPackage> {
        self.packages
            .values()
            .filter(|p| p.tags.contains(&tag.to_string()))
            .cloned()
            .collect()
    }

    fn list_package_versions(&self, name: &str, namespace: &str) -> Vec<StoredPolicyPackage> {
        self.packages
            .values()
            .filter(|p| p.name == name && p.namespace == namespace)
            .cloned()
            .collect()
    }

    fn resolve_package_version(
        &self,
        name: &str,
        namespace: &str,
        _version_constraint: &str,
    ) -> Result<StoredPolicyPackage, PolicyExtError> {
        // Simple: return latest matching name+namespace
        self.packages
            .values()
            .filter(|p| p.name == name && p.namespace == namespace)
            .max_by(|a, b| a.version.cmp(&b.version))
            .cloned()
            .ok_or_else(|| {
                PolicyExtError::PolicyNotFound(format!("{namespace}/{name}"))
            })
    }

    fn package_count(&self) -> usize {
        self.packages.len()
    }

    fn store_rule_set(&mut self, rule_set: StoredRuleSet) -> Result<(), PolicyExtError> {
        self.rule_sets.insert(rule_set.rule_set_id.clone(), rule_set);
        Ok(())
    }

    fn retrieve_rule_set(&self, rule_set_id: &str) -> Result<StoredRuleSet, PolicyExtError> {
        self.rule_sets
            .get(rule_set_id)
            .cloned()
            .ok_or_else(|| PolicyExtError::PolicyNotFound(rule_set_id.to_string()))
    }

    fn list_rule_sets_for_package(&self, package_id: &str) -> Vec<StoredRuleSet> {
        self.rule_sets
            .values()
            .filter(|r| r.package_id == package_id)
            .cloned()
            .collect()
    }

    fn store_evaluation_record(
        &mut self,
        record: StoredPolicyEvaluationRecord,
    ) -> Result<(), PolicyExtError> {
        self.evaluation_records
            .insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_evaluation_record(
        &self,
        record_id: &str,
    ) -> Result<StoredPolicyEvaluationRecord, PolicyExtError> {
        self.evaluation_records
            .get(record_id)
            .cloned()
            .ok_or_else(|| PolicyExtError::PolicyNotFound(record_id.to_string()))
    }

    fn list_evaluation_records_for_package(
        &self,
        package_id: &str,
    ) -> Vec<StoredPolicyEvaluationRecord> {
        self.evaluation_records
            .values()
            .filter(|r| r.package_id == package_id)
            .cloned()
            .collect()
    }

    fn store_package_signature(
        &mut self,
        signature: StoredPackageSignature,
    ) -> Result<(), PolicyExtError> {
        self.signatures
            .insert(signature.signature_id.clone(), signature);
        Ok(())
    }

    fn retrieve_package_signature(
        &self,
        signature_id: &str,
    ) -> Result<StoredPackageSignature, PolicyExtError> {
        self.signatures
            .get(signature_id)
            .cloned()
            .ok_or_else(|| PolicyExtError::PolicyNotFound(signature_id.to_string()))
    }

    fn flush(&mut self) {
        self.packages.clear();
        self.rule_sets.clear();
        self.evaluation_records.clear();
        self.signatures.clear();
    }

    fn backend_info(&self) -> PolicyPackageBackendInfo {
        PolicyPackageBackendInfo {
            backend_name: "in-memory".to_string(),
            backend_version: "1.0.0".to_string(),
            supports_signatures: true,
            supports_versioning: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_package(id: &str, ns: &str, name: &str, version: &str) -> StoredPolicyPackage {
        StoredPolicyPackage {
            package_id: id.to_string(),
            name: name.to_string(),
            namespace: ns.to_string(),
            version: version.to_string(),
            description: "test package".to_string(),
            tags: vec!["access".to_string()],
            rule_set_refs: vec!["rs-1".to_string()],
            dependencies: vec![PackageDependency {
                name: "base-policy".to_string(),
                version_constraint: ">=1.0.0".to_string(),
                optional: false,
                purpose: "core rules".to_string(),
            }],
            signature_ref: None,
            created_at: "2026-04-20T00:00:00Z".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_package() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        let pkg = sample_package("pkg-1", "org.rune", "access-policy", "1.0.0");
        backend.store_package(pkg).unwrap();
        let retrieved = backend.retrieve_package("pkg-1").unwrap();
        assert_eq!(retrieved.name, "access-policy");
        assert_eq!(retrieved.version, "1.0.0");
    }

    #[test]
    fn test_delete_package() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org", "p", "1.0.0"))
            .unwrap();
        backend.delete_package("pkg-1").unwrap();
        assert!(backend.retrieve_package("pkg-1").is_err());
    }

    #[test]
    fn test_list_by_namespace() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org.rune", "p1", "1.0.0"))
            .unwrap();
        backend
            .store_package(sample_package("pkg-2", "org.rune", "p2", "1.0.0"))
            .unwrap();
        backend
            .store_package(sample_package("pkg-3", "other", "p3", "1.0.0"))
            .unwrap();
        assert_eq!(backend.list_packages_by_namespace("org.rune").len(), 2);
    }

    #[test]
    fn test_list_by_tag() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org", "p1", "1.0.0"))
            .unwrap();
        assert_eq!(backend.list_packages_by_tag("access").len(), 1);
        assert_eq!(backend.list_packages_by_tag("unknown").len(), 0);
    }

    #[test]
    fn test_list_package_versions() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org", "access", "1.0.0"))
            .unwrap();
        backend
            .store_package(sample_package("pkg-2", "org", "access", "2.0.0"))
            .unwrap();
        assert_eq!(backend.list_package_versions("access", "org").len(), 2);
    }

    #[test]
    fn test_resolve_package_version() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org", "access", "1.0.0"))
            .unwrap();
        backend
            .store_package(sample_package("pkg-2", "org", "access", "2.0.0"))
            .unwrap();
        let resolved = backend
            .resolve_package_version("access", "org", ">=1.0.0")
            .unwrap();
        assert_eq!(resolved.version, "2.0.0");
    }

    #[test]
    fn test_store_and_retrieve_rule_set() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        let rs = StoredRuleSet {
            rule_set_id: "rs-1".to_string(),
            package_id: "pkg-1".to_string(),
            rule_definitions_bytes: b"allow if true".to_vec(),
            rule_count: 1,
            precedence_level: 0,
            metadata: HashMap::new(),
        };
        backend.store_rule_set(rs).unwrap();
        let retrieved = backend.retrieve_rule_set("rs-1").unwrap();
        assert_eq!(retrieved.rule_count, 1);
    }

    #[test]
    fn test_list_rule_sets_for_package() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        for i in 0..3 {
            backend
                .store_rule_set(StoredRuleSet {
                    rule_set_id: format!("rs-{i}"),
                    package_id: "pkg-1".to_string(),
                    rule_definitions_bytes: vec![],
                    rule_count: i,
                    precedence_level: i,
                    metadata: HashMap::new(),
                })
                .unwrap();
        }
        assert_eq!(backend.list_rule_sets_for_package("pkg-1").len(), 3);
    }

    #[test]
    fn test_evaluation_records() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        let rec = StoredPolicyEvaluationRecord {
            record_id: "eval-1".to_string(),
            package_id: "pkg-1".to_string(),
            package_version: "1.0.0".to_string(),
            request_digest: "abc123".to_string(),
            decision_outcome: "Permit".to_string(),
            evaluated_at: "2026-04-20T00:00:00Z".to_string(),
            evaluation_duration_microseconds: "1500".to_string(),
        };
        backend.store_evaluation_record(rec).unwrap();
        let retrieved = backend.retrieve_evaluation_record("eval-1").unwrap();
        assert_eq!(retrieved.decision_outcome, "Permit");
        assert_eq!(
            backend
                .list_evaluation_records_for_package("pkg-1")
                .len(),
            1
        );
    }

    #[test]
    fn test_package_signatures() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        let sig = StoredPackageSignature {
            signature_id: "sig-1".to_string(),
            package_id: "pkg-1".to_string(),
            package_version: "1.0.0".to_string(),
            signer_identity: "admin@org".to_string(),
            signature_bytes: vec![0xDE, 0xAD],
            signed_at: "2026-04-20T00:00:00Z".to_string(),
            signature_algorithm: "HMAC-SHA3-256".to_string(),
        };
        backend.store_package_signature(sig).unwrap();
        let retrieved = backend.retrieve_package_signature("sig-1").unwrap();
        assert_eq!(retrieved.signer_identity, "admin@org");
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryPolicyPackageBackend::new();
        backend
            .store_package(sample_package("pkg-1", "org", "p", "1.0.0"))
            .unwrap();
        assert_eq!(backend.package_count(), 1);
        backend.flush();
        assert_eq!(backend.package_count(), 0);
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryPolicyPackageBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_name, "in-memory");
        assert!(info.supports_signatures);
        assert!(!info.to_string().is_empty());
    }

    #[test]
    fn test_default() {
        let backend = InMemoryPolicyPackageBackend::default();
        assert_eq!(backend.package_count(), 0);
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let backend = InMemoryPolicyPackageBackend::new();
        assert!(backend.retrieve_package("nope").is_err());
        assert!(backend.retrieve_rule_set("nope").is_err());
        assert!(backend.retrieve_evaluation_record("nope").is_err());
        assert!(backend.retrieve_package_signature("nope").is_err());
    }
}
