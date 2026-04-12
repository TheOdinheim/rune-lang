// ═══════════════════════════════════════════════════════════════════════
// Supply Chain — dependency tracking and build reproducibility.
//
// SupplyChain tracks dependencies with hashes, vulnerability status,
// direct/transitive relationships, and a lockable build hash.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ProvenanceError;

// ── DependencyId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencyId(pub String);

impl DependencyId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for DependencyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── DependencySource ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencySource {
    CratesIo { name: String, version: String },
    PyPI { name: String, version: String },
    Npm { name: String, version: String },
    Git { url: String, commit: String },
    LocalPath(String),
    ModelRegistry { registry: String, id: String },
    Custom(String),
}

impl fmt::Display for DependencySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CratesIo { name, version } => write!(f, "crates.io:{name}@{version}"),
            Self::PyPI { name, version } => write!(f, "pypi:{name}@{version}"),
            Self::Npm { name, version } => write!(f, "npm:{name}@{version}"),
            Self::Git { url, commit } => write!(f, "git:{url}@{}", &commit[..8.min(commit.len())]),
            Self::LocalPath(p) => write!(f, "local:{p}"),
            Self::ModelRegistry { registry, id } => write!(f, "model:{registry}/{id}"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

impl DependencySource {
    pub fn source_type(&self) -> &str {
        match self {
            Self::CratesIo { .. } => "crates.io",
            Self::PyPI { .. } => "pypi",
            Self::Npm { .. } => "npm",
            Self::Git { .. } => "git",
            Self::LocalPath(_) => "local",
            Self::ModelRegistry { .. } => "model-registry",
            Self::Custom(_) => "custom",
        }
    }
}

// ── VulnerabilityStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilityStatus {
    Clean,
    Advisory { count: u32, max_severity: String },
    Vulnerable { cve_ids: Vec<String> },
    Unknown,
}

impl fmt::Display for VulnerabilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Advisory { count, max_severity } => {
                write!(f, "{count} advisories (max: {max_severity})")
            }
            Self::Vulnerable { cve_ids } => write!(f, "vulnerable: {}", cve_ids.join(", ")),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ── Dependency ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Dependency {
    pub id: DependencyId,
    pub name: String,
    pub version: String,
    pub source: DependencySource,
    pub content_hash: String,
    pub license: Option<String>,
    pub verified: bool,
    pub verified_at: Option<i64>,
    pub vulnerability_status: VulnerabilityStatus,
    pub transitive: bool,
    pub parent_id: Option<DependencyId>,
}

impl Dependency {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        source: DependencySource,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            id: DependencyId::new(id),
            name: name.into(),
            version: version.into(),
            source,
            content_hash: content_hash.into(),
            license: None,
            verified: false,
            verified_at: None,
            vulnerability_status: VulnerabilityStatus::Unknown,
            transitive: false,
            parent_id: None,
        }
    }

    pub fn transitive(mut self, parent: DependencyId) -> Self {
        self.transitive = true;
        self.parent_id = Some(parent);
        self
    }

    pub fn with_license(mut self, l: impl Into<String>) -> Self {
        self.license = Some(l.into());
        self
    }

    pub fn with_vulnerability(mut self, status: VulnerabilityStatus) -> Self {
        self.vulnerability_status = status;
        self
    }
}

// ── SupplyChain ───────────────────────────────────────────────────────

#[derive(Default)]
pub struct SupplyChain {
    pub dependencies: HashMap<DependencyId, Dependency>,
    pub build_hash: Option<String>,
    pub locked_at: Option<i64>,
}

impl SupplyChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_dependency(&mut self, dep: Dependency) -> Result<(), ProvenanceError> {
        if self.dependencies.contains_key(&dep.id) {
            return Err(ProvenanceError::DependencyAlreadyExists(dep.id.0.clone()));
        }
        self.dependencies.insert(dep.id.clone(), dep);
        Ok(())
    }

    pub fn get(&self, id: &DependencyId) -> Option<&Dependency> {
        self.dependencies.get(id)
    }

    pub fn verify_dependency(
        &mut self,
        id: &DependencyId,
        content_hash: &str,
        now: i64,
    ) -> Result<bool, ProvenanceError> {
        let dep = self
            .dependencies
            .get_mut(id)
            .ok_or_else(|| ProvenanceError::DependencyNotFound(id.0.clone()))?;
        let matches = dep.content_hash == content_hash;
        dep.verified = matches;
        dep.verified_at = Some(now);
        Ok(matches)
    }

    pub fn unverified(&self) -> Vec<&Dependency> {
        self.dependencies.values().filter(|d| !d.verified).collect()
    }

    pub fn vulnerable(&self) -> Vec<&Dependency> {
        self.dependencies
            .values()
            .filter(|d| matches!(d.vulnerability_status, VulnerabilityStatus::Vulnerable { .. }))
            .collect()
    }

    pub fn direct_dependencies(&self) -> Vec<&Dependency> {
        self.dependencies.values().filter(|d| !d.transitive).collect()
    }

    pub fn transitive_dependencies(&self) -> Vec<&Dependency> {
        self.dependencies.values().filter(|d| d.transitive).collect()
    }

    pub fn by_source_type(&self, source_type: &str) -> Vec<&Dependency> {
        self.dependencies
            .values()
            .filter(|d| d.source.source_type() == source_type)
            .collect()
    }

    /// BFS from a dependency through its transitive children.
    pub fn dependency_tree(&self, id: &DependencyId) -> Vec<&Dependency> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        if let Some(dep) = self.dependencies.get(id) {
            visited.insert(id.clone());
            result.push(dep);
            queue.push_back(id.clone());
        }
        while let Some(current) = queue.pop_front() {
            for dep in self.dependencies.values() {
                if dep.parent_id.as_ref() == Some(&current) && visited.insert(dep.id.clone()) {
                    result.push(dep);
                    queue.push_back(dep.id.clone());
                }
            }
        }
        result
    }

    /// SHA3-256 of all dependency hashes sorted alphabetically by id.
    pub fn compute_build_hash(&self) -> String {
        use rune_lang::stdlib::crypto::hash::sha3_256_hex;
        let mut entries: Vec<_> = self
            .dependencies
            .iter()
            .map(|(id, dep)| format!("{}:{}", id.0, dep.content_hash))
            .collect();
        entries.sort();
        sha3_256_hex(entries.join("|").as_bytes())
    }

    pub fn lock(&mut self, now: i64) {
        self.build_hash = Some(self.compute_build_hash());
        self.locked_at = Some(now);
    }

    pub fn verify_lock(&self) -> bool {
        match &self.build_hash {
            Some(stored) => self.compute_build_hash() == *stored,
            None => false,
        }
    }

    pub fn count(&self) -> usize {
        self.dependencies.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_dep(id: &str, name: &str, version: &str) -> Dependency {
        Dependency::new(
            id,
            name,
            version,
            DependencySource::CratesIo {
                name: name.into(),
                version: version.into(),
            },
            format!("hash-{id}"),
        )
    }

    #[test]
    fn test_add_and_get() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("serde", "serde", "1.0")).unwrap();
        assert!(sc.get(&DependencyId::new("serde")).is_some());
        assert_eq!(sc.count(), 1);
    }

    #[test]
    fn test_duplicate_dependency_fails() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        let err = sc.add_dependency(crate_dep("a", "a", "2")).unwrap_err();
        assert!(matches!(err, ProvenanceError::DependencyAlreadyExists(_)));
    }

    #[test]
    fn test_verify_dependency_match() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        let m = sc
            .verify_dependency(&DependencyId::new("a"), "hash-a", 1000)
            .unwrap();
        assert!(m);
        assert!(sc.get(&DependencyId::new("a")).unwrap().verified);
    }

    #[test]
    fn test_verify_dependency_mismatch() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        let m = sc
            .verify_dependency(&DependencyId::new("a"), "wrong", 1000)
            .unwrap();
        assert!(!m);
    }

    #[test]
    fn test_unverified() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.add_dependency(crate_dep("b", "b", "1")).unwrap();
        sc.verify_dependency(&DependencyId::new("a"), "hash-a", 1).unwrap();
        assert_eq!(sc.unverified().len(), 1);
    }

    #[test]
    fn test_vulnerable() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(
            crate_dep("a", "a", "1").with_vulnerability(VulnerabilityStatus::Vulnerable {
                cve_ids: vec!["CVE-2024-0001".into()],
            }),
        )
        .unwrap();
        sc.add_dependency(crate_dep("b", "b", "1")).unwrap();
        assert_eq!(sc.vulnerable().len(), 1);
    }

    #[test]
    fn test_direct_vs_transitive() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.add_dependency(
            crate_dep("b", "b", "1").transitive(DependencyId::new("a")),
        )
        .unwrap();
        assert_eq!(sc.direct_dependencies().len(), 1);
        assert_eq!(sc.transitive_dependencies().len(), 1);
    }

    #[test]
    fn test_dependency_tree() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.add_dependency(
            crate_dep("b", "b", "1").transitive(DependencyId::new("a")),
        )
        .unwrap();
        sc.add_dependency(
            crate_dep("c", "c", "1").transitive(DependencyId::new("b")),
        )
        .unwrap();
        let tree = sc.dependency_tree(&DependencyId::new("a"));
        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_compute_build_hash_deterministic() {
        let mut sc1 = SupplyChain::new();
        sc1.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc1.add_dependency(crate_dep("b", "b", "1")).unwrap();
        let mut sc2 = SupplyChain::new();
        sc2.add_dependency(crate_dep("b", "b", "1")).unwrap();
        sc2.add_dependency(crate_dep("a", "a", "1")).unwrap();
        assert_eq!(sc1.compute_build_hash(), sc2.compute_build_hash());
    }

    #[test]
    fn test_lock_and_verify() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.lock(1000);
        assert!(sc.verify_lock());
        assert!(sc.locked_at.is_some());
    }

    #[test]
    fn test_verify_lock_detects_changes() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.lock(1000);
        sc.add_dependency(crate_dep("b", "b", "1")).unwrap();
        assert!(!sc.verify_lock());
    }

    #[test]
    fn test_dependency_source_display() {
        assert!(DependencySource::CratesIo { name: "serde".into(), version: "1.0".into() }
            .to_string()
            .contains("serde@1.0"));
        assert!(DependencySource::PyPI { name: "torch".into(), version: "2.4".into() }
            .to_string()
            .contains("torch@2.4"));
        assert!(DependencySource::Npm { name: "react".into(), version: "19".into() }
            .to_string()
            .contains("react@19"));
        assert!(DependencySource::Git { url: "https://x".into(), commit: "abcdefgh1234".into() }
            .to_string()
            .contains("abcdefgh"));
        assert!(DependencySource::LocalPath("/a/b".into()).to_string().contains("/a/b"));
        assert!(DependencySource::Custom("x".into()).to_string().contains("custom:x"));
    }

    #[test]
    fn test_vulnerability_status_display() {
        assert_eq!(VulnerabilityStatus::Clean.to_string(), "clean");
        assert_eq!(VulnerabilityStatus::Unknown.to_string(), "unknown");
        assert!(
            VulnerabilityStatus::Advisory { count: 3, max_severity: "High".into() }
                .to_string()
                .contains("3 advisories")
        );
        assert!(
            VulnerabilityStatus::Vulnerable { cve_ids: vec!["CVE-1".into()] }
                .to_string()
                .contains("CVE-1")
        );
    }

    #[test]
    fn test_by_source_type() {
        let mut sc = SupplyChain::new();
        sc.add_dependency(crate_dep("a", "a", "1")).unwrap();
        sc.add_dependency(Dependency::new(
            "b",
            "torch",
            "2.4",
            DependencySource::PyPI { name: "torch".into(), version: "2.4".into() },
            "h",
        ))
        .unwrap();
        assert_eq!(sc.by_source_type("crates.io").len(), 1);
        assert_eq!(sc.by_source_type("pypi").len(), 1);
    }
}
