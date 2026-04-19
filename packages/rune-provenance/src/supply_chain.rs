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
// Layer 2: Enhanced Supply Chain Verification
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

fn sha3_hex(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// A verified dependency with hash check result.
#[derive(Debug, Clone)]
pub struct VerifiedDependency {
    pub name: String,
    pub version: String,
    pub content_hash: String,
    pub signature_valid: bool,
    pub source: VerifiedDependencySource,
    pub checked_at: i64,
}

/// Source type for verified dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedDependencySource {
    Registry,
    Git { commit: String },
    Local { path: String },
    Mirror { url: String },
}

/// Verify a dependency by hashing its content and comparing to expected hash.
pub fn verify_dependency_hash(
    name: &str,
    version: &str,
    content: &[u8],
    expected_hash: &str,
) -> VerifiedDependency {
    let actual = sha3_hex(content);
    VerifiedDependency {
        name: name.to_string(),
        version: version.to_string(),
        content_hash: actual.clone(),
        signature_valid: actual == expected_hash,
        source: VerifiedDependencySource::Registry,
        checked_at: 0,
    }
}

/// Dependency graph for analyzing transitive relationships.
#[derive(Default)]
pub struct DependencyGraph {
    pub dependencies: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_dependency(&mut self, package: &str, depends_on: &str) {
        self.dependencies
            .entry(package.to_string())
            .or_default()
            .push(depends_on.to_string());
        // Ensure depends_on is also in the graph
        self.dependencies.entry(depends_on.to_string()).or_default();
    }

    pub fn transitive_dependencies(&self, package: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        if let Some(deps) = self.dependencies.get(package) {
            for d in deps {
                if visited.insert(d.clone()) {
                    queue.push_back(d.clone());
                }
            }
        }
        while let Some(current) = queue.pop_front() {
            result.push(current.clone());
            if let Some(deps) = self.dependencies.get(&current) {
                for d in deps {
                    if visited.insert(d.clone()) {
                        queue.push_back(d.clone());
                    }
                }
            }
        }
        result
    }

    pub fn has_cycle(&self) -> bool {
        let mut white: HashSet<String> = self.dependencies.keys().cloned().collect();
        let mut gray = HashSet::new();

        while let Some(start) = white.iter().next().cloned() {
            if self.dfs_cycle(&start, &mut white, &mut gray) {
                return true;
            }
        }
        false
    }

    fn dfs_cycle(
        &self,
        node: &str,
        white: &mut HashSet<String>,
        gray: &mut HashSet<String>,
    ) -> bool {
        white.remove(node);
        gray.insert(node.to_string());
        if let Some(deps) = self.dependencies.get(node) {
            for dep in deps {
                if gray.contains(dep) {
                    return true;
                }
                if white.contains(dep) && self.dfs_cycle(dep, white, gray) {
                    return true;
                }
            }
        }
        gray.remove(node);
        false
    }

    pub fn dependency_depth(&self, package: &str) -> usize {
        self.transitive_dependencies(package).len()
    }

    pub fn leaf_dependencies(&self) -> Vec<String> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn reverse_dependencies(&self, package: &str) -> Vec<String> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.contains(&package.to_string()))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Build reproducibility check result.
#[derive(Debug, Clone)]
pub struct BuildReproducibilityCheck {
    pub source_hash: String,
    pub build_config_hash: String,
    pub expected_output_hash: String,
    pub actual_output_hash: String,
    pub reproducible: bool,
    pub checked_at: i64,
}

/// Check build reproducibility by hashing all inputs/outputs.
pub fn check_reproducibility(
    source: &[u8],
    build_config: &[u8],
    expected_output: &[u8],
    actual_output: &[u8],
) -> BuildReproducibilityCheck {
    let expected_hash = sha3_hex(expected_output);
    let actual_hash = sha3_hex(actual_output);
    BuildReproducibilityCheck {
        source_hash: sha3_hex(source),
        build_config_hash: sha3_hex(build_config),
        expected_output_hash: expected_hash.clone(),
        actual_output_hash: actual_hash.clone(),
        reproducible: expected_hash == actual_hash,
        checked_at: 0,
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_verify_dependency_hash_match() {
        let content = b"package content";
        let hash = sha3_hex(content);
        let v = verify_dependency_hash("mylib", "1.0", content, &hash);
        assert!(v.signature_valid);
        assert_eq!(v.content_hash, hash);
    }

    #[test]
    fn test_verify_dependency_hash_mismatch() {
        let v = verify_dependency_hash("mylib", "1.0", b"content", "wrong_hash");
        assert!(!v.signature_valid);
    }

    #[test]
    fn test_dep_graph_transitive() {
        let mut g = DependencyGraph::new();
        g.add_dependency("app", "lib-a");
        g.add_dependency("lib-a", "lib-b");
        g.add_dependency("lib-b", "lib-c");
        let trans = g.transitive_dependencies("app");
        assert_eq!(trans.len(), 3);
        assert!(trans.contains(&"lib-c".to_string()));
    }

    #[test]
    fn test_dep_graph_has_cycle() {
        let mut g = DependencyGraph::new();
        g.add_dependency("a", "b");
        g.add_dependency("b", "a");
        assert!(g.has_cycle());
    }

    #[test]
    fn test_dep_graph_no_cycle() {
        let mut g = DependencyGraph::new();
        g.add_dependency("a", "b");
        g.add_dependency("b", "c");
        assert!(!g.has_cycle());
    }

    #[test]
    fn test_dep_graph_leaves() {
        let mut g = DependencyGraph::new();
        g.add_dependency("app", "lib-a");
        g.add_dependency("lib-a", "lib-b");
        let leaves = g.leaf_dependencies();
        assert!(leaves.contains(&"lib-b".to_string()));
        assert!(!leaves.contains(&"app".to_string()));
    }

    #[test]
    fn test_dep_graph_reverse() {
        let mut g = DependencyGraph::new();
        g.add_dependency("app", "lib-a");
        g.add_dependency("other", "lib-a");
        let rev = g.reverse_dependencies("lib-a");
        assert_eq!(rev.len(), 2);
    }

    #[test]
    fn test_check_reproducibility_match() {
        let output = b"compiled binary";
        let r = check_reproducibility(b"source", b"config", output, output);
        assert!(r.reproducible);
    }

    #[test]
    fn test_check_reproducibility_mismatch() {
        let r = check_reproducibility(b"source", b"config", b"output_a", b"output_b");
        assert!(!r.reproducible);
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
