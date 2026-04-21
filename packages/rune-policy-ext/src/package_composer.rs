// ═══════════════════════════════════════════════════════════════════════
// Package Composer — Layer 3 trait boundary for composing multiple
// policy packages into a unified package.
//
// Distinct from L1 CompositionStrategy (MostRestrictive/LeastRestrictive/
// PriorityBased/FirstMatch) which operates on individual rule evaluation.
// PackageCompositionStrategy operates on entire packages: Union merges
// all rule sets, Intersection keeps shared rules, Override replaces
// with highest-priority, Explicit uses caller-specified ordering.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::backend::StoredPolicyPackage;
use crate::error::PolicyExtError;

// ── PackageCompositionStrategy ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageCompositionStrategy {
    Union,
    Intersection,
    Override,
    Explicit { priority_order: Vec<String> },
}

impl fmt::Display for PackageCompositionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Union => f.write_str("union"),
            Self::Intersection => f.write_str("intersection"),
            Self::Override => f.write_str("override"),
            Self::Explicit { .. } => f.write_str("explicit"),
        }
    }
}

// ── PackagePolicyConflict ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePolicyConflict {
    pub conflict_id: String,
    pub rule_a_ref: String,
    pub rule_b_ref: String,
    pub conflict_type: PackageConflictCategory,
    pub description: String,
}

// ── PackageConflictCategory ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageConflictCategory {
    ContradictoryOutcome,
    OverlappingScope,
    AmbiguousPriority,
}

impl fmt::Display for PackageConflictCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContradictoryOutcome => f.write_str("contradictory-outcome"),
            Self::OverlappingScope => f.write_str("overlapping-scope"),
            Self::AmbiguousPriority => f.write_str("ambiguous-priority"),
        }
    }
}

// ── PackageConflictResolutionStrategy ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageConflictResolutionStrategy {
    PreferMoreRestrictive,
    PreferMoreSpecific,
    PreferNewer,
    PreferExplicit,
}

impl fmt::Display for PackageConflictResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreferMoreRestrictive => f.write_str("prefer-more-restrictive"),
            Self::PreferMoreSpecific => f.write_str("prefer-more-specific"),
            Self::PreferNewer => f.write_str("prefer-newer"),
            Self::PreferExplicit => f.write_str("prefer-explicit"),
        }
    }
}

// ── ComposedPackage ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedPackage {
    pub package: StoredPolicyPackage,
    pub composition_origin: Vec<String>,
    pub composition_strategy: PackageCompositionStrategy,
}

// ── PolicyPackageComposer trait ───────────────────────────────────

pub trait PolicyPackageComposer {
    fn compose_packages(
        &self,
        packages: &[StoredPolicyPackage],
        strategy: &PackageCompositionStrategy,
    ) -> Result<ComposedPackage, PolicyExtError>;

    fn detect_conflicts(
        &self,
        packages: &[StoredPolicyPackage],
    ) -> Vec<PackagePolicyConflict>;

    fn resolve_conflict(
        &self,
        conflict: &PackagePolicyConflict,
        strategy: &PackageConflictResolutionStrategy,
    ) -> Result<String, PolicyExtError>;

    fn composer_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryPolicyPackageComposer ─────────────────────────────────

pub struct InMemoryPolicyPackageComposer {
    id: String,
}

impl InMemoryPolicyPackageComposer {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageComposer for InMemoryPolicyPackageComposer {
    fn compose_packages(
        &self,
        packages: &[StoredPolicyPackage],
        strategy: &PackageCompositionStrategy,
    ) -> Result<ComposedPackage, PolicyExtError> {
        if packages.is_empty() {
            return Err(PolicyExtError::InvalidOperation(
                "cannot compose empty package list".to_string(),
            ));
        }

        let origin: Vec<String> = packages.iter().map(|p| p.package_id.clone()).collect();
        let mut merged_refs: Vec<String> = Vec::new();
        let mut merged_tags: Vec<String> = Vec::new();
        let mut merged_deps: Vec<crate::backend::PackageDependency> = Vec::new();

        for pkg in packages {
            merged_tags.extend(pkg.tags.clone());

            match strategy {
                PackageCompositionStrategy::Union => {
                    for r in &pkg.rule_set_refs {
                        if !merged_refs.contains(r) {
                            merged_refs.push(r.clone());
                        }
                    }
                    merged_deps.extend(pkg.dependencies.clone());
                }
                PackageCompositionStrategy::Intersection => {
                    if merged_refs.is_empty() && pkg == &packages[0] {
                        merged_refs = pkg.rule_set_refs.clone();
                    } else {
                        merged_refs.retain(|r| pkg.rule_set_refs.contains(r));
                    }
                }
                PackageCompositionStrategy::Override => {
                    // Last package wins
                    merged_refs = pkg.rule_set_refs.clone();
                    merged_deps = pkg.dependencies.clone();
                }
                PackageCompositionStrategy::Explicit { priority_order } => {
                    if priority_order.contains(&pkg.package_id) {
                        for r in &pkg.rule_set_refs {
                            if !merged_refs.contains(r) {
                                merged_refs.push(r.clone());
                            }
                        }
                    }
                    merged_deps.extend(pkg.dependencies.clone());
                }
            }
        }

        merged_tags.sort();
        merged_tags.dedup();

        let base = &packages[0];
        Ok(ComposedPackage {
            package: StoredPolicyPackage {
                package_id: format!("composed-{}", base.package_id),
                name: format!("composed-{}", base.name),
                namespace: base.namespace.clone(),
                version: base.version.clone(),
                description: format!("Composed from {} packages", packages.len()),
                tags: merged_tags,
                rule_set_refs: merged_refs,
                dependencies: merged_deps,
                signature_ref: None,
                created_at: base.created_at.clone(),
                metadata: HashMap::new(),
            },
            composition_origin: origin,
            composition_strategy: strategy.clone(),
        })
    }

    fn detect_conflicts(&self, packages: &[StoredPolicyPackage]) -> Vec<PackagePolicyConflict> {
        let mut conflicts = Vec::new();
        for i in 0..packages.len() {
            for j in (i + 1)..packages.len() {
                // Heuristic: overlapping rule_set_refs suggest scope overlap
                let overlap: Vec<_> = packages[i]
                    .rule_set_refs
                    .iter()
                    .filter(|r| packages[j].rule_set_refs.contains(r))
                    .collect();
                if !overlap.is_empty() {
                    conflicts.push(PackagePolicyConflict {
                        conflict_id: format!("conflict-{i}-{j}"),
                        rule_a_ref: packages[i].package_id.clone(),
                        rule_b_ref: packages[j].package_id.clone(),
                        conflict_type: PackageConflictCategory::OverlappingScope,
                        description: format!(
                            "{} shared rule set ref(s)",
                            overlap.len()
                        ),
                    });
                }
            }
        }
        conflicts
    }

    fn resolve_conflict(
        &self,
        conflict: &PackagePolicyConflict,
        strategy: &PackageConflictResolutionStrategy,
    ) -> Result<String, PolicyExtError> {
        Ok(format!(
            "resolved {} using {}",
            conflict.conflict_id, strategy
        ))
    }

    fn composer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── UnionPolicyPackageComposer ────────────────────────────────────

pub struct UnionPolicyPackageComposer {
    inner: InMemoryPolicyPackageComposer,
}

impl UnionPolicyPackageComposer {
    pub fn new(id: &str) -> Self {
        Self {
            inner: InMemoryPolicyPackageComposer::new(id),
        }
    }
}

impl PolicyPackageComposer for UnionPolicyPackageComposer {
    fn compose_packages(
        &self,
        packages: &[StoredPolicyPackage],
        _strategy: &PackageCompositionStrategy,
    ) -> Result<ComposedPackage, PolicyExtError> {
        self.inner
            .compose_packages(packages, &PackageCompositionStrategy::Union)
    }

    fn detect_conflicts(&self, packages: &[StoredPolicyPackage]) -> Vec<PackagePolicyConflict> {
        self.inner.detect_conflicts(packages)
    }

    fn resolve_conflict(
        &self,
        conflict: &PackagePolicyConflict,
        strategy: &PackageConflictResolutionStrategy,
    ) -> Result<String, PolicyExtError> {
        self.inner.resolve_conflict(conflict, strategy)
    }

    fn composer_id(&self) -> &str { self.inner.composer_id() }
    fn is_active(&self) -> bool { true }
}

// ── OverridePolicyPackageComposer ─────────────────────────────────

pub struct OverridePolicyPackageComposer {
    inner: InMemoryPolicyPackageComposer,
}

impl OverridePolicyPackageComposer {
    pub fn new(id: &str) -> Self {
        Self {
            inner: InMemoryPolicyPackageComposer::new(id),
        }
    }
}

impl PolicyPackageComposer for OverridePolicyPackageComposer {
    fn compose_packages(
        &self,
        packages: &[StoredPolicyPackage],
        _strategy: &PackageCompositionStrategy,
    ) -> Result<ComposedPackage, PolicyExtError> {
        self.inner
            .compose_packages(packages, &PackageCompositionStrategy::Override)
    }

    fn detect_conflicts(&self, packages: &[StoredPolicyPackage]) -> Vec<PackagePolicyConflict> {
        self.inner.detect_conflicts(packages)
    }

    fn resolve_conflict(
        &self,
        conflict: &PackagePolicyConflict,
        strategy: &PackageConflictResolutionStrategy,
    ) -> Result<String, PolicyExtError> {
        self.inner.resolve_conflict(conflict, strategy)
    }

    fn composer_id(&self) -> &str { self.inner.composer_id() }
    fn is_active(&self) -> bool { true }
}

// ── NullPolicyPackageComposer ─────────────────────────────────────

pub struct NullPolicyPackageComposer {
    id: String,
}

impl NullPolicyPackageComposer {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageComposer for NullPolicyPackageComposer {
    fn compose_packages(
        &self,
        _packages: &[StoredPolicyPackage],
        _strategy: &PackageCompositionStrategy,
    ) -> Result<ComposedPackage, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "null composer".to_string(),
        ))
    }

    fn detect_conflicts(&self, _packages: &[StoredPolicyPackage]) -> Vec<PackagePolicyConflict> {
        Vec::new()
    }

    fn resolve_conflict(
        &self,
        _conflict: &PackagePolicyConflict,
        _strategy: &PackageConflictResolutionStrategy,
    ) -> Result<String, PolicyExtError> {
        Err(PolicyExtError::InvalidOperation(
            "null composer".to_string(),
        ))
    }

    fn composer_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pkg(id: &str, refs: &[&str]) -> StoredPolicyPackage {
        StoredPolicyPackage {
            package_id: id.to_string(),
            name: id.to_string(),
            namespace: "org.test".to_string(),
            version: "1.0.0".to_string(),
            description: String::new(),
            tags: vec!["test".to_string()],
            rule_set_refs: refs.iter().map(|r| r.to_string()).collect(),
            dependencies: Vec::new(),
            signature_ref: None,
            created_at: "2026-04-20".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_composition_strategy_display() {
        assert_eq!(PackageCompositionStrategy::Union.to_string(), "union");
        assert_eq!(PackageCompositionStrategy::Override.to_string(), "override");
        assert_eq!(
            PackageCompositionStrategy::Explicit {
                priority_order: vec![]
            }
            .to_string(),
            "explicit"
        );
    }

    #[test]
    fn test_conflict_category_display() {
        assert_eq!(
            PackageConflictCategory::ContradictoryOutcome.to_string(),
            "contradictory-outcome"
        );
        assert_eq!(
            PackageConflictCategory::OverlappingScope.to_string(),
            "overlapping-scope"
        );
    }

    #[test]
    fn test_resolution_strategy_display() {
        assert_eq!(
            PackageConflictResolutionStrategy::PreferMoreRestrictive.to_string(),
            "prefer-more-restrictive"
        );
    }

    #[test]
    fn test_compose_union() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a", "rs-b"]),
            sample_pkg("p2", &["rs-b", "rs-c"]),
        ];
        let result = composer
            .compose_packages(&pkgs, &PackageCompositionStrategy::Union)
            .unwrap();
        assert_eq!(result.composition_origin.len(), 2);
        assert_eq!(result.package.rule_set_refs.len(), 3); // rs-a, rs-b, rs-c
    }

    #[test]
    fn test_compose_intersection() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a", "rs-b"]),
            sample_pkg("p2", &["rs-b", "rs-c"]),
        ];
        let result = composer
            .compose_packages(&pkgs, &PackageCompositionStrategy::Intersection)
            .unwrap();
        assert_eq!(result.package.rule_set_refs, vec!["rs-b"]);
    }

    #[test]
    fn test_compose_override() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a"]),
            sample_pkg("p2", &["rs-x", "rs-y"]),
        ];
        let result = composer
            .compose_packages(&pkgs, &PackageCompositionStrategy::Override)
            .unwrap();
        assert_eq!(result.package.rule_set_refs, vec!["rs-x", "rs-y"]);
    }

    #[test]
    fn test_compose_empty_fails() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        assert!(composer
            .compose_packages(&[], &PackageCompositionStrategy::Union)
            .is_err());
    }

    #[test]
    fn test_detect_conflicts() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-shared"]),
            sample_pkg("p2", &["rs-shared"]),
        ];
        let conflicts = composer.detect_conflicts(&pkgs);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].conflict_type,
            PackageConflictCategory::OverlappingScope
        );
    }

    #[test]
    fn test_no_conflicts() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a"]),
            sample_pkg("p2", &["rs-b"]),
        ];
        assert!(composer.detect_conflicts(&pkgs).is_empty());
    }

    #[test]
    fn test_resolve_conflict() {
        let composer = InMemoryPolicyPackageComposer::new("comp-1");
        let conflict = PackagePolicyConflict {
            conflict_id: "c-1".to_string(),
            rule_a_ref: "p1".to_string(),
            rule_b_ref: "p2".to_string(),
            conflict_type: PackageConflictCategory::ContradictoryOutcome,
            description: "test".to_string(),
        };
        let result = composer
            .resolve_conflict(&conflict, &PackageConflictResolutionStrategy::PreferNewer)
            .unwrap();
        assert!(result.contains("c-1"));
    }

    #[test]
    fn test_union_composer() {
        let composer = UnionPolicyPackageComposer::new("union-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a"]),
            sample_pkg("p2", &["rs-b"]),
        ];
        let result = composer
            .compose_packages(&pkgs, &PackageCompositionStrategy::Override)
            .unwrap();
        // Always uses Union regardless of passed strategy
        assert_eq!(result.package.rule_set_refs.len(), 2);
        assert!(composer.is_active());
    }

    #[test]
    fn test_override_composer() {
        let composer = OverridePolicyPackageComposer::new("ovr-1");
        let pkgs = vec![
            sample_pkg("p1", &["rs-a"]),
            sample_pkg("p2", &["rs-b"]),
        ];
        let result = composer
            .compose_packages(&pkgs, &PackageCompositionStrategy::Union)
            .unwrap();
        // Always uses Override
        assert_eq!(result.package.rule_set_refs, vec!["rs-b"]);
    }

    #[test]
    fn test_null_composer() {
        let composer = NullPolicyPackageComposer::new("null-1");
        assert!(!composer.is_active());
        assert!(composer
            .compose_packages(&[], &PackageCompositionStrategy::Union)
            .is_err());
        assert!(composer.detect_conflicts(&[]).is_empty());
    }

    #[test]
    fn test_composer_ids() {
        let c = InMemoryPolicyPackageComposer::new("my-comp");
        assert_eq!(c.composer_id(), "my-comp");
        assert!(c.is_active());
    }
}
