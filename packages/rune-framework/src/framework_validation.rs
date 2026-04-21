// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — FrameworkManifestValidator trait for validating framework
// manifests before registration. Structural, referential, mapping, and
// composite validators.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::StoredFrameworkManifest;

// ── ManifestValidationSeverity ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManifestValidationSeverity {
    Clean = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

impl std::fmt::Display for ManifestValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => f.write_str("Clean"),
            Self::Info => f.write_str("Info"),
            Self::Warning => f.write_str("Warning"),
            Self::Error => f.write_str("Error"),
            Self::Critical => f.write_str("Critical"),
        }
    }
}

// ── ManifestCheckCategory ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCheckCategory {
    Structural,
    Referential,
    Dependency,
    Mapping,
    Metadata,
}

impl std::fmt::Display for ManifestCheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Structural => f.write_str("Structural"),
            Self::Referential => f.write_str("Referential"),
            Self::Dependency => f.write_str("Dependency"),
            Self::Mapping => f.write_str("Mapping"),
            Self::Metadata => f.write_str("Metadata"),
        }
    }
}

// ── ManifestCheckResult ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ManifestCheckResult {
    pub check_name: String,
    pub check_category: ManifestCheckCategory,
    pub passed: bool,
    pub severity: ManifestValidationSeverity,
    pub message: String,
    pub affected_requirement_refs: Vec<String>,
}

// ── FrameworkValidationReport ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FrameworkValidationReport {
    pub report_id: String,
    pub framework_id: String,
    pub passed: bool,
    pub validation_checks: Vec<ManifestCheckResult>,
    pub overall_severity: ManifestValidationSeverity,
}

impl FrameworkValidationReport {
    pub fn failed_checks(&self) -> Vec<&ManifestCheckResult> {
        self.validation_checks.iter().filter(|c| !c.passed).collect()
    }

    pub fn checks_by_category(&self, category: &ManifestCheckCategory) -> Vec<&ManifestCheckResult> {
        self.validation_checks
            .iter()
            .filter(|c| &c.check_category == category)
            .collect()
    }
}

// ── FrameworkManifestValidator trait ──────────────────────────────────

pub trait FrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport;
    fn validator_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── StructuralFrameworkManifestValidator ──────────────────────────────

pub struct StructuralFrameworkManifestValidator;

impl StructuralFrameworkManifestValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StructuralFrameworkManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkManifestValidator for StructuralFrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport {
        let mut checks = Vec::new();

        // Check framework_id not empty
        checks.push(ManifestCheckResult {
            check_name: "framework-id-present".to_string(),
            check_category: ManifestCheckCategory::Structural,
            passed: !manifest.framework_id.is_empty(),
            severity: if manifest.framework_id.is_empty() {
                ManifestValidationSeverity::Critical
            } else {
                ManifestValidationSeverity::Clean
            },
            message: if manifest.framework_id.is_empty() {
                "framework_id is empty".to_string()
            } else {
                "framework_id present".to_string()
            },
            affected_requirement_refs: vec![],
        });

        // Check semver format (basic: contains at least one dot or slash)
        let semver_ok = manifest.version.contains('.') || manifest.version.contains('/');
        checks.push(ManifestCheckResult {
            check_name: "version-format".to_string(),
            check_category: ManifestCheckCategory::Structural,
            passed: semver_ok,
            severity: if semver_ok {
                ManifestValidationSeverity::Clean
            } else {
                ManifestValidationSeverity::Warning
            },
            message: if semver_ok {
                "version format acceptable".to_string()
            } else {
                "version does not follow semver or versioned format".to_string()
            },
            affected_requirement_refs: vec![],
        });

        // Check name present
        checks.push(ManifestCheckResult {
            check_name: "name-present".to_string(),
            check_category: ManifestCheckCategory::Structural,
            passed: !manifest.name.is_empty(),
            severity: if manifest.name.is_empty() {
                ManifestValidationSeverity::Error
            } else {
                ManifestValidationSeverity::Clean
            },
            message: if manifest.name.is_empty() {
                "name is empty".to_string()
            } else {
                "name present".to_string()
            },
            affected_requirement_refs: vec![],
        });

        // Check requirement_refs not empty
        checks.push(ManifestCheckResult {
            check_name: "requirement-refs-present".to_string(),
            check_category: ManifestCheckCategory::Structural,
            passed: !manifest.requirement_refs.is_empty(),
            severity: if manifest.requirement_refs.is_empty() {
                ManifestValidationSeverity::Warning
            } else {
                ManifestValidationSeverity::Clean
            },
            message: if manifest.requirement_refs.is_empty() {
                "no requirement references".to_string()
            } else {
                format!("{} requirement references", manifest.requirement_refs.len())
            },
            affected_requirement_refs: vec![],
        });

        // Check authority present
        checks.push(ManifestCheckResult {
            check_name: "authority-present".to_string(),
            check_category: ManifestCheckCategory::Metadata,
            passed: !manifest.authority.is_empty(),
            severity: if manifest.authority.is_empty() {
                ManifestValidationSeverity::Info
            } else {
                ManifestValidationSeverity::Clean
            },
            message: if manifest.authority.is_empty() {
                "authority not specified".to_string()
            } else {
                "authority present".to_string()
            },
            affected_requirement_refs: vec![],
        });

        let passed = checks.iter().all(|c| c.passed);
        let overall_severity = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ManifestValidationSeverity::Clean);

        FrameworkValidationReport {
            report_id: format!("structural-{}", manifest.framework_id),
            framework_id: manifest.framework_id.clone(),
            passed,
            validation_checks: checks,
            overall_severity,
        }
    }

    fn validator_id(&self) -> &str {
        "structural"
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── ReferentialFrameworkManifestValidator ─────────────────────────────

pub struct ReferentialFrameworkManifestValidator {
    known_libraries: Vec<String>,
}

impl ReferentialFrameworkManifestValidator {
    pub fn new() -> Self {
        Self {
            known_libraries: vec![
                "rune-identity".to_string(),
                "rune-privacy".to_string(),
                "rune-security".to_string(),
                "rune-policy-ext".to_string(),
                "rune-document".to_string(),
                "rune-audit-ext".to_string(),
                "rune-explainability".to_string(),
                "rune-truth".to_string(),
                "rune-provenance".to_string(),
                "rune-permissions".to_string(),
                "rune-monitoring".to_string(),
                "rune-detection".to_string(),
                "rune-web".to_string(),
                "rune-framework".to_string(),
                "rune-shield".to_string(),
            ],
        }
    }

    pub fn with_known_library(mut self, library: impl Into<String>) -> Self {
        self.known_libraries.push(library.into());
        self
    }
}

impl Default for ReferentialFrameworkManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkManifestValidator for ReferentialFrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport {
        let mut checks = Vec::new();

        // Check no empty requirement refs
        let empty_refs: Vec<String> = manifest
            .requirement_refs
            .iter()
            .filter(|r| r.is_empty())
            .cloned()
            .collect();
        checks.push(ManifestCheckResult {
            check_name: "no-empty-requirement-refs".to_string(),
            check_category: ManifestCheckCategory::Referential,
            passed: empty_refs.is_empty(),
            severity: if empty_refs.is_empty() {
                ManifestValidationSeverity::Clean
            } else {
                ManifestValidationSeverity::Error
            },
            message: if empty_refs.is_empty() {
                "all requirement refs are non-empty".to_string()
            } else {
                "found empty requirement references".to_string()
            },
            affected_requirement_refs: empty_refs,
        });

        // Check no duplicate requirement refs
        let mut seen = std::collections::HashSet::new();
        let duplicates: Vec<String> = manifest
            .requirement_refs
            .iter()
            .filter(|r| !seen.insert(r.as_str()))
            .cloned()
            .collect();
        checks.push(ManifestCheckResult {
            check_name: "no-duplicate-requirement-refs".to_string(),
            check_category: ManifestCheckCategory::Referential,
            passed: duplicates.is_empty(),
            severity: if duplicates.is_empty() {
                ManifestValidationSeverity::Clean
            } else {
                ManifestValidationSeverity::Warning
            },
            message: if duplicates.is_empty() {
                "no duplicate requirement refs".to_string()
            } else {
                format!("{} duplicate requirement refs", duplicates.len())
            },
            affected_requirement_refs: duplicates,
        });

        let passed = checks.iter().all(|c| c.passed);
        let overall_severity = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ManifestValidationSeverity::Clean);

        FrameworkValidationReport {
            report_id: format!("referential-{}", manifest.framework_id),
            framework_id: manifest.framework_id.clone(),
            passed,
            validation_checks: checks,
            overall_severity,
        }
    }

    fn validator_id(&self) -> &str {
        "referential"
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── MappingFrameworkManifestValidator ─────────────────────────────────

pub struct MappingFrameworkManifestValidator;

impl MappingFrameworkManifestValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MappingFrameworkManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkManifestValidator for MappingFrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport {
        let mut checks = Vec::new();

        // Check no empty mapping refs
        let empty_mappings: Vec<String> = manifest
            .mapping_refs
            .iter()
            .filter(|m| m.is_empty())
            .cloned()
            .collect();
        checks.push(ManifestCheckResult {
            check_name: "no-empty-mapping-refs".to_string(),
            check_category: ManifestCheckCategory::Mapping,
            passed: empty_mappings.is_empty(),
            severity: if empty_mappings.is_empty() {
                ManifestValidationSeverity::Clean
            } else {
                ManifestValidationSeverity::Warning
            },
            message: if empty_mappings.is_empty() {
                "all mapping refs valid".to_string()
            } else {
                "found empty mapping references".to_string()
            },
            affected_requirement_refs: vec![],
        });

        let passed = checks.iter().all(|c| c.passed);
        let overall_severity = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ManifestValidationSeverity::Clean);

        FrameworkValidationReport {
            report_id: format!("mapping-{}", manifest.framework_id),
            framework_id: manifest.framework_id.clone(),
            passed,
            validation_checks: checks,
            overall_severity,
        }
    }

    fn validator_id(&self) -> &str {
        "mapping"
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── CompositeFrameworkManifestValidator ───────────────────────────────

pub struct CompositeFrameworkManifestValidator {
    validators: Vec<Box<dyn FrameworkManifestValidator>>,
}

impl CompositeFrameworkManifestValidator {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    pub fn with_validator(mut self, validator: Box<dyn FrameworkManifestValidator>) -> Self {
        self.validators.push(validator);
        self
    }

    pub fn add_validator(&mut self, validator: Box<dyn FrameworkManifestValidator>) {
        self.validators.push(validator);
    }
}

impl Default for CompositeFrameworkManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkManifestValidator for CompositeFrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport {
        let mut all_checks = Vec::new();

        for validator in &self.validators {
            if validator.is_active() {
                let report = validator.validate_manifest(manifest);
                all_checks.extend(report.validation_checks);
            }
        }

        let passed = all_checks.iter().all(|c| c.passed);
        let overall_severity = all_checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ManifestValidationSeverity::Clean);

        FrameworkValidationReport {
            report_id: format!("composite-{}", manifest.framework_id),
            framework_id: manifest.framework_id.clone(),
            passed,
            validation_checks: all_checks,
            overall_severity,
        }
    }

    fn validator_id(&self) -> &str {
        "composite"
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullFrameworkManifestValidator ────────────────────────────────────

pub struct NullFrameworkManifestValidator;

impl NullFrameworkManifestValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullFrameworkManifestValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkManifestValidator for NullFrameworkManifestValidator {
    fn validate_manifest(&self, manifest: &StoredFrameworkManifest) -> FrameworkValidationReport {
        FrameworkValidationReport {
            report_id: format!("null-{}", manifest.framework_id),
            framework_id: manifest.framework_id.clone(),
            passed: true,
            validation_checks: vec![],
            overall_severity: ManifestValidationSeverity::Clean,
        }
    }

    fn validator_id(&self) -> &str {
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
    use crate::backend::{FrameworkDomain, Jurisdiction};
    use std::collections::HashMap;

    fn valid_manifest() -> StoredFrameworkManifest {
        StoredFrameworkManifest {
            framework_id: "cjis-v6.0".to_string(),
            name: "CJIS Security Policy".to_string(),
            version: "6.0.0".to_string(),
            jurisdiction: Jurisdiction::UnitedStates,
            domain: FrameworkDomain::CriminalJustice,
            description: "FBI CJIS".to_string(),
            authority: "FBI CJIS Division".to_string(),
            policy_area_count: 20,
            requirement_refs: vec!["cjis-5.6".to_string()],
            mapping_refs: vec![],
            published_at: 1000,
            effective_date: 1000,
            sunset_date: None,
            metadata: HashMap::new(),
        }
    }

    fn invalid_manifest() -> StoredFrameworkManifest {
        StoredFrameworkManifest {
            framework_id: String::new(),
            name: String::new(),
            version: "bad".to_string(),
            jurisdiction: Jurisdiction::UnitedStates,
            domain: FrameworkDomain::CriminalJustice,
            description: String::new(),
            authority: String::new(),
            policy_area_count: 0,
            requirement_refs: vec![],
            mapping_refs: vec![],
            published_at: 0,
            effective_date: 0,
            sunset_date: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_structural_valid_manifest() {
        let validator = StructuralFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&valid_manifest());
        assert!(report.passed);
        assert_eq!(report.overall_severity, ManifestValidationSeverity::Clean);
    }

    #[test]
    fn test_structural_invalid_manifest() {
        let validator = StructuralFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&invalid_manifest());
        assert!(!report.passed);
        assert!(report.overall_severity >= ManifestValidationSeverity::Warning);
        assert!(!report.failed_checks().is_empty());
    }

    #[test]
    fn test_referential_valid() {
        let validator = ReferentialFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&valid_manifest());
        assert!(report.passed);
    }

    #[test]
    fn test_referential_duplicate_refs() {
        let mut manifest = valid_manifest();
        manifest.requirement_refs = vec!["cjis-5.6".to_string(), "cjis-5.6".to_string()];
        let validator = ReferentialFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&manifest);
        assert!(!report.passed);
    }

    #[test]
    fn test_mapping_validator_valid() {
        let validator = MappingFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&valid_manifest());
        assert!(report.passed);
    }

    #[test]
    fn test_mapping_validator_empty_refs() {
        let mut manifest = valid_manifest();
        manifest.mapping_refs = vec![String::new()];
        let validator = MappingFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&manifest);
        assert!(!report.passed);
    }

    #[test]
    fn test_composite_aggregates() {
        let composite = CompositeFrameworkManifestValidator::new()
            .with_validator(Box::new(StructuralFrameworkManifestValidator::new()))
            .with_validator(Box::new(ReferentialFrameworkManifestValidator::new()))
            .with_validator(Box::new(MappingFrameworkManifestValidator::new()));
        let report = composite.validate_manifest(&valid_manifest());
        assert!(report.passed);
        // should have checks from all three validators
        assert!(report.validation_checks.len() >= 5);
    }

    #[test]
    fn test_composite_catches_structural_failure() {
        let composite = CompositeFrameworkManifestValidator::new()
            .with_validator(Box::new(StructuralFrameworkManifestValidator::new()));
        let report = composite.validate_manifest(&invalid_manifest());
        assert!(!report.passed);
    }

    #[test]
    fn test_null_validator() {
        let validator = NullFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&valid_manifest());
        assert!(report.passed);
        assert!(!validator.is_active());
    }

    #[test]
    fn test_checks_by_category() {
        let validator = StructuralFrameworkManifestValidator::new();
        let report = validator.validate_manifest(&valid_manifest());
        let structural = report.checks_by_category(&ManifestCheckCategory::Structural);
        assert!(structural.len() >= 3);
        let metadata = report.checks_by_category(&ManifestCheckCategory::Metadata);
        assert_eq!(metadata.len(), 1);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ManifestValidationSeverity::Clean < ManifestValidationSeverity::Info);
        assert!(ManifestValidationSeverity::Info < ManifestValidationSeverity::Warning);
        assert!(ManifestValidationSeverity::Warning < ManifestValidationSeverity::Error);
        assert!(ManifestValidationSeverity::Error < ManifestValidationSeverity::Critical);
    }

    #[test]
    fn test_with_known_library() {
        let validator =
            ReferentialFrameworkManifestValidator::new().with_known_library("rune-custom");
        assert_eq!(validator.known_libraries.len(), 16); // 15 defaults + 1 custom
    }
}
