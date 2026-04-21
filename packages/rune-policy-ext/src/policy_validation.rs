// ═══════════════════════════════════════════════════════════════════════
// Policy Package Validator — Layer 3 trait boundary for validating
// policy packages before publishing or evaluation.
//
// Ships SyntacticPackageValidator (structural checks),
// SecurityPackageValidator (heuristic policy smells), and
// CompositePackageValidator. Full symbolic analysis belongs in Layer 5.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::StoredPolicyPackage;

// ── ValidationSeverity ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    Clean,
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ── ValidationCheckCategory ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationCheckCategory {
    Syntactic,
    Semantic,
    Security,
    Compatibility,
    Compliance,
}

impl fmt::Display for ValidationCheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntactic => f.write_str("syntactic"),
            Self::Semantic => f.write_str("semantic"),
            Self::Security => f.write_str("security"),
            Self::Compatibility => f.write_str("compatibility"),
            Self::Compliance => f.write_str("compliance"),
        }
    }
}

// ── ValidationCheckResult ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCheckResult {
    pub check_name: String,
    pub check_category: ValidationCheckCategory,
    pub passed: bool,
    pub severity: ValidationSeverity,
    pub message: String,
    pub affected_rule_refs: Vec<String>,
}

// ── PackageValidationReport ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageValidationReport {
    pub report_id: String,
    pub package_id: String,
    pub passed: bool,
    pub validation_checks: Vec<ValidationCheckResult>,
    pub overall_severity: ValidationSeverity,
}

impl PackageValidationReport {
    pub fn failed_checks(&self) -> Vec<&ValidationCheckResult> {
        self.validation_checks.iter().filter(|c| !c.passed).collect()
    }

    pub fn checks_by_category(&self, category: &ValidationCheckCategory) -> Vec<&ValidationCheckResult> {
        self.validation_checks
            .iter()
            .filter(|c| &c.check_category == category)
            .collect()
    }
}

// ── PolicyPackageValidator trait ──────────────────────────────────

pub trait PolicyPackageValidator {
    fn validate_package(&self, package: &StoredPolicyPackage) -> PackageValidationReport;
    fn validator_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── SyntacticPackageValidator ─────────────────────────────────────

pub struct SyntacticPackageValidator {
    id: String,
}

impl SyntacticPackageValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageValidator for SyntacticPackageValidator {
    fn validate_package(&self, package: &StoredPolicyPackage) -> PackageValidationReport {
        let mut checks = Vec::new();

        // Check: package_id is non-empty
        checks.push(ValidationCheckResult {
            check_name: "package-id-present".to_string(),
            check_category: ValidationCheckCategory::Syntactic,
            passed: !package.package_id.is_empty(),
            severity: if package.package_id.is_empty() {
                ValidationSeverity::Error
            } else {
                ValidationSeverity::Clean
            },
            message: if package.package_id.is_empty() {
                "package_id is empty".to_string()
            } else {
                "package_id is present".to_string()
            },
            affected_rule_refs: vec![],
        });

        // Check: version is semver-like (contains dots)
        let valid_version = package.version.contains('.');
        checks.push(ValidationCheckResult {
            check_name: "version-format".to_string(),
            check_category: ValidationCheckCategory::Syntactic,
            passed: valid_version,
            severity: if valid_version {
                ValidationSeverity::Clean
            } else {
                ValidationSeverity::Warning
            },
            message: if valid_version {
                "version appears to be semver".to_string()
            } else {
                "version does not appear to be semver".to_string()
            },
            affected_rule_refs: vec![],
        });

        // Check: has at least one rule set ref
        let has_rules = !package.rule_set_refs.is_empty();
        checks.push(ValidationCheckResult {
            check_name: "rule-sets-present".to_string(),
            check_category: ValidationCheckCategory::Syntactic,
            passed: has_rules,
            severity: if has_rules {
                ValidationSeverity::Clean
            } else {
                ValidationSeverity::Warning
            },
            message: if has_rules {
                format!("{} rule set ref(s)", package.rule_set_refs.len())
            } else {
                "no rule set refs".to_string()
            },
            affected_rule_refs: vec![],
        });

        // Check: dependencies have valid version constraints
        for dep in &package.dependencies {
            let valid_constraint = dep.version_constraint.contains('.')
                || dep.version_constraint.starts_with(">=")
                || dep.version_constraint.starts_with("^")
                || dep.version_constraint.starts_with("~")
                || dep.version_constraint == "*";
            checks.push(ValidationCheckResult {
                check_name: format!("dependency-version-{}", dep.name),
                check_category: ValidationCheckCategory::Syntactic,
                passed: valid_constraint,
                severity: if valid_constraint {
                    ValidationSeverity::Clean
                } else {
                    ValidationSeverity::Error
                },
                message: if valid_constraint {
                    format!("dependency {} has valid constraint", dep.name)
                } else {
                    format!(
                        "dependency {} has invalid version constraint: {}",
                        dep.name, dep.version_constraint
                    )
                },
                affected_rule_refs: vec![],
            });
        }

        // Check: namespace is non-empty
        checks.push(ValidationCheckResult {
            check_name: "namespace-present".to_string(),
            check_category: ValidationCheckCategory::Syntactic,
            passed: !package.namespace.is_empty(),
            severity: if package.namespace.is_empty() {
                ValidationSeverity::Error
            } else {
                ValidationSeverity::Clean
            },
            message: if package.namespace.is_empty() {
                "namespace is empty".to_string()
            } else {
                "namespace is present".to_string()
            },
            affected_rule_refs: vec![],
        });

        let overall = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ValidationSeverity::Clean);
        let passed = !checks.iter().any(|c| {
            !c.passed
                && matches!(
                    c.severity,
                    ValidationSeverity::Error | ValidationSeverity::Critical
                )
        });

        PackageValidationReport {
            report_id: format!("syntactic-{}", package.package_id),
            package_id: package.package_id.clone(),
            passed,
            validation_checks: checks,
            overall_severity: overall,
        }
    }

    fn validator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── SecurityPackageValidator ──────────────────────────────────────

pub struct SecurityPackageValidator {
    id: String,
}

impl SecurityPackageValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageValidator for SecurityPackageValidator {
    fn validate_package(&self, package: &StoredPolicyPackage) -> PackageValidationReport {
        let mut checks = Vec::new();

        // Heuristic: unsigned packages are a security concern
        let is_signed = package.signature_ref.is_some();
        checks.push(ValidationCheckResult {
            check_name: "package-signature".to_string(),
            check_category: ValidationCheckCategory::Security,
            passed: is_signed,
            severity: if is_signed {
                ValidationSeverity::Clean
            } else {
                ValidationSeverity::Warning
            },
            message: if is_signed {
                "package has signature reference".to_string()
            } else {
                "package is unsigned — consider signing before distribution".to_string()
            },
            affected_rule_refs: vec![],
        });

        // Heuristic: check for overly-permissive metadata patterns
        let has_wildcard_tags = package.tags.iter().any(|t| t == "*" || t == "any");
        checks.push(ValidationCheckResult {
            check_name: "overly-permissive-tags".to_string(),
            check_category: ValidationCheckCategory::Security,
            passed: !has_wildcard_tags,
            severity: if has_wildcard_tags {
                ValidationSeverity::Warning
            } else {
                ValidationSeverity::Clean
            },
            message: if has_wildcard_tags {
                "wildcard tags detected — may indicate overly-permissive defaults".to_string()
            } else {
                "no wildcard tags".to_string()
            },
            affected_rule_refs: vec![],
        });

        // Heuristic: optional-only dependencies may indicate missing default-deny
        let all_optional = !package.dependencies.is_empty()
            && package.dependencies.iter().all(|d| d.optional);
        checks.push(ValidationCheckResult {
            check_name: "missing-required-dependencies".to_string(),
            check_category: ValidationCheckCategory::Security,
            passed: !all_optional,
            severity: if all_optional {
                ValidationSeverity::Info
            } else {
                ValidationSeverity::Clean
            },
            message: if all_optional {
                "all dependencies are optional — may lack required base policies".to_string()
            } else {
                "has required dependencies or no dependencies".to_string()
            },
            affected_rule_refs: vec![],
        });

        let overall = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ValidationSeverity::Clean);
        let passed = !checks.iter().any(|c| {
            !c.passed
                && matches!(
                    c.severity,
                    ValidationSeverity::Error | ValidationSeverity::Critical
                )
        });

        PackageValidationReport {
            report_id: format!("security-{}", package.package_id),
            package_id: package.package_id.clone(),
            passed,
            validation_checks: checks,
            overall_severity: overall,
        }
    }

    fn validator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── CompositePackageValidator ─────────────────────────────────────

pub struct CompositePackageValidator {
    id: String,
    validators: Vec<Box<dyn PolicyPackageValidator>>,
}

impl CompositePackageValidator {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            validators: Vec::new(),
        }
    }

    pub fn add_validator(&mut self, validator: Box<dyn PolicyPackageValidator>) {
        self.validators.push(validator);
    }
}

impl PolicyPackageValidator for CompositePackageValidator {
    fn validate_package(&self, package: &StoredPolicyPackage) -> PackageValidationReport {
        let mut all_checks = Vec::new();
        let mut any_failed = false;

        for validator in &self.validators {
            if !validator.is_active() {
                continue;
            }
            let report = validator.validate_package(package);
            if !report.passed {
                any_failed = true;
            }
            all_checks.extend(report.validation_checks);
        }

        let overall = all_checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.severity.clone())
            .max()
            .unwrap_or(ValidationSeverity::Clean);

        PackageValidationReport {
            report_id: format!("composite-{}", package.package_id),
            package_id: package.package_id.clone(),
            passed: !any_failed,
            validation_checks: all_checks,
            overall_severity: overall,
        }
    }

    fn validator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullPolicyPackageValidator ────────────────────────────────────

pub struct NullPolicyPackageValidator {
    id: String,
}

impl NullPolicyPackageValidator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PolicyPackageValidator for NullPolicyPackageValidator {
    fn validate_package(&self, package: &StoredPolicyPackage) -> PackageValidationReport {
        PackageValidationReport {
            report_id: format!("null-{}", package.package_id),
            package_id: package.package_id.clone(),
            passed: true,
            validation_checks: vec![],
            overall_severity: ValidationSeverity::Clean,
        }
    }

    fn validator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::PackageDependency;
    use std::collections::HashMap;

    fn sample_package() -> StoredPolicyPackage {
        StoredPolicyPackage {
            package_id: "pkg-1".to_string(),
            name: "access-control".to_string(),
            namespace: "org.rune".to_string(),
            version: "1.0.0".to_string(),
            description: "test".to_string(),
            tags: vec!["access".to_string()],
            rule_set_refs: vec!["rs-1".to_string()],
            dependencies: vec![PackageDependency {
                name: "base".to_string(),
                version_constraint: ">=1.0.0".to_string(),
                optional: false,
                purpose: "core".to_string(),
            }],
            signature_ref: Some("sig-1".to_string()),
            created_at: "2026-04-20".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_validation_severity_display() {
        assert_eq!(ValidationSeverity::Clean.to_string(), "clean");
        assert_eq!(ValidationSeverity::Warning.to_string(), "warning");
        assert_eq!(ValidationSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_validation_severity_ord() {
        assert!(ValidationSeverity::Critical > ValidationSeverity::Error);
        assert!(ValidationSeverity::Error > ValidationSeverity::Warning);
        assert!(ValidationSeverity::Warning > ValidationSeverity::Info);
        assert!(ValidationSeverity::Info > ValidationSeverity::Clean);
    }

    #[test]
    fn test_check_category_display() {
        assert_eq!(ValidationCheckCategory::Syntactic.to_string(), "syntactic");
        assert_eq!(ValidationCheckCategory::Security.to_string(), "security");
    }

    #[test]
    fn test_syntactic_validator_passes() {
        let validator = SyntacticPackageValidator::new("syn-1");
        let report = validator.validate_package(&sample_package());
        assert!(report.passed);
        assert_eq!(report.overall_severity, ValidationSeverity::Clean);
        assert!(!report.validation_checks.is_empty());
    }

    #[test]
    fn test_syntactic_validator_missing_version() {
        let validator = SyntacticPackageValidator::new("syn-1");
        let mut pkg = sample_package();
        pkg.version = "bad".to_string();
        let report = validator.validate_package(&pkg);
        // Warning-level, still passes (not Error)
        assert!(report.passed);
        assert_eq!(report.overall_severity, ValidationSeverity::Warning);
    }

    #[test]
    fn test_syntactic_validator_empty_package_id() {
        let validator = SyntacticPackageValidator::new("syn-1");
        let mut pkg = sample_package();
        pkg.package_id = String::new();
        let report = validator.validate_package(&pkg);
        assert!(!report.passed);
        assert!(report.overall_severity >= ValidationSeverity::Error);
    }

    #[test]
    fn test_syntactic_validator_empty_namespace() {
        let validator = SyntacticPackageValidator::new("syn-1");
        let mut pkg = sample_package();
        pkg.namespace = String::new();
        let report = validator.validate_package(&pkg);
        assert!(!report.passed);
    }

    #[test]
    fn test_syntactic_validator_bad_dependency() {
        let validator = SyntacticPackageValidator::new("syn-1");
        let mut pkg = sample_package();
        pkg.dependencies.push(PackageDependency {
            name: "bad-dep".to_string(),
            version_constraint: "invalid".to_string(),
            optional: false,
            purpose: "test".to_string(),
        });
        let report = validator.validate_package(&pkg);
        assert!(!report.passed);
    }

    #[test]
    fn test_security_validator_signed() {
        let validator = SecurityPackageValidator::new("sec-1");
        let report = validator.validate_package(&sample_package());
        assert!(report.passed);
    }

    #[test]
    fn test_security_validator_unsigned() {
        let validator = SecurityPackageValidator::new("sec-1");
        let mut pkg = sample_package();
        pkg.signature_ref = None;
        let report = validator.validate_package(&pkg);
        // Warning-level only, still passes
        assert!(report.passed);
        assert!(report
            .failed_checks()
            .iter()
            .any(|c| c.check_name == "package-signature"));
    }

    #[test]
    fn test_security_validator_wildcard_tags() {
        let validator = SecurityPackageValidator::new("sec-1");
        let mut pkg = sample_package();
        pkg.tags.push("*".to_string());
        let report = validator.validate_package(&pkg);
        assert!(report
            .failed_checks()
            .iter()
            .any(|c| c.check_name == "overly-permissive-tags"));
    }

    #[test]
    fn test_composite_validator() {
        let mut composite = CompositePackageValidator::new("comp-1");
        composite.add_validator(Box::new(SyntacticPackageValidator::new("syn")));
        composite.add_validator(Box::new(SecurityPackageValidator::new("sec")));

        let report = composite.validate_package(&sample_package());
        assert!(report.passed);
        // Should have checks from both validators
        assert!(report.validation_checks.len() >= 5);
    }

    #[test]
    fn test_composite_validator_failure_propagation() {
        let mut composite = CompositePackageValidator::new("comp-1");
        composite.add_validator(Box::new(SyntacticPackageValidator::new("syn")));

        let mut pkg = sample_package();
        pkg.package_id = String::new();
        let report = composite.validate_package(&pkg);
        assert!(!report.passed);
    }

    #[test]
    fn test_null_validator() {
        let validator = NullPolicyPackageValidator::new("null-1");
        assert!(!validator.is_active());
        let report = validator.validate_package(&sample_package());
        assert!(report.passed);
        assert!(report.validation_checks.is_empty());
    }

    #[test]
    fn test_validator_ids() {
        let syn = SyntacticPackageValidator::new("my-syn");
        assert_eq!(syn.validator_id(), "my-syn");
        assert!(syn.is_active());

        let sec = SecurityPackageValidator::new("my-sec");
        assert_eq!(sec.validator_id(), "my-sec");
    }

    #[test]
    fn test_report_helpers() {
        let validator = SyntacticPackageValidator::new("syn");
        let report = validator.validate_package(&sample_package());
        assert!(report.failed_checks().is_empty());
        assert!(!report
            .checks_by_category(&ValidationCheckCategory::Syntactic)
            .is_empty());
    }
}
