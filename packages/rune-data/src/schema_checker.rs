// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Schema compatibility checking. Compares two schema
// versions to detect breaking changes (field removal, type change,
// nullability change), determines compatibility level, and evaluates
// schema evolution policy compliance.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::quality::QualitySeverity;
use crate::schema::{
    SchemaBreakingChange, SchemaChangeType, SchemaCompatibility, SchemaEvolutionPolicy,
    SchemaField, SchemaRecord,
};

// ── SchemaEvolutionDecision ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaEvolutionDecision {
    Approved { reason: String },
    Rejected { reason: String, breaking_changes: Vec<SchemaBreakingChange> },
    RequiresMigrationPlan { breaking_changes: Vec<SchemaBreakingChange> },
    RequiresDeprecationPeriod { field_changes: Vec<String>, period_days: String },
}

impl fmt::Display for SchemaEvolutionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved { reason } => write!(f, "Approved: {reason}"),
            Self::Rejected { reason, .. } => write!(f, "Rejected: {reason}"),
            Self::RequiresMigrationPlan { breaking_changes } => {
                write!(f, "RequiresMigrationPlan({} changes)", breaking_changes.len())
            }
            Self::RequiresDeprecationPeriod { period_days, .. } => {
                write!(f, "RequiresDeprecationPeriod({period_days} days)")
            }
        }
    }
}

// ── SchemaCompatibilityChecker ───────────────────────────────────────

pub struct SchemaCompatibilityChecker;

impl SchemaCompatibilityChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn check_compatibility(
        &self,
        old_schema: &SchemaRecord,
        new_schema: &SchemaRecord,
    ) -> SchemaCompatibility {
        let breaking_changes = self.detect_breaking_changes(&old_schema.fields, &new_schema.fields);

        if breaking_changes.is_empty() {
            let old_names: Vec<&str> = old_schema.fields.iter().map(|f| f.field_name.as_str()).collect();
            let new_names: Vec<&str> = new_schema.fields.iter().map(|f| f.field_name.as_str()).collect();

            let has_new_fields = new_names.iter().any(|n| !old_names.contains(n));
            let has_removed_fields = old_names.iter().any(|o| !new_names.contains(o));

            if !has_new_fields && !has_removed_fields {
                SchemaCompatibility::FullyCompatible
            } else if has_new_fields && !has_removed_fields {
                SchemaCompatibility::BackwardCompatible {
                    notes: "New fields added — old readers can ignore them".to_string(),
                }
            } else {
                SchemaCompatibility::ForwardCompatible {
                    notes: "Fields removed — new readers can handle missing fields".to_string(),
                }
            }
        } else {
            SchemaCompatibility::Breaking { breaking_changes }
        }
    }

    pub fn detect_breaking_changes(
        &self,
        old_fields: &[SchemaField],
        new_fields: &[SchemaField],
    ) -> Vec<SchemaBreakingChange> {
        let mut changes = Vec::new();

        changes.extend(self.check_field_removal(old_fields, new_fields));
        changes.extend(self.check_field_type_change(old_fields, new_fields));
        changes.extend(self.check_nullability_change(old_fields, new_fields));

        changes
    }

    pub fn check_field_removal(
        &self,
        old_fields: &[SchemaField],
        new_fields: &[SchemaField],
    ) -> Vec<SchemaBreakingChange> {
        let new_names: Vec<&str> = new_fields.iter().map(|f| f.field_name.as_str()).collect();
        old_fields
            .iter()
            .filter(|f| !f.nullable && !new_names.contains(&f.field_name.as_str()))
            .map(|f| SchemaBreakingChange {
                change_type: SchemaChangeType::FieldRemoved {
                    field_name: f.field_name.clone(),
                },
                severity: QualitySeverity::Critical,
                description: format!("Required field '{}' was removed", f.field_name),
            })
            .collect()
    }

    pub fn check_field_type_change(
        &self,
        old_fields: &[SchemaField],
        new_fields: &[SchemaField],
    ) -> Vec<SchemaBreakingChange> {
        let mut changes = Vec::new();
        for old in old_fields {
            for new in new_fields {
                if old.field_name == new.field_name && old.field_type != new.field_type {
                    changes.push(SchemaBreakingChange {
                        change_type: SchemaChangeType::FieldTypeChanged {
                            field_name: old.field_name.clone(),
                            from_type: old.field_type.clone(),
                            to_type: new.field_type.clone(),
                        },
                        severity: QualitySeverity::Critical,
                        description: format!(
                            "Field '{}' type changed from '{}' to '{}'",
                            old.field_name, old.field_type, new.field_type
                        ),
                    });
                }
            }
        }
        changes
    }

    pub fn check_nullability_change(
        &self,
        old_fields: &[SchemaField],
        new_fields: &[SchemaField],
    ) -> Vec<SchemaBreakingChange> {
        let mut changes = Vec::new();
        for old in old_fields {
            for new in new_fields {
                if old.field_name == new.field_name && old.nullable != new.nullable {
                    changes.push(SchemaBreakingChange {
                        change_type: SchemaChangeType::NullabilityChanged {
                            field_name: old.field_name.clone(),
                            was_nullable: old.nullable,
                        },
                        severity: QualitySeverity::Warning,
                        description: format!(
                            "Field '{}' nullability changed (was_nullable={})",
                            old.field_name, old.nullable
                        ),
                    });
                }
            }
        }
        changes
    }

    pub fn evaluate_evolution_policy(
        &self,
        compatibility: &SchemaCompatibility,
        policy: &SchemaEvolutionPolicy,
    ) -> SchemaEvolutionDecision {
        match compatibility {
            SchemaCompatibility::FullyCompatible
            | SchemaCompatibility::BackwardCompatible { .. } => {
                SchemaEvolutionDecision::Approved {
                    reason: "Schema change is compatible".to_string(),
                }
            }
            SchemaCompatibility::ForwardCompatible { .. } => {
                if policy.require_deprecation_period {
                    let period = policy.deprecation_period_days.clone().unwrap_or_else(|| "30".to_string());
                    SchemaEvolutionDecision::RequiresDeprecationPeriod {
                        field_changes: vec!["fields removed".to_string()],
                        period_days: period,
                    }
                } else {
                    SchemaEvolutionDecision::Approved {
                        reason: "Forward compatible — no deprecation period required".to_string(),
                    }
                }
            }
            SchemaCompatibility::Breaking { breaking_changes } => {
                if !policy.allow_breaking_changes {
                    SchemaEvolutionDecision::Rejected {
                        reason: "Breaking changes are not allowed by policy".to_string(),
                        breaking_changes: breaking_changes.clone(),
                    }
                } else if policy.require_migration_plan {
                    SchemaEvolutionDecision::RequiresMigrationPlan {
                        breaking_changes: breaking_changes.clone(),
                    }
                } else {
                    SchemaEvolutionDecision::Approved {
                        reason: "Breaking changes allowed by policy".to_string(),
                    }
                }
            }
            SchemaCompatibility::Unknown => {
                SchemaEvolutionDecision::Rejected {
                    reason: "Compatibility unknown — cannot approve".to_string(),
                    breaking_changes: Vec::new(),
                }
            }
        }
    }
}

impl Default for SchemaCompatibilityChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SchemaFormat;
    use std::collections::HashMap;

    fn make_field(name: &str, ftype: &str, nullable: bool) -> SchemaField {
        SchemaField {
            field_name: name.into(),
            field_type: ftype.into(),
            nullable,
            description: None,
            sensitivity_label: None,
            constraints: Vec::new(),
        }
    }

    fn make_schema(id: &str, version: &str, fields: Vec<SchemaField>) -> SchemaRecord {
        SchemaRecord {
            schema_id: id.into(),
            dataset_ref: "ds-test".into(),
            version: version.into(),
            fields,
            format: SchemaFormat::JsonSchema,
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
        }
    }

    fn make_strict_policy() -> SchemaEvolutionPolicy {
        SchemaEvolutionPolicy {
            policy_id: "sep-1".into(),
            dataset_ref: "ds-test".into(),
            allow_breaking_changes: false,
            require_compatibility_check: true,
            require_migration_plan: true,
            require_deprecation_period: true,
            deprecation_period_days: Some("30".into()),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_identical_schemas_fully_compatible() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![
            make_field("id", "string", false),
            make_field("name", "string", true),
        ]);
        let new = make_schema("sch-1", "1.1.0", vec![
            make_field("id", "string", false),
            make_field("name", "string", true),
        ]);
        let compat = checker.check_compatibility(&old, &new);
        assert_eq!(compat, SchemaCompatibility::FullyCompatible);
    }

    #[test]
    fn test_field_added_backward_compatible() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![make_field("id", "string", false)]);
        let new = make_schema("sch-1", "1.1.0", vec![
            make_field("id", "string", false),
            make_field("email", "string", true),
        ]);
        let compat = checker.check_compatibility(&old, &new);
        assert!(matches!(compat, SchemaCompatibility::BackwardCompatible { .. }));
    }

    #[test]
    fn test_field_removed_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![
            make_field("id", "string", false),
            make_field("email", "string", false),
        ]);
        let new = make_schema("sch-1", "2.0.0", vec![make_field("id", "string", false)]);
        let compat = checker.check_compatibility(&old, &new);
        assert!(matches!(compat, SchemaCompatibility::Breaking { .. }));
    }

    #[test]
    fn test_field_type_changed_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![make_field("age", "string", false)]);
        let new = make_schema("sch-1", "2.0.0", vec![make_field("age", "int64", false)]);
        let compat = checker.check_compatibility(&old, &new);
        if let SchemaCompatibility::Breaking { breaking_changes } = &compat {
            assert!(breaking_changes.iter().any(|c| matches!(c.change_type, SchemaChangeType::FieldTypeChanged { .. })));
        } else {
            panic!("Expected Breaking compatibility");
        }
    }

    #[test]
    fn test_nullability_changed_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![make_field("email", "string", true)]);
        let new = make_schema("sch-1", "2.0.0", vec![make_field("email", "string", false)]);
        let compat = checker.check_compatibility(&old, &new);
        if let SchemaCompatibility::Breaking { breaking_changes } = &compat {
            assert!(breaking_changes.iter().any(|c| matches!(c.change_type, SchemaChangeType::NullabilityChanged { .. })));
        } else {
            panic!("Expected Breaking compatibility");
        }
    }

    #[test]
    fn test_policy_approves_non_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let compat = SchemaCompatibility::FullyCompatible;
        let policy = make_strict_policy();
        let decision = checker.evaluate_evolution_policy(&compat, &policy);
        assert!(matches!(decision, SchemaEvolutionDecision::Approved { .. }));
    }

    #[test]
    fn test_policy_rejects_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let compat = SchemaCompatibility::Breaking {
            breaking_changes: vec![SchemaBreakingChange {
                change_type: SchemaChangeType::FieldRemoved { field_name: "x".into() },
                severity: QualitySeverity::Critical,
                description: "removed x".into(),
            }],
        };
        let policy = make_strict_policy();
        let decision = checker.evaluate_evolution_policy(&compat, &policy);
        assert!(matches!(decision, SchemaEvolutionDecision::Rejected { .. }));
    }

    #[test]
    fn test_policy_requires_migration_plan() {
        let checker = SchemaCompatibilityChecker::new();
        let compat = SchemaCompatibility::Breaking {
            breaking_changes: vec![SchemaBreakingChange {
                change_type: SchemaChangeType::FieldRemoved { field_name: "y".into() },
                severity: QualitySeverity::Critical,
                description: "removed y".into(),
            }],
        };
        let mut policy = make_strict_policy();
        policy.allow_breaking_changes = true;
        let decision = checker.evaluate_evolution_policy(&compat, &policy);
        assert!(matches!(decision, SchemaEvolutionDecision::RequiresMigrationPlan { .. }));
    }

    #[test]
    fn test_policy_requires_deprecation_period() {
        let checker = SchemaCompatibilityChecker::new();
        let compat = SchemaCompatibility::ForwardCompatible { notes: "optional fields removed".into() };
        let policy = make_strict_policy();
        let decision = checker.evaluate_evolution_policy(&compat, &policy);
        if let SchemaEvolutionDecision::RequiresDeprecationPeriod { period_days, .. } = &decision {
            assert_eq!(period_days, "30");
        } else {
            panic!("Expected RequiresDeprecationPeriod");
        }
    }

    #[test]
    fn test_evolution_decision_display() {
        let decisions = vec![
            SchemaEvolutionDecision::Approved { reason: "ok".into() },
            SchemaEvolutionDecision::Rejected { reason: "no".into(), breaking_changes: Vec::new() },
            SchemaEvolutionDecision::RequiresMigrationPlan { breaking_changes: Vec::new() },
            SchemaEvolutionDecision::RequiresDeprecationPeriod {
                field_changes: Vec::new(), period_days: "30".into(),
            },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }

    #[test]
    fn test_checker_default() {
        let _c = SchemaCompatibilityChecker;
    }

    #[test]
    fn test_nullable_field_removed_not_breaking() {
        let checker = SchemaCompatibilityChecker::new();
        let old = make_schema("sch-1", "1.0.0", vec![
            make_field("id", "string", false),
            make_field("optional_note", "string", true), // nullable — removal is not breaking
        ]);
        let new = make_schema("sch-1", "2.0.0", vec![make_field("id", "string", false)]);
        let compat = checker.check_compatibility(&old, &new);
        // Nullable field removal is not a breaking change (only required fields count)
        assert!(!matches!(compat, SchemaCompatibility::Breaking { .. }));
    }
}
