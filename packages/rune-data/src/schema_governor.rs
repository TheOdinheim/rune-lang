// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — Schema governor trait. Governs schema evolution at the
// integration boundary. Reference implementations:
// InMemorySchemaGovernor, NullSchemaGovernor.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::schema::{SchemaCompatibility, SchemaEvolutionPolicy, SchemaRecord};
use crate::schema_checker::SchemaCompatibilityChecker;

// ── SchemaGovernanceDecision ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaGovernanceDecision {
    Approved { compatibility: String, policy_ref: String },
    Rejected { breaking_changes: Vec<String>, policy_ref: String },
    RequiresMigrationPlan { changes: Vec<String> },
    RequiresDeprecationPeriod { period_days: String },
}

impl fmt::Display for SchemaGovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved { compatibility, policy_ref } => {
                write!(f, "Approved(compat={compatibility}, policy={policy_ref})")
            }
            Self::Rejected { breaking_changes, policy_ref } => {
                write!(f, "Rejected(changes={}, policy={policy_ref})", breaking_changes.len())
            }
            Self::RequiresMigrationPlan { changes } => {
                write!(f, "RequiresMigrationPlan(changes={})", changes.len())
            }
            Self::RequiresDeprecationPeriod { period_days } => {
                write!(f, "RequiresDeprecationPeriod({period_days} days)")
            }
        }
    }
}

// ── SchemaGovernanceResult ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaGovernanceResult {
    pub schema_id: String,
    pub decision: SchemaGovernanceDecision,
    pub evaluated_at: i64,
}

// ── SchemaHealthStatus ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaHealthStatus {
    Healthy,
    Outdated { reason: String },
    Incompatible { reason: String },
    Unknown,
}

impl fmt::Display for SchemaHealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => f.write_str("Healthy"),
            Self::Outdated { reason } => write!(f, "Outdated: {reason}"),
            Self::Incompatible { reason } => write!(f, "Incompatible: {reason}"),
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ── SchemaHealthAssessment ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaHealthAssessment {
    pub dataset_ref: String,
    pub schema_count: String,
    pub latest_version: Option<String>,
    pub health_status: SchemaHealthStatus,
    pub assessed_at: i64,
}

// ── SchemaGovernor trait ─────────────────────────────────────────────

pub trait SchemaGovernor {
    fn evaluate_schema_change(
        &self,
        old_schema: &SchemaRecord,
        new_schema: &SchemaRecord,
        evaluated_at: i64,
    ) -> SchemaGovernanceResult;

    fn register_evolution_policy(&mut self, policy: SchemaEvolutionPolicy);
    fn remove_evolution_policy(&mut self, policy_id: &str);
    fn list_evolution_policies(&self) -> Vec<&SchemaEvolutionPolicy>;

    fn check_schema_health(
        &self,
        dataset_ref: &str,
        assessed_at: i64,
    ) -> SchemaHealthAssessment;

    fn governor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemorySchemaGovernor ───────────────────────────────────────────

pub struct InMemorySchemaGovernor {
    id: String,
    active: bool,
    checker: SchemaCompatibilityChecker,
    policies: HashMap<String, SchemaEvolutionPolicy>,
    schemas: HashMap<String, Vec<SchemaRecord>>,
}

impl InMemorySchemaGovernor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            checker: SchemaCompatibilityChecker::new(),
            policies: HashMap::new(),
            schemas: HashMap::new(),
        }
    }

    pub fn add_schema(&mut self, record: SchemaRecord) {
        self.schemas.entry(record.dataset_ref.clone()).or_default().push(record);
    }
}

impl SchemaGovernor for InMemorySchemaGovernor {
    fn evaluate_schema_change(
        &self,
        old_schema: &SchemaRecord,
        new_schema: &SchemaRecord,
        evaluated_at: i64,
    ) -> SchemaGovernanceResult {
        let compat = self.checker.check_compatibility(old_schema, new_schema);

        let policy = self.policies.values()
            .find(|p| p.dataset_ref == new_schema.dataset_ref);

        let decision = match policy {
            Some(pol) => {
                let evolution = self.checker.evaluate_evolution_policy(&compat, pol);
                match evolution {
                    crate::schema_checker::SchemaEvolutionDecision::Approved { .. } => {
                        SchemaGovernanceDecision::Approved {
                            compatibility: compat.to_string(),
                            policy_ref: pol.policy_id.clone(),
                        }
                    }
                    crate::schema_checker::SchemaEvolutionDecision::Rejected { breaking_changes, .. } => {
                        SchemaGovernanceDecision::Rejected {
                            breaking_changes: breaking_changes.iter().map(|c| c.description.clone()).collect(),
                            policy_ref: pol.policy_id.clone(),
                        }
                    }
                    crate::schema_checker::SchemaEvolutionDecision::RequiresMigrationPlan { breaking_changes } => {
                        SchemaGovernanceDecision::RequiresMigrationPlan {
                            changes: breaking_changes.iter().map(|c| c.description.clone()).collect(),
                        }
                    }
                    crate::schema_checker::SchemaEvolutionDecision::RequiresDeprecationPeriod { period_days, .. } => {
                        SchemaGovernanceDecision::RequiresDeprecationPeriod { period_days }
                    }
                }
            }
            None => {
                // No policy — approve if not breaking, reject if breaking
                match &compat {
                    SchemaCompatibility::Breaking { breaking_changes } => {
                        SchemaGovernanceDecision::Rejected {
                            breaking_changes: breaking_changes.iter().map(|c| c.description.clone()).collect(),
                            policy_ref: "default".to_string(),
                        }
                    }
                    _ => SchemaGovernanceDecision::Approved {
                        compatibility: compat.to_string(),
                        policy_ref: "default".to_string(),
                    },
                }
            }
        };

        SchemaGovernanceResult {
            schema_id: new_schema.schema_id.clone(),
            decision,
            evaluated_at,
        }
    }

    fn register_evolution_policy(&mut self, policy: SchemaEvolutionPolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }

    fn remove_evolution_policy(&mut self, policy_id: &str) {
        self.policies.remove(policy_id);
    }

    fn list_evolution_policies(&self) -> Vec<&SchemaEvolutionPolicy> {
        self.policies.values().collect()
    }

    fn check_schema_health(
        &self,
        dataset_ref: &str,
        assessed_at: i64,
    ) -> SchemaHealthAssessment {
        let schemas = self.schemas.get(dataset_ref);
        match schemas {
            None => SchemaHealthAssessment {
                dataset_ref: dataset_ref.to_string(),
                schema_count: "0".to_string(),
                latest_version: None,
                health_status: SchemaHealthStatus::Unknown,
                assessed_at,
            },
            Some(list) if list.is_empty() => SchemaHealthAssessment {
                dataset_ref: dataset_ref.to_string(),
                schema_count: "0".to_string(),
                latest_version: None,
                health_status: SchemaHealthStatus::Unknown,
                assessed_at,
            },
            Some(list) => {
                let latest = list.last().unwrap();
                let health = if list.len() >= 2 {
                    let prev = &list[list.len() - 2];
                    let compat = self.checker.check_compatibility(prev, latest);
                    match compat {
                        SchemaCompatibility::Breaking { .. } => SchemaHealthStatus::Incompatible {
                            reason: format!("Latest version {} has breaking changes from {}", latest.version, prev.version),
                        },
                        _ => SchemaHealthStatus::Healthy,
                    }
                } else {
                    SchemaHealthStatus::Healthy
                };
                SchemaHealthAssessment {
                    dataset_ref: dataset_ref.to_string(),
                    schema_count: list.len().to_string(),
                    latest_version: Some(latest.version.clone()),
                    health_status: health,
                    assessed_at,
                }
            }
        }
    }

    fn governor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullSchemaGovernor ───────────────────────────────────────────────

pub struct NullSchemaGovernor;

impl SchemaGovernor for NullSchemaGovernor {
    fn evaluate_schema_change(&self, _old: &SchemaRecord, new: &SchemaRecord, evaluated_at: i64) -> SchemaGovernanceResult {
        SchemaGovernanceResult {
            schema_id: new.schema_id.clone(),
            decision: SchemaGovernanceDecision::Approved {
                compatibility: "FullyCompatible".to_string(),
                policy_ref: "null".to_string(),
            },
            evaluated_at,
        }
    }

    fn register_evolution_policy(&mut self, _policy: SchemaEvolutionPolicy) {}
    fn remove_evolution_policy(&mut self, _policy_id: &str) {}
    fn list_evolution_policies(&self) -> Vec<&SchemaEvolutionPolicy> { Vec::new() }
    fn check_schema_health(&self, dataset_ref: &str, assessed_at: i64) -> SchemaHealthAssessment {
        SchemaHealthAssessment {
            dataset_ref: dataset_ref.to_string(),
            schema_count: "0".to_string(),
            latest_version: None,
            health_status: SchemaHealthStatus::Unknown,
            assessed_at,
        }
    }
    fn governor_id(&self) -> &str { "null-schema-governor" }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{SchemaField, SchemaFormat};

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

    fn make_schema(id: &str, dataset: &str, version: &str, fields: Vec<SchemaField>) -> SchemaRecord {
        SchemaRecord {
            schema_id: id.into(),
            dataset_ref: dataset.into(),
            version: version.into(),
            fields,
            format: SchemaFormat::JsonSchema,
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_approve_compatible_change() {
        let gov = InMemorySchemaGovernor::new("sg-1");
        let old = make_schema("sch-1", "ds-1", "1.0.0", vec![make_field("id", "string", false)]);
        let new = make_schema("sch-1", "ds-1", "1.1.0", vec![
            make_field("id", "string", false),
            make_field("email", "string", true),
        ]);
        let result = gov.evaluate_schema_change(&old, &new, 2000);
        assert!(matches!(result.decision, SchemaGovernanceDecision::Approved { .. }));
    }

    #[test]
    fn test_reject_breaking_change() {
        let gov = InMemorySchemaGovernor::new("sg-1");
        let old = make_schema("sch-1", "ds-1", "1.0.0", vec![
            make_field("id", "string", false),
            make_field("email", "string", false),
        ]);
        let new = make_schema("sch-1", "ds-1", "2.0.0", vec![make_field("id", "string", false)]);
        let result = gov.evaluate_schema_change(&old, &new, 2000);
        assert!(matches!(result.decision, SchemaGovernanceDecision::Rejected { .. }));
    }

    #[test]
    fn test_policy_rejects_breaking() {
        let mut gov = InMemorySchemaGovernor::new("sg-1");
        gov.register_evolution_policy(SchemaEvolutionPolicy {
            policy_id: "sep-1".into(),
            dataset_ref: "ds-1".into(),
            allow_breaking_changes: false,
            require_compatibility_check: true,
            require_migration_plan: true,
            require_deprecation_period: false,
            deprecation_period_days: None,
            created_at: 1000,
            metadata: HashMap::new(),
        });
        let old = make_schema("sch-1", "ds-1", "1.0.0", vec![make_field("email", "string", false)]);
        let new = make_schema("sch-1", "ds-1", "2.0.0", vec![make_field("email", "int64", false)]);
        let result = gov.evaluate_schema_change(&old, &new, 2000);
        assert!(matches!(result.decision, SchemaGovernanceDecision::Rejected { .. }));
    }

    #[test]
    fn test_policy_requires_migration_plan() {
        let mut gov = InMemorySchemaGovernor::new("sg-1");
        gov.register_evolution_policy(SchemaEvolutionPolicy {
            policy_id: "sep-1".into(),
            dataset_ref: "ds-1".into(),
            allow_breaking_changes: true,
            require_compatibility_check: true,
            require_migration_plan: true,
            require_deprecation_period: false,
            deprecation_period_days: None,
            created_at: 1000,
            metadata: HashMap::new(),
        });
        let old = make_schema("sch-1", "ds-1", "1.0.0", vec![make_field("email", "string", false)]);
        let new = make_schema("sch-1", "ds-1", "2.0.0", vec![make_field("email", "int64", false)]);
        let result = gov.evaluate_schema_change(&old, &new, 2000);
        assert!(matches!(result.decision, SchemaGovernanceDecision::RequiresMigrationPlan { .. }));
    }

    #[test]
    fn test_schema_health_unknown_no_schemas() {
        let gov = InMemorySchemaGovernor::new("sg-1");
        let health = gov.check_schema_health("ds-missing", 2000);
        assert_eq!(health.schema_count, "0");
        assert!(matches!(health.health_status, SchemaHealthStatus::Unknown));
    }

    #[test]
    fn test_schema_health_healthy() {
        let mut gov = InMemorySchemaGovernor::new("sg-1");
        gov.add_schema(make_schema("sch-1", "ds-1", "1.0.0", vec![make_field("id", "string", false)]));
        gov.add_schema(make_schema("sch-2", "ds-1", "1.1.0", vec![
            make_field("id", "string", false),
            make_field("name", "string", true),
        ]));
        let health = gov.check_schema_health("ds-1", 2000);
        assert_eq!(health.schema_count, "2");
        assert_eq!(health.latest_version.as_deref(), Some("1.1.0"));
        assert!(matches!(health.health_status, SchemaHealthStatus::Healthy));
    }

    #[test]
    fn test_schema_health_incompatible() {
        let mut gov = InMemorySchemaGovernor::new("sg-1");
        gov.add_schema(make_schema("sch-1", "ds-1", "1.0.0", vec![
            make_field("id", "string", false),
            make_field("email", "string", false),
        ]));
        gov.add_schema(make_schema("sch-2", "ds-1", "2.0.0", vec![
            make_field("id", "string", false),
        ]));
        let health = gov.check_schema_health("ds-1", 2000);
        assert!(matches!(health.health_status, SchemaHealthStatus::Incompatible { .. }));
    }

    #[test]
    fn test_register_remove_policy() {
        let mut gov = InMemorySchemaGovernor::new("sg-1");
        gov.register_evolution_policy(SchemaEvolutionPolicy {
            policy_id: "sep-1".into(), dataset_ref: "ds-1".into(),
            allow_breaking_changes: false, require_compatibility_check: true,
            require_migration_plan: false, require_deprecation_period: false,
            deprecation_period_days: None, created_at: 1000, metadata: HashMap::new(),
        });
        assert_eq!(gov.list_evolution_policies().len(), 1);
        gov.remove_evolution_policy("sep-1");
        assert_eq!(gov.list_evolution_policies().len(), 0);
    }

    #[test]
    fn test_governor_id_and_active() {
        let gov = InMemorySchemaGovernor::new("sg-1");
        assert_eq!(gov.governor_id(), "sg-1");
        assert!(gov.is_active());
    }

    #[test]
    fn test_null_governor() {
        let mut gov = NullSchemaGovernor;
        let s = make_schema("sch-1", "ds-1", "1.0.0", vec![]);
        let result = gov.evaluate_schema_change(&s, &s, 2000);
        assert!(matches!(result.decision, SchemaGovernanceDecision::Approved { .. }));
        let health = gov.check_schema_health("ds-1", 2000);
        assert!(matches!(health.health_status, SchemaHealthStatus::Unknown));
        assert_eq!(gov.governor_id(), "null-schema-governor");
        assert!(!gov.is_active());
        gov.register_evolution_policy(SchemaEvolutionPolicy {
            policy_id: "x".into(), dataset_ref: "x".into(),
            allow_breaking_changes: false, require_compatibility_check: false,
            require_migration_plan: false, require_deprecation_period: false,
            deprecation_period_days: None, created_at: 0, metadata: HashMap::new(),
        });
        gov.remove_evolution_policy("x");
        assert!(gov.list_evolution_policies().is_empty());
    }

    #[test]
    fn test_decision_display() {
        let decisions = vec![
            SchemaGovernanceDecision::Approved { compatibility: "FullyCompatible".into(), policy_ref: "sep-1".into() },
            SchemaGovernanceDecision::Rejected { breaking_changes: vec!["removed field".into()], policy_ref: "sep-1".into() },
            SchemaGovernanceDecision::RequiresMigrationPlan { changes: vec!["type change".into()] },
            SchemaGovernanceDecision::RequiresDeprecationPeriod { period_days: "30".into() },
        ];
        for d in &decisions {
            assert!(!d.to_string().is_empty());
        }
    }

    #[test]
    fn test_health_status_display() {
        let statuses = vec![
            SchemaHealthStatus::Healthy,
            SchemaHealthStatus::Outdated { reason: "old".into() },
            SchemaHealthStatus::Incompatible { reason: "breaking".into() },
            SchemaHealthStatus::Unknown,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
    }
}
