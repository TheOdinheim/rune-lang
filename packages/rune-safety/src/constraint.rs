// ═══════════════════════════════════════════════════════════════════════
// Constraint — Safety constraints as typed predicates that can be
// verified at compile time or evaluated at runtime.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;
use crate::integrity::SafetyIntegrityLevel;

// ── ConstraintId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConstraintId(pub String);

impl ConstraintId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ConstraintId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ConstraintType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintType {
    Invariant,
    Precondition,
    Postcondition,
    BoundaryConstraint,
    TimingConstraint,
    ResourceConstraint,
    BehavioralConstraint,
    DataConstraint,
}

impl fmt::Display for ConstraintType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Invariant => "Invariant",
            Self::Precondition => "Precondition",
            Self::Postcondition => "Postcondition",
            Self::BoundaryConstraint => "BoundaryConstraint",
            Self::TimingConstraint => "TimingConstraint",
            Self::ResourceConstraint => "ResourceConstraint",
            Self::BehavioralConstraint => "BehavioralConstraint",
            Self::DataConstraint => "DataConstraint",
        };
        f.write_str(s)
    }
}

// ── ConstraintSeverity ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConstraintSeverity {
    Advisory = 0,
    Caution = 1,
    Warning = 2,
    Critical = 3,
    Catastrophic = 4,
}

impl fmt::Display for ConstraintSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Advisory => "Advisory",
            Self::Caution => "Caution",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
            Self::Catastrophic => "Catastrophic",
        };
        f.write_str(s)
    }
}

// ── SafetyCondition ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SafetyCondition {
    ValueInRange { field: String, min: f64, max: f64 },
    ValueAbove { field: String, threshold: f64 },
    ValueBelow { field: String, threshold: f64 },
    ValueEquals { field: String, expected: String },
    FieldPresent { field: String },
    FieldAbsent { field: String },
    LatencyBelow { max_ms: f64 },
    And(Vec<SafetyCondition>),
    Or(Vec<SafetyCondition>),
    Not(Box<SafetyCondition>),
    Custom { name: String, description: String },
}

// ── SafetyConstraint ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConstraint {
    pub id: ConstraintId,
    pub name: String,
    pub description: String,
    pub constraint_type: ConstraintType,
    pub condition: SafetyCondition,
    pub severity: ConstraintSeverity,
    pub integrity_level: SafetyIntegrityLevel,
    pub active: bool,
    pub verified: bool,
    pub verification_method: Option<String>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl SafetyConstraint {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        constraint_type: ConstraintType,
        condition: SafetyCondition,
        severity: ConstraintSeverity,
    ) -> Self {
        Self {
            id: ConstraintId::new(id),
            name: name.into(),
            description: String::new(),
            constraint_type,
            condition,
            severity,
            integrity_level: SafetyIntegrityLevel::Sil0,
            active: true,
            verified: false,
            verification_method: None,
            created_at: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_integrity_level(mut self, level: SafetyIntegrityLevel) -> Self {
        self.integrity_level = level;
        self
    }

    pub fn with_verified(mut self, method: impl Into<String>) -> Self {
        self.verified = true;
        self.verification_method = Some(method.into());
        self
    }
}

// ── ConstraintEvaluation ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConstraintEvaluation {
    pub constraint_id: ConstraintId,
    pub satisfied: bool,
    pub detail: String,
    pub evaluated_at: i64,
    pub context_snapshot: HashMap<String, String>,
}

// ── evaluate_safety_condition ─────────────────────────────────────────

pub fn evaluate_safety_condition(
    condition: &SafetyCondition,
    context: &HashMap<String, String>,
) -> bool {
    match condition {
        SafetyCondition::ValueInRange { field, min, max } => {
            context
                .get(field)
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| v >= *min && v <= *max)
                .unwrap_or(false)
        }
        SafetyCondition::ValueAbove { field, threshold } => {
            context
                .get(field)
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| v > *threshold)
                .unwrap_or(false)
        }
        SafetyCondition::ValueBelow { field, threshold } => {
            context
                .get(field)
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| v < *threshold)
                .unwrap_or(false)
        }
        SafetyCondition::ValueEquals { field, expected } => {
            context.get(field).map(|v| v == expected).unwrap_or(false)
        }
        SafetyCondition::FieldPresent { field } => context.contains_key(field),
        SafetyCondition::FieldAbsent { field } => !context.contains_key(field),
        SafetyCondition::LatencyBelow { max_ms } => {
            context
                .get("latency_ms")
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| v < *max_ms)
                .unwrap_or(false)
        }
        SafetyCondition::And(conditions) => {
            conditions.iter().all(|c| evaluate_safety_condition(c, context))
        }
        SafetyCondition::Or(conditions) => {
            conditions.iter().any(|c| evaluate_safety_condition(c, context))
        }
        SafetyCondition::Not(inner) => !evaluate_safety_condition(inner, context),
        SafetyCondition::Custom { .. } => true, // placeholder for external verification
    }
}

// ── ConstraintStore ───────────────────────────────────────────────────

pub struct ConstraintStore {
    constraints: HashMap<ConstraintId, SafetyConstraint>,
}

impl ConstraintStore {
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
        }
    }

    pub fn add(&mut self, constraint: SafetyConstraint) -> Result<(), SafetyError> {
        if self.constraints.contains_key(&constraint.id) {
            return Err(SafetyError::ConstraintAlreadyExists(constraint.id.0.clone()));
        }
        self.constraints.insert(constraint.id.clone(), constraint);
        Ok(())
    }

    pub fn get(&self, id: &ConstraintId) -> Option<&SafetyConstraint> {
        self.constraints.get(id)
    }

    pub fn evaluate_all(
        &self,
        context: &HashMap<String, String>,
        now: i64,
    ) -> Vec<ConstraintEvaluation> {
        self.constraints
            .values()
            .filter(|c| c.active)
            .map(|c| {
                let satisfied = evaluate_safety_condition(&c.condition, context);
                ConstraintEvaluation {
                    constraint_id: c.id.clone(),
                    satisfied,
                    detail: if satisfied {
                        "Constraint satisfied".into()
                    } else {
                        format!("Constraint '{}' violated", c.name)
                    },
                    evaluated_at: now,
                    context_snapshot: context.clone(),
                }
            })
            .collect()
    }

    pub fn violated(
        &self,
        context: &HashMap<String, String>,
        now: i64,
    ) -> Vec<(&SafetyConstraint, ConstraintEvaluation)> {
        self.constraints
            .values()
            .filter(|c| c.active)
            .filter_map(|c| {
                let satisfied = evaluate_safety_condition(&c.condition, context);
                if !satisfied {
                    Some((
                        c,
                        ConstraintEvaluation {
                            constraint_id: c.id.clone(),
                            satisfied: false,
                            detail: format!("Constraint '{}' violated", c.name),
                            evaluated_at: now,
                            context_snapshot: context.clone(),
                        },
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn by_type(&self, constraint_type: &ConstraintType) -> Vec<&SafetyConstraint> {
        self.constraints
            .values()
            .filter(|c| &c.constraint_type == constraint_type)
            .collect()
    }

    pub fn by_severity(&self, severity: ConstraintSeverity) -> Vec<&SafetyConstraint> {
        self.constraints
            .values()
            .filter(|c| c.severity == severity)
            .collect()
    }

    pub fn by_integrity_level(&self, level: SafetyIntegrityLevel) -> Vec<&SafetyConstraint> {
        self.constraints
            .values()
            .filter(|c| c.integrity_level == level)
            .collect()
    }

    pub fn verified_constraints(&self) -> Vec<&SafetyConstraint> {
        self.constraints.values().filter(|c| c.verified).collect()
    }

    pub fn unverified_constraints(&self) -> Vec<&SafetyConstraint> {
        self.constraints.values().filter(|c| !c.verified).collect()
    }

    pub fn count(&self) -> usize {
        self.constraints.len()
    }
}

impl Default for ConstraintStore {
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

    fn sample_constraint(id: &str, severity: ConstraintSeverity) -> SafetyConstraint {
        SafetyConstraint::new(
            id,
            format!("Constraint {id}"),
            ConstraintType::Invariant,
            SafetyCondition::ValueAbove {
                field: "confidence".into(),
                threshold: 0.5,
            },
            severity,
        )
    }

    #[test]
    fn test_constraint_construction() {
        let c = SafetyConstraint::new(
            "sc-001",
            "Min confidence",
            ConstraintType::Invariant,
            SafetyCondition::ValueAbove {
                field: "confidence".into(),
                threshold: 0.5,
            },
            ConstraintSeverity::Critical,
        )
        .with_description("Model must have >0.5 confidence")
        .with_integrity_level(SafetyIntegrityLevel::Sil3)
        .with_verified("formal proof");
        assert_eq!(c.id.0, "sc-001");
        assert!(c.verified);
        assert_eq!(c.verification_method.unwrap(), "formal proof");
        assert_eq!(c.integrity_level, SafetyIntegrityLevel::Sil3);
    }

    #[test]
    fn test_constraint_type_display() {
        let types = vec![
            ConstraintType::Invariant,
            ConstraintType::Precondition,
            ConstraintType::Postcondition,
            ConstraintType::BoundaryConstraint,
            ConstraintType::TimingConstraint,
            ConstraintType::ResourceConstraint,
            ConstraintType::BehavioralConstraint,
            ConstraintType::DataConstraint,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 8);
    }

    #[test]
    fn test_constraint_severity_ordering() {
        assert!(ConstraintSeverity::Advisory < ConstraintSeverity::Caution);
        assert!(ConstraintSeverity::Caution < ConstraintSeverity::Warning);
        assert!(ConstraintSeverity::Warning < ConstraintSeverity::Critical);
        assert!(ConstraintSeverity::Critical < ConstraintSeverity::Catastrophic);
    }

    #[test]
    fn test_eval_value_in_range_satisfied() {
        let cond = SafetyCondition::ValueInRange {
            field: "temp".into(),
            min: 0.0,
            max: 100.0,
        };
        let mut ctx = HashMap::new();
        ctx.insert("temp".into(), "50.0".into());
        assert!(evaluate_safety_condition(&cond, &ctx));
    }

    #[test]
    fn test_eval_value_in_range_violated() {
        let cond = SafetyCondition::ValueInRange {
            field: "temp".into(),
            min: 0.0,
            max: 100.0,
        };
        let mut ctx = HashMap::new();
        ctx.insert("temp".into(), "150.0".into());
        assert!(!evaluate_safety_condition(&cond, &ctx));
    }

    #[test]
    fn test_eval_value_above_and_below() {
        let mut ctx = HashMap::new();
        ctx.insert("score".into(), "0.8".into());
        assert!(evaluate_safety_condition(
            &SafetyCondition::ValueAbove { field: "score".into(), threshold: 0.5 },
            &ctx,
        ));
        assert!(evaluate_safety_condition(
            &SafetyCondition::ValueBelow { field: "score".into(), threshold: 0.9 },
            &ctx,
        ));
        assert!(!evaluate_safety_condition(
            &SafetyCondition::ValueAbove { field: "score".into(), threshold: 0.9 },
            &ctx,
        ));
    }

    #[test]
    fn test_eval_value_equals() {
        let mut ctx = HashMap::new();
        ctx.insert("mode".into(), "safe".into());
        assert!(evaluate_safety_condition(
            &SafetyCondition::ValueEquals { field: "mode".into(), expected: "safe".into() },
            &ctx,
        ));
        assert!(!evaluate_safety_condition(
            &SafetyCondition::ValueEquals { field: "mode".into(), expected: "normal".into() },
            &ctx,
        ));
    }

    #[test]
    fn test_eval_field_present_absent() {
        let mut ctx = HashMap::new();
        ctx.insert("key".into(), "val".into());
        assert!(evaluate_safety_condition(
            &SafetyCondition::FieldPresent { field: "key".into() },
            &ctx,
        ));
        assert!(!evaluate_safety_condition(
            &SafetyCondition::FieldPresent { field: "missing".into() },
            &ctx,
        ));
        assert!(evaluate_safety_condition(
            &SafetyCondition::FieldAbsent { field: "missing".into() },
            &ctx,
        ));
        assert!(!evaluate_safety_condition(
            &SafetyCondition::FieldAbsent { field: "key".into() },
            &ctx,
        ));
    }

    #[test]
    fn test_eval_latency_below() {
        let mut ctx = HashMap::new();
        ctx.insert("latency_ms".into(), "5.0".into());
        assert!(evaluate_safety_condition(
            &SafetyCondition::LatencyBelow { max_ms: 10.0 },
            &ctx,
        ));
        ctx.insert("latency_ms".into(), "15.0".into());
        assert!(!evaluate_safety_condition(
            &SafetyCondition::LatencyBelow { max_ms: 10.0 },
            &ctx,
        ));
    }

    #[test]
    fn test_eval_and_combinator() {
        let cond = SafetyCondition::And(vec![
            SafetyCondition::FieldPresent { field: "a".into() },
            SafetyCondition::FieldPresent { field: "b".into() },
        ]);
        let mut ctx = HashMap::new();
        ctx.insert("a".into(), "1".into());
        ctx.insert("b".into(), "2".into());
        assert!(evaluate_safety_condition(&cond, &ctx));

        let ctx2 = HashMap::from([("a".into(), "1".into())]);
        assert!(!evaluate_safety_condition(&cond, &ctx2));
    }

    #[test]
    fn test_eval_or_combinator() {
        let cond = SafetyCondition::Or(vec![
            SafetyCondition::FieldPresent { field: "a".into() },
            SafetyCondition::FieldPresent { field: "b".into() },
        ]);
        let ctx = HashMap::from([("b".into(), "1".into())]);
        assert!(evaluate_safety_condition(&cond, &ctx));

        let empty: HashMap<String, String> = HashMap::new();
        assert!(!evaluate_safety_condition(&cond, &empty));
    }

    #[test]
    fn test_eval_not_combinator() {
        let cond = SafetyCondition::Not(Box::new(SafetyCondition::FieldPresent {
            field: "dangerous".into(),
        }));
        let empty: HashMap<String, String> = HashMap::new();
        assert!(evaluate_safety_condition(&cond, &empty));

        let ctx = HashMap::from([("dangerous".into(), "true".into())]);
        assert!(!evaluate_safety_condition(&cond, &ctx));
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = ConstraintStore::new();
        store.add(sample_constraint("c1", ConstraintSeverity::Critical)).unwrap();
        assert!(store.get(&ConstraintId::new("c1")).is_some());
        assert!(store.get(&ConstraintId::new("c2")).is_none());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_store_evaluate_all() {
        let mut store = ConstraintStore::new();
        store.add(sample_constraint("c1", ConstraintSeverity::Critical)).unwrap();
        store.add(sample_constraint("c2", ConstraintSeverity::Warning)).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.8".into())]);
        let results = store.evaluate_all(&ctx, 1000);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.satisfied));
    }

    #[test]
    fn test_store_violated() {
        let mut store = ConstraintStore::new();
        store.add(sample_constraint("c1", ConstraintSeverity::Critical)).unwrap();
        let ctx = HashMap::from([("confidence".into(), "0.3".into())]);
        let violated = store.violated(&ctx, 1000);
        assert_eq!(violated.len(), 1);
        assert_eq!(violated[0].0.id.0, "c1");
    }

    #[test]
    fn test_store_by_type() {
        let mut store = ConstraintStore::new();
        store.add(sample_constraint("c1", ConstraintSeverity::Critical)).unwrap();
        assert_eq!(store.by_type(&ConstraintType::Invariant).len(), 1);
        assert_eq!(store.by_type(&ConstraintType::Precondition).len(), 0);
    }

    #[test]
    fn test_store_by_severity_and_integrity() {
        let mut store = ConstraintStore::new();
        store.add(sample_constraint("c1", ConstraintSeverity::Critical)).unwrap();
        store.add(sample_constraint("c2", ConstraintSeverity::Warning)).unwrap();
        assert_eq!(store.by_severity(ConstraintSeverity::Critical).len(), 1);
        assert_eq!(store.by_integrity_level(SafetyIntegrityLevel::Sil0).len(), 2);
    }

    #[test]
    fn test_store_verified_unverified() {
        let mut store = ConstraintStore::new();
        store
            .add(sample_constraint("c1", ConstraintSeverity::Critical).with_verified("testing"))
            .unwrap();
        store.add(sample_constraint("c2", ConstraintSeverity::Warning)).unwrap();
        assert_eq!(store.verified_constraints().len(), 1);
        assert_eq!(store.unverified_constraints().len(), 1);
    }
}
