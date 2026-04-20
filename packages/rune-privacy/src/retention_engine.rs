// ═══════════════════════════════════════════════════════════════════════
// Retention Engine — Pluggable retention policy evaluation.
//
// RetentionDecision includes LegalHold as a first-class outcome because
// a retention engine that cannot model legal hold produces incorrect
// deletion decisions under investigation. LegalHold prevents retention-
// driven deletion when a record is subject to litigation hold, regulatory
// investigation, or statutory preservation obligation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::backend::SubjectRef;
use crate::error::PrivacyError;

// ── RetentionDecision ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionDecision {
    Retain { next_check_at: i64 },
    MarkForDeletion { reason: String },
    RequireReview { reason: String },
    LegalHold { hold_reason: String, held_until: Option<i64> },
}

impl fmt::Display for RetentionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retain { next_check_at } => write!(f, "Retain(next_check={next_check_at})"),
            Self::MarkForDeletion { reason } => write!(f, "MarkForDeletion({reason})"),
            Self::RequireReview { reason } => write!(f, "RequireReview({reason})"),
            Self::LegalHold { hold_reason, .. } => write!(f, "LegalHold({hold_reason})"),
        }
    }
}

// ── RetentionRecord ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionRecord {
    pub record_id: String,
    pub subject_ref: SubjectRef,
    pub data_category: String,
    pub created_at: i64,
    pub purpose: String,
    pub metadata: HashMap<String, String>,
}

impl RetentionRecord {
    pub fn new(record_id: &str, subject_ref: SubjectRef, category: &str, created_at: i64, purpose: &str) -> Self {
        Self {
            record_id: record_id.to_string(),
            subject_ref,
            data_category: category.to_string(),
            created_at,
            purpose: purpose.to_string(),
            metadata: HashMap::new(),
        }
    }
}

// ── RetentionPolicyDef ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionPolicyDef {
    pub policy_id: String,
    pub applies_to: String,
    pub minimum_retention_days: u64,
    pub maximum_retention_days: u64,
    pub deletion_strategy: String,
}

// ── RetentionPolicyEngine trait ─────────────────────────────────────

pub trait RetentionPolicyEngine {
    fn evaluate(&self, record: &RetentionRecord, policy: &RetentionPolicyDef, now: i64) -> Result<RetentionDecision, PrivacyError>;
    fn schedule_next_evaluation(&self, record: &RetentionRecord, policy: &RetentionPolicyDef, now: i64) -> i64;
    fn record_deletion_outcome(&mut self, record_id: &str, deleted: bool, timestamp: i64);
    fn engine_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── TimeBasedRetentionEngine ────────────────────────────────────────

pub struct TimeBasedRetentionEngine {
    id: String,
    deletion_outcomes: Vec<(String, bool, i64)>,
}

impl TimeBasedRetentionEngine {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string(), deletion_outcomes: Vec::new() }
    }
}

impl RetentionPolicyEngine for TimeBasedRetentionEngine {
    fn evaluate(&self, record: &RetentionRecord, policy: &RetentionPolicyDef, now: i64) -> Result<RetentionDecision, PrivacyError> {
        let age_days = (now - record.created_at) / (24 * 60 * 60 * 1000);
        if age_days < policy.minimum_retention_days as i64 {
            let next = record.created_at + (policy.minimum_retention_days as i64 * 24 * 60 * 60 * 1000);
            return Ok(RetentionDecision::Retain { next_check_at: next });
        }
        if age_days > policy.maximum_retention_days as i64 {
            return Ok(RetentionDecision::MarkForDeletion {
                reason: format!("record age ({age_days} days) exceeds maximum retention ({} days)", policy.maximum_retention_days),
            });
        }
        let next = now + (30 * 24 * 60 * 60 * 1000); // check again in 30 days
        Ok(RetentionDecision::Retain { next_check_at: next })
    }

    fn schedule_next_evaluation(&self, _record: &RetentionRecord, _policy: &RetentionPolicyDef, now: i64) -> i64 {
        now + (30 * 24 * 60 * 60 * 1000)
    }

    fn record_deletion_outcome(&mut self, record_id: &str, deleted: bool, timestamp: i64) {
        self.deletion_outcomes.push((record_id.to_string(), deleted, timestamp));
    }

    fn engine_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── EventBasedRetentionEngine ───────────────────────────────────────

pub struct EventBasedRetentionEngine {
    id: String,
    days_after_event: u64,
    deletion_outcomes: Vec<(String, bool, i64)>,
}

impl EventBasedRetentionEngine {
    pub fn new(id: &str, days_after_event: u64) -> Self {
        Self { id: id.to_string(), days_after_event, deletion_outcomes: Vec::new() }
    }
}

impl RetentionPolicyEngine for EventBasedRetentionEngine {
    fn evaluate(&self, record: &RetentionRecord, _policy: &RetentionPolicyDef, now: i64) -> Result<RetentionDecision, PrivacyError> {
        let age_days = (now - record.created_at) / (24 * 60 * 60 * 1000);
        if age_days > self.days_after_event as i64 {
            return Ok(RetentionDecision::MarkForDeletion {
                reason: format!("record is {age_days} days past triggering event (limit: {} days)", self.days_after_event),
            });
        }
        let next = record.created_at + (self.days_after_event as i64 * 24 * 60 * 60 * 1000);
        Ok(RetentionDecision::Retain { next_check_at: next })
    }

    fn schedule_next_evaluation(&self, record: &RetentionRecord, _policy: &RetentionPolicyDef, _now: i64) -> i64 {
        record.created_at + (self.days_after_event as i64 * 24 * 60 * 60 * 1000)
    }

    fn record_deletion_outcome(&mut self, record_id: &str, deleted: bool, timestamp: i64) {
        self.deletion_outcomes.push((record_id.to_string(), deleted, timestamp));
    }

    fn engine_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── PurposeBasedRetentionEngine ─────────────────────────────────────

pub struct PurposeBasedRetentionEngine {
    id: String,
    active_purposes: Vec<String>,
    deletion_outcomes: Vec<(String, bool, i64)>,
}

impl PurposeBasedRetentionEngine {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string(), active_purposes: Vec::new(), deletion_outcomes: Vec::new() }
    }

    pub fn set_active_purposes(&mut self, purposes: Vec<String>) {
        self.active_purposes = purposes;
    }
}

impl RetentionPolicyEngine for PurposeBasedRetentionEngine {
    fn evaluate(&self, record: &RetentionRecord, _policy: &RetentionPolicyDef, now: i64) -> Result<RetentionDecision, PrivacyError> {
        if self.active_purposes.contains(&record.purpose) {
            let next = now + (30 * 24 * 60 * 60 * 1000);
            return Ok(RetentionDecision::Retain { next_check_at: next });
        }
        Ok(RetentionDecision::MarkForDeletion {
            reason: format!("purpose '{}' is no longer active", record.purpose),
        })
    }

    fn schedule_next_evaluation(&self, _record: &RetentionRecord, _policy: &RetentionPolicyDef, now: i64) -> i64 {
        now + (30 * 24 * 60 * 60 * 1000)
    }

    fn record_deletion_outcome(&mut self, record_id: &str, deleted: bool, timestamp: i64) {
        self.deletion_outcomes.push((record_id.to_string(), deleted, timestamp));
    }

    fn engine_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── LegalHoldAwareRetentionEngine ───────────────────────────────────

pub struct LegalHoldAwareRetentionEngine {
    id: String,
    inner: Box<dyn RetentionPolicyEngine>,
    held_subjects: HashMap<String, String>,
    deletion_outcomes: Vec<(String, bool, i64)>,
}

impl LegalHoldAwareRetentionEngine {
    pub fn new(id: &str, inner: Box<dyn RetentionPolicyEngine>) -> Self {
        Self {
            id: id.to_string(),
            inner,
            held_subjects: HashMap::new(),
            deletion_outcomes: Vec::new(),
        }
    }

    pub fn place_hold(&mut self, subject_ref: &SubjectRef, reason: &str) {
        self.held_subjects.insert(subject_ref.as_str().to_string(), reason.to_string());
    }

    pub fn release_hold(&mut self, subject_ref: &SubjectRef) {
        self.held_subjects.remove(subject_ref.as_str());
    }

    pub fn is_held(&self, subject_ref: &SubjectRef) -> bool {
        self.held_subjects.contains_key(subject_ref.as_str())
    }
}

impl RetentionPolicyEngine for LegalHoldAwareRetentionEngine {
    fn evaluate(&self, record: &RetentionRecord, policy: &RetentionPolicyDef, now: i64) -> Result<RetentionDecision, PrivacyError> {
        if let Some(reason) = self.held_subjects.get(record.subject_ref.as_str()) {
            return Ok(RetentionDecision::LegalHold {
                hold_reason: reason.clone(),
                held_until: None,
            });
        }
        self.inner.evaluate(record, policy, now)
    }

    fn schedule_next_evaluation(&self, record: &RetentionRecord, policy: &RetentionPolicyDef, now: i64) -> i64 {
        self.inner.schedule_next_evaluation(record, policy, now)
    }

    fn record_deletion_outcome(&mut self, record_id: &str, deleted: bool, timestamp: i64) {
        self.deletion_outcomes.push((record_id.to_string(), deleted, timestamp));
    }

    fn engine_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.inner.is_active() }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    fn make_record(id: &str, created_at: i64) -> RetentionRecord {
        RetentionRecord::new(id, SubjectRef::new("alice"), "email", created_at, "analytics")
    }

    fn make_policy() -> RetentionPolicyDef {
        RetentionPolicyDef {
            policy_id: "p1".to_string(),
            applies_to: "email".to_string(),
            minimum_retention_days: 30,
            maximum_retention_days: 365,
            deletion_strategy: "Anonymize".to_string(),
        }
    }

    #[test]
    fn test_time_based_retain() {
        let engine = TimeBasedRetentionEngine::new("tb-1");
        let record = make_record("r1", 1000);
        let now = 1000 + (60 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::Retain { .. }));
    }

    #[test]
    fn test_time_based_delete() {
        let engine = TimeBasedRetentionEngine::new("tb-1");
        let record = make_record("r1", 1000);
        let now = 1000 + (400 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::MarkForDeletion { .. }));
    }

    #[test]
    fn test_time_based_too_young() {
        let engine = TimeBasedRetentionEngine::new("tb-1");
        let record = make_record("r1", 1000);
        let now = 1000 + (10 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::Retain { .. }));
    }

    #[test]
    fn test_event_based_retain() {
        let engine = EventBasedRetentionEngine::new("eb-1", 90);
        let record = make_record("r1", 1000);
        let now = 1000 + (30 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::Retain { .. }));
    }

    #[test]
    fn test_event_based_delete() {
        let engine = EventBasedRetentionEngine::new("eb-1", 90);
        let record = make_record("r1", 1000);
        let now = 1000 + (100 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::MarkForDeletion { .. }));
    }

    #[test]
    fn test_purpose_based_retain() {
        let mut engine = PurposeBasedRetentionEngine::new("pb-1");
        engine.set_active_purposes(vec!["analytics".to_string()]);
        let record = make_record("r1", 1000);
        let decision = engine.evaluate(&record, &make_policy(), 5000).unwrap();
        assert!(matches!(decision, RetentionDecision::Retain { .. }));
    }

    #[test]
    fn test_purpose_based_delete() {
        let mut engine = PurposeBasedRetentionEngine::new("pb-1");
        engine.set_active_purposes(vec!["marketing".to_string()]);
        let record = make_record("r1", 1000);
        let decision = engine.evaluate(&record, &make_policy(), 5000).unwrap();
        assert!(matches!(decision, RetentionDecision::MarkForDeletion { .. }));
    }

    #[test]
    fn test_legal_hold_overrides() {
        let inner = TimeBasedRetentionEngine::new("tb-1");
        let mut engine = LegalHoldAwareRetentionEngine::new("lh-1", Box::new(inner));
        engine.place_hold(&SubjectRef::new("alice"), "litigation");

        let record = make_record("r1", 1000);
        let now = 1000 + (400 * DAY_MS); // would normally delete
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::LegalHold { .. }));
    }

    #[test]
    fn test_legal_hold_release() {
        let inner = TimeBasedRetentionEngine::new("tb-1");
        let mut engine = LegalHoldAwareRetentionEngine::new("lh-1", Box::new(inner));
        engine.place_hold(&SubjectRef::new("alice"), "litigation");
        assert!(engine.is_held(&SubjectRef::new("alice")));
        engine.release_hold(&SubjectRef::new("alice"));
        assert!(!engine.is_held(&SubjectRef::new("alice")));

        let record = make_record("r1", 1000);
        let now = 1000 + (400 * DAY_MS);
        let decision = engine.evaluate(&record, &make_policy(), now).unwrap();
        assert!(matches!(decision, RetentionDecision::MarkForDeletion { .. }));
    }

    #[test]
    fn test_retention_decision_display() {
        assert!(RetentionDecision::Retain { next_check_at: 100 }.to_string().contains("Retain"));
        assert!(RetentionDecision::MarkForDeletion { reason: "old".into() }.to_string().contains("MarkForDeletion"));
        assert!(RetentionDecision::RequireReview { reason: "check".into() }.to_string().contains("RequireReview"));
        assert!(RetentionDecision::LegalHold { hold_reason: "lit".into(), held_until: None }.to_string().contains("LegalHold"));
    }

    #[test]
    fn test_record_deletion_outcome() {
        let mut engine = TimeBasedRetentionEngine::new("tb-1");
        engine.record_deletion_outcome("r1", true, 5000);
        assert_eq!(engine.engine_id(), "tb-1");
        assert!(engine.is_active());
    }

    #[test]
    fn test_schedule_next_evaluation() {
        let engine = TimeBasedRetentionEngine::new("tb-1");
        let record = make_record("r1", 1000);
        let next = engine.schedule_next_evaluation(&record, &make_policy(), 5000);
        assert!(next > 5000);
    }
}
