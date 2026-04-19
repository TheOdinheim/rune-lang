// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Document lifecycle management.
//
// Structured lifecycle state machine with workflow transitions,
// approval gates, lifecycle policies, and policy violation detection.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::DocumentError;

// ── DocumentLifecycleState ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentLifecycleState {
    Draft,
    UnderReview,
    Approved,
    Published,
    Archived,
    Superseded,
    Withdrawn,
}

impl fmt::Display for DocumentLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => f.write_str("draft"),
            Self::UnderReview => f.write_str("under-review"),
            Self::Approved => f.write_str("approved"),
            Self::Published => f.write_str("published"),
            Self::Archived => f.write_str("archived"),
            Self::Superseded => f.write_str("superseded"),
            Self::Withdrawn => f.write_str("withdrawn"),
        }
    }
}

// ── is_valid_transition ─────────────────────────────────────────────

pub fn is_valid_transition(
    from: &DocumentLifecycleState,
    to: &DocumentLifecycleState,
) -> bool {
    use DocumentLifecycleState::*;
    matches!(
        (from, to),
        (Draft, UnderReview)
            | (UnderReview, Approved)
            | (UnderReview, Draft)
            | (Approved, Published)
            | (Approved, Draft)
            | (Published, Archived)
            | (Published, Superseded)
            | (Published, Withdrawn)
            | (Archived, Draft)
            | (Withdrawn, Draft)
    )
}

// ── LifecycleTransition ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LifecycleTransition {
    pub from: DocumentLifecycleState,
    pub to: DocumentLifecycleState,
    pub actor: String,
    pub timestamp: i64,
    pub reason: Option<String>,
    pub requires_approval: bool,
}

// ── DocumentLifecycleTracker ────────────────────────────────────────

#[derive(Debug)]
pub struct DocumentLifecycleTracker {
    pub doc_id: String,
    pub current_state: DocumentLifecycleState,
    pub transitions: Vec<LifecycleTransition>,
    pub created_at: i64,
}

impl DocumentLifecycleTracker {
    pub fn new(doc_id: &str, now: i64) -> Self {
        Self {
            doc_id: doc_id.into(),
            current_state: DocumentLifecycleState::Draft,
            transitions: Vec::new(),
            created_at: now,
        }
    }

    pub fn transition(
        &mut self,
        to: DocumentLifecycleState,
        actor: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<&LifecycleTransition, DocumentError> {
        if !is_valid_transition(&self.current_state, &to) {
            return Err(DocumentError::InvalidStatus {
                from: self.current_state.to_string(),
                to: to.to_string(),
            });
        }

        let requires_approval = matches!(
            to,
            DocumentLifecycleState::Approved | DocumentLifecycleState::Published
        );

        let transition = LifecycleTransition {
            from: self.current_state.clone(),
            to: to.clone(),
            actor: actor.into(),
            timestamp: now,
            reason: reason.map(String::from),
            requires_approval,
        };

        self.current_state = to;
        self.transitions.push(transition);
        Ok(self.transitions.last().unwrap())
    }

    pub fn current_state(&self) -> &DocumentLifecycleState {
        &self.current_state
    }

    pub fn time_in_current_state_ms(&self, now: i64) -> i64 {
        let last_transition_time = self
            .transitions
            .last()
            .map(|t| t.timestamp)
            .unwrap_or(self.created_at);
        now - last_transition_time
    }

    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    pub fn last_actor(&self) -> Option<&str> {
        self.transitions.last().map(|t| t.actor.as_str())
    }

    pub fn was_ever_published(&self) -> bool {
        self.transitions
            .iter()
            .any(|t| t.to == DocumentLifecycleState::Published)
    }
}

// ── ViolationSeverity ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationSeverity {
    Warning,
    Error,
    Critical,
}

impl fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => f.write_str("warning"),
            Self::Error => f.write_str("error"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ── PolicyViolation ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub violation_type: String,
    pub description: String,
    pub severity: ViolationSeverity,
}

// ── LifecyclePolicy ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LifecyclePolicy {
    pub max_draft_duration_ms: Option<i64>,
    pub require_review_before_publish: bool,
    pub auto_archive_after_ms: Option<i64>,
    pub min_reviewers: usize,
}

impl LifecyclePolicy {
    pub fn new() -> Self {
        Self {
            max_draft_duration_ms: None,
            require_review_before_publish: true,
            auto_archive_after_ms: None,
            min_reviewers: 1,
        }
    }
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self::new()
    }
}

pub fn check_policy(
    tracker: &DocumentLifecycleTracker,
    policy: &LifecyclePolicy,
    now: i64,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();

    // Check max draft duration
    if let Some(max_ms) = policy.max_draft_duration_ms {
        if tracker.current_state == DocumentLifecycleState::Draft {
            let time_in_draft = tracker.time_in_current_state_ms(now);
            if time_in_draft > max_ms {
                violations.push(PolicyViolation {
                    violation_type: "max_draft_duration_exceeded".into(),
                    description: format!(
                        "Document has been in draft for {}ms, max allowed is {}ms",
                        time_in_draft, max_ms
                    ),
                    severity: ViolationSeverity::Warning,
                });
            }
        }
    }

    // Check require review before publish
    if policy.require_review_before_publish {
        if tracker.was_ever_published() {
            let went_through_review = tracker
                .transitions
                .iter()
                .any(|t| t.to == DocumentLifecycleState::UnderReview);
            if !went_through_review {
                violations.push(PolicyViolation {
                    violation_type: "missing_review".into(),
                    description: "Document was published without going through review".into(),
                    severity: ViolationSeverity::Error,
                });
            }
        }
    }

    // Check auto archive
    if let Some(archive_ms) = policy.auto_archive_after_ms {
        if tracker.current_state == DocumentLifecycleState::Published {
            let time_published = tracker.time_in_current_state_ms(now);
            if time_published > archive_ms {
                violations.push(PolicyViolation {
                    violation_type: "auto_archive_overdue".into(),
                    description: format!(
                        "Document has been published for {}ms, should be archived after {}ms",
                        time_published, archive_ms
                    ),
                    severity: ViolationSeverity::Warning,
                });
            }
        }
    }

    violations
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_starts_in_draft() {
        let tracker = DocumentLifecycleTracker::new("doc1", 1000);
        assert_eq!(tracker.current_state(), &DocumentLifecycleState::Draft);
    }

    #[test]
    fn test_transition_draft_to_under_review() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        let result = tracker.transition(
            DocumentLifecycleState::UnderReview,
            "reviewer",
            Some("Ready for review"),
            2000,
        );
        assert!(result.is_ok());
        assert_eq!(
            tracker.current_state(),
            &DocumentLifecycleState::UnderReview
        );
    }

    #[test]
    fn test_transition_draft_to_published_fails() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        let result = tracker.transition(
            DocumentLifecycleState::Published,
            "actor",
            None,
            2000,
        );
        assert!(result.is_err());
        assert_eq!(tracker.current_state(), &DocumentLifecycleState::Draft);
    }

    #[test]
    fn test_transition_records_actor_and_reason() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        tracker
            .transition(
                DocumentLifecycleState::UnderReview,
                "alice",
                Some("Initial review"),
                2000,
            )
            .unwrap();
        assert_eq!(tracker.last_actor(), Some("alice"));
        assert_eq!(
            tracker.transitions[0].reason.as_deref(),
            Some("Initial review")
        );
    }

    #[test]
    fn test_time_in_current_state_ms() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        assert_eq!(tracker.time_in_current_state_ms(3000), 2000);
        tracker
            .transition(DocumentLifecycleState::UnderReview, "x", None, 2000)
            .unwrap();
        assert_eq!(tracker.time_in_current_state_ms(5000), 3000);
    }

    #[test]
    fn test_was_ever_published() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        assert!(!tracker.was_ever_published());
        tracker
            .transition(DocumentLifecycleState::UnderReview, "x", None, 2000)
            .unwrap();
        tracker
            .transition(DocumentLifecycleState::Approved, "x", None, 3000)
            .unwrap();
        tracker
            .transition(DocumentLifecycleState::Published, "x", None, 4000)
            .unwrap();
        assert!(tracker.was_ever_published());
    }

    #[test]
    fn test_is_valid_transition_rejects_invalid() {
        assert!(!is_valid_transition(
            &DocumentLifecycleState::Draft,
            &DocumentLifecycleState::Published
        ));
        assert!(!is_valid_transition(
            &DocumentLifecycleState::Superseded,
            &DocumentLifecycleState::Published
        ));
        assert!(!is_valid_transition(
            &DocumentLifecycleState::Archived,
            &DocumentLifecycleState::Published
        ));
    }

    #[test]
    fn test_check_policy_max_draft_duration() {
        let tracker = DocumentLifecycleTracker::new("doc1", 1000);
        let policy = LifecyclePolicy {
            max_draft_duration_ms: Some(5000),
            require_review_before_publish: false,
            auto_archive_after_ms: None,
            min_reviewers: 0,
        };
        let violations = check_policy(&tracker, &policy, 7000);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "max_draft_duration_exceeded");
    }

    #[test]
    fn test_check_policy_missing_review() {
        // Simulate a tracker that somehow published without review
        // (by building transitions manually — in practice, the state machine prevents this
        //  unless the code is bypassed, but the policy check catches it)
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        // Bypass state machine for policy test: directly set transitions
        tracker.transitions.push(LifecycleTransition {
            from: DocumentLifecycleState::Draft,
            to: DocumentLifecycleState::Published,
            actor: "rogue".into(),
            timestamp: 2000,
            reason: None,
            requires_approval: false,
        });
        tracker.current_state = DocumentLifecycleState::Published;

        let policy = LifecyclePolicy {
            max_draft_duration_ms: None,
            require_review_before_publish: true,
            auto_archive_after_ms: None,
            min_reviewers: 1,
        };
        let violations = check_policy(&tracker, &policy, 3000);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "missing_review");
        assert_eq!(violations[0].severity, ViolationSeverity::Error);
    }

    #[test]
    fn test_check_policy_multiple_violations() {
        let mut tracker = DocumentLifecycleTracker::new("doc1", 1000);
        // Bypass state machine to test policy
        tracker.transitions.push(LifecycleTransition {
            from: DocumentLifecycleState::Draft,
            to: DocumentLifecycleState::Published,
            actor: "rogue".into(),
            timestamp: 2000,
            reason: None,
            requires_approval: false,
        });
        tracker.current_state = DocumentLifecycleState::Published;

        let policy = LifecyclePolicy {
            max_draft_duration_ms: None,
            require_review_before_publish: true,
            auto_archive_after_ms: Some(1000),
            min_reviewers: 1,
        };
        let violations = check_policy(&tracker, &policy, 5000);
        assert!(violations.len() >= 2); // missing_review + auto_archive_overdue
    }
}
