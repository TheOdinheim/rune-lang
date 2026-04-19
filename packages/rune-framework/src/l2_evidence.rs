// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Framework-specific evidence collection tracking.
//
// Tracks evidence requirements per framework control, monitors
// collection status, and identifies overdue or missing evidence.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── CollectionStatus ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionStatus {
    NotStarted,
    InProgress,
    Collected,
    Verified,
    Overdue,
}

impl fmt::Display for CollectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotStarted => "NotStarted",
            Self::InProgress => "InProgress",
            Self::Collected => "Collected",
            Self::Verified => "Verified",
            Self::Overdue => "Overdue",
        };
        f.write_str(s)
    }
}

// ── EvidenceRequirement ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EvidenceRequirement {
    pub requirement_id: String,
    pub framework_id: String,
    pub control_id: String,
    pub description: String,
    pub due_date: Option<i64>,
    pub status: CollectionStatus,
    pub assignee: String,
    pub collected_at: Option<i64>,
}

impl EvidenceRequirement {
    pub fn new(
        requirement_id: impl Into<String>,
        framework_id: impl Into<String>,
        control_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            requirement_id: requirement_id.into(),
            framework_id: framework_id.into(),
            control_id: control_id.into(),
            description: description.into(),
            due_date: None,
            status: CollectionStatus::NotStarted,
            assignee: String::new(),
            collected_at: None,
        }
    }

    pub fn with_due_date(mut self, due_date: i64) -> Self {
        self.due_date = Some(due_date);
        self
    }

    pub fn with_assignee(mut self, assignee: impl Into<String>) -> Self {
        self.assignee = assignee.into();
        self
    }

    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            CollectionStatus::Collected | CollectionStatus::Verified
        )
    }

    pub fn is_overdue(&self, now: i64) -> bool {
        if self.is_complete() {
            return false;
        }
        self.due_date.is_some_and(|d| now > d)
    }
}

// ── EvidenceCollectionTracker ─────────────────────────────────────

#[derive(Debug, Default)]
pub struct EvidenceCollectionTracker {
    requirements: HashMap<String, EvidenceRequirement>,
}

impl EvidenceCollectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_requirement(&mut self, req: EvidenceRequirement) {
        self.requirements.insert(req.requirement_id.clone(), req);
    }

    pub fn get(&self, requirement_id: &str) -> Option<&EvidenceRequirement> {
        self.requirements.get(requirement_id)
    }

    pub fn update_status(&mut self, requirement_id: &str, status: CollectionStatus, now: i64) -> bool {
        if let Some(req) = self.requirements.get_mut(requirement_id) {
            req.status = status.clone();
            if matches!(status, CollectionStatus::Collected | CollectionStatus::Verified) {
                req.collected_at = Some(now);
            }
            true
        } else {
            false
        }
    }

    pub fn requirements_for_framework(&self, framework_id: &str) -> Vec<&EvidenceRequirement> {
        self.requirements
            .values()
            .filter(|r| r.framework_id == framework_id)
            .collect()
    }

    pub fn requirements_for_control(
        &self,
        framework_id: &str,
        control_id: &str,
    ) -> Vec<&EvidenceRequirement> {
        self.requirements
            .values()
            .filter(|r| r.framework_id == framework_id && r.control_id == control_id)
            .collect()
    }

    pub fn overdue_requirements(&self, now: i64) -> Vec<&EvidenceRequirement> {
        self.requirements
            .values()
            .filter(|r| r.is_overdue(now))
            .collect()
    }

    pub fn completion_rate(&self, framework_id: &str) -> f64 {
        let reqs: Vec<_> = self.requirements_for_framework(framework_id);
        if reqs.is_empty() {
            return 0.0;
        }
        let complete = reqs.iter().filter(|r| r.is_complete()).count();
        complete as f64 / reqs.len() as f64
    }

    pub fn requirement_count(&self) -> usize {
        self.requirements.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_requirement_is_overdue() {
        let req = EvidenceRequirement::new("r-1", "nist", "GOV-1", "Provide governance doc")
            .with_due_date(1000);
        assert!(req.is_overdue(1500));
        assert!(!req.is_overdue(500));
        assert!(!req.is_overdue(1000)); // at exactly due_date, not overdue
    }

    #[test]
    fn test_evidence_collection_tracker_add_and_update() {
        let mut tracker = EvidenceCollectionTracker::new();
        tracker.add_requirement(
            EvidenceRequirement::new("r-1", "nist", "GOV-1", "Governance doc")
                .with_due_date(2000)
                .with_assignee("alice"),
        );
        assert_eq!(tracker.requirement_count(), 1);
        assert!(!tracker.get("r-1").unwrap().is_complete());

        tracker.update_status("r-1", CollectionStatus::Collected, 1500);
        assert!(tracker.get("r-1").unwrap().is_complete());
        assert_eq!(tracker.get("r-1").unwrap().collected_at, Some(1500));
    }

    #[test]
    fn test_overdue_requirements() {
        let mut tracker = EvidenceCollectionTracker::new();
        tracker.add_requirement(
            EvidenceRequirement::new("r-1", "nist", "GOV-1", "Doc A").with_due_date(1000),
        );
        tracker.add_requirement(
            EvidenceRequirement::new("r-2", "nist", "GOV-2", "Doc B").with_due_date(3000),
        );
        tracker.add_requirement(
            EvidenceRequirement::new("r-3", "nist", "MEA-1", "Doc C").with_due_date(1000),
        );
        // Mark r-3 as collected so it's no longer overdue
        tracker.update_status("r-3", CollectionStatus::Collected, 900);

        let overdue = tracker.overdue_requirements(2000);
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].requirement_id, "r-1");
    }

    #[test]
    fn test_completion_rate() {
        let mut tracker = EvidenceCollectionTracker::new();
        tracker.add_requirement(EvidenceRequirement::new("r-1", "fw", "C-1", "A"));
        tracker.add_requirement(EvidenceRequirement::new("r-2", "fw", "C-2", "B"));
        tracker.update_status("r-1", CollectionStatus::Verified, 1000);
        let rate = tracker.completion_rate("fw");
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_requirements_for_control() {
        let mut tracker = EvidenceCollectionTracker::new();
        tracker.add_requirement(EvidenceRequirement::new("r-1", "nist", "GOV-1", "A"));
        tracker.add_requirement(EvidenceRequirement::new("r-2", "nist", "GOV-1", "B"));
        tracker.add_requirement(EvidenceRequirement::new("r-3", "nist", "GOV-2", "C"));
        let reqs = tracker.requirements_for_control("nist", "GOV-1");
        assert_eq!(reqs.len(), 2);
    }
}
