// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Regulatory change tracking and impact assessment.
//
// Monitors changes to regulatory frameworks, assesses their impact on
// existing compliance posture, and estimates remediation effort.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── RegulatoryChangeType ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegulatoryChangeType {
    NewRequirement,
    ModifiedRequirement,
    RemovedRequirement,
    Clarification,
    EnforcementChange,
}

impl fmt::Display for RegulatoryChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NewRequirement => "NewRequirement",
            Self::ModifiedRequirement => "ModifiedRequirement",
            Self::RemovedRequirement => "RemovedRequirement",
            Self::Clarification => "Clarification",
            Self::EnforcementChange => "EnforcementChange",
        };
        f.write_str(s)
    }
}

// ── ChangeImpact ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeImpact {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for ChangeImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(s)
    }
}

// ── RemediationEffort ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RemediationEffort {
    Trivial = 0,
    Minor = 1,
    Moderate = 2,
    Major = 3,
    Overhaul = 4,
}

impl fmt::Display for RemediationEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Trivial => "Trivial",
            Self::Minor => "Minor",
            Self::Moderate => "Moderate",
            Self::Major => "Major",
            Self::Overhaul => "Overhaul",
        };
        f.write_str(s)
    }
}

// ── RegulatoryChange ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegulatoryChange {
    pub change_id: String,
    pub framework_id: String,
    pub change_type: RegulatoryChangeType,
    pub affected_controls: Vec<String>,
    pub description: String,
    pub effective_date: i64,
    pub published_date: i64,
}

impl RegulatoryChange {
    pub fn new(
        change_id: impl Into<String>,
        framework_id: impl Into<String>,
        change_type: RegulatoryChangeType,
        description: impl Into<String>,
        effective_date: i64,
        published_date: i64,
    ) -> Self {
        Self {
            change_id: change_id.into(),
            framework_id: framework_id.into(),
            change_type,
            affected_controls: Vec::new(),
            description: description.into(),
            effective_date,
            published_date,
        }
    }

    pub fn with_affected_controls(mut self, controls: Vec<String>) -> Self {
        self.affected_controls = controls;
        self
    }

    pub fn is_effective(&self, now: i64) -> bool {
        now >= self.effective_date
    }

    pub fn days_until_effective(&self, now: i64) -> Option<i64> {
        if self.is_effective(now) {
            None
        } else {
            Some((self.effective_date - now) / 86_400_000)
        }
    }
}

// ── ChangeImpactAssessment ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChangeImpactAssessment {
    pub change_id: String,
    pub impact: ChangeImpact,
    pub remediation_effort: RemediationEffort,
    pub affected_control_count: usize,
    pub description: String,
    pub assessed_at: i64,
}

// ── assess_change_impact ──────────────────────────────────────────

pub fn assess_change_impact(change: &RegulatoryChange, now: i64) -> ChangeImpactAssessment {
    let affected = change.affected_controls.len();

    let impact = match (&change.change_type, affected) {
        (RegulatoryChangeType::RemovedRequirement, _) => ChangeImpact::Low,
        (RegulatoryChangeType::Clarification, _) => ChangeImpact::Low,
        (RegulatoryChangeType::NewRequirement, n) if n >= 5 => ChangeImpact::Critical,
        (RegulatoryChangeType::NewRequirement, _) => ChangeImpact::High,
        (RegulatoryChangeType::EnforcementChange, _) => ChangeImpact::High,
        (RegulatoryChangeType::ModifiedRequirement, n) if n >= 5 => ChangeImpact::High,
        (RegulatoryChangeType::ModifiedRequirement, _) => ChangeImpact::Medium,
    };

    let remediation_effort = match &impact {
        ChangeImpact::None => RemediationEffort::Trivial,
        ChangeImpact::Low => RemediationEffort::Minor,
        ChangeImpact::Medium => RemediationEffort::Moderate,
        ChangeImpact::High => RemediationEffort::Major,
        ChangeImpact::Critical => RemediationEffort::Overhaul,
    };

    ChangeImpactAssessment {
        change_id: change.change_id.clone(),
        impact,
        remediation_effort,
        affected_control_count: affected,
        description: format!(
            "{} affecting {} controls in {}",
            change.change_type, affected, change.framework_id
        ),
        assessed_at: now,
    }
}

// ── RegulatoryChangeTracker ───────────────────────────────────────

#[derive(Debug, Default)]
pub struct RegulatoryChangeTracker {
    changes: HashMap<String, RegulatoryChange>,
    assessments: HashMap<String, ChangeImpactAssessment>,
}

impl RegulatoryChangeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track_change(&mut self, change: RegulatoryChange) {
        self.changes.insert(change.change_id.clone(), change);
    }

    pub fn record_assessment(&mut self, assessment: ChangeImpactAssessment) {
        self.assessments
            .insert(assessment.change_id.clone(), assessment);
    }

    pub fn get_change(&self, change_id: &str) -> Option<&RegulatoryChange> {
        self.changes.get(change_id)
    }

    pub fn get_assessment(&self, change_id: &str) -> Option<&ChangeImpactAssessment> {
        self.assessments.get(change_id)
    }

    pub fn changes_for_framework(&self, framework_id: &str) -> Vec<&RegulatoryChange> {
        self.changes
            .values()
            .filter(|c| c.framework_id == framework_id)
            .collect()
    }

    pub fn pending_changes(&self, now: i64) -> Vec<&RegulatoryChange> {
        self.changes
            .values()
            .filter(|c| !c.is_effective(now))
            .collect()
    }

    pub fn effective_changes(&self, now: i64) -> Vec<&RegulatoryChange> {
        self.changes
            .values()
            .filter(|c| c.is_effective(now))
            .collect()
    }

    pub fn unassessed_changes(&self) -> Vec<&RegulatoryChange> {
        self.changes
            .values()
            .filter(|c| !self.assessments.contains_key(&c.change_id))
            .collect()
    }

    pub fn high_impact_changes(&self) -> Vec<&ChangeImpactAssessment> {
        self.assessments
            .values()
            .filter(|a| a.impact >= ChangeImpact::High)
            .collect()
    }

    pub fn change_count(&self) -> usize {
        self.changes.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regulatory_change_is_effective() {
        let change = RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "New transparency requirement", 2000, 1000,
        );
        assert!(!change.is_effective(1500));
        assert!(change.is_effective(2000));
        assert!(change.is_effective(3000));
    }

    #[test]
    fn test_assess_change_impact_new_requirement() {
        let change = RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "New controls", 2000, 1000,
        )
        .with_affected_controls(vec![
            "ART-6".into(), "ART-9".into(), "ART-10".into(),
            "ART-13".into(), "ART-14".into(),
        ]);
        let assessment = assess_change_impact(&change, 1500);
        assert_eq!(assessment.impact, ChangeImpact::Critical);
        assert_eq!(assessment.remediation_effort, RemediationEffort::Overhaul);
        assert_eq!(assessment.affected_control_count, 5);
    }

    #[test]
    fn test_assess_change_impact_clarification() {
        let change = RegulatoryChange::new(
            "rc-2", "nist-ai-rmf", RegulatoryChangeType::Clarification,
            "Clarified GOV-1 requirements", 2000, 1000,
        )
        .with_affected_controls(vec!["GOV-1".into()]);
        let assessment = assess_change_impact(&change, 1500);
        assert_eq!(assessment.impact, ChangeImpact::Low);
        assert_eq!(assessment.remediation_effort, RemediationEffort::Minor);
    }

    #[test]
    fn test_regulatory_change_tracker_pending_and_effective() {
        let mut tracker = RegulatoryChangeTracker::new();
        tracker.track_change(RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "Future requirement", 3000, 1000,
        ));
        tracker.track_change(RegulatoryChange::new(
            "rc-2", "nist-ai-rmf", RegulatoryChangeType::ModifiedRequirement,
            "Past change", 1000, 500,
        ));
        let pending = tracker.pending_changes(2000);
        assert_eq!(pending.len(), 1);
        let effective = tracker.effective_changes(2000);
        assert_eq!(effective.len(), 1);
    }

    #[test]
    fn test_unassessed_changes() {
        let mut tracker = RegulatoryChangeTracker::new();
        tracker.track_change(RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "New", 2000, 1000,
        ));
        tracker.track_change(RegulatoryChange::new(
            "rc-2", "nist-ai-rmf", RegulatoryChangeType::Clarification,
            "Clarification", 2000, 1000,
        ));
        assert_eq!(tracker.unassessed_changes().len(), 2);

        let change = tracker.get_change("rc-1").unwrap();
        let assessment = assess_change_impact(change, 1500);
        tracker.record_assessment(assessment);
        assert_eq!(tracker.unassessed_changes().len(), 1);
    }

    #[test]
    fn test_high_impact_changes() {
        let mut tracker = RegulatoryChangeTracker::new();
        let c1 = RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "Major change", 2000, 1000,
        )
        .with_affected_controls(vec!["ART-6".into(), "ART-9".into()]);
        let c2 = RegulatoryChange::new(
            "rc-2", "nist", RegulatoryChangeType::Clarification,
            "Minor", 2000, 1000,
        );
        tracker.track_change(c1.clone());
        tracker.track_change(c2.clone());
        tracker.record_assessment(assess_change_impact(&c1, 1500));
        tracker.record_assessment(assess_change_impact(&c2, 1500));
        let high = tracker.high_impact_changes();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].change_id, "rc-1");
    }

    #[test]
    fn test_days_until_effective() {
        let change = RegulatoryChange::new(
            "rc-1", "eu-ai-act", RegulatoryChangeType::NewRequirement,
            "Future", 86_400_000 * 30, 0,
        );
        let days = change.days_until_effective(0);
        assert_eq!(days, Some(30));
        assert_eq!(change.days_until_effective(86_400_000 * 30), None);
    }
}
