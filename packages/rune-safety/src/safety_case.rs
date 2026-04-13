// ═══════════════════════════════════════════════════════════════════════
// Safety Case — Structured safety arguments inspired by Goal
// Structuring Notation (GSN). A safety case argues that a system
// is acceptably safe by decomposing a top-level claim into sub-goals,
// strategies, and evidence.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;
use crate::integrity::SafetyClassification;

// ── SafetyCaseId ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafetyCaseId(pub String);

impl SafetyCaseId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for SafetyCaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── GoalStatus ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalStatus {
    Undeveloped,
    InProgress,
    Supported,
    Challenged,
    Accepted,
}

impl fmt::Display for GoalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Undeveloped => "Undeveloped",
            Self::InProgress => "InProgress",
            Self::Supported => "Supported",
            Self::Challenged => "Challenged",
            Self::Accepted => "Accepted",
        };
        f.write_str(s)
    }
}

// ── EvidenceType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    TestResult,
    FormalProof,
    Analysis,
    Review,
    OperationalExperience,
    Simulation,
    Certification,
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TestResult => "TestResult",
            Self::FormalProof => "FormalProof",
            Self::Analysis => "Analysis",
            Self::Review => "Review",
            Self::OperationalExperience => "OperationalExperience",
            Self::Simulation => "Simulation",
            Self::Certification => "Certification",
        };
        f.write_str(s)
    }
}

// ── EvidenceStrength ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceStrength {
    Weak = 0,
    Moderate = 1,
    Strong = 2,
    Conclusive = 3,
}

impl fmt::Display for EvidenceStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Weak => "Weak",
            Self::Moderate => "Moderate",
            Self::Strong => "Strong",
            Self::Conclusive => "Conclusive",
        };
        f.write_str(s)
    }
}

// ── SafetyEvidence ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyEvidence {
    pub id: String,
    pub description: String,
    pub evidence_type: EvidenceType,
    pub reference: String,
    pub strength: EvidenceStrength,
    pub verified: bool,
}

// ── SafetyStrategy ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyStrategy {
    pub id: String,
    pub description: String,
    pub justification: Option<String>,
}

// ── SafetyGoal ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyGoal {
    pub id: String,
    pub claim: String,
    pub strategy: Option<SafetyStrategy>,
    pub evidence: Vec<SafetyEvidence>,
    pub sub_goals: Vec<SafetyGoal>,
    pub context: Vec<String>,
    pub status: GoalStatus,
}

impl SafetyGoal {
    pub fn new(id: impl Into<String>, claim: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            claim: claim.into(),
            strategy: None,
            evidence: Vec::new(),
            sub_goals: Vec::new(),
            context: Vec::new(),
            status: GoalStatus::Undeveloped,
        }
    }

    pub fn with_status(mut self, status: GoalStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_evidence(mut self, evidence: SafetyEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_sub_goal(mut self, goal: SafetyGoal) -> Self {
        self.sub_goals.push(goal);
        self
    }

    pub fn with_strategy(mut self, strategy: SafetyStrategy) -> Self {
        self.strategy = Some(strategy);
        self
    }
}

// ── SafetyCaseStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyCaseStatus {
    Draft,
    UnderReview,
    Accepted,
    Rejected { reason: String },
    Archived,
}

impl fmt::Display for SafetyCaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => write!(f, "Draft"),
            Self::UnderReview => write!(f, "UnderReview"),
            Self::Accepted => write!(f, "Accepted"),
            Self::Rejected { reason } => write!(f, "Rejected: {reason}"),
            Self::Archived => write!(f, "Archived"),
        }
    }
}

// ── SafetyCase ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCase {
    pub id: SafetyCaseId,
    pub name: String,
    pub description: String,
    pub system: String,
    pub top_goal: SafetyGoal,
    pub status: SafetyCaseStatus,
    pub classification: SafetyClassification,
    pub created_at: i64,
    pub updated_at: i64,
    pub author: String,
    pub reviewer: Option<String>,
}

impl SafetyCase {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        system: impl Into<String>,
        top_goal: SafetyGoal,
    ) -> Self {
        Self {
            id: SafetyCaseId::new(id),
            name: name.into(),
            description: String::new(),
            system: system.into(),
            top_goal,
            status: SafetyCaseStatus::Draft,
            classification: SafetyClassification::new(),
            created_at: 0,
            updated_at: 0,
            author: String::new(),
            reviewer: None,
        }
    }
}

// ── Helper: recursive goal traversal ──────────────────────────────────

fn count_goals_recursive(goal: &SafetyGoal) -> (usize, usize) {
    let total = 1;
    let supported = if matches!(goal.status, GoalStatus::Supported | GoalStatus::Accepted) {
        1
    } else {
        0
    };
    let (sub_total, sub_supported) = goal
        .sub_goals
        .iter()
        .map(count_goals_recursive)
        .fold((0, 0), |(at, as_), (bt, bs)| (at + bt, as_ + bs));
    (total + sub_total, supported + sub_supported)
}

fn collect_unsupported<'a>(goal: &'a SafetyGoal, out: &mut Vec<&'a SafetyGoal>) {
    if matches!(goal.status, GoalStatus::Undeveloped | GoalStatus::Challenged) {
        out.push(goal);
    }
    for sub in &goal.sub_goals {
        collect_unsupported(sub, out);
    }
}

fn count_evidence_recursive(goal: &SafetyGoal) -> usize {
    let own = goal.evidence.len();
    let sub: usize = goal.sub_goals.iter().map(count_evidence_recursive).sum();
    own + sub
}

// ── SafetyCaseStore ───────────────────────────────────────────────────

pub struct SafetyCaseStore {
    cases: HashMap<SafetyCaseId, SafetyCase>,
}

impl SafetyCaseStore {
    pub fn new() -> Self {
        Self {
            cases: HashMap::new(),
        }
    }

    pub fn add(&mut self, case: SafetyCase) -> Result<(), SafetyError> {
        if self.cases.contains_key(&case.id) {
            return Err(SafetyError::SafetyCaseAlreadyExists(case.id.0.clone()));
        }
        self.cases.insert(case.id.clone(), case);
        Ok(())
    }

    pub fn get(&self, id: &SafetyCaseId) -> Option<&SafetyCase> {
        self.cases.get(id)
    }

    /// Percentage of goals that are Supported or Accepted (recursively).
    pub fn completeness(&self, id: &SafetyCaseId) -> Option<f64> {
        let case = self.cases.get(id)?;
        let (total, supported) = count_goals_recursive(&case.top_goal);
        if total == 0 {
            return Some(0.0);
        }
        Some(supported as f64 / total as f64)
    }

    /// Goals that are Undeveloped or Challenged (recursively).
    pub fn unsupported_goals(&self, id: &SafetyCaseId) -> Vec<&SafetyGoal> {
        let Some(case) = self.cases.get(id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        collect_unsupported(&case.top_goal, &mut out);
        out
    }

    /// Total evidence items across all goals (recursively).
    pub fn evidence_count(&self, id: &SafetyCaseId) -> usize {
        self.cases
            .get(id)
            .map(|c| count_evidence_recursive(&c.top_goal))
            .unwrap_or(0)
    }

    pub fn by_status(&self, status: &SafetyCaseStatus) -> Vec<&SafetyCase> {
        self.cases.values().filter(|c| &c.status == status).collect()
    }

    pub fn count(&self) -> usize {
        self.cases.len()
    }
}

impl Default for SafetyCaseStore {
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

    fn sample_evidence(id: &str) -> SafetyEvidence {
        SafetyEvidence {
            id: id.into(),
            description: "Test evidence".into(),
            evidence_type: EvidenceType::TestResult,
            reference: "test-suite-1".into(),
            strength: EvidenceStrength::Strong,
            verified: true,
        }
    }

    fn sample_case() -> SafetyCase {
        let sub1 = SafetyGoal::new("g1.1", "No single point of failure")
            .with_status(GoalStatus::Supported)
            .with_evidence(sample_evidence("e1"));

        let sub2 = SafetyGoal::new("g1.2", "Fail-safe behavior verified")
            .with_status(GoalStatus::Undeveloped);

        let top = SafetyGoal::new("g1", "System is acceptably safe")
            .with_status(GoalStatus::InProgress)
            .with_sub_goal(sub1)
            .with_sub_goal(sub2)
            .with_strategy(SafetyStrategy {
                id: "s1".into(),
                description: "Argue over hazards".into(),
                justification: Some("Standard approach".into()),
            });

        SafetyCase::new("sc-001", "System Safety Case", "AI Inference Engine", top)
    }

    #[test]
    fn test_safety_case_construction() {
        let sc = sample_case();
        assert_eq!(sc.id.0, "sc-001");
        assert_eq!(sc.top_goal.sub_goals.len(), 2);
        assert!(sc.top_goal.strategy.is_some());
    }

    #[test]
    fn test_nested_goal_structure() {
        let sc = sample_case();
        assert_eq!(sc.top_goal.sub_goals[0].status, GoalStatus::Supported);
        assert_eq!(sc.top_goal.sub_goals[1].status, GoalStatus::Undeveloped);
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = SafetyCaseStore::new();
        store.add(sample_case()).unwrap();
        assert!(store.get(&SafetyCaseId::new("sc-001")).is_some());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_completeness_mixed() {
        let mut store = SafetyCaseStore::new();
        store.add(sample_case()).unwrap();
        // 3 goals: top=InProgress, sub1=Supported, sub2=Undeveloped → 1/3
        let completeness = store.completeness(&SafetyCaseId::new("sc-001")).unwrap();
        assert!((completeness - 1.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_completeness_all_supported() {
        let top = SafetyGoal::new("g1", "Safe")
            .with_status(GoalStatus::Accepted)
            .with_sub_goal(SafetyGoal::new("g1.1", "Sub").with_status(GoalStatus::Supported));
        let sc = SafetyCase::new("sc-002", "Full", "sys", top);
        let mut store = SafetyCaseStore::new();
        store.add(sc).unwrap();
        let completeness = store.completeness(&SafetyCaseId::new("sc-002")).unwrap();
        assert!((completeness - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_unsupported_goals() {
        let mut store = SafetyCaseStore::new();
        store.add(sample_case()).unwrap();
        let unsupported = store.unsupported_goals(&SafetyCaseId::new("sc-001"));
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].id, "g1.2");
    }

    #[test]
    fn test_evidence_count() {
        let mut store = SafetyCaseStore::new();
        store.add(sample_case()).unwrap();
        assert_eq!(store.evidence_count(&SafetyCaseId::new("sc-001")), 1);
    }

    #[test]
    fn test_by_status() {
        let mut store = SafetyCaseStore::new();
        store.add(sample_case()).unwrap();
        assert_eq!(store.by_status(&SafetyCaseStatus::Draft).len(), 1);
        assert_eq!(store.by_status(&SafetyCaseStatus::Accepted).len(), 0);
    }

    #[test]
    fn test_goal_status_display() {
        let statuses = vec![
            GoalStatus::Undeveloped,
            GoalStatus::InProgress,
            GoalStatus::Supported,
            GoalStatus::Challenged,
            GoalStatus::Accepted,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_safety_case_status_display() {
        let statuses: Vec<SafetyCaseStatus> = vec![
            SafetyCaseStatus::Draft,
            SafetyCaseStatus::UnderReview,
            SafetyCaseStatus::Accepted,
            SafetyCaseStatus::Rejected { reason: "r".into() },
            SafetyCaseStatus::Archived,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 5);
    }

    #[test]
    fn test_evidence_type_display() {
        let types = vec![
            EvidenceType::TestResult,
            EvidenceType::FormalProof,
            EvidenceType::Analysis,
            EvidenceType::Review,
            EvidenceType::OperationalExperience,
            EvidenceType::Simulation,
            EvidenceType::Certification,
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_evidence_strength_ordering() {
        assert!(EvidenceStrength::Weak < EvidenceStrength::Moderate);
        assert!(EvidenceStrength::Moderate < EvidenceStrength::Strong);
        assert!(EvidenceStrength::Strong < EvidenceStrength::Conclusive);
    }
}
