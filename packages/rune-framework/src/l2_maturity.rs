// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Compliance scoring with maturity modeling.
//
// Tracks control maturity levels across frameworks using a five-level
// maturity model (Initial → Optimizing), with trend analysis and
// framework-level scoring.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── MaturityLevel ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaturityLevel {
    Initial = 0,
    Developing = 1,
    Defined = 2,
    Managed = 3,
    Optimizing = 4,
}

impl MaturityLevel {
    pub fn score(&self) -> u32 {
        match self {
            Self::Initial => 0,
            Self::Developing => 1,
            Self::Defined => 2,
            Self::Managed => 3,
            Self::Optimizing => 4,
        }
    }
}

impl fmt::Display for MaturityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Initial => "Initial",
            Self::Developing => "Developing",
            Self::Defined => "Defined",
            Self::Managed => "Managed",
            Self::Optimizing => "Optimizing",
        };
        f.write_str(s)
    }
}

// ── ControlMaturityAssessment ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ControlMaturityAssessment {
    pub control_id: String,
    pub framework_id: String,
    pub current_level: MaturityLevel,
    pub target_level: MaturityLevel,
    pub assessed_at: i64,
    pub assessor: String,
    pub notes: String,
}

impl ControlMaturityAssessment {
    pub fn new(
        control_id: impl Into<String>,
        framework_id: impl Into<String>,
        current_level: MaturityLevel,
        target_level: MaturityLevel,
        assessed_at: i64,
        assessor: impl Into<String>,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            framework_id: framework_id.into(),
            current_level,
            target_level,
            assessed_at,
            assessor: assessor.into(),
            notes: String::new(),
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    pub fn meets_target(&self) -> bool {
        self.current_level >= self.target_level
    }

    pub fn gap(&self) -> u32 {
        if self.meets_target() {
            0
        } else {
            self.target_level.score() - self.current_level.score()
        }
    }
}

// ── MaturityTrend ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MaturityTrend {
    pub control_id: String,
    pub framework_id: String,
    pub previous_level: MaturityLevel,
    pub current_level: MaturityLevel,
    pub change_timestamp: i64,
}

impl MaturityTrend {
    pub fn is_improving(&self) -> bool {
        self.current_level > self.previous_level
    }

    pub fn is_declining(&self) -> bool {
        self.current_level < self.previous_level
    }

    pub fn is_stable(&self) -> bool {
        self.current_level == self.previous_level
    }
}

// ── MaturityTracker ───────────────────────────────────────────────

/// Key: (framework_id, control_id)
#[derive(Debug, Default)]
pub struct MaturityTracker {
    assessments: HashMap<(String, String), Vec<ControlMaturityAssessment>>,
}

impl MaturityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_assessment(&mut self, assessment: ControlMaturityAssessment) {
        let key = (assessment.framework_id.clone(), assessment.control_id.clone());
        self.assessments.entry(key).or_default().push(assessment);
    }

    pub fn current_maturity(
        &self,
        framework_id: &str,
        control_id: &str,
    ) -> Option<&ControlMaturityAssessment> {
        self.assessments
            .get(&(framework_id.to_string(), control_id.to_string()))
            .and_then(|v| v.last())
    }

    pub fn framework_maturity_score(&self, framework_id: &str) -> f64 {
        let assessments: Vec<&ControlMaturityAssessment> = self
            .assessments
            .iter()
            .filter(|((fid, _), _)| fid == framework_id)
            .filter_map(|(_, v)| v.last())
            .collect();

        if assessments.is_empty() {
            return 0.0;
        }

        let total: f64 = assessments
            .iter()
            .map(|a| a.current_level.score() as f64)
            .sum();
        total / assessments.len() as f64
    }

    pub fn controls_below_target(&self, framework_id: &str) -> Vec<&ControlMaturityAssessment> {
        self.assessments
            .iter()
            .filter(|((fid, _), _)| fid == framework_id)
            .filter_map(|(_, v)| v.last())
            .filter(|a| !a.meets_target())
            .collect()
    }

    pub fn maturity_distribution(&self, framework_id: &str) -> HashMap<MaturityLevel, usize> {
        let mut dist = HashMap::new();
        for ((fid, _), assessments) in &self.assessments {
            if fid == framework_id {
                if let Some(latest) = assessments.last() {
                    *dist.entry(latest.current_level.clone()).or_insert(0) += 1;
                }
            }
        }
        dist
    }

    pub fn overall_maturity_score(&self) -> f64 {
        let all_latest: Vec<&ControlMaturityAssessment> = self
            .assessments
            .values()
            .filter_map(|v| v.last())
            .collect();

        if all_latest.is_empty() {
            return 0.0;
        }

        let total: f64 = all_latest
            .iter()
            .map(|a| a.current_level.score() as f64)
            .sum();
        total / all_latest.len() as f64
    }

    pub fn trends(&self, framework_id: &str) -> Vec<MaturityTrend> {
        let mut trends = Vec::new();
        for ((fid, cid), assessments) in &self.assessments {
            if fid == framework_id && assessments.len() >= 2 {
                let prev = &assessments[assessments.len() - 2];
                let curr = &assessments[assessments.len() - 1];
                trends.push(MaturityTrend {
                    control_id: cid.clone(),
                    framework_id: fid.clone(),
                    previous_level: prev.current_level.clone(),
                    current_level: curr.current_level.clone(),
                    change_timestamp: curr.assessed_at,
                });
            }
        }
        trends
    }

    pub fn assessment_count(&self) -> usize {
        self.assessments.values().map(|v| v.len()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maturity_level_ordering() {
        assert!(MaturityLevel::Initial < MaturityLevel::Developing);
        assert!(MaturityLevel::Developing < MaturityLevel::Defined);
        assert!(MaturityLevel::Defined < MaturityLevel::Managed);
        assert!(MaturityLevel::Managed < MaturityLevel::Optimizing);
    }

    #[test]
    fn test_control_maturity_assessment_meets_target() {
        let a = ControlMaturityAssessment::new(
            "GOV-1", "nist", MaturityLevel::Managed, MaturityLevel::Defined, 1000, "auditor",
        );
        assert!(a.meets_target());
        assert_eq!(a.gap(), 0);

        let b = ControlMaturityAssessment::new(
            "GOV-2", "nist", MaturityLevel::Initial, MaturityLevel::Managed, 1000, "auditor",
        );
        assert!(!b.meets_target());
        assert_eq!(b.gap(), 3);
    }

    #[test]
    fn test_maturity_tracker_framework_score() {
        let mut tracker = MaturityTracker::new();
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-1", "nist", MaturityLevel::Managed, MaturityLevel::Optimizing, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-2", "nist", MaturityLevel::Defined, MaturityLevel::Optimizing, 1000, "a",
        ));
        // Managed=3, Defined=2 → avg 2.5
        let score = tracker.framework_maturity_score("nist");
        assert!((score - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_controls_below_target() {
        let mut tracker = MaturityTracker::new();
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-1", "nist", MaturityLevel::Optimizing, MaturityLevel::Optimizing, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-2", "nist", MaturityLevel::Initial, MaturityLevel::Managed, 1000, "a",
        ));
        let below = tracker.controls_below_target("nist");
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].control_id, "GOV-2");
    }

    #[test]
    fn test_maturity_distribution() {
        let mut tracker = MaturityTracker::new();
        tracker.record_assessment(ControlMaturityAssessment::new(
            "C-1", "fw", MaturityLevel::Managed, MaturityLevel::Optimizing, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "C-2", "fw", MaturityLevel::Managed, MaturityLevel::Optimizing, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "C-3", "fw", MaturityLevel::Initial, MaturityLevel::Managed, 1000, "a",
        ));
        let dist = tracker.maturity_distribution("fw");
        assert_eq!(dist.get(&MaturityLevel::Managed), Some(&2));
        assert_eq!(dist.get(&MaturityLevel::Initial), Some(&1));
    }

    #[test]
    fn test_maturity_trend_is_improving() {
        let mut tracker = MaturityTracker::new();
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-1", "nist", MaturityLevel::Initial, MaturityLevel::Managed, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "GOV-1", "nist", MaturityLevel::Defined, MaturityLevel::Managed, 2000, "a",
        ));
        let trends = tracker.trends("nist");
        assert_eq!(trends.len(), 1);
        assert!(trends[0].is_improving());
        assert!(!trends[0].is_declining());
        assert!(!trends[0].is_stable());
    }

    #[test]
    fn test_overall_maturity_score() {
        let mut tracker = MaturityTracker::new();
        tracker.record_assessment(ControlMaturityAssessment::new(
            "C-1", "fw-a", MaturityLevel::Optimizing, MaturityLevel::Optimizing, 1000, "a",
        ));
        tracker.record_assessment(ControlMaturityAssessment::new(
            "C-1", "fw-b", MaturityLevel::Initial, MaturityLevel::Managed, 1000, "a",
        ));
        // Optimizing=4, Initial=0 → avg 2.0
        let score = tracker.overall_maturity_score();
        assert!((score - 2.0).abs() < f64::EPSILON);
    }
}
