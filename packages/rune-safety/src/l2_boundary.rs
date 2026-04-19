// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — AI safety boundary enforcement.
//
// Structured safety boundaries that define hard limits on AI system
// behavior, with enforcement modes and violation tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── L2BoundaryType ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum L2BoundaryType {
    OutputRange { min: f64, max: f64 },
    ContentFilter { blocked_categories: Vec<String> },
    RateLimit { max_per_window: u64, window_ms: i64 },
    ConfidenceFloor { min_confidence: f64 },
    ResourceCap { max_tokens: u64, max_compute_ms: i64 },
    Custom { validator: String },
}

impl L2BoundaryType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::OutputRange { .. } => "OutputRange",
            Self::ContentFilter { .. } => "ContentFilter",
            Self::RateLimit { .. } => "RateLimit",
            Self::ConfidenceFloor { .. } => "ConfidenceFloor",
            Self::ResourceCap { .. } => "ResourceCap",
            Self::Custom { .. } => "Custom",
        }
    }
}

impl fmt::Display for L2BoundaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

// ── L2EnforcementMode ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2EnforcementMode {
    HardStop,
    SoftWarn,
    Escalate,
    Monitor,
}

impl fmt::Display for L2EnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HardStop => "HardStop",
            Self::SoftWarn => "SoftWarn",
            Self::Escalate => "Escalate",
            Self::Monitor => "Monitor",
        };
        f.write_str(s)
    }
}

// ── L2SafetyBoundary ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2SafetyBoundary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub boundary_type: L2BoundaryType,
    pub enforcement: L2EnforcementMode,
    pub threshold: Option<f64>,
    pub created_at: i64,
}

impl L2SafetyBoundary {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        boundary_type: L2BoundaryType,
        enforcement: L2EnforcementMode,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            boundary_type,
            enforcement,
            threshold: None,
            created_at,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }
}

// ── L2BoundaryViolation ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2BoundaryViolation {
    pub boundary_id: String,
    pub boundary_name: String,
    pub violation_type: String,
    pub observed_value: String,
    pub threshold: String,
    pub enforcement: L2EnforcementMode,
    pub timestamp: i64,
}

// ── L2BoundaryCheckResult ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2BoundaryCheckResult {
    pub passed: bool,
    pub violations: Vec<L2BoundaryViolation>,
    pub hard_stops: usize,
    pub warnings: usize,
    pub escalations: usize,
}

// ── L2BoundaryChecker ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2BoundaryChecker {
    boundaries: Vec<L2SafetyBoundary>,
}

impl L2BoundaryChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_boundary(&mut self, boundary: L2SafetyBoundary) {
        self.boundaries.push(boundary);
    }

    pub fn check_output_range(&self, value: f64) -> Vec<L2BoundaryViolation> {
        let now = 0; // caller should use check_all for timestamped results
        self.boundaries
            .iter()
            .filter_map(|b| {
                if let L2BoundaryType::OutputRange { min, max } = &b.boundary_type {
                    if value < *min || value > *max {
                        Some(L2BoundaryViolation {
                            boundary_id: b.id.clone(),
                            boundary_name: b.name.clone(),
                            violation_type: "OutputRange".to_string(),
                            observed_value: value.to_string(),
                            threshold: format!("[{min}, {max}]"),
                            enforcement: b.enforcement.clone(),
                            timestamp: now,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn check_rate(&self, current_count: u64, window_ms: i64) -> Vec<L2BoundaryViolation> {
        self.boundaries
            .iter()
            .filter_map(|b| {
                if let L2BoundaryType::RateLimit {
                    max_per_window,
                    window_ms: bw,
                } = &b.boundary_type
                {
                    if current_count > *max_per_window && window_ms <= *bw {
                        Some(L2BoundaryViolation {
                            boundary_id: b.id.clone(),
                            boundary_name: b.name.clone(),
                            violation_type: "RateLimit".to_string(),
                            observed_value: current_count.to_string(),
                            threshold: max_per_window.to_string(),
                            enforcement: b.enforcement.clone(),
                            timestamp: 0,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn check_confidence(&self, confidence: f64) -> Vec<L2BoundaryViolation> {
        self.boundaries
            .iter()
            .filter_map(|b| {
                if let L2BoundaryType::ConfidenceFloor { min_confidence } = &b.boundary_type {
                    if confidence < *min_confidence {
                        Some(L2BoundaryViolation {
                            boundary_id: b.id.clone(),
                            boundary_name: b.name.clone(),
                            violation_type: "ConfidenceFloor".to_string(),
                            observed_value: confidence.to_string(),
                            threshold: min_confidence.to_string(),
                            enforcement: b.enforcement.clone(),
                            timestamp: 0,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn check_all(&self, value: f64, confidence: f64) -> L2BoundaryCheckResult {
        let mut violations = Vec::new();
        violations.extend(self.check_output_range(value));
        violations.extend(self.check_confidence(confidence));

        let hard_stops = violations
            .iter()
            .filter(|v| v.enforcement == L2EnforcementMode::HardStop)
            .count();
        let warnings = violations
            .iter()
            .filter(|v| v.enforcement == L2EnforcementMode::SoftWarn)
            .count();
        let escalations = violations
            .iter()
            .filter(|v| v.enforcement == L2EnforcementMode::Escalate)
            .count();

        L2BoundaryCheckResult {
            passed: violations.is_empty(),
            violations,
            hard_stops,
            warnings,
            escalations,
        }
    }

    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }
}

// ── L2BoundaryStore ───────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2BoundaryStore {
    boundaries: HashMap<String, L2SafetyBoundary>,
    violation_counts: HashMap<String, u64>,
}

impl L2BoundaryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, boundary: L2SafetyBoundary) {
        self.boundaries.insert(boundary.id.clone(), boundary);
    }

    pub fn get(&self, id: &str) -> Option<&L2SafetyBoundary> {
        self.boundaries.get(id)
    }

    pub fn record_violation(&mut self, boundary_id: &str) {
        *self.violation_counts.entry(boundary_id.to_string()).or_insert(0) += 1;
    }

    pub fn violation_count(&self, boundary_id: &str) -> u64 {
        self.violation_counts.get(boundary_id).copied().unwrap_or(0)
    }

    pub fn most_violated(&self, n: usize) -> Vec<(&str, u64)> {
        let mut pairs: Vec<(&str, u64)> = self
            .violation_counts
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    pub fn boundaries_by_type(&self, boundary_type_name: &str) -> Vec<&L2SafetyBoundary> {
        self.boundaries
            .values()
            .filter(|b| b.boundary_type.type_name() == boundary_type_name)
            .collect()
    }

    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_boundary_construction_all_types() {
        let types = vec![
            L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2BoundaryType::ContentFilter { blocked_categories: vec!["hate".into()] },
            L2BoundaryType::RateLimit { max_per_window: 100, window_ms: 60000 },
            L2BoundaryType::ConfidenceFloor { min_confidence: 0.8 },
            L2BoundaryType::ResourceCap { max_tokens: 4096, max_compute_ms: 5000 },
            L2BoundaryType::Custom { validator: "custom_check".into() },
        ];
        for (i, bt) in types.into_iter().enumerate() {
            let b = L2SafetyBoundary::new(
                format!("b-{i}"), format!("Boundary {i}"), bt, L2EnforcementMode::HardStop, 1000,
            );
            assert!(!b.id.is_empty());
        }
    }

    #[test]
    fn test_boundary_checker_output_range_detects_violation() {
        let mut checker = L2BoundaryChecker::new();
        checker.add_boundary(L2SafetyBoundary::new(
            "range-1", "Output range", L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2EnforcementMode::HardStop, 1000,
        ));
        let violations = checker.check_output_range(1.5);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].enforcement, L2EnforcementMode::HardStop);
    }

    #[test]
    fn test_boundary_checker_output_range_passes_within_range() {
        let mut checker = L2BoundaryChecker::new();
        checker.add_boundary(L2SafetyBoundary::new(
            "range-1", "Output range", L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2EnforcementMode::HardStop, 1000,
        ));
        let violations = checker.check_output_range(0.5);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_boundary_checker_confidence_detects_low() {
        let mut checker = L2BoundaryChecker::new();
        checker.add_boundary(L2SafetyBoundary::new(
            "conf-1", "Min confidence",
            L2BoundaryType::ConfidenceFloor { min_confidence: 0.8 },
            L2EnforcementMode::Escalate, 1000,
        ));
        let violations = checker.check_confidence(0.5);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, "ConfidenceFloor");
    }

    #[test]
    fn test_boundary_checker_check_all_returns_counts() {
        let mut checker = L2BoundaryChecker::new();
        checker.add_boundary(L2SafetyBoundary::new(
            "range-1", "Range",
            L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2EnforcementMode::HardStop, 1000,
        ));
        checker.add_boundary(L2SafetyBoundary::new(
            "conf-1", "Confidence",
            L2BoundaryType::ConfidenceFloor { min_confidence: 0.9 },
            L2EnforcementMode::SoftWarn, 1000,
        ));
        let result = checker.check_all(1.5, 0.5);
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 2);
        assert_eq!(result.hard_stops, 1);
        assert_eq!(result.warnings, 1);
        assert_eq!(result.escalations, 0);
    }

    #[test]
    fn test_boundary_store_register_and_violation_count() {
        let mut store = L2BoundaryStore::new();
        store.register(L2SafetyBoundary::new(
            "b-1", "Test",
            L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2EnforcementMode::HardStop, 1000,
        ));
        assert!(store.get("b-1").is_some());
        assert_eq!(store.violation_count("b-1"), 0);
        store.record_violation("b-1");
        store.record_violation("b-1");
        assert_eq!(store.violation_count("b-1"), 2);
    }

    #[test]
    fn test_boundary_store_most_violated_sorted() {
        let mut store = L2BoundaryStore::new();
        store.register(L2SafetyBoundary::new(
            "b-1", "A", L2BoundaryType::OutputRange { min: 0.0, max: 1.0 },
            L2EnforcementMode::HardStop, 1000,
        ));
        store.register(L2SafetyBoundary::new(
            "b-2", "B", L2BoundaryType::ConfidenceFloor { min_confidence: 0.5 },
            L2EnforcementMode::SoftWarn, 1000,
        ));
        store.record_violation("b-1");
        store.record_violation("b-2");
        store.record_violation("b-2");
        store.record_violation("b-2");
        let top = store.most_violated(2);
        assert_eq!(top[0].0, "b-2");
        assert_eq!(top[0].1, 3);
        assert_eq!(top[1].0, "b-1");
    }

    #[test]
    fn test_boundary_violation_records_enforcement_mode() {
        let mut checker = L2BoundaryChecker::new();
        checker.add_boundary(L2SafetyBoundary::new(
            "esc-1", "Escalation boundary",
            L2BoundaryType::ConfidenceFloor { min_confidence: 0.95 },
            L2EnforcementMode::Escalate, 1000,
        ));
        let violations = checker.check_confidence(0.5);
        assert_eq!(violations[0].enforcement, L2EnforcementMode::Escalate);
    }
}
