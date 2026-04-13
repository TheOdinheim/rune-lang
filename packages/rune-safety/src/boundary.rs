// ═══════════════════════════════════════════════════════════════════════
// Boundary — Safety boundaries and containment zones. Defines safe
// operating envelopes with limit checking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── BoundaryType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoundaryType {
    OperatingEnvelope,
    ContainmentZone,
    PerformanceEnvelope,
    RegulatoryBoundary,
    Custom(String),
}

impl fmt::Display for BoundaryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatingEnvelope => write!(f, "OperatingEnvelope"),
            Self::ContainmentZone => write!(f, "ContainmentZone"),
            Self::PerformanceEnvelope => write!(f, "PerformanceEnvelope"),
            Self::RegulatoryBoundary => write!(f, "RegulatoryBoundary"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ── BoundaryStatus ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BoundaryStatus {
    WithinLimits,
    ApproachingLimit { parameter: String, margin_percent: f64 },
    Breached { parameter: String, value: f64, limit: f64 },
    Unknown,
}

impl fmt::Display for BoundaryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinLimits => write!(f, "WithinLimits"),
            Self::ApproachingLimit { parameter, margin_percent } => {
                write!(f, "ApproachingLimit({parameter}, {margin_percent:.1}% margin)")
            }
            Self::Breached { parameter, value, limit } => {
                write!(f, "Breached({parameter}: {value} exceeds {limit})")
            }
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// Eq impl — f64 fields use bitwise comparison for Eq
impl Eq for BoundaryStatus {}

// ── OperatingLimit ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingLimit {
    pub parameter: String,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub unit: String,
    pub current_value: Option<f64>,
}

impl OperatingLimit {
    pub fn new(parameter: impl Into<String>, unit: impl Into<String>) -> Self {
        Self {
            parameter: parameter.into(),
            min_value: None,
            max_value: None,
            unit: unit.into(),
            current_value: None,
        }
    }

    pub fn with_range(mut self, min: f64, max: f64) -> Self {
        self.min_value = Some(min);
        self.max_value = Some(max);
        self
    }

    pub fn with_max(mut self, max: f64) -> Self {
        self.max_value = Some(max);
        self
    }

    pub fn is_within(&self) -> bool {
        let Some(current) = self.current_value else {
            return false; // no current value = cannot confirm within limits
        };
        if let Some(min) = self.min_value {
            if current < min {
                return false;
            }
        }
        if let Some(max) = self.max_value {
            if current > max {
                return false;
            }
        }
        true
    }
}

// ── SafetyBoundary ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyBoundary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub boundary_type: BoundaryType,
    pub limits: Vec<OperatingLimit>,
    pub current_status: BoundaryStatus,
    pub breach_response: String,
    pub last_assessed: Option<i64>,
}

impl SafetyBoundary {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        boundary_type: BoundaryType,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            boundary_type,
            limits: Vec::new(),
            current_status: BoundaryStatus::Unknown,
            breach_response: String::new(),
            last_assessed: None,
        }
    }

    pub fn with_limit(mut self, limit: OperatingLimit) -> Self {
        self.limits.push(limit);
        self
    }

    pub fn with_breach_response(mut self, response: impl Into<String>) -> Self {
        self.breach_response = response.into();
        self
    }
}

// ── BoundaryCheckResult ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BoundaryCheckResult {
    pub boundary_id: String,
    pub status: BoundaryStatus,
    pub detail: String,
}

// ── SafetyBoundarySet ─────────────────────────────────────────────────

pub struct SafetyBoundarySet {
    boundaries: HashMap<String, SafetyBoundary>,
}

impl SafetyBoundarySet {
    pub fn new() -> Self {
        Self {
            boundaries: HashMap::new(),
        }
    }

    pub fn add(&mut self, boundary: SafetyBoundary) {
        self.boundaries.insert(boundary.id.clone(), boundary);
    }

    pub fn get(&self, id: &str) -> Option<&SafetyBoundary> {
        self.boundaries.get(id)
    }

    /// Checks all boundaries against provided values.
    pub fn check_all(&self, values: &HashMap<String, f64>) -> Vec<BoundaryCheckResult> {
        self.boundaries
            .values()
            .map(|boundary| {
                let mut worst_status = BoundaryStatus::WithinLimits;
                let mut detail_parts = Vec::new();

                for limit in &boundary.limits {
                    let Some(&current) = values.get(&limit.parameter) else {
                        continue;
                    };

                    if let Some(max) = limit.max_value {
                        if current > max {
                            worst_status = BoundaryStatus::Breached {
                                parameter: limit.parameter.clone(),
                                value: current,
                                limit: max,
                            };
                            detail_parts.push(format!(
                                "{} = {} exceeds max {}",
                                limit.parameter, current, max
                            ));
                        } else {
                            let range = if let Some(min) = limit.min_value {
                                max - min
                            } else {
                                max
                            };
                            if range > 0.0 {
                                let margin = (max - current) / range * 100.0;
                                if margin < 10.0 && worst_status == BoundaryStatus::WithinLimits {
                                    worst_status = BoundaryStatus::ApproachingLimit {
                                        parameter: limit.parameter.clone(),
                                        margin_percent: margin,
                                    };
                                }
                            }
                        }
                    }

                    if let Some(min) = limit.min_value {
                        if current < min {
                            worst_status = BoundaryStatus::Breached {
                                parameter: limit.parameter.clone(),
                                value: current,
                                limit: min,
                            };
                            detail_parts.push(format!(
                                "{} = {} below min {}",
                                limit.parameter, current, min
                            ));
                        }
                    }
                }

                BoundaryCheckResult {
                    boundary_id: boundary.id.clone(),
                    status: worst_status,
                    detail: if detail_parts.is_empty() {
                        "All limits satisfied".into()
                    } else {
                        detail_parts.join("; ")
                    },
                }
            })
            .collect()
    }

    pub fn breached(&self) -> Vec<&SafetyBoundary> {
        self.boundaries
            .values()
            .filter(|b| matches!(b.current_status, BoundaryStatus::Breached { .. }))
            .collect()
    }

    pub fn approaching(&self) -> Vec<&SafetyBoundary> {
        self.boundaries
            .values()
            .filter(|b| matches!(b.current_status, BoundaryStatus::ApproachingLimit { .. }))
            .collect()
    }

    pub fn count(&self) -> usize {
        self.boundaries.len()
    }
}

impl Default for SafetyBoundarySet {
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

    fn sample_boundary() -> SafetyBoundary {
        SafetyBoundary::new("b1", "Temperature boundary", BoundaryType::OperatingEnvelope)
            .with_limit(OperatingLimit::new("temperature", "°C").with_range(0.0, 100.0))
            .with_limit(OperatingLimit::new("pressure", "psi").with_max(50.0))
            .with_breach_response("fs-shutdown")
    }

    #[test]
    fn test_add_and_get() {
        let mut set = SafetyBoundarySet::new();
        set.add(sample_boundary());
        assert!(set.get("b1").is_some());
        assert!(set.get("missing").is_none());
        assert_eq!(set.count(), 1);
    }

    #[test]
    fn test_check_all_within_limits() {
        let mut set = SafetyBoundarySet::new();
        set.add(sample_boundary());
        let values = HashMap::from([
            ("temperature".into(), 50.0),
            ("pressure".into(), 30.0),
        ]);
        let results = set.check_all(&values);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, BoundaryStatus::WithinLimits);
    }

    #[test]
    fn test_check_all_approaching() {
        let mut set = SafetyBoundarySet::new();
        set.add(sample_boundary());
        let values = HashMap::from([
            ("temperature".into(), 95.0), // within 5% of max 100
            ("pressure".into(), 30.0),
        ]);
        let results = set.check_all(&values);
        assert!(matches!(results[0].status, BoundaryStatus::ApproachingLimit { .. }));
    }

    #[test]
    fn test_check_all_breached() {
        let mut set = SafetyBoundarySet::new();
        set.add(sample_boundary());
        let values = HashMap::from([
            ("temperature".into(), 110.0), // exceeds max 100
            ("pressure".into(), 30.0),
        ]);
        let results = set.check_all(&values);
        assert!(matches!(results[0].status, BoundaryStatus::Breached { .. }));
    }

    #[test]
    fn test_breached_and_approaching() {
        let mut set = SafetyBoundarySet::new();
        let mut b = sample_boundary();
        b.current_status = BoundaryStatus::Breached {
            parameter: "temperature".into(),
            value: 110.0,
            limit: 100.0,
        };
        set.add(b);
        assert_eq!(set.breached().len(), 1);
        assert_eq!(set.approaching().len(), 0);
    }

    #[test]
    fn test_operating_limit_is_within() {
        let mut limit = OperatingLimit::new("temp", "°C").with_range(0.0, 100.0);
        assert!(!limit.is_within()); // no current value
        limit.current_value = Some(50.0);
        assert!(limit.is_within());
        limit.current_value = Some(150.0);
        assert!(!limit.is_within());
        limit.current_value = Some(-10.0);
        assert!(!limit.is_within());
    }

    #[test]
    fn test_boundary_type_display() {
        let types = vec![
            BoundaryType::OperatingEnvelope,
            BoundaryType::ContainmentZone,
            BoundaryType::PerformanceEnvelope,
            BoundaryType::RegulatoryBoundary,
            BoundaryType::Custom("test".into()),
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn test_boundary_status_display() {
        let statuses = vec![
            BoundaryStatus::WithinLimits,
            BoundaryStatus::ApproachingLimit { parameter: "p".into(), margin_percent: 5.0 },
            BoundaryStatus::Breached { parameter: "p".into(), value: 110.0, limit: 100.0 },
            BoundaryStatus::Unknown,
        ];
        for s in &statuses {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(statuses.len(), 4);
    }
}
