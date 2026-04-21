// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — SafetyEnvelopeMonitor trait for operational envelope
// monitoring, boundary proximity detection, and safe-response
// recommendation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::SafetyError;

// ── EnvelopeStatus ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvelopeStatus {
    WithinEnvelope,
    ApproachingBoundary {
        constraint_ref: String,
        proximity_indicator: String,
    },
    BoundaryViolated {
        constraint_ref: String,
        violation_description: String,
    },
    EnvelopeSuspended {
        reason: String,
    },
    Unknown,
}

impl fmt::Display for EnvelopeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinEnvelope => f.write_str("WithinEnvelope"),
            Self::ApproachingBoundary { constraint_ref, .. } => {
                write!(f, "ApproachingBoundary({constraint_ref})")
            }
            Self::BoundaryViolated { constraint_ref, .. } => {
                write!(f, "BoundaryViolated({constraint_ref})")
            }
            Self::EnvelopeSuspended { reason } => {
                write!(f, "EnvelopeSuspended({reason})")
            }
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ── RecommendedSafetyResponse ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedSafetyResponse {
    ContinueOperation,
    IncreasedMonitoring { monitoring_hint: String },
    DegradedOperation { degradation_description: String },
    EmergencyShutdown { reason: String },
    EscalateToHuman { reason: String },
}

impl fmt::Display for RecommendedSafetyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContinueOperation => f.write_str("ContinueOperation"),
            Self::IncreasedMonitoring { .. } => f.write_str("IncreasedMonitoring"),
            Self::DegradedOperation { .. } => f.write_str("DegradedOperation"),
            Self::EmergencyShutdown { .. } => f.write_str("EmergencyShutdown"),
            Self::EscalateToHuman { .. } => f.write_str("EscalateToHuman"),
        }
    }
}

// ── EnvelopeConstraintEntry ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeConstraintEntry {
    pub constraint_ref: String,
    pub context_key: String,
    pub threshold_value: String,
    pub comparison: ThresholdComparison,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdComparison {
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Equal,
    NotEqual,
}

// ── SafetyEnvelopeMonitor trait ─────────────────────────────────────

pub trait SafetyEnvelopeMonitor {
    fn check_envelope(
        &self,
        system_id: &str,
        context: &HashMap<String, String>,
    ) -> Result<EnvelopeStatus, SafetyError>;

    fn register_constraint(
        &mut self,
        system_id: &str,
        entry: EnvelopeConstraintEntry,
    ) -> Result<(), SafetyError>;

    fn remove_constraint(
        &mut self,
        system_id: &str,
        constraint_ref: &str,
    ) -> Result<(), SafetyError>;

    fn list_active_constraints(&self, system_id: &str) -> Vec<EnvelopeConstraintEntry>;

    fn recommend_response(
        &self,
        status: &EnvelopeStatus,
    ) -> RecommendedSafetyResponse;

    fn monitor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemorySafetyEnvelopeMonitor ───────────────────────────────────

pub struct InMemorySafetyEnvelopeMonitor {
    id: String,
    constraints: HashMap<String, Vec<EnvelopeConstraintEntry>>,
    active: bool,
}

impl InMemorySafetyEnvelopeMonitor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            constraints: HashMap::new(),
            active: true,
        }
    }
}

impl SafetyEnvelopeMonitor for InMemorySafetyEnvelopeMonitor {
    fn check_envelope(
        &self,
        system_id: &str,
        context: &HashMap<String, String>,
    ) -> Result<EnvelopeStatus, SafetyError> {
        let entries = match self.constraints.get(system_id) {
            Some(e) => e,
            None => return Ok(EnvelopeStatus::Unknown),
        };
        for entry in entries {
            if let Some(val) = context.get(&entry.context_key) && val != &entry.threshold_value {
                return Ok(EnvelopeStatus::BoundaryViolated {
                    constraint_ref: entry.constraint_ref.clone(),
                    violation_description: format!(
                        "key {} value {} does not match threshold {}",
                        entry.context_key, val, entry.threshold_value
                    ),
                });
            }
        }
        Ok(EnvelopeStatus::WithinEnvelope)
    }

    fn register_constraint(
        &mut self,
        system_id: &str,
        entry: EnvelopeConstraintEntry,
    ) -> Result<(), SafetyError> {
        self.constraints
            .entry(system_id.to_string())
            .or_default()
            .push(entry);
        Ok(())
    }

    fn remove_constraint(
        &mut self,
        system_id: &str,
        constraint_ref: &str,
    ) -> Result<(), SafetyError> {
        if let Some(entries) = self.constraints.get_mut(system_id) {
            entries.retain(|e| e.constraint_ref != constraint_ref);
        }
        Ok(())
    }

    fn list_active_constraints(&self, system_id: &str) -> Vec<EnvelopeConstraintEntry> {
        self.constraints
            .get(system_id)
            .cloned()
            .unwrap_or_default()
    }

    fn recommend_response(&self, status: &EnvelopeStatus) -> RecommendedSafetyResponse {
        match status {
            EnvelopeStatus::WithinEnvelope => RecommendedSafetyResponse::ContinueOperation,
            EnvelopeStatus::ApproachingBoundary { .. } => {
                RecommendedSafetyResponse::IncreasedMonitoring {
                    monitoring_hint: "approaching boundary — increase sampling rate".into(),
                }
            }
            EnvelopeStatus::BoundaryViolated { constraint_ref, .. } => {
                RecommendedSafetyResponse::DegradedOperation {
                    degradation_description: format!(
                        "constraint {} violated — enter degraded mode", constraint_ref
                    ),
                }
            }
            EnvelopeStatus::EnvelopeSuspended { reason } => {
                RecommendedSafetyResponse::EscalateToHuman {
                    reason: format!("envelope suspended: {reason}"),
                }
            }
            EnvelopeStatus::Unknown => RecommendedSafetyResponse::EscalateToHuman {
                reason: "envelope status unknown — escalate".into(),
            },
        }
    }

    fn monitor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── ThresholdBasedSafetyEnvelopeMonitor ─────────────────────────────

pub struct ThresholdBasedSafetyEnvelopeMonitor {
    id: String,
    constraints: HashMap<String, Vec<EnvelopeConstraintEntry>>,
    proximity_percentage: String,
    active: bool,
}

impl ThresholdBasedSafetyEnvelopeMonitor {
    pub fn new(id: impl Into<String>, proximity_percentage: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            constraints: HashMap::new(),
            proximity_percentage: proximity_percentage.into(),
            active: true,
        }
    }

    fn parse_f64(s: &str) -> Option<f64> {
        s.parse::<f64>().ok()
    }

    fn check_numeric(
        value: f64,
        threshold: f64,
        comparison: &ThresholdComparison,
    ) -> bool {
        match comparison {
            ThresholdComparison::LessThan => value < threshold,
            ThresholdComparison::LessThanOrEqual => value <= threshold,
            ThresholdComparison::GreaterThan => value > threshold,
            ThresholdComparison::GreaterThanOrEqual => value >= threshold,
            ThresholdComparison::Equal => (value - threshold).abs() < f64::EPSILON,
            ThresholdComparison::NotEqual => (value - threshold).abs() >= f64::EPSILON,
        }
    }
}

impl SafetyEnvelopeMonitor for ThresholdBasedSafetyEnvelopeMonitor {
    fn check_envelope(
        &self,
        system_id: &str,
        context: &HashMap<String, String>,
    ) -> Result<EnvelopeStatus, SafetyError> {
        let entries = match self.constraints.get(system_id) {
            Some(e) => e,
            None => return Ok(EnvelopeStatus::Unknown),
        };
        let prox = Self::parse_f64(&self.proximity_percentage).unwrap_or(0.1);

        for entry in entries {
            if let Some(val_str) = context.get(&entry.context_key) {
                let val = match Self::parse_f64(val_str) {
                    Some(v) => v,
                    None => continue,
                };
                let threshold = match Self::parse_f64(&entry.threshold_value) {
                    Some(t) => t,
                    None => continue,
                };
                let within = Self::check_numeric(val, threshold, &entry.comparison);
                if !within {
                    return Ok(EnvelopeStatus::BoundaryViolated {
                        constraint_ref: entry.constraint_ref.clone(),
                        violation_description: format!(
                            "{} = {} violates threshold {}",
                            entry.context_key, val_str, entry.threshold_value
                        ),
                    });
                }
                // Check proximity for upper-bound comparisons
                let boundary_distance = (val - threshold).abs();
                let range = threshold.abs();
                if range > f64::EPSILON && boundary_distance / range < prox {
                    return Ok(EnvelopeStatus::ApproachingBoundary {
                        constraint_ref: entry.constraint_ref.clone(),
                        proximity_indicator: format!(
                            "{} = {} within {}% of threshold {}",
                            entry.context_key, val_str, prox * 100.0, entry.threshold_value
                        ),
                    });
                }
            }
        }
        Ok(EnvelopeStatus::WithinEnvelope)
    }

    fn register_constraint(
        &mut self,
        system_id: &str,
        entry: EnvelopeConstraintEntry,
    ) -> Result<(), SafetyError> {
        self.constraints
            .entry(system_id.to_string())
            .or_default()
            .push(entry);
        Ok(())
    }

    fn remove_constraint(
        &mut self,
        system_id: &str,
        constraint_ref: &str,
    ) -> Result<(), SafetyError> {
        if let Some(entries) = self.constraints.get_mut(system_id) {
            entries.retain(|e| e.constraint_ref != constraint_ref);
        }
        Ok(())
    }

    fn list_active_constraints(&self, system_id: &str) -> Vec<EnvelopeConstraintEntry> {
        self.constraints
            .get(system_id)
            .cloned()
            .unwrap_or_default()
    }

    fn recommend_response(&self, status: &EnvelopeStatus) -> RecommendedSafetyResponse {
        match status {
            EnvelopeStatus::WithinEnvelope => RecommendedSafetyResponse::ContinueOperation,
            EnvelopeStatus::ApproachingBoundary { .. } => {
                RecommendedSafetyResponse::IncreasedMonitoring {
                    monitoring_hint: "threshold proximity detected".into(),
                }
            }
            EnvelopeStatus::BoundaryViolated { .. } => {
                RecommendedSafetyResponse::EmergencyShutdown {
                    reason: "numeric threshold violated".into(),
                }
            }
            EnvelopeStatus::EnvelopeSuspended { reason } => {
                RecommendedSafetyResponse::EscalateToHuman {
                    reason: reason.clone(),
                }
            }
            EnvelopeStatus::Unknown => RecommendedSafetyResponse::EscalateToHuman {
                reason: "unknown state".into(),
            },
        }
    }

    fn monitor_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── NullSafetyEnvelopeMonitor ───────────────────────────────────────

pub struct NullSafetyEnvelopeMonitor;

impl SafetyEnvelopeMonitor for NullSafetyEnvelopeMonitor {
    fn check_envelope(
        &self,
        _system_id: &str,
        _context: &HashMap<String, String>,
    ) -> Result<EnvelopeStatus, SafetyError> {
        Ok(EnvelopeStatus::Unknown)
    }

    fn register_constraint(
        &mut self,
        _system_id: &str,
        _entry: EnvelopeConstraintEntry,
    ) -> Result<(), SafetyError> {
        Ok(())
    }

    fn remove_constraint(
        &mut self,
        _system_id: &str,
        _constraint_ref: &str,
    ) -> Result<(), SafetyError> {
        Ok(())
    }

    fn list_active_constraints(&self, _system_id: &str) -> Vec<EnvelopeConstraintEntry> {
        Vec::new()
    }

    fn recommend_response(&self, _status: &EnvelopeStatus) -> RecommendedSafetyResponse {
        RecommendedSafetyResponse::ContinueOperation
    }

    fn monitor_id(&self) -> &str {
        "null-envelope-monitor"
    }

    fn is_active(&self) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint_entry(key: &str, value: &str) -> EnvelopeConstraintEntry {
        EnvelopeConstraintEntry {
            constraint_ref: format!("c-{key}"),
            context_key: key.into(),
            threshold_value: value.into(),
            comparison: ThresholdComparison::LessThan,
        }
    }

    #[test]
    fn test_inmemory_within_envelope() {
        let mut mon = InMemorySafetyEnvelopeMonitor::new("m1");
        mon.register_constraint("sys", EnvelopeConstraintEntry {
            constraint_ref: "c1".into(),
            context_key: "mode".into(),
            threshold_value: "normal".into(),
            comparison: ThresholdComparison::Equal,
        }).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("mode".into(), "normal".into());
        let status = mon.check_envelope("sys", &ctx).unwrap();
        assert_eq!(status, EnvelopeStatus::WithinEnvelope);
    }

    #[test]
    fn test_inmemory_boundary_violated() {
        let mut mon = InMemorySafetyEnvelopeMonitor::new("m1");
        mon.register_constraint("sys", EnvelopeConstraintEntry {
            constraint_ref: "c1".into(),
            context_key: "mode".into(),
            threshold_value: "normal".into(),
            comparison: ThresholdComparison::Equal,
        }).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("mode".into(), "degraded".into());
        let status = mon.check_envelope("sys", &ctx).unwrap();
        assert!(matches!(status, EnvelopeStatus::BoundaryViolated { .. }));
    }

    #[test]
    fn test_inmemory_unknown_system() {
        let mon = InMemorySafetyEnvelopeMonitor::new("m1");
        let status = mon.check_envelope("unknown", &HashMap::new()).unwrap();
        assert_eq!(status, EnvelopeStatus::Unknown);
    }

    #[test]
    fn test_remove_constraint() {
        let mut mon = InMemorySafetyEnvelopeMonitor::new("m1");
        mon.register_constraint("sys", constraint_entry("temp", "100")).unwrap();
        assert_eq!(mon.list_active_constraints("sys").len(), 1);
        mon.remove_constraint("sys", "c-temp").unwrap();
        assert_eq!(mon.list_active_constraints("sys").len(), 0);
    }

    #[test]
    fn test_recommend_response_mapping() {
        let mon = InMemorySafetyEnvelopeMonitor::new("m1");
        assert!(matches!(
            mon.recommend_response(&EnvelopeStatus::WithinEnvelope),
            RecommendedSafetyResponse::ContinueOperation
        ));
        assert!(matches!(
            mon.recommend_response(&EnvelopeStatus::BoundaryViolated {
                constraint_ref: "c".into(),
                violation_description: "x".into()
            }),
            RecommendedSafetyResponse::DegradedOperation { .. }
        ));
    }

    #[test]
    fn test_threshold_within() {
        let mut mon = ThresholdBasedSafetyEnvelopeMonitor::new("t1", "0.1");
        mon.register_constraint("sys", EnvelopeConstraintEntry {
            constraint_ref: "c-temp".into(),
            context_key: "temperature".into(),
            threshold_value: "100.0".into(),
            comparison: ThresholdComparison::LessThan,
        }).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("temperature".into(), "50.0".into());
        let status = mon.check_envelope("sys", &ctx).unwrap();
        assert_eq!(status, EnvelopeStatus::WithinEnvelope);
    }

    #[test]
    fn test_threshold_violated() {
        let mut mon = ThresholdBasedSafetyEnvelopeMonitor::new("t1", "0.1");
        mon.register_constraint("sys", EnvelopeConstraintEntry {
            constraint_ref: "c-temp".into(),
            context_key: "temperature".into(),
            threshold_value: "100.0".into(),
            comparison: ThresholdComparison::LessThan,
        }).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("temperature".into(), "105.0".into());
        let status = mon.check_envelope("sys", &ctx).unwrap();
        assert!(matches!(status, EnvelopeStatus::BoundaryViolated { .. }));
    }

    #[test]
    fn test_threshold_approaching() {
        let mut mon = ThresholdBasedSafetyEnvelopeMonitor::new("t1", "0.1");
        mon.register_constraint("sys", EnvelopeConstraintEntry {
            constraint_ref: "c-temp".into(),
            context_key: "temperature".into(),
            threshold_value: "100.0".into(),
            comparison: ThresholdComparison::LessThan,
        }).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("temperature".into(), "95.0".into());
        let status = mon.check_envelope("sys", &ctx).unwrap();
        assert!(matches!(status, EnvelopeStatus::ApproachingBoundary { .. }));
    }

    #[test]
    fn test_threshold_recommends_shutdown_on_violation() {
        let mon = ThresholdBasedSafetyEnvelopeMonitor::new("t1", "0.1");
        let resp = mon.recommend_response(&EnvelopeStatus::BoundaryViolated {
            constraint_ref: "c".into(),
            violation_description: "x".into(),
        });
        assert!(matches!(resp, RecommendedSafetyResponse::EmergencyShutdown { .. }));
    }

    #[test]
    fn test_null_monitor() {
        let mut mon = NullSafetyEnvelopeMonitor;
        assert!(!mon.is_active());
        assert_eq!(mon.check_envelope("s", &HashMap::new()).unwrap(), EnvelopeStatus::Unknown);
        mon.register_constraint("s", constraint_entry("k", "v")).unwrap();
        assert!(mon.list_active_constraints("s").is_empty());
    }

    #[test]
    fn test_enum_display() {
        assert!(!EnvelopeStatus::WithinEnvelope.to_string().is_empty());
        assert!(!EnvelopeStatus::ApproachingBoundary {
            constraint_ref: "c".into(),
            proximity_indicator: "p".into()
        }.to_string().is_empty());
        assert!(!RecommendedSafetyResponse::ContinueOperation.to_string().is_empty());
        assert!(!RecommendedSafetyResponse::EmergencyShutdown { reason: "r".into() }.to_string().is_empty());
    }

    #[test]
    fn test_monitor_id() {
        let mon = InMemorySafetyEnvelopeMonitor::new("my-monitor");
        assert_eq!(mon.monitor_id(), "my-monitor");
        assert!(mon.is_active());
    }
}
