// ═══════════════════════════════════════════════════════════════════════
// Posture Aggregator — Computes security posture snapshots and deltas
// from backend data.
//
// Uses StoredPostureSnapshot and PostureClass from backend.rs for
// the output type.  PostureDelta captures how a system's posture
// changed between two snapshots.
//
// PostureWeights controls how the four subscores (vulnerability,
// control, incident, threat exposure) are weighted in the overall
// score.  Weights are stored as String to support Eq derivation
// (same pattern as backend.rs score fields).
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::{PostureClass, StoredPostureSnapshot};
use crate::error::SecurityError;

// ── PostureDelta ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureChangeDirection {
    Improved,
    Degraded,
    Unchanged,
}

impl fmt::Display for PostureChangeDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureDelta {
    pub system_identifier: String,
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub from_overall: String,
    pub to_overall: String,
    pub overall_change: PostureChangeDirection,
    pub from_class: PostureClass,
    pub to_class: PostureClass,
}

impl PostureDelta {
    pub fn compute(from: &StoredPostureSnapshot, to: &StoredPostureSnapshot) -> Self {
        let from_score: f64 = from.overall_score.parse().unwrap_or(0.0);
        let to_score: f64 = to.overall_score.parse().unwrap_or(0.0);
        let direction = if to_score > from_score + 0.001 {
            PostureChangeDirection::Improved
        } else if to_score < from_score - 0.001 {
            PostureChangeDirection::Degraded
        } else {
            PostureChangeDirection::Unchanged
        };
        Self {
            system_identifier: to.system_identifier.clone(),
            from_snapshot_id: from.snapshot_id.clone(),
            to_snapshot_id: to.snapshot_id.clone(),
            from_overall: from.overall_score.clone(),
            to_overall: to.overall_score.clone(),
            overall_change: direction,
            from_class: from.posture_class.clone(),
            to_class: to.posture_class.clone(),
        }
    }
}

// ── PostureWeights ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureWeights {
    pub vulnerability_weight: String,
    pub control_weight: String,
    pub incident_weight: String,
    pub threat_exposure_weight: String,
}

impl Default for PostureWeights {
    fn default() -> Self {
        Self {
            vulnerability_weight: "0.30".to_string(),
            control_weight: "0.25".to_string(),
            incident_weight: "0.25".to_string(),
            threat_exposure_weight: "0.20".to_string(),
        }
    }
}

impl PostureWeights {
    fn as_f64(&self) -> (f64, f64, f64, f64) {
        (
            self.vulnerability_weight.parse().unwrap_or(0.25),
            self.control_weight.parse().unwrap_or(0.25),
            self.incident_weight.parse().unwrap_or(0.25),
            self.threat_exposure_weight.parse().unwrap_or(0.25),
        )
    }
}

// ── SecurityPostureAggregator trait ──────────────────────────────

pub trait SecurityPostureAggregator {
    fn compute_posture_snapshot(
        &self,
        system_identifier: &str,
        snapshot_id: &str,
        captured_at: i64,
        vulnerability_subscore: &str,
        control_subscore: &str,
        incident_subscore: &str,
        threat_exposure_subscore: &str,
    ) -> Result<StoredPostureSnapshot, SecurityError>;

    fn compute_posture_delta(
        &self,
        from: &StoredPostureSnapshot,
        to: &StoredPostureSnapshot,
    ) -> Result<PostureDelta, SecurityError>;

    fn configure_weights(&mut self, weights: PostureWeights);

    fn aggregator_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemorySecurityPostureAggregator ────────────────────────────
// Simple average: (v + c + i + t) / 4

pub struct InMemorySecurityPostureAggregator {
    id: String,
}

impl InMemorySecurityPostureAggregator {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl SecurityPostureAggregator for InMemorySecurityPostureAggregator {
    fn compute_posture_snapshot(
        &self,
        system_identifier: &str,
        snapshot_id: &str,
        captured_at: i64,
        vulnerability_subscore: &str,
        control_subscore: &str,
        incident_subscore: &str,
        threat_exposure_subscore: &str,
    ) -> Result<StoredPostureSnapshot, SecurityError> {
        let v: f64 = vulnerability_subscore.parse().unwrap_or(0.0);
        let c: f64 = control_subscore.parse().unwrap_or(0.0);
        let i: f64 = incident_subscore.parse().unwrap_or(0.0);
        let t: f64 = threat_exposure_subscore.parse().unwrap_or(0.0);
        let overall = (v + c + i + t) / 4.0;
        let overall_str = format!("{overall:.2}");
        let posture_class = PostureClass::from_score_str(&overall_str);
        Ok(StoredPostureSnapshot {
            snapshot_id: snapshot_id.to_string(),
            system_identifier: system_identifier.to_string(),
            captured_at,
            vulnerability_subscore: vulnerability_subscore.to_string(),
            control_subscore: control_subscore.to_string(),
            incident_subscore: incident_subscore.to_string(),
            threat_exposure_subscore: threat_exposure_subscore.to_string(),
            overall_score: overall_str,
            posture_class,
        })
    }

    fn compute_posture_delta(
        &self,
        from: &StoredPostureSnapshot,
        to: &StoredPostureSnapshot,
    ) -> Result<PostureDelta, SecurityError> {
        Ok(PostureDelta::compute(from, to))
    }

    fn configure_weights(&mut self, _weights: PostureWeights) {
        // Simple average ignores weights
    }

    fn aggregator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── WeightedAverageSecurityPostureAggregator ─────────────────────

pub struct WeightedAverageSecurityPostureAggregator {
    id: String,
    weights: PostureWeights,
}

impl WeightedAverageSecurityPostureAggregator {
    pub fn new(id: &str, weights: PostureWeights) -> Self {
        Self {
            id: id.to_string(),
            weights,
        }
    }
}

impl SecurityPostureAggregator for WeightedAverageSecurityPostureAggregator {
    fn compute_posture_snapshot(
        &self,
        system_identifier: &str,
        snapshot_id: &str,
        captured_at: i64,
        vulnerability_subscore: &str,
        control_subscore: &str,
        incident_subscore: &str,
        threat_exposure_subscore: &str,
    ) -> Result<StoredPostureSnapshot, SecurityError> {
        let v: f64 = vulnerability_subscore.parse().unwrap_or(0.0);
        let c: f64 = control_subscore.parse().unwrap_or(0.0);
        let i: f64 = incident_subscore.parse().unwrap_or(0.0);
        let t: f64 = threat_exposure_subscore.parse().unwrap_or(0.0);
        let (wv, wc, wi, wt) = self.weights.as_f64();
        let total_weight = wv + wc + wi + wt;
        let overall = if total_weight > 0.0 {
            (v * wv + c * wc + i * wi + t * wt) / total_weight
        } else {
            0.0
        };
        let overall_str = format!("{overall:.2}");
        let posture_class = PostureClass::from_score_str(&overall_str);
        Ok(StoredPostureSnapshot {
            snapshot_id: snapshot_id.to_string(),
            system_identifier: system_identifier.to_string(),
            captured_at,
            vulnerability_subscore: vulnerability_subscore.to_string(),
            control_subscore: control_subscore.to_string(),
            incident_subscore: incident_subscore.to_string(),
            threat_exposure_subscore: threat_exposure_subscore.to_string(),
            overall_score: overall_str,
            posture_class,
        })
    }

    fn compute_posture_delta(
        &self,
        from: &StoredPostureSnapshot,
        to: &StoredPostureSnapshot,
    ) -> Result<PostureDelta, SecurityError> {
        Ok(PostureDelta::compute(from, to))
    }

    fn configure_weights(&mut self, weights: PostureWeights) {
        self.weights = weights;
    }

    fn aggregator_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_aggregator_snapshot() {
        let agg = InMemorySecurityPostureAggregator::new("agg-1");
        let snap = agg.compute_posture_snapshot(
            "sys-1", "snap-1", 1000, "80.0", "90.0", "70.0", "60.0",
        ).unwrap();
        assert_eq!(snap.overall_score, "75.00");
        assert_eq!(snap.posture_class, PostureClass::Adequate);
    }

    #[test]
    fn test_weighted_aggregator_snapshot() {
        let agg = WeightedAverageSecurityPostureAggregator::new("agg-2", PostureWeights::default());
        let snap = agg.compute_posture_snapshot(
            "sys-1", "snap-1", 1000, "80.0", "90.0", "70.0", "60.0",
        ).unwrap();
        // 80*0.30 + 90*0.25 + 70*0.25 + 60*0.20 = 24 + 22.5 + 17.5 + 12 = 76.0
        assert_eq!(snap.overall_score, "76.00");
    }

    #[test]
    fn test_posture_delta_improved() {
        let from = StoredPostureSnapshot {
            snapshot_id: "s1".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 1000,
            vulnerability_subscore: "70.0".to_string(),
            control_subscore: "70.0".to_string(),
            incident_subscore: "70.0".to_string(),
            threat_exposure_subscore: "70.0".to_string(),
            overall_score: "70.00".to_string(),
            posture_class: PostureClass::Adequate,
        };
        let to = StoredPostureSnapshot {
            snapshot_id: "s2".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 2000,
            vulnerability_subscore: "90.0".to_string(),
            control_subscore: "90.0".to_string(),
            incident_subscore: "90.0".to_string(),
            threat_exposure_subscore: "90.0".to_string(),
            overall_score: "90.00".to_string(),
            posture_class: PostureClass::Strong,
        };
        let delta = PostureDelta::compute(&from, &to);
        assert_eq!(delta.overall_change, PostureChangeDirection::Improved);
        assert_eq!(delta.from_class, PostureClass::Adequate);
        assert_eq!(delta.to_class, PostureClass::Strong);
    }

    #[test]
    fn test_posture_delta_degraded() {
        let from = StoredPostureSnapshot {
            snapshot_id: "s1".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 1000,
            vulnerability_subscore: "90.0".to_string(),
            control_subscore: "90.0".to_string(),
            incident_subscore: "90.0".to_string(),
            threat_exposure_subscore: "90.0".to_string(),
            overall_score: "90.00".to_string(),
            posture_class: PostureClass::Strong,
        };
        let to = StoredPostureSnapshot {
            snapshot_id: "s2".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 2000,
            vulnerability_subscore: "30.0".to_string(),
            control_subscore: "30.0".to_string(),
            incident_subscore: "30.0".to_string(),
            threat_exposure_subscore: "30.0".to_string(),
            overall_score: "30.00".to_string(),
            posture_class: PostureClass::Critical,
        };
        let delta = PostureDelta::compute(&from, &to);
        assert_eq!(delta.overall_change, PostureChangeDirection::Degraded);
    }

    #[test]
    fn test_posture_delta_unchanged() {
        let snap = StoredPostureSnapshot {
            snapshot_id: "s1".to_string(),
            system_identifier: "sys-1".to_string(),
            captured_at: 1000,
            vulnerability_subscore: "80.0".to_string(),
            control_subscore: "80.0".to_string(),
            incident_subscore: "80.0".to_string(),
            threat_exposure_subscore: "80.0".to_string(),
            overall_score: "80.00".to_string(),
            posture_class: PostureClass::Adequate,
        };
        let delta = PostureDelta::compute(&snap, &snap);
        assert_eq!(delta.overall_change, PostureChangeDirection::Unchanged);
    }

    #[test]
    fn test_configure_weights() {
        let mut agg = WeightedAverageSecurityPostureAggregator::new("agg-3", PostureWeights::default());
        let new_weights = PostureWeights {
            vulnerability_weight: "0.50".to_string(),
            control_weight: "0.20".to_string(),
            incident_weight: "0.20".to_string(),
            threat_exposure_weight: "0.10".to_string(),
        };
        agg.configure_weights(new_weights);
        let snap = agg.compute_posture_snapshot(
            "sys-1", "snap-1", 1000, "100.0", "0.0", "0.0", "0.0",
        ).unwrap();
        // 100*0.50 + 0 + 0 + 0 = 50.0
        assert_eq!(snap.overall_score, "50.00");
    }

    #[test]
    fn test_aggregator_metadata() {
        let agg = InMemorySecurityPostureAggregator::new("agg-1");
        assert_eq!(agg.aggregator_id(), "agg-1");
        assert!(agg.is_active());
    }

    #[test]
    fn test_posture_weights_default() {
        let w = PostureWeights::default();
        assert_eq!(w.vulnerability_weight, "0.30");
        assert_eq!(w.control_weight, "0.25");
        assert_eq!(w.incident_weight, "0.25");
        assert_eq!(w.threat_exposure_weight, "0.20");
    }

    #[test]
    fn test_posture_change_direction_display() {
        assert_eq!(PostureChangeDirection::Improved.to_string(), "Improved");
        assert_eq!(PostureChangeDirection::Degraded.to_string(), "Degraded");
        assert_eq!(PostureChangeDirection::Unchanged.to_string(), "Unchanged");
    }

    #[test]
    fn test_strong_posture_class() {
        let agg = InMemorySecurityPostureAggregator::new("agg-1");
        let snap = agg.compute_posture_snapshot(
            "sys-1", "snap-1", 1000, "95.0", "95.0", "95.0", "95.0",
        ).unwrap();
        assert_eq!(snap.posture_class, PostureClass::Strong);
    }

    #[test]
    fn test_critical_posture_class() {
        let agg = InMemorySecurityPostureAggregator::new("agg-1");
        let snap = agg.compute_posture_snapshot(
            "sys-1", "snap-1", 1000, "20.0", "20.0", "20.0", "20.0",
        ).unwrap();
        assert_eq!(snap.posture_class, PostureClass::Critical);
    }

    #[test]
    fn test_aggregator_delta_via_trait() {
        let agg = InMemorySecurityPostureAggregator::new("agg-1");
        let from = agg.compute_posture_snapshot("sys-1", "s1", 1000, "60.0", "60.0", "60.0", "60.0").unwrap();
        let to = agg.compute_posture_snapshot("sys-1", "s2", 2000, "80.0", "80.0", "80.0", "80.0").unwrap();
        let delta = agg.compute_posture_delta(&from, &to).unwrap();
        assert_eq!(delta.overall_change, PostureChangeDirection::Improved);
    }
}
