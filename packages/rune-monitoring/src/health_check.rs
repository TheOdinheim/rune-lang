// ═══════════════════════════════════════════════════════════════════════
// Health Check Probes — Kubernetes-aligned health check probe trait.
//
// ProbeKind matches Kubernetes semantics: Liveness (is the process
// alive?), Readiness (can it accept traffic?), Startup (has it
// finished initialising?).
//
// HealthProbeResult is distinct from the L1 HealthCheckResult in
// health.rs.  HealthProbeResult is the L3 backend-facing type with
// response_time as String for Eq derivation.
//
// CompositeHealthCheckProbe aggregates multiple probes into a single
// result.  DependencyAwareHealthCheckProbe checks a named dependency
// first and only proceeds to the main probe if the dependency is
// healthy.  NullHealthCheckProbe always returns healthy — useful for
// testing and fallback wiring.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::MonitoringError;

// ── ProbeKind ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    Liveness,
    Readiness,
    Startup,
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Liveness => write!(f, "liveness"),
            Self::Readiness => write!(f, "readiness"),
            Self::Startup => write!(f, "startup"),
        }
    }
}

// ── HealthProbeStatus ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HealthProbeStatus {
    Healthy,
    Unhealthy,
    Degraded,
    Unknown,
}

impl fmt::Display for HealthProbeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ── HealthProbeResult ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthProbeResult {
    pub probe_id: String,
    pub kind: ProbeKind,
    pub status: HealthProbeStatus,
    pub checked_at: i64,
    pub response_time: String,
    pub observations: HashMap<String, String>,
}

impl HealthProbeResult {
    pub fn healthy(probe_id: &str, kind: ProbeKind, checked_at: i64, response_time: &str) -> Self {
        Self {
            probe_id: probe_id.to_string(),
            kind,
            status: HealthProbeStatus::Healthy,
            checked_at,
            response_time: response_time.to_string(),
            observations: HashMap::new(),
        }
    }

    pub fn unhealthy(probe_id: &str, kind: ProbeKind, checked_at: i64, reason: &str) -> Self {
        Self {
            probe_id: probe_id.to_string(),
            kind,
            status: HealthProbeStatus::Unhealthy,
            checked_at,
            response_time: "0".to_string(),
            observations: HashMap::from([("reason".to_string(), reason.to_string())]),
        }
    }

    pub fn with_observation(mut self, key: &str, value: &str) -> Self {
        self.observations.insert(key.to_string(), value.to_string());
        self
    }
}

// ── HealthCheckProbe trait ──────────────────────────────────────

pub trait HealthCheckProbe {
    fn probe(&self) -> Result<HealthProbeResult, MonitoringError>;
    fn probe_kind(&self) -> ProbeKind;
    fn probe_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── NullHealthCheckProbe ────────────────────────────────────────

pub struct NullHealthCheckProbe {
    id: String,
    kind: ProbeKind,
}

impl NullHealthCheckProbe {
    pub fn new(id: &str, kind: ProbeKind) -> Self {
        Self { id: id.to_string(), kind }
    }
}

impl HealthCheckProbe for NullHealthCheckProbe {
    fn probe(&self) -> Result<HealthProbeResult, MonitoringError> {
        Ok(HealthProbeResult::healthy(&self.id, self.kind.clone(), 0, "0"))
    }

    fn probe_kind(&self) -> ProbeKind { self.kind.clone() }
    fn probe_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── CompositeHealthCheckProbe ───────────────────────────────────

pub struct CompositeHealthCheckProbe {
    id: String,
    kind: ProbeKind,
    probes: Vec<Box<dyn HealthCheckProbe>>,
}

impl CompositeHealthCheckProbe {
    pub fn new(id: &str, kind: ProbeKind, probes: Vec<Box<dyn HealthCheckProbe>>) -> Self {
        Self {
            id: id.to_string(),
            kind,
            probes,
        }
    }
}

impl HealthCheckProbe for CompositeHealthCheckProbe {
    fn probe(&self) -> Result<HealthProbeResult, MonitoringError> {
        let mut worst_status = HealthProbeStatus::Healthy;
        let mut observations = HashMap::new();

        for p in &self.probes {
            if !p.is_active() {
                continue;
            }
            let result = p.probe()?;
            observations.insert(
                format!("probe:{}", p.probe_id()),
                result.status.to_string(),
            );
            match result.status {
                HealthProbeStatus::Unhealthy => {
                    worst_status = HealthProbeStatus::Unhealthy;
                }
                HealthProbeStatus::Degraded if worst_status == HealthProbeStatus::Healthy => {
                    worst_status = HealthProbeStatus::Degraded;
                }
                HealthProbeStatus::Unknown
                    if worst_status == HealthProbeStatus::Healthy =>
                {
                    worst_status = HealthProbeStatus::Unknown;
                }
                _ => {}
            }
        }

        Ok(HealthProbeResult {
            probe_id: self.id.clone(),
            kind: self.kind.clone(),
            status: worst_status,
            checked_at: 0,
            response_time: "0".to_string(),
            observations,
        })
    }

    fn probe_kind(&self) -> ProbeKind { self.kind.clone() }
    fn probe_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── DependencyAwareHealthCheckProbe ─────────────────────────────

pub struct DependencyAwareHealthCheckProbe {
    id: String,
    dependency: Box<dyn HealthCheckProbe>,
    main_probe: Box<dyn HealthCheckProbe>,
}

impl DependencyAwareHealthCheckProbe {
    pub fn new(
        id: &str,
        dependency: Box<dyn HealthCheckProbe>,
        main_probe: Box<dyn HealthCheckProbe>,
    ) -> Self {
        Self {
            id: id.to_string(),
            dependency,
            main_probe,
        }
    }
}

impl HealthCheckProbe for DependencyAwareHealthCheckProbe {
    fn probe(&self) -> Result<HealthProbeResult, MonitoringError> {
        let dep_result = self.dependency.probe()?;
        if dep_result.status != HealthProbeStatus::Healthy {
            return Ok(HealthProbeResult {
                probe_id: self.id.clone(),
                kind: self.main_probe.probe_kind(),
                status: HealthProbeStatus::Unhealthy,
                checked_at: 0,
                response_time: "0".to_string(),
                observations: HashMap::from([(
                    "dependency_failed".to_string(),
                    format!("{}: {}", self.dependency.probe_id(), dep_result.status),
                )]),
            });
        }
        self.main_probe.probe()
    }

    fn probe_kind(&self) -> ProbeKind { self.main_probe.probe_kind() }
    fn probe_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { self.main_probe.is_active() }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProbe {
        id: String,
        kind: ProbeKind,
        status: HealthProbeStatus,
    }

    impl FixedProbe {
        fn new(id: &str, kind: ProbeKind, status: HealthProbeStatus) -> Self {
            Self { id: id.to_string(), kind, status }
        }
    }

    impl HealthCheckProbe for FixedProbe {
        fn probe(&self) -> Result<HealthProbeResult, MonitoringError> {
            Ok(HealthProbeResult {
                probe_id: self.id.clone(),
                kind: self.kind.clone(),
                status: self.status.clone(),
                checked_at: 1000,
                response_time: "5".to_string(),
                observations: HashMap::new(),
            })
        }

        fn probe_kind(&self) -> ProbeKind { self.kind.clone() }
        fn probe_id(&self) -> &str { &self.id }
        fn is_active(&self) -> bool { true }
    }

    #[test]
    fn test_probe_kind_display() {
        assert_eq!(ProbeKind::Liveness.to_string(), "liveness");
        assert_eq!(ProbeKind::Readiness.to_string(), "readiness");
        assert_eq!(ProbeKind::Startup.to_string(), "startup");
    }

    #[test]
    fn test_health_probe_status_display() {
        assert_eq!(HealthProbeStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthProbeStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthProbeStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthProbeStatus::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_health_probe_result_constructors() {
        let healthy = HealthProbeResult::healthy("p1", ProbeKind::Liveness, 1000, "5");
        assert_eq!(healthy.status, HealthProbeStatus::Healthy);
        assert_eq!(healthy.response_time, "5");

        let unhealthy = HealthProbeResult::unhealthy("p1", ProbeKind::Readiness, 1000, "timeout");
        assert_eq!(unhealthy.status, HealthProbeStatus::Unhealthy);
        assert_eq!(unhealthy.observations.get("reason").unwrap(), "timeout");
    }

    #[test]
    fn test_health_probe_result_with_observation() {
        let result = HealthProbeResult::healthy("p1", ProbeKind::Liveness, 1000, "5")
            .with_observation("version", "1.2.3");
        assert_eq!(result.observations.get("version").unwrap(), "1.2.3");
    }

    #[test]
    fn test_null_probe() {
        let probe = NullHealthCheckProbe::new("null-1", ProbeKind::Liveness);
        let result = probe.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Healthy);
        assert_eq!(probe.probe_kind(), ProbeKind::Liveness);
        assert_eq!(probe.probe_id(), "null-1");
        assert!(probe.is_active());
    }

    #[test]
    fn test_composite_all_healthy() {
        let composite = CompositeHealthCheckProbe::new(
            "comp-1",
            ProbeKind::Readiness,
            vec![
                Box::new(FixedProbe::new("a", ProbeKind::Readiness, HealthProbeStatus::Healthy)),
                Box::new(FixedProbe::new("b", ProbeKind::Readiness, HealthProbeStatus::Healthy)),
            ],
        );
        let result = composite.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Healthy);
        assert_eq!(result.observations.len(), 2);
    }

    #[test]
    fn test_composite_one_degraded() {
        let composite = CompositeHealthCheckProbe::new(
            "comp-1",
            ProbeKind::Readiness,
            vec![
                Box::new(FixedProbe::new("a", ProbeKind::Readiness, HealthProbeStatus::Healthy)),
                Box::new(FixedProbe::new("b", ProbeKind::Readiness, HealthProbeStatus::Degraded)),
            ],
        );
        let result = composite.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Degraded);
    }

    #[test]
    fn test_composite_one_unhealthy() {
        let composite = CompositeHealthCheckProbe::new(
            "comp-1",
            ProbeKind::Readiness,
            vec![
                Box::new(FixedProbe::new("a", ProbeKind::Readiness, HealthProbeStatus::Healthy)),
                Box::new(FixedProbe::new("b", ProbeKind::Readiness, HealthProbeStatus::Unhealthy)),
            ],
        );
        let result = composite.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Unhealthy);
    }

    #[test]
    fn test_dependency_aware_healthy_dependency() {
        let dep = Box::new(FixedProbe::new("dep", ProbeKind::Liveness, HealthProbeStatus::Healthy));
        let main = Box::new(FixedProbe::new("main", ProbeKind::Readiness, HealthProbeStatus::Healthy));
        let probe = DependencyAwareHealthCheckProbe::new("da-1", dep, main);
        let result = probe.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Healthy);
        assert_eq!(result.probe_id, "main"); // Delegates to main probe
    }

    #[test]
    fn test_dependency_aware_unhealthy_dependency() {
        let dep = Box::new(FixedProbe::new("dep", ProbeKind::Liveness, HealthProbeStatus::Unhealthy));
        let main = Box::new(FixedProbe::new("main", ProbeKind::Readiness, HealthProbeStatus::Healthy));
        let probe = DependencyAwareHealthCheckProbe::new("da-1", dep, main);
        let result = probe.probe().unwrap();
        assert_eq!(result.status, HealthProbeStatus::Unhealthy);
        assert!(result.observations.contains_key("dependency_failed"));
    }

    #[test]
    fn test_dependency_aware_probe_kind() {
        let dep = Box::new(NullHealthCheckProbe::new("dep", ProbeKind::Liveness));
        let main = Box::new(NullHealthCheckProbe::new("main", ProbeKind::Startup));
        let probe = DependencyAwareHealthCheckProbe::new("da-1", dep, main);
        assert_eq!(probe.probe_kind(), ProbeKind::Startup);
        assert_eq!(probe.probe_id(), "da-1");
        assert!(probe.is_active());
    }
}
