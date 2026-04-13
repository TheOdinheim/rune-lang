// ═══════════════════════════════════════════════════════════════════════
// Health — Framework health aggregation across components and pipeline.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::registry::{ComponentRegistry, ComponentStatus};

// ── FrameworkHealthStatus ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameworkHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl fmt::Display for FrameworkHealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ComponentHealthEntry ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealthEntry {
    pub component_id: String,
    pub component_name: String,
    pub status: ComponentStatus,
    pub last_heartbeat: i64,
    pub is_stale: bool,
}

// ── PipelineStats ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStats {
    pub total_evaluations: u64,
    pub successful: u64,
    pub denied: u64,
    pub errors: u64,
    pub total_duration_ms: u64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self {
            total_evaluations: 0,
            successful: 0,
            denied: 0,
            errors: 0,
            total_duration_ms: 0,
        }
    }

    pub fn record_evaluation(&mut self, permitted: bool, errored: bool, duration_ms: u64) {
        self.total_evaluations += 1;
        self.total_duration_ms += duration_ms;
        if errored {
            self.errors += 1;
        } else if permitted {
            self.successful += 1;
        } else {
            self.denied += 1;
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_evaluations == 0 {
            return 0.0;
        }
        self.successful as f64 / self.total_evaluations as f64
    }

    pub fn denial_rate(&self) -> f64 {
        if self.total_evaluations == 0 {
            return 0.0;
        }
        self.denied as f64 / self.total_evaluations as f64
    }

    pub fn error_rate(&self) -> f64 {
        if self.total_evaluations == 0 {
            return 0.0;
        }
        self.errors as f64 / self.total_evaluations as f64
    }

    pub fn avg_duration_ms(&self) -> f64 {
        if self.total_evaluations == 0 {
            return 0.0;
        }
        self.total_duration_ms as f64 / self.total_evaluations as f64
    }
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── PipelineHealth ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineHealth {
    pub configured_stages: usize,
    pub enabled_stages: usize,
    pub stats: PipelineStats,
}

// ── FrameworkHealth ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkHealth {
    pub status: FrameworkHealthStatus,
    pub components: Vec<ComponentHealthEntry>,
    pub pipeline: PipelineHealth,
    pub message: String,
}

impl fmt::Display for FrameworkHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Framework: {} — {} components, {}/{} stages enabled, {} evaluations",
            self.status,
            self.components.len(),
            self.pipeline.enabled_stages,
            self.pipeline.configured_stages,
            self.pipeline.stats.total_evaluations,
        )
    }
}

// ── FrameworkHealthAssessor ───────────────────────────────────────────

pub struct FrameworkHealthAssessor;

impl FrameworkHealthAssessor {
    pub fn assess(
        registry: &ComponentRegistry,
        configured_stages: usize,
        enabled_stages: usize,
        stats: &PipelineStats,
        current_time: i64,
        max_stale_seconds: i64,
    ) -> FrameworkHealth {
        let readiness = registry.system_readiness();

        let mut component_entries = Vec::new();
        // Build entries from available info via readiness counts
        // We need to iterate all components in the registry
        // Since ComponentRegistry doesn't expose an iterator, we use by_type for each
        // Actually, let's use the stale_components + available_components approach
        let stale = registry.stale_components(current_time, max_stale_seconds);
        let stale_ids: Vec<String> = stale.iter().map(|c| c.id.0.clone()).collect();

        // Use by_type across all types to gather components
        let all_types = [
            crate::registry::ComponentType::Identity,
            crate::registry::ComponentType::Permission,
            crate::registry::ComponentType::Secret,
            crate::registry::ComponentType::Privacy,
            crate::registry::ComponentType::Security,
            crate::registry::ComponentType::Detection,
            crate::registry::ComponentType::Shield,
            crate::registry::ComponentType::Monitoring,
            crate::registry::ComponentType::Provenance,
            crate::registry::ComponentType::Trust,
        ];

        for ct in &all_types {
            for info in registry.by_type(*ct) {
                component_entries.push(ComponentHealthEntry {
                    component_id: info.id.0.clone(),
                    component_name: info.name.clone(),
                    status: info.status,
                    last_heartbeat: info.last_heartbeat,
                    is_stale: stale_ids.contains(&info.id.0),
                });
            }
        }

        let status = if readiness.unavailable > 0 {
            FrameworkHealthStatus::Unhealthy
        } else if readiness.degraded > 0 || !stale_ids.is_empty() {
            FrameworkHealthStatus::Degraded
        } else if readiness.total_components == 0 {
            FrameworkHealthStatus::Unknown
        } else {
            FrameworkHealthStatus::Healthy
        };

        let message = match status {
            FrameworkHealthStatus::Healthy => "All components operational".into(),
            FrameworkHealthStatus::Degraded => format!(
                "{} degraded, {} stale",
                readiness.degraded,
                stale_ids.len()
            ),
            FrameworkHealthStatus::Unhealthy => format!(
                "{} components unavailable",
                readiness.unavailable
            ),
            FrameworkHealthStatus::Unknown => "No components registered".into(),
        };

        FrameworkHealth {
            status,
            components: component_entries,
            pipeline: PipelineHealth {
                configured_stages,
                enabled_stages,
                stats: stats.clone(),
            },
            message,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(FrameworkHealthStatus::Healthy.to_string(), "Healthy");
        assert_eq!(FrameworkHealthStatus::Degraded.to_string(), "Degraded");
        assert_eq!(FrameworkHealthStatus::Unhealthy.to_string(), "Unhealthy");
        assert_eq!(FrameworkHealthStatus::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_pipeline_stats_new() {
        let stats = PipelineStats::new();
        assert_eq!(stats.total_evaluations, 0);
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.denial_rate(), 0.0);
        assert_eq!(stats.error_rate(), 0.0);
        assert_eq!(stats.avg_duration_ms(), 0.0);
    }

    #[test]
    fn test_pipeline_stats_record() {
        let mut stats = PipelineStats::new();
        stats.record_evaluation(true, false, 10);
        stats.record_evaluation(true, false, 20);
        stats.record_evaluation(false, false, 15);
        stats.record_evaluation(false, true, 5);
        assert_eq!(stats.total_evaluations, 4);
        assert_eq!(stats.successful, 2);
        assert_eq!(stats.denied, 1);
        assert_eq!(stats.errors, 1);
        assert!((stats.success_rate() - 0.5).abs() < f64::EPSILON);
        assert!((stats.denial_rate() - 0.25).abs() < f64::EPSILON);
        assert!((stats.error_rate() - 0.25).abs() < f64::EPSILON);
        assert!((stats.avg_duration_ms() - 12.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_assess_healthy() {
        let mut reg = ComponentRegistry::new();
        reg.register(ComponentInfo::new("sec-1", ComponentType::Security, "Security", "1.0.0"))
            .unwrap();
        reg.heartbeat(&ComponentId::new("sec-1"), 1000).unwrap();

        let stats = PipelineStats::new();
        let health = FrameworkHealthAssessor::assess(&reg, 3, 3, &stats, 1010, 300);
        assert_eq!(health.status, FrameworkHealthStatus::Healthy);
        assert_eq!(health.components.len(), 1);
        assert!(!health.components[0].is_stale);
    }

    #[test]
    fn test_assess_degraded_stale() {
        let mut reg = ComponentRegistry::new();
        reg.register(ComponentInfo::new("sec-1", ComponentType::Security, "Security", "1.0.0"))
            .unwrap();
        reg.heartbeat(&ComponentId::new("sec-1"), 100).unwrap();

        let stats = PipelineStats::new();
        let health = FrameworkHealthAssessor::assess(&reg, 3, 3, &stats, 1000, 300);
        assert_eq!(health.status, FrameworkHealthStatus::Degraded);
        assert!(health.components[0].is_stale);
    }

    #[test]
    fn test_assess_unhealthy() {
        let mut reg = ComponentRegistry::new();
        reg.register(ComponentInfo::new("sec-1", ComponentType::Security, "Security", "1.0.0"))
            .unwrap();
        reg.update_status(&ComponentId::new("sec-1"), ComponentStatus::Unavailable)
            .unwrap();

        let stats = PipelineStats::new();
        let health = FrameworkHealthAssessor::assess(&reg, 3, 3, &stats, 1000, 300);
        assert_eq!(health.status, FrameworkHealthStatus::Unhealthy);
    }

    #[test]
    fn test_assess_unknown_empty() {
        let reg = ComponentRegistry::new();
        let stats = PipelineStats::new();
        let health = FrameworkHealthAssessor::assess(&reg, 0, 0, &stats, 1000, 300);
        assert_eq!(health.status, FrameworkHealthStatus::Unknown);
        assert_eq!(health.message, "No components registered");
    }

    #[test]
    fn test_framework_health_display() {
        let health = FrameworkHealth {
            status: FrameworkHealthStatus::Healthy,
            components: vec![],
            pipeline: PipelineHealth {
                configured_stages: 5,
                enabled_stages: 4,
                stats: PipelineStats::new(),
            },
            message: "ok".into(),
        };
        let display = health.to_string();
        assert!(display.contains("Healthy"));
        assert!(display.contains("4/5"));
    }

    #[test]
    fn test_assess_degraded_component_status() {
        let mut reg = ComponentRegistry::new();
        reg.register(ComponentInfo::new("sec-1", ComponentType::Security, "Security", "1.0.0"))
            .unwrap();
        reg.update_status(&ComponentId::new("sec-1"), ComponentStatus::Degraded)
            .unwrap();

        let stats = PipelineStats::new();
        let health = FrameworkHealthAssessor::assess(&reg, 3, 3, &stats, 1000, 300);
        assert_eq!(health.status, FrameworkHealthStatus::Degraded);
        assert!(health.message.contains("degraded"));
    }
}
