// ═══════════════════════════════════════════════════════════════════════
// rune-monitoring — Health Checks, Metrics, Threshold Alerting, SLAs
//
// Layer 1: the observation layer of the RUNE governance ecosystem.
// Provides health checks, metric collection, threshold-based alerting,
// SLA tracking, uptime/MTBF, and aggregated system status. Speaks in
// rune-security's SecuritySeverity vocabulary so monitoring events flow
// naturally into security dashboards and incident management.
// ═══════════════════════════════════════════════════════════════════════

pub mod audit;
pub mod collector;
pub mod error;
pub mod health;
pub mod metric;
pub mod policy;
pub mod sla;
pub mod status;
pub mod threshold;
pub mod uptime;

pub use audit::{MonitoringAuditEvent, MonitoringAuditLog, MonitoringEventType};
pub use collector::{CollectorEngine, MetricSource, MetricSourceType};
pub use error::{MonitoringError, MonitoringResult};
pub use health::{
    HealthCheck, HealthCheckId, HealthCheckResult, HealthCheckRunner, HealthCheckType,
    HealthStatus, HealthSummary,
};
pub use metric::{
    MetricId, MetricRegistry, MetricSample, MetricTrendResult, MonitoringMetric,
    MonitoringMetricType, MonitoringTrend,
};
pub use policy::{
    default_production, high_availability, AlertChannel, MonitoringPolicy, MonitoringPolicySet,
    MonitoringTarget,
};
pub use sla::{
    fast_api, five_nines, four_nines, standard_api, three_nines, Sla, SlaComparison, SlaId,
    SlaState, SlaStatus, SlaTarget, SlaTracker, SlaViolation,
};
pub use status::{
    ComponentStatusEntry, OverallStatus, StatusAggregator, StatusPage, SystemStatus,
};
pub use threshold::{
    high_error_rate, high_latency, high_memory, low_availability, queue_depth, ThresholdAlert,
    ThresholdAlertStatus, ThresholdCondition, ThresholdEngine, ThresholdRule,
};
pub use uptime::{ComponentStatus, ComponentUptime, StatusChange, UptimeTracker};

// Layer 2 re-exports
pub use health::{
    DegradedStateDetector, DegradedThresholds, DependencyAwareScheduler, GroupHealthResult,
    GroupStrategy, HealthCheckDependency, HealthCheckGroup, SystemHealthState,
};
pub use metric::{
    AnomalyResult, DerivedFormula, DerivedMetric, Histogram, HistogramRegistry,
    MetricAnomalyDetector, MetricPipeline, MetricTransform, RateMetric,
};
pub use threshold::{
    AlertCorrelator, AlertDeduplicator, AlertSuppressor, CorrelatedAlert, CorrelationRule,
    SuppressionRule,
};
pub use sla::{BurnRateAlert, BurnRateAlertLevel, BurnRateWindow, ErrorBudget};
pub use status::{
    DashboardComponent, DashboardStatus, StatusHistory, StatusHistoryEntry, StatusPageBuilder,
};
