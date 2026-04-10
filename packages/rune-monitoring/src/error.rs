// ═══════════════════════════════════════════════════════════════════════
// MonitoringError — typed errors for health/metric/threshold/SLA ops.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitoringError {
    HealthCheckNotFound { id: String },
    HealthCheckTimeout { id: String, timeout_ms: u64 },
    MetricNotFound { id: String },
    InvalidMetricValue { reason: String },
    InvalidThreshold { reason: String },
    SlaNotFound { id: String },
    ComponentNotFound { id: String },
    PolicyNotFound { id: String },
    CollectorNotFound { id: String },
    InvalidConfiguration { reason: String },
    InsufficientData { reason: String },
}

impl fmt::Display for MonitoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HealthCheckNotFound { id } => write!(f, "health check not found: {id}"),
            Self::HealthCheckTimeout { id, timeout_ms } => {
                write!(f, "health check {id} timed out after {timeout_ms}ms")
            }
            Self::MetricNotFound { id } => write!(f, "metric not found: {id}"),
            Self::InvalidMetricValue { reason } => write!(f, "invalid metric value: {reason}"),
            Self::InvalidThreshold { reason } => write!(f, "invalid threshold: {reason}"),
            Self::SlaNotFound { id } => write!(f, "SLA not found: {id}"),
            Self::ComponentNotFound { id } => write!(f, "component not found: {id}"),
            Self::PolicyNotFound { id } => write!(f, "monitoring policy not found: {id}"),
            Self::CollectorNotFound { id } => write!(f, "metric collector not found: {id}"),
            Self::InvalidConfiguration { reason } => {
                write!(f, "invalid monitoring configuration: {reason}")
            }
            Self::InsufficientData { reason } => write!(f, "insufficient data: {reason}"),
        }
    }
}

impl std::error::Error for MonitoringError {}

pub type MonitoringResult<T> = Result<T, MonitoringError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_all_variants() {
        let cases = [
            MonitoringError::HealthCheckNotFound { id: "h1".into() },
            MonitoringError::HealthCheckTimeout { id: "h1".into(), timeout_ms: 5000 },
            MonitoringError::MetricNotFound { id: "m1".into() },
            MonitoringError::InvalidMetricValue { reason: "NaN".into() },
            MonitoringError::InvalidThreshold { reason: "min>max".into() },
            MonitoringError::SlaNotFound { id: "s1".into() },
            MonitoringError::ComponentNotFound { id: "c1".into() },
            MonitoringError::PolicyNotFound { id: "p1".into() },
            MonitoringError::CollectorNotFound { id: "col1".into() },
            MonitoringError::InvalidConfiguration { reason: "x".into() },
            MonitoringError::InsufficientData { reason: "need 4".into() },
        ];
        for e in cases {
            assert!(!e.to_string().is_empty());
        }
    }
}
