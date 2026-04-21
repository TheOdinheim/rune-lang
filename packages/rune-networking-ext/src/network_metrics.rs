// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — NetworkGovernanceMetricsCollector trait for computing
// network governance metrics: TLS compliance rate, mTLS adoption rate,
// certificate health, segmentation compliance rate, DNS block rate.
// All computed values are String for Eq derivation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── NetworkGovernanceMetricSnapshot ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkGovernanceMetricSnapshot {
    pub snapshot_id: String,
    pub computed_at: i64,
    pub tls_compliance_rate: String,
    pub mtls_adoption_rate: String,
    pub certificate_health_rate: String,
    pub segmentation_compliance_rate: String,
    pub dns_block_rate: String,
    pub metadata: HashMap<String, String>,
}

// ── TlsConnectionRecord ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TlsConnectionRecord {
    pub connection_id: String,
    pub tls_version: String,
    pub has_client_cert: bool,
    pub compliant: bool,
    pub recorded_at: i64,
}

// ── CertificateHealthRecord ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CertificateHealthRecord {
    pub certificate_id: String,
    pub healthy: bool,
    pub checked_at: i64,
}

// ── SegmentationFlowRecord ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SegmentationFlowRecord {
    pub source_zone: String,
    pub dest_zone: String,
    pub compliant: bool,
    pub checked_at: i64,
}

// ── DnsQueryRecord ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsQueryRecord {
    pub domain: String,
    pub blocked: bool,
    pub queried_at: i64,
}

// ── NetworkGovernanceMetricsCollector trait ──────────────────────────

pub trait NetworkGovernanceMetricsCollector {
    fn compute_tls_compliance_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError>;

    fn compute_mtls_adoption_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError>;

    fn compute_certificate_health(
        &self,
    ) -> Result<String, NetworkError>;

    fn compute_segmentation_compliance_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError>;

    fn compute_dns_block_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError>;

    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryNetworkGovernanceMetricsCollector ───────────────────────

pub struct InMemoryNetworkGovernanceMetricsCollector {
    id: String,
    tls_connections: Vec<TlsConnectionRecord>,
    certificate_health: Vec<CertificateHealthRecord>,
    segmentation_flows: Vec<SegmentationFlowRecord>,
    dns_queries: Vec<DnsQueryRecord>,
}

impl InMemoryNetworkGovernanceMetricsCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tls_connections: Vec::new(),
            certificate_health: Vec::new(),
            segmentation_flows: Vec::new(),
            dns_queries: Vec::new(),
        }
    }

    pub fn add_tls_connection(&mut self, record: TlsConnectionRecord) {
        self.tls_connections.push(record);
    }

    pub fn add_certificate_health(&mut self, record: CertificateHealthRecord) {
        self.certificate_health.push(record);
    }

    pub fn add_segmentation_flow(&mut self, record: SegmentationFlowRecord) {
        self.segmentation_flows.push(record);
    }

    pub fn add_dns_query(&mut self, record: DnsQueryRecord) {
        self.dns_queries.push(record);
    }
}

impl NetworkGovernanceMetricsCollector for InMemoryNetworkGovernanceMetricsCollector {
    fn compute_tls_compliance_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError> {
        if window_end <= window_start {
            return Err(NetworkError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let in_window: Vec<&TlsConnectionRecord> = self
            .tls_connections
            .iter()
            .filter(|c| c.recorded_at >= window_start && c.recorded_at <= window_end)
            .collect();
        if in_window.is_empty() {
            return Ok("0.0000".into());
        }
        let compliant = in_window.iter().filter(|c| c.compliant).count();
        let rate = compliant as f64 / in_window.len() as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_mtls_adoption_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError> {
        if window_end <= window_start {
            return Err(NetworkError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let in_window: Vec<&TlsConnectionRecord> = self
            .tls_connections
            .iter()
            .filter(|c| c.recorded_at >= window_start && c.recorded_at <= window_end)
            .collect();
        if in_window.is_empty() {
            return Ok("0.0000".into());
        }
        let with_mtls = in_window.iter().filter(|c| c.has_client_cert).count();
        let rate = with_mtls as f64 / in_window.len() as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_certificate_health(
        &self,
    ) -> Result<String, NetworkError> {
        if self.certificate_health.is_empty() {
            return Ok("0.0000".into());
        }
        let healthy = self
            .certificate_health
            .iter()
            .filter(|c| c.healthy)
            .count();
        let rate = healthy as f64 / self.certificate_health.len() as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_segmentation_compliance_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError> {
        if window_end <= window_start {
            return Err(NetworkError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let in_window: Vec<&SegmentationFlowRecord> = self
            .segmentation_flows
            .iter()
            .filter(|f| f.checked_at >= window_start && f.checked_at <= window_end)
            .collect();
        if in_window.is_empty() {
            return Ok("0.0000".into());
        }
        let compliant = in_window.iter().filter(|f| f.compliant).count();
        let rate = compliant as f64 / in_window.len() as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_dns_block_rate(
        &self,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, NetworkError> {
        if window_end <= window_start {
            return Err(NetworkError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let in_window: Vec<&DnsQueryRecord> = self
            .dns_queries
            .iter()
            .filter(|q| q.queried_at >= window_start && q.queried_at <= window_end)
            .collect();
        if in_window.is_empty() {
            return Ok("0.0000".into());
        }
        let blocked = in_window.iter().filter(|q| q.blocked).count();
        let rate = blocked as f64 / in_window.len() as f64;
        Ok(format!("{:.4}", rate))
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullNetworkGovernanceMetricsCollector ───────────────────────────

pub struct NullNetworkGovernanceMetricsCollector;

impl NetworkGovernanceMetricsCollector for NullNetworkGovernanceMetricsCollector {
    fn compute_tls_compliance_rate(
        &self,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, NetworkError> {
        Ok("0.0000".into())
    }

    fn compute_mtls_adoption_rate(
        &self,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, NetworkError> {
        Ok("0.0000".into())
    }

    fn compute_certificate_health(
        &self,
    ) -> Result<String, NetworkError> {
        Ok("0.0000".into())
    }

    fn compute_segmentation_compliance_rate(
        &self,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, NetworkError> {
        Ok("0.0000".into())
    }

    fn compute_dns_block_rate(
        &self,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, NetworkError> {
        Ok("0.0000".into())
    }

    fn collector_id(&self) -> &str {
        "null-network-metrics-collector"
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

    #[test]
    fn test_tls_compliance_rate() {
        let mut c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        c.add_tls_connection(TlsConnectionRecord {
            connection_id: "c1".into(),
            tls_version: "TLS 1.3".into(),
            has_client_cert: true,
            compliant: true,
            recorded_at: 500,
        });
        c.add_tls_connection(TlsConnectionRecord {
            connection_id: "c2".into(),
            tls_version: "TLS 1.0".into(),
            has_client_cert: false,
            compliant: false,
            recorded_at: 600,
        });
        let rate = c.compute_tls_compliance_rate(0, 1000).unwrap();
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_tls_compliance_no_data() {
        let c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        let rate = c.compute_tls_compliance_rate(0, 1000).unwrap();
        assert_eq!(rate, "0.0000");
    }

    #[test]
    fn test_mtls_adoption_rate() {
        let mut c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        c.add_tls_connection(TlsConnectionRecord {
            connection_id: "c1".into(),
            tls_version: "TLS 1.3".into(),
            has_client_cert: true,
            compliant: true,
            recorded_at: 500,
        });
        c.add_tls_connection(TlsConnectionRecord {
            connection_id: "c2".into(),
            tls_version: "TLS 1.3".into(),
            has_client_cert: false,
            compliant: true,
            recorded_at: 600,
        });
        let rate = c.compute_mtls_adoption_rate(0, 1000).unwrap();
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_certificate_health() {
        let mut c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        c.add_certificate_health(CertificateHealthRecord {
            certificate_id: "cert-1".into(),
            healthy: true,
            checked_at: 500,
        });
        c.add_certificate_health(CertificateHealthRecord {
            certificate_id: "cert-2".into(),
            healthy: false,
            checked_at: 600,
        });
        c.add_certificate_health(CertificateHealthRecord {
            certificate_id: "cert-3".into(),
            healthy: true,
            checked_at: 700,
        });
        let rate = c.compute_certificate_health().unwrap();
        assert_eq!(rate, "0.6667");
    }

    #[test]
    fn test_segmentation_compliance_rate() {
        let mut c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        c.add_segmentation_flow(SegmentationFlowRecord {
            source_zone: "dmz".into(),
            dest_zone: "internal".into(),
            compliant: true,
            checked_at: 500,
        });
        c.add_segmentation_flow(SegmentationFlowRecord {
            source_zone: "dmz".into(),
            dest_zone: "restricted".into(),
            compliant: false,
            checked_at: 600,
        });
        let rate = c.compute_segmentation_compliance_rate(0, 1000).unwrap();
        assert_eq!(rate, "0.5000");
    }

    #[test]
    fn test_dns_block_rate() {
        let mut c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        c.add_dns_query(DnsQueryRecord {
            domain: "evil.com".into(),
            blocked: true,
            queried_at: 500,
        });
        c.add_dns_query(DnsQueryRecord {
            domain: "good.com".into(),
            blocked: false,
            queried_at: 600,
        });
        c.add_dns_query(DnsQueryRecord {
            domain: "ok.com".into(),
            blocked: false,
            queried_at: 700,
        });
        let rate = c.compute_dns_block_rate(0, 1000).unwrap();
        assert_eq!(rate, "0.3333");
    }

    #[test]
    fn test_null_collector() {
        let c = NullNetworkGovernanceMetricsCollector;
        assert!(!c.is_active());
        assert_eq!(c.collector_id(), "null-network-metrics-collector");
        assert_eq!(c.compute_tls_compliance_rate(0, 1000).unwrap(), "0.0000");
        assert_eq!(c.compute_mtls_adoption_rate(0, 1000).unwrap(), "0.0000");
        assert_eq!(c.compute_certificate_health().unwrap(), "0.0000");
        assert_eq!(
            c.compute_segmentation_compliance_rate(0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(c.compute_dns_block_rate(0, 1000).unwrap(), "0.0000");
    }

    #[test]
    fn test_collector_id() {
        let c = InMemoryNetworkGovernanceMetricsCollector::new("my-metrics");
        assert_eq!(c.collector_id(), "my-metrics");
        assert!(c.is_active());
    }

    #[test]
    fn test_snapshot_eq() {
        let s = NetworkGovernanceMetricSnapshot {
            snapshot_id: "snap-1".into(),
            computed_at: 5000,
            tls_compliance_rate: "0.9500".into(),
            mtls_adoption_rate: "0.7500".into(),
            certificate_health_rate: "0.9000".into(),
            segmentation_compliance_rate: "0.8500".into(),
            dns_block_rate: "0.0500".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(s, s.clone());
    }

    #[test]
    fn test_invalid_window() {
        let c = InMemoryNetworkGovernanceMetricsCollector::new("m1");
        assert!(c.compute_tls_compliance_rate(1000, 500).is_err());
        assert!(c.compute_mtls_adoption_rate(1000, 500).is_err());
        assert!(c
            .compute_segmentation_compliance_rate(1000, 500)
            .is_err());
        assert!(c.compute_dns_block_rate(1000, 500).is_err());
    }
}
