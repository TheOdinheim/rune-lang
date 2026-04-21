// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — NetworkGovernanceBackend trait for pluggable storage of
// TLS policies, connection records, segmentation policies, DNS policies,
// certificate records, and governance snapshots.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

// ── StoredTlsPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTlsPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub scope: TlsPolicyScope,
    pub min_tls_version: StoredMinTlsVersion,
    pub require_forward_secrecy: bool,
    pub require_client_certificate: bool,
    pub require_certificate_transparency: bool,
    pub allowed_cipher_suites: Vec<String>,
    pub denied_cipher_suites: Vec<String>,
    pub enforce_ocsp_stapling: bool,
    pub max_session_duration_ms: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── TlsPolicyScope ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsPolicyScope {
    Global,
    ServiceLevel,
    EndpointLevel,
}

impl fmt::Display for TlsPolicyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Global => "Global",
            Self::ServiceLevel => "ServiceLevel",
            Self::EndpointLevel => "EndpointLevel",
        };
        f.write_str(s)
    }
}

// ── StoredMinTlsVersion ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredMinTlsVersion {
    Tls12,
    Tls13,
}

impl fmt::Display for StoredMinTlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        };
        f.write_str(s)
    }
}

// ── StoredConnectionRecord ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConnectionRecord {
    pub record_id: String,
    pub connection_id: String,
    pub source_addr: String,
    pub dest_addr: String,
    pub protocol: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub connection_status: StoredConnectionStatus,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

// ── StoredConnectionStatus ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredConnectionStatus {
    Active,
    Closed,
    Failed,
    Rejected,
}

impl fmt::Display for StoredConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Active => "Active",
            Self::Closed => "Closed",
            Self::Failed => "Failed",
            Self::Rejected => "Rejected",
        };
        f.write_str(s)
    }
}

// ── StoredSegmentationPolicy ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSegmentationPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub default_action: StoredSegmentationDefaultAction,
    pub enforcement_mode: StoredEnforcementMode,
    pub zone_count: String,
    pub flow_rule_count: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredSegmentationDefaultAction ────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredSegmentationDefaultAction {
    Allow,
    Deny,
    LogOnly,
}

impl fmt::Display for StoredSegmentationDefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allow => "Allow",
            Self::Deny => "Deny",
            Self::LogOnly => "LogOnly",
        };
        f.write_str(s)
    }
}

// ── StoredEnforcementMode ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredEnforcementMode {
    Enforcing,
    Permissive,
    Disabled,
}

impl fmt::Display for StoredEnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Enforcing => "Enforcing",
            Self::Permissive => "Permissive",
            Self::Disabled => "Disabled",
        };
        f.write_str(s)
    }
}

// ── StoredDnsPolicy ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDnsPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub require_dnssec: bool,
    pub blocked_domain_count: String,
    pub allowed_domain_count: String,
    pub require_encrypted_transport: bool,
    pub encrypted_transport_protocol: String,
    pub max_queries_per_minute: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredCertificateRecord ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCertificateRecord {
    pub record_id: String,
    pub certificate_id: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub key_algorithm: String,
    pub key_size_bits: String,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
    pub certificate_status: StoredCertificateRecordStatus,
    pub certificate_transparency_logged: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredCertificateRecordStatus ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredCertificateRecordStatus {
    Valid,
    Expired,
    Revoked,
    PendingRenewal,
    Unknown,
}

impl fmt::Display for StoredCertificateRecordStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Valid => "Valid",
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
            Self::PendingRenewal => "PendingRenewal",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ── StoredNetworkGovernanceSnapshot ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredNetworkGovernanceSnapshot {
    pub snapshot_id: String,
    pub captured_at: i64,
    pub active_tls_policies: String,
    pub active_connections: String,
    pub active_segmentation_policies: String,
    pub active_dns_policies: String,
    pub active_certificates: String,
    pub metadata: HashMap<String, String>,
}

// ── NetworkGovernanceBackend trait ──────────────────────────────────

pub trait NetworkGovernanceBackend {
    // TLS policies
    fn store_tls_policy(&mut self, policy: StoredTlsPolicy) -> Result<(), NetworkError>;
    fn retrieve_tls_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredTlsPolicy>, NetworkError>;
    fn list_tls_policies(&self) -> Vec<StoredTlsPolicy>;
    fn tls_policy_count(&self) -> usize;

    // Connection records
    fn store_connection_record(
        &mut self,
        record: StoredConnectionRecord,
    ) -> Result<(), NetworkError>;
    fn retrieve_connection_record(
        &self,
        record_id: &str,
    ) -> Result<Option<StoredConnectionRecord>, NetworkError>;
    fn list_connections_by_status(
        &self,
        status: &StoredConnectionStatus,
    ) -> Vec<StoredConnectionRecord>;
    fn connection_record_count(&self) -> usize;

    // Segmentation policies
    fn store_segmentation_policy(
        &mut self,
        policy: StoredSegmentationPolicy,
    ) -> Result<(), NetworkError>;
    fn retrieve_segmentation_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredSegmentationPolicy>, NetworkError>;
    fn list_segmentation_policies(&self) -> Vec<StoredSegmentationPolicy>;

    // DNS policies
    fn store_dns_policy(&mut self, policy: StoredDnsPolicy) -> Result<(), NetworkError>;
    fn retrieve_dns_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredDnsPolicy>, NetworkError>;
    fn list_dns_policies(&self) -> Vec<StoredDnsPolicy>;

    // Certificate records
    fn store_certificate_record(
        &mut self,
        record: StoredCertificateRecord,
    ) -> Result<(), NetworkError>;
    fn retrieve_certificate_record(
        &self,
        record_id: &str,
    ) -> Result<Option<StoredCertificateRecord>, NetworkError>;
    fn list_certificates_by_status(
        &self,
        status: &StoredCertificateRecordStatus,
    ) -> Vec<StoredCertificateRecord>;

    // Snapshots
    fn store_governance_snapshot(
        &mut self,
        snapshot: StoredNetworkGovernanceSnapshot,
    ) -> Result<(), NetworkError>;
    fn retrieve_governance_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<StoredNetworkGovernanceSnapshot>, NetworkError>;
    fn list_snapshots(&self) -> Vec<StoredNetworkGovernanceSnapshot>;

    // Lifecycle
    fn flush(&mut self) -> Result<(), NetworkError>;
    fn backend_info(&self) -> String;
}

// ── InMemoryNetworkGovernanceBackend ────────────────────────────────

pub struct InMemoryNetworkGovernanceBackend {
    tls_policies: HashMap<String, StoredTlsPolicy>,
    connection_records: HashMap<String, StoredConnectionRecord>,
    segmentation_policies: HashMap<String, StoredSegmentationPolicy>,
    dns_policies: HashMap<String, StoredDnsPolicy>,
    certificate_records: HashMap<String, StoredCertificateRecord>,
    snapshots: HashMap<String, StoredNetworkGovernanceSnapshot>,
}

impl InMemoryNetworkGovernanceBackend {
    pub fn new() -> Self {
        Self {
            tls_policies: HashMap::new(),
            connection_records: HashMap::new(),
            segmentation_policies: HashMap::new(),
            dns_policies: HashMap::new(),
            certificate_records: HashMap::new(),
            snapshots: HashMap::new(),
        }
    }
}

impl Default for InMemoryNetworkGovernanceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkGovernanceBackend for InMemoryNetworkGovernanceBackend {
    fn store_tls_policy(&mut self, policy: StoredTlsPolicy) -> Result<(), NetworkError> {
        self.tls_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_tls_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredTlsPolicy>, NetworkError> {
        Ok(self.tls_policies.get(policy_id).cloned())
    }

    fn list_tls_policies(&self) -> Vec<StoredTlsPolicy> {
        self.tls_policies.values().cloned().collect()
    }

    fn tls_policy_count(&self) -> usize {
        self.tls_policies.len()
    }

    fn store_connection_record(
        &mut self,
        record: StoredConnectionRecord,
    ) -> Result<(), NetworkError> {
        self.connection_records
            .insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_connection_record(
        &self,
        record_id: &str,
    ) -> Result<Option<StoredConnectionRecord>, NetworkError> {
        Ok(self.connection_records.get(record_id).cloned())
    }

    fn list_connections_by_status(
        &self,
        status: &StoredConnectionStatus,
    ) -> Vec<StoredConnectionRecord> {
        self.connection_records
            .values()
            .filter(|r| &r.connection_status == status)
            .cloned()
            .collect()
    }

    fn connection_record_count(&self) -> usize {
        self.connection_records.len()
    }

    fn store_segmentation_policy(
        &mut self,
        policy: StoredSegmentationPolicy,
    ) -> Result<(), NetworkError> {
        self.segmentation_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_segmentation_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredSegmentationPolicy>, NetworkError> {
        Ok(self.segmentation_policies.get(policy_id).cloned())
    }

    fn list_segmentation_policies(&self) -> Vec<StoredSegmentationPolicy> {
        self.segmentation_policies.values().cloned().collect()
    }

    fn store_dns_policy(&mut self, policy: StoredDnsPolicy) -> Result<(), NetworkError> {
        self.dns_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_dns_policy(
        &self,
        policy_id: &str,
    ) -> Result<Option<StoredDnsPolicy>, NetworkError> {
        Ok(self.dns_policies.get(policy_id).cloned())
    }

    fn list_dns_policies(&self) -> Vec<StoredDnsPolicy> {
        self.dns_policies.values().cloned().collect()
    }

    fn store_certificate_record(
        &mut self,
        record: StoredCertificateRecord,
    ) -> Result<(), NetworkError> {
        self.certificate_records
            .insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_certificate_record(
        &self,
        record_id: &str,
    ) -> Result<Option<StoredCertificateRecord>, NetworkError> {
        Ok(self.certificate_records.get(record_id).cloned())
    }

    fn list_certificates_by_status(
        &self,
        status: &StoredCertificateRecordStatus,
    ) -> Vec<StoredCertificateRecord> {
        self.certificate_records
            .values()
            .filter(|r| &r.certificate_status == status)
            .cloned()
            .collect()
    }

    fn store_governance_snapshot(
        &mut self,
        snapshot: StoredNetworkGovernanceSnapshot,
    ) -> Result<(), NetworkError> {
        self.snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    fn retrieve_governance_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<StoredNetworkGovernanceSnapshot>, NetworkError> {
        Ok(self.snapshots.get(snapshot_id).cloned())
    }

    fn list_snapshots(&self) -> Vec<StoredNetworkGovernanceSnapshot> {
        self.snapshots.values().cloned().collect()
    }

    fn flush(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }

    fn backend_info(&self) -> String {
        format!(
            "InMemoryNetworkGovernanceBackend(tls={}, conn={}, seg={}, dns={}, cert={}, snap={})",
            self.tls_policies.len(),
            self.connection_records.len(),
            self.segmentation_policies.len(),
            self.dns_policies.len(),
            self.certificate_records.len(),
            self.snapshots.len(),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tls_policy() -> StoredTlsPolicy {
        StoredTlsPolicy {
            policy_id: "tls-1".into(),
            policy_name: "Modern".into(),
            scope: TlsPolicyScope::Global,
            min_tls_version: StoredMinTlsVersion::Tls13,
            require_forward_secrecy: true,
            require_client_certificate: false,
            require_certificate_transparency: true,
            allowed_cipher_suites: vec!["AES_256_GCM_SHA384".into()],
            denied_cipher_suites: vec!["RC4_SHA".into()],
            enforce_ocsp_stapling: true,
            max_session_duration_ms: "3600000".into(),
            created_at: 1000,
            updated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_connection() -> StoredConnectionRecord {
        StoredConnectionRecord {
            record_id: "rec-1".into(),
            connection_id: "conn-1".into(),
            source_addr: "10.0.0.1".into(),
            dest_addr: "10.0.0.2".into(),
            protocol: "TLS".into(),
            tls_version: "TLS 1.3".into(),
            cipher_suite: "AES_256_GCM_SHA384".into(),
            connection_status: StoredConnectionStatus::Active,
            opened_at: 1000,
            closed_at: None,
            metadata: HashMap::new(),
        }
    }

    fn sample_segmentation_policy() -> StoredSegmentationPolicy {
        StoredSegmentationPolicy {
            policy_id: "seg-1".into(),
            policy_name: "Production".into(),
            default_action: StoredSegmentationDefaultAction::Deny,
            enforcement_mode: StoredEnforcementMode::Enforcing,
            zone_count: "4".into(),
            flow_rule_count: "12".into(),
            created_at: 1000,
            updated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_dns_policy() -> StoredDnsPolicy {
        StoredDnsPolicy {
            policy_id: "dns-1".into(),
            policy_name: "Strict DNS".into(),
            require_dnssec: true,
            blocked_domain_count: "150".into(),
            allowed_domain_count: "0".into(),
            require_encrypted_transport: true,
            encrypted_transport_protocol: "DoH".into(),
            max_queries_per_minute: "1000".into(),
            created_at: 1000,
            updated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_certificate() -> StoredCertificateRecord {
        StoredCertificateRecord {
            record_id: "cert-rec-1".into(),
            certificate_id: "cert-1".into(),
            subject: "CN=example.com".into(),
            issuer: "CN=TestCA".into(),
            serial_number: "001".into(),
            key_algorithm: "RSA".into(),
            key_size_bits: "2048".into(),
            not_before: 1000,
            not_after: 100_000_000,
            fingerprint: "abc123".into(),
            certificate_status: StoredCertificateRecordStatus::Valid,
            certificate_transparency_logged: true,
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_snapshot() -> StoredNetworkGovernanceSnapshot {
        StoredNetworkGovernanceSnapshot {
            snapshot_id: "snap-1".into(),
            captured_at: 5000,
            active_tls_policies: "2".into(),
            active_connections: "10".into(),
            active_segmentation_policies: "1".into(),
            active_dns_policies: "1".into(),
            active_certificates: "5".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_retrieve_tls_policy() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend.store_tls_policy(sample_tls_policy()).unwrap();
        let retrieved = backend.retrieve_tls_policy("tls-1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().policy_name, "Modern");
        assert_eq!(backend.tls_policy_count(), 1);
    }

    #[test]
    fn test_list_tls_policies() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend.store_tls_policy(sample_tls_policy()).unwrap();
        assert_eq!(backend.list_tls_policies().len(), 1);
    }

    #[test]
    fn test_store_and_retrieve_connection() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend.store_connection_record(sample_connection()).unwrap();
        let retrieved = backend.retrieve_connection_record("rec-1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(backend.connection_record_count(), 1);
    }

    #[test]
    fn test_list_connections_by_status() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend.store_connection_record(sample_connection()).unwrap();
        let active = backend.list_connections_by_status(&StoredConnectionStatus::Active);
        assert_eq!(active.len(), 1);
        let closed = backend.list_connections_by_status(&StoredConnectionStatus::Closed);
        assert!(closed.is_empty());
    }

    #[test]
    fn test_store_and_retrieve_segmentation_policy() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend
            .store_segmentation_policy(sample_segmentation_policy())
            .unwrap();
        let retrieved = backend.retrieve_segmentation_policy("seg-1").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_store_and_retrieve_dns_policy() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend.store_dns_policy(sample_dns_policy()).unwrap();
        let retrieved = backend.retrieve_dns_policy("dns-1").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_store_and_retrieve_certificate() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend
            .store_certificate_record(sample_certificate())
            .unwrap();
        let retrieved = backend.retrieve_certificate_record("cert-rec-1").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_list_certificates_by_status() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend
            .store_certificate_record(sample_certificate())
            .unwrap();
        let valid = backend
            .list_certificates_by_status(&StoredCertificateRecordStatus::Valid);
        assert_eq!(valid.len(), 1);
        let expired = backend
            .list_certificates_by_status(&StoredCertificateRecordStatus::Expired);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_store_and_retrieve_snapshot() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend
            .store_governance_snapshot(sample_snapshot())
            .unwrap();
        let retrieved = backend.retrieve_governance_snapshot("snap-1").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_list_snapshots() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        backend
            .store_governance_snapshot(sample_snapshot())
            .unwrap();
        assert_eq!(backend.list_snapshots().len(), 1);
    }

    #[test]
    fn test_flush() {
        let mut backend = InMemoryNetworkGovernanceBackend::new();
        assert!(backend.flush().is_ok());
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryNetworkGovernanceBackend::new();
        let info = backend.backend_info();
        assert!(info.contains("InMemoryNetworkGovernanceBackend"));
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let backend = InMemoryNetworkGovernanceBackend::new();
        assert!(backend.retrieve_tls_policy("nope").unwrap().is_none());
        assert!(backend
            .retrieve_connection_record("nope")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_segmentation_policy("nope")
            .unwrap()
            .is_none());
        assert!(backend.retrieve_dns_policy("nope").unwrap().is_none());
        assert!(backend
            .retrieve_certificate_record("nope")
            .unwrap()
            .is_none());
        assert!(backend
            .retrieve_governance_snapshot("nope")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_enum_display() {
        assert_eq!(TlsPolicyScope::Global.to_string(), "Global");
        assert_eq!(StoredMinTlsVersion::Tls13.to_string(), "TLS 1.3");
        assert_eq!(StoredConnectionStatus::Active.to_string(), "Active");
        assert_eq!(StoredSegmentationDefaultAction::Deny.to_string(), "Deny");
        assert_eq!(StoredEnforcementMode::Enforcing.to_string(), "Enforcing");
        assert_eq!(
            StoredCertificateRecordStatus::PendingRenewal.to_string(),
            "PendingRenewal"
        );
    }

    #[test]
    fn test_stored_types_eq() {
        let p = sample_tls_policy();
        assert_eq!(p, p.clone());
        let c = sample_connection();
        assert_eq!(c, c.clone());
        let s = sample_segmentation_policy();
        assert_eq!(s, s.clone());
        let d = sample_dns_policy();
        assert_eq!(d, d.clone());
        let cert = sample_certificate();
        assert_eq!(cert, cert.clone());
        let snap = sample_snapshot();
        assert_eq!(snap, snap.clone());
    }
}
