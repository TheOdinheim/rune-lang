// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — NetworkGovernanceExporter trait for exporting network
// governance data: JSON, PCI DSS v4.0 network compliance, CJIS
// network security, zero trust assessment (NIST SP 800-207),
// TLS certificate inventory.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{
    StoredCertificateRecord, StoredDnsPolicy, StoredSegmentationPolicy, StoredTlsPolicy,
};
use crate::error::NetworkError;

// ── NetworkGovernanceExporter trait ─────────────────────────────────

pub trait NetworkGovernanceExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError>;

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError>;

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError>;

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError>;

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        segmentation_policies: &[StoredSegmentationPolicy],
        dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError>;

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonNetworkGovernanceExporter ──────────────────────────────────

pub struct JsonNetworkGovernanceExporter;

impl NetworkGovernanceExporter for JsonNetworkGovernanceExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError> {
        serde_json::to_string_pretty(policy)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError> {
        serde_json::to_string_pretty(policy)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError> {
        serde_json::to_string_pretty(policy)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "certificate_inventory": certificates,
            "certificate_count": certificates.len(),
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        segmentation_policies: &[StoredSegmentationPolicy],
        dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "tls_policies": tls_policies,
            "segmentation_policies": segmentation_policies,
            "dns_policies": dns_policies,
            "tls_policy_count": tls_policies.len(),
            "segmentation_policy_count": segmentation_policies.len(),
            "dns_policy_count": dns_policies.len(),
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── PciDssNetworkComplianceExporter ────────────────────────────────
// PCI DSS v4.0 Requirement 1: network security controls report.

pub struct PciDssNetworkComplianceExporter;

impl NetworkGovernanceExporter for PciDssNetworkComplianceExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "pci_dss_v4_requirement_1": {
                "tls_policy": {
                    "policy_id": policy.policy_id,
                    "min_tls_version": policy.min_tls_version.to_string(),
                    "forward_secrecy": policy.require_forward_secrecy,
                    "certificate_transparency": policy.require_certificate_transparency,
                    "ocsp_stapling": policy.enforce_ocsp_stapling,
                },
                "compliance_note": "PCI DSS v4.0 requires TLS 1.2+ for cardholder data",
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "pci_dss_v4_network_segmentation": {
                "policy_id": policy.policy_id,
                "default_action": policy.default_action.to_string(),
                "enforcement_mode": policy.enforcement_mode.to_string(),
                "zone_count": policy.zone_count,
                "compliance_note": "PCI DSS v4.0 Requirement 1.2: network segmentation controls",
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "pci_dss_v4_dns_security": {
                "policy_id": policy.policy_id,
                "dnssec_required": policy.require_dnssec,
                "encrypted_transport": policy.require_encrypted_transport,
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError> {
        let entries: Vec<serde_json::Value> = certificates
            .iter()
            .map(|c| {
                serde_json::json!({
                    "subject": c.subject,
                    "key_algorithm": c.key_algorithm,
                    "key_size": c.key_size_bits,
                    "status": c.certificate_status.to_string(),
                    "ct_logged": c.certificate_transparency_logged,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "pci_dss_v4_certificate_inventory": entries,
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        segmentation_policies: &[StoredSegmentationPolicy],
        dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "pci_dss_v4_network_compliance_summary": {
                "tls_policy_count": tls_policies.len(),
                "segmentation_policy_count": segmentation_policies.len(),
                "dns_policy_count": dns_policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "PciDssNetworkCompliance"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── CjisNetworkSecurityExporter ────────────────────────────────────
// CJIS Security Policy v6.0 Policy Area 6 compliance.

pub struct CjisNetworkSecurityExporter;

impl NetworkGovernanceExporter for CjisNetworkSecurityExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# CJIS Network Security Report — TLS Policy\n\n");
        report.push_str(&format!("- **Policy**: {} ({})\n", policy.policy_name, policy.policy_id));
        report.push_str(&format!("- **Min TLS**: {}\n", policy.min_tls_version));
        report.push_str(&format!("- **mTLS Required**: {}\n", policy.require_client_certificate));
        report.push_str(&format!("- **Forward Secrecy**: {}\n\n", policy.require_forward_secrecy));
        report.push_str("### CJIS Policy Area 6 Compliance\n\n");
        report.push_str("- Encryption in transit: enforced via TLS policy\n");
        report.push_str("- mTLS for law enforcement channels: documented\n");
        Ok(report)
    }

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# CJIS Network Segmentation Report\n\n");
        report.push_str(&format!("- **Policy**: {} ({})\n", policy.policy_name, policy.policy_id));
        report.push_str(&format!("- **Default Action**: {}\n", policy.default_action));
        report.push_str(&format!("- **Enforcement**: {}\n", policy.enforcement_mode));
        report.push_str(&format!("- **Zones**: {}\n", policy.zone_count));
        Ok(report)
    }

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# CJIS DNS Security Report\n\n");
        report.push_str(&format!("- **Policy**: {} ({})\n", policy.policy_name, policy.policy_id));
        report.push_str(&format!("- **DNSSEC Required**: {}\n", policy.require_dnssec));
        report.push_str(&format!("- **Encrypted DNS**: {}\n", policy.require_encrypted_transport));
        Ok(report)
    }

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# CJIS Certificate Inventory\n\n");
        report.push_str(&format!("Total certificates: {}\n\n", certificates.len()));
        for c in certificates {
            report.push_str(&format!(
                "- {} ({}): {} — {}\n",
                c.subject, c.key_algorithm, c.certificate_status, c.fingerprint
            ));
        }
        Ok(report)
    }

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        segmentation_policies: &[StoredSegmentationPolicy],
        dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# CJIS Network Security Summary\n\n");
        report.push_str(&format!("- TLS policies: {}\n", tls_policies.len()));
        report.push_str(&format!("- Segmentation policies: {}\n", segmentation_policies.len()));
        report.push_str(&format!("- DNS policies: {}\n", dns_policies.len()));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "CjisNetworkSecurity"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── ZeroTrustAssessmentExporter ────────────────────────────────────
// NIST SP 800-207 zero trust architecture assessment.

pub struct ZeroTrustAssessmentExporter;

impl NetworkGovernanceExporter for ZeroTrustAssessmentExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "nist_sp_800_207_tls": {
                "policy_id": policy.policy_id,
                "min_tls_version": policy.min_tls_version.to_string(),
                "mutual_authentication": policy.require_client_certificate,
                "certificate_transparency": policy.require_certificate_transparency,
                "zero_trust_principle": "verify explicitly — all connections authenticated",
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "nist_sp_800_207_segmentation": {
                "policy_id": policy.policy_id,
                "micro_segmentation": {
                    "default_action": policy.default_action.to_string(),
                    "enforcement_mode": policy.enforcement_mode.to_string(),
                    "zone_count": policy.zone_count,
                },
                "zero_trust_principle": "assume breach — segment all network zones",
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "nist_sp_800_207_dns": {
                "policy_id": policy.policy_id,
                "dnssec_validation": policy.require_dnssec,
                "encrypted_transport": {
                    "required": policy.require_encrypted_transport,
                    "protocol": policy.encrypted_transport_protocol,
                },
                "zero_trust_principle": "never trust DNS — validate and encrypt",
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError> {
        let entries: Vec<serde_json::Value> = certificates
            .iter()
            .map(|c| {
                serde_json::json!({
                    "subject": c.subject,
                    "status": c.certificate_status.to_string(),
                    "ct_logged": c.certificate_transparency_logged,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "nist_sp_800_207_certificate_inventory": entries,
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        segmentation_policies: &[StoredSegmentationPolicy],
        dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError> {
        let doc = serde_json::json!({
            "nist_sp_800_207_assessment": {
                "tls_policies": tls_policies.len(),
                "segmentation_policies": segmentation_policies.len(),
                "dns_policies": dns_policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| NetworkError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "ZeroTrustAssessment"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── TlsCertificateInventoryExporter ────────────────────────────────

pub struct TlsCertificateInventoryExporter;

impl NetworkGovernanceExporter for TlsCertificateInventoryExporter {
    fn export_tls_policy(
        &self,
        policy: &StoredTlsPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# TLS Certificate Inventory — Policy Context\n\n");
        report.push_str(&format!("Policy: {} ({})\n", policy.policy_name, policy.policy_id));
        report.push_str(&format!("Min TLS: {}\n", policy.min_tls_version));
        Ok(report)
    }

    fn export_segmentation_policy(
        &self,
        policy: &StoredSegmentationPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# TLS Certificate Inventory — Segmentation Context\n\n");
        report.push_str(&format!("Policy: {} ({})\n", policy.policy_name, policy.policy_id));
        Ok(report)
    }

    fn export_dns_policy(
        &self,
        policy: &StoredDnsPolicy,
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# TLS Certificate Inventory — DNS Context\n\n");
        report.push_str(&format!("Policy: {} ({})\n", policy.policy_name, policy.policy_id));
        Ok(report)
    }

    fn export_certificate_inventory(
        &self,
        certificates: &[StoredCertificateRecord],
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# TLS Certificate Inventory\n\n");
        report.push_str(&format!("Total certificates: {}\n\n", certificates.len()));
        for c in certificates {
            report.push_str(&format!(
                "## {}\n\n- **Issuer**: {}\n- **Algorithm**: {} ({} bits)\n- **Status**: {}\n- **CT Logged**: {}\n- **Fingerprint**: {}\n\n",
                c.subject, c.issuer, c.key_algorithm, c.key_size_bits,
                c.certificate_status, c.certificate_transparency_logged,
                c.fingerprint
            ));
        }
        Ok(report)
    }

    fn export_batch(
        &self,
        tls_policies: &[StoredTlsPolicy],
        _segmentation_policies: &[StoredSegmentationPolicy],
        _dns_policies: &[StoredDnsPolicy],
    ) -> Result<String, NetworkError> {
        let mut report = String::new();
        report.push_str("# TLS Certificate Inventory — Batch Summary\n\n");
        report.push_str(&format!("TLS policies governing certificates: {}\n", tls_policies.len()));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "TlsCertificateInventory"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        StoredCertificateRecordStatus, StoredEnforcementMode, StoredMinTlsVersion,
        StoredSegmentationDefaultAction, TlsPolicyScope,
    };
    use std::collections::HashMap;

    fn sample_tls_policy() -> StoredTlsPolicy {
        StoredTlsPolicy {
            policy_id: "tls-1".into(),
            policy_name: "Modern".into(),
            scope: TlsPolicyScope::Global,
            min_tls_version: StoredMinTlsVersion::Tls13,
            require_forward_secrecy: true,
            require_client_certificate: true,
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

    fn sample_certificates() -> Vec<StoredCertificateRecord> {
        vec![StoredCertificateRecord {
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
        }]
    }

    #[test]
    fn test_json_exporter_tls() {
        let exp = JsonNetworkGovernanceExporter;
        let out = exp.export_tls_policy(&sample_tls_policy()).unwrap();
        assert!(out.contains("tls-1"));
        assert!(out.contains("Modern"));
    }

    #[test]
    fn test_json_exporter_segmentation() {
        let exp = JsonNetworkGovernanceExporter;
        let out = exp
            .export_segmentation_policy(&sample_segmentation_policy())
            .unwrap();
        assert!(out.contains("seg-1"));
    }

    #[test]
    fn test_json_exporter_dns() {
        let exp = JsonNetworkGovernanceExporter;
        let out = exp.export_dns_policy(&sample_dns_policy()).unwrap();
        assert!(out.contains("dns-1"));
    }

    #[test]
    fn test_json_exporter_certificates() {
        let exp = JsonNetworkGovernanceExporter;
        let out = exp
            .export_certificate_inventory(&sample_certificates())
            .unwrap();
        assert!(out.contains("certificate_inventory"));
    }

    #[test]
    fn test_json_exporter_batch() {
        let exp = JsonNetworkGovernanceExporter;
        let out = exp
            .export_batch(
                &[sample_tls_policy()],
                &[sample_segmentation_policy()],
                &[sample_dns_policy()],
            )
            .unwrap();
        assert!(out.contains("tls_policies"));
    }

    #[test]
    fn test_pci_dss_exporter() {
        let exp = PciDssNetworkComplianceExporter;
        let out = exp.export_tls_policy(&sample_tls_policy()).unwrap();
        assert!(out.contains("pci_dss_v4_requirement_1"));
        assert_eq!(exp.format_name(), "PciDssNetworkCompliance");
    }

    #[test]
    fn test_cjis_exporter() {
        let exp = CjisNetworkSecurityExporter;
        let out = exp.export_tls_policy(&sample_tls_policy()).unwrap();
        assert!(out.contains("CJIS"));
        assert_eq!(exp.content_type(), "text/markdown");
    }

    #[test]
    fn test_zero_trust_exporter() {
        let exp = ZeroTrustAssessmentExporter;
        let out = exp.export_tls_policy(&sample_tls_policy()).unwrap();
        assert!(out.contains("nist_sp_800_207"));
        assert_eq!(exp.format_name(), "ZeroTrustAssessment");
    }

    #[test]
    fn test_certificate_inventory_exporter() {
        let exp = TlsCertificateInventoryExporter;
        let out = exp
            .export_certificate_inventory(&sample_certificates())
            .unwrap();
        assert!(out.contains("TLS Certificate Inventory"));
        assert!(out.contains("CN=example.com"));
        assert_eq!(exp.format_name(), "TlsCertificateInventory");
    }

    #[test]
    fn test_all_exporters_format_and_content_type() {
        let exporters: Vec<Box<dyn NetworkGovernanceExporter>> = vec![
            Box::new(JsonNetworkGovernanceExporter),
            Box::new(PciDssNetworkComplianceExporter),
            Box::new(CjisNetworkSecurityExporter),
            Box::new(ZeroTrustAssessmentExporter),
            Box::new(TlsCertificateInventoryExporter),
        ];
        for e in &exporters {
            assert!(!e.format_name().is_empty());
            assert!(!e.content_type().is_empty());
        }
        assert_eq!(exporters.len(), 5);
    }
}
