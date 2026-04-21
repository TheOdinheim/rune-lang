// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — MemoryGovernanceExporter trait for exporting memory
// governance data: JSON, retention compliance, isolation report,
// GDPR deletion report, retrieval audit.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{
    StoredIsolationBoundary, StoredIsolationViolationRecord, StoredMemoryEntry,
    StoredMemoryScope, StoredRetentionPolicy, StoredRetrievalPolicy,
};
use crate::error::MemoryError;

// ── MemoryGovernanceExporter trait ──────────────────────────────────

pub trait MemoryGovernanceExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError>;

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError>;

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError>;

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError>;

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
        policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError>;

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonMemoryExporter ─────────────────────────────────────────────

pub struct JsonMemoryExporter;

impl MemoryGovernanceExporter for JsonMemoryExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError> {
        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "entry_id": e.entry_id,
                    "scope_id": e.scope_id,
                    "content_type": format!("{:?}", e.content_type),
                    "sensitivity_level": format!("{:?}", e.sensitivity_level),
                    "created_by": e.created_by,
                    "created_at": e.created_at,
                    "stored_at": e.stored_at,
                    "access_count": e.access_count,
                    "content_hash": e.content_hash,
                })
            })
            .collect();
        let scopes_json: Vec<serde_json::Value> = scopes
            .iter()
            .map(|s| {
                serde_json::json!({
                    "scope_id": s.scope_id,
                    "scope_type": format!("{:?}", s.scope_type),
                    "owner_id": s.owner_id,
                    "isolation_level": format!("{:?}", s.isolation_level),
                    "entry_count": s.entry_count,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "memory_inventory": {
                "entries": entries_json,
                "entry_count": entries.len(),
                "scopes": scopes_json,
                "scope_count": scopes.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError> {
        let policies_json: Vec<serde_json::Value> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "policy_id": p.policy_id,
                    "scope_pattern": p.scope_pattern,
                    "on_expiry": format!("{:?}", p.on_expiry),
                    "entries_governed": p.entries_governed,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "retention_report": {
                "policies": policies_json,
                "policy_count": policies.len(),
                "total_entries": entries.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError> {
        let boundaries_json: Vec<serde_json::Value> = boundaries
            .iter()
            .map(|b| {
                serde_json::json!({
                    "boundary_id": b.boundary_id,
                    "scope_a": b.scope_a,
                    "scope_b": b.scope_b,
                    "boundary_type": format!("{:?}", b.boundary_type),
                    "violations_detected": b.violations_detected,
                })
            })
            .collect();
        let violations_json: Vec<serde_json::Value> = violations
            .iter()
            .map(|v| {
                serde_json::json!({
                    "violation_id": v.violation_id,
                    "boundary_id": v.boundary_id,
                    "violating_requester": v.violating_requester,
                    "violation_type": format!("{:?}", v.violation_type),
                    "severity": format!("{:?}", v.severity),
                    "resolution_status": v.resolution_status.to_string(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "isolation_report": {
                "boundaries": boundaries_json,
                "boundary_count": boundaries.len(),
                "violations": violations_json,
                "violation_count": violations.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError> {
        let policies_json: Vec<serde_json::Value> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "policy_id": p.policy_id,
                    "agent_id_pattern": p.agent_id_pattern,
                    "allowed_collections": p.allowed_collections,
                    "denied_collections": p.denied_collections,
                    "require_provenance": p.require_provenance,
                    "queries_evaluated": p.queries_evaluated,
                    "queries_denied": p.queries_denied,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "retrieval_audit": {
                "policies": policies_json,
                "policy_count": policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
        policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError> {
        let doc = serde_json::json!({
            "memory_governance_batch": {
                "entry_count": entries.len(),
                "scope_count": scopes.len(),
                "retention_policy_count": policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── MemoryRetentionComplianceExporter ──────────────────────────────
// Exports retention compliance data in a human-readable markdown format.

pub struct MemoryRetentionComplianceExporter;

impl MemoryGovernanceExporter for MemoryRetentionComplianceExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Memory Inventory — Retention Compliance\n\n");
        report.push_str(&format!("- **Total entries**: {}\n", entries.len()));
        report.push_str(&format!("- **Total scopes**: {}\n\n", scopes.len()));
        let with_retention: usize = entries
            .iter()
            .filter(|e| e.retention_policy_ref.is_some())
            .count();
        report.push_str(&format!(
            "- **Entries with retention policy**: {}/{}\n",
            with_retention,
            entries.len()
        ));
        Ok(report)
    }

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Retention Compliance Report\n\n");
        report.push_str(&format!("Total policies: {}\n", policies.len()));
        report.push_str(&format!("Total entries: {}\n\n", entries.len()));
        for p in policies {
            report.push_str(&format!(
                "## Policy: {}\n\n- Scope pattern: {}\n- On expiry: {:?}\n- Entries governed: {}\n\n",
                p.policy_id, p.scope_pattern, p.on_expiry, p.entries_governed
            ));
        }
        Ok(report)
    }

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Isolation — Retention Context\n\n");
        report.push_str(&format!("Boundaries: {}\n", boundaries.len()));
        report.push_str(&format!("Violations: {}\n", violations.len()));
        Ok(report)
    }

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Retrieval — Retention Context\n\n");
        report.push_str(&format!("Policies: {}\n", policies.len()));
        Ok(report)
    }

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
        policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Retention Compliance Summary\n\n");
        report.push_str(&format!("- Entries: {}\n", entries.len()));
        report.push_str(&format!("- Scopes: {}\n", scopes.len()));
        report.push_str(&format!("- Retention policies: {}\n", policies.len()));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "RetentionCompliance"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── MemoryIsolationReportExporter ──────────────────────────────────
// Isolation boundary and violation report.

pub struct MemoryIsolationReportExporter;

impl MemoryGovernanceExporter for MemoryIsolationReportExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Memory Inventory — Isolation Context\n\n");
        report.push_str(&format!("Entries: {}\n", entries.len()));
        report.push_str(&format!("Scopes: {}\n", scopes.len()));
        Ok(report)
    }

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        _entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Retention — Isolation Context\n\n");
        report.push_str(&format!("Policies: {}\n", policies.len()));
        Ok(report)
    }

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Memory Isolation Report\n\n");
        report.push_str(&format!("Total boundaries: {}\n", boundaries.len()));
        report.push_str(&format!("Total violations: {}\n\n", violations.len()));
        for b in boundaries {
            report.push_str(&format!(
                "## Boundary: {}\n\n- Scope A: {}\n- Scope B: {}\n- Type: {:?}\n- Violations detected: {}\n\n",
                b.boundary_id, b.scope_a, b.scope_b, b.boundary_type, b.violations_detected
            ));
        }
        if !violations.is_empty() {
            report.push_str("## Violations\n\n");
            for v in violations {
                report.push_str(&format!(
                    "- {} (boundary={}, requester={}, type={:?}, status={})\n",
                    v.violation_id, v.boundary_id, v.violating_requester,
                    v.violation_type, v.resolution_status
                ));
            }
        }
        Ok(report)
    }

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Retrieval — Isolation Context\n\n");
        report.push_str(&format!("Policies: {}\n", policies.len()));
        Ok(report)
    }

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
        _policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# Isolation Batch Summary\n\n");
        report.push_str(&format!("- Entries: {}\n", entries.len()));
        report.push_str(&format!("- Scopes: {}\n", scopes.len()));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "IsolationReport"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── GdprMemoryDeletionExporter ─────────────────────────────────────
// GDPR Article 17 right-to-erasure compliance report.

pub struct GdprMemoryDeletionExporter;

impl MemoryGovernanceExporter for GdprMemoryDeletionExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# GDPR Article 17 — Memory Inventory\n\n");
        report.push_str(&format!("- **Entries subject to erasure review**: {}\n", entries.len()));
        report.push_str(&format!("- **Scopes**: {}\n\n", scopes.len()));
        report.push_str("### Data Subject Memory Entries\n\n");
        for e in entries {
            report.push_str(&format!(
                "- Entry `{}` (scope={}, sensitivity={:?}, hash={})\n",
                e.entry_id, e.scope_id, e.sensitivity_level, e.content_hash
            ));
        }
        Ok(report)
    }

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# GDPR — Retention Policies\n\n");
        report.push_str(&format!("Policies: {}\n", policies.len()));
        report.push_str(&format!("Entries: {}\n", entries.len()));
        Ok(report)
    }

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# GDPR — Isolation & Data Separation\n\n");
        report.push_str(&format!(
            "- Isolation boundaries: {}\n- Violations: {}\n",
            boundaries.len(),
            violations.len()
        ));
        report.push_str("\n### GDPR Compliance Note\n\n");
        report.push_str("- Data separation enforced via isolation boundaries\n");
        report.push_str("- Cross-scope violations tracked for DPA reporting\n");
        Ok(report)
    }

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# GDPR — Retrieval Audit\n\n");
        report.push_str(&format!("Retrieval policies: {}\n\n", policies.len()));
        for p in policies {
            report.push_str(&format!(
                "- Policy `{}` (agent_pattern={}, provenance_required={})\n",
                p.policy_id, p.agent_id_pattern, p.require_provenance
            ));
        }
        Ok(report)
    }

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        scopes: &[StoredMemoryScope],
        policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError> {
        let mut report = String::new();
        report.push_str("# GDPR Deletion Summary\n\n");
        report.push_str(&format!("- Entries for review: {}\n", entries.len()));
        report.push_str(&format!("- Scopes: {}\n", scopes.len()));
        report.push_str(&format!("- Retention policies: {}\n", policies.len()));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "GdprDeletion"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── RetrievalAuditExporter ─────────────────────────────────────────
// RAG retrieval governance audit export.

pub struct RetrievalAuditExporter;

impl MemoryGovernanceExporter for RetrievalAuditExporter {
    fn export_memory_inventory(
        &self,
        entries: &[StoredMemoryEntry],
        _scopes: &[StoredMemoryScope],
    ) -> Result<String, MemoryError> {
        let doc = serde_json::json!({
            "retrieval_audit_inventory": {
                "total_entries": entries.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_retention_report(
        &self,
        policies: &[StoredRetentionPolicy],
        _entries: &[StoredMemoryEntry],
    ) -> Result<String, MemoryError> {
        let doc = serde_json::json!({
            "retrieval_audit_retention": {
                "policy_count": policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_isolation_report(
        &self,
        boundaries: &[StoredIsolationBoundary],
        violations: &[StoredIsolationViolationRecord],
    ) -> Result<String, MemoryError> {
        let doc = serde_json::json!({
            "retrieval_audit_isolation": {
                "boundary_count": boundaries.len(),
                "violation_count": violations.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_retrieval_audit(
        &self,
        policies: &[StoredRetrievalPolicy],
    ) -> Result<String, MemoryError> {
        let policies_json: Vec<serde_json::Value> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "policy_id": p.policy_id,
                    "agent_id_pattern": p.agent_id_pattern,
                    "allowed_collections": p.allowed_collections,
                    "denied_collections": p.denied_collections,
                    "max_results_per_query": p.max_results_per_query,
                    "require_provenance": p.require_provenance,
                    "sensitivity_ceiling": p.sensitivity_ceiling.as_ref().map(|s| format!("{s:?}")),
                    "queries_evaluated": p.queries_evaluated,
                    "queries_denied": p.queries_denied,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "retrieval_governance_audit": {
                "policies": policies_json,
                "policy_count": policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn export_batch(
        &self,
        entries: &[StoredMemoryEntry],
        _scopes: &[StoredMemoryScope],
        policies: &[StoredRetentionPolicy],
    ) -> Result<String, MemoryError> {
        let doc = serde_json::json!({
            "retrieval_audit_batch": {
                "entry_count": entries.len(),
                "retention_policy_count": policies.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| MemoryError::InvalidOperation(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "RetrievalAudit"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{StoredIsolationBoundary, StoredIsolationViolationRecord};
    use crate::isolation::{IsolationBoundaryType, IsolationViolationType};
    use crate::memory::{
        MemoryContentType, MemoryIsolationLevel, MemoryScopeType, MemorySensitivity,
    };
    use crate::retention::ExpiryAction;
    fn sample_entry() -> StoredMemoryEntry {
        StoredMemoryEntry::new(
            "e1", "scope-1", "test content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal,
            "agent-1", 1000, 1001, "abc123hash",
        )
    }

    fn sample_scope() -> StoredMemoryScope {
        StoredMemoryScope::new(
            "scope-1", MemoryScopeType::AgentLocal,
            "agent-1", MemoryIsolationLevel::Strict, 1000,
        )
    }

    fn sample_retention_policy() -> StoredRetentionPolicy {
        StoredRetentionPolicy::new("rp-1", "scope-*", ExpiryAction::Delete, 1000)
    }

    fn sample_retrieval_policy() -> StoredRetrievalPolicy {
        StoredRetrievalPolicy::new("rgp-1", "agent-*", 1000)
    }

    fn sample_boundary() -> StoredIsolationBoundary {
        StoredIsolationBoundary::new(
            "ib-1", "scope-a", "scope-b",
            IsolationBoundaryType::HardIsolation,
            "admin", 1000,
        )
    }

    fn sample_violation() -> StoredIsolationViolationRecord {
        StoredIsolationViolationRecord::new(
            "iv-1", "ib-1", "agent-rogue", "scope-b",
            IsolationViolationType::CrossScopeRead,
            2000, MemorySensitivity::Sensitive,
        )
    }

    #[test]
    fn test_json_exporter_inventory() {
        let exp = JsonMemoryExporter;
        let out = exp
            .export_memory_inventory(&[sample_entry()], &[sample_scope()])
            .unwrap();
        assert!(out.contains("memory_inventory"));
        assert!(out.contains("e1"));
    }

    #[test]
    fn test_json_exporter_retention_report() {
        let exp = JsonMemoryExporter;
        let out = exp
            .export_retention_report(&[sample_retention_policy()], &[sample_entry()])
            .unwrap();
        assert!(out.contains("retention_report"));
        assert!(out.contains("rp-1"));
    }

    #[test]
    fn test_json_exporter_isolation_report() {
        let exp = JsonMemoryExporter;
        let out = exp
            .export_isolation_report(&[sample_boundary()], &[sample_violation()])
            .unwrap();
        assert!(out.contains("isolation_report"));
        assert!(out.contains("ib-1"));
    }

    #[test]
    fn test_json_exporter_retrieval_audit() {
        let exp = JsonMemoryExporter;
        let out = exp
            .export_retrieval_audit(&[sample_retrieval_policy()])
            .unwrap();
        assert!(out.contains("retrieval_audit"));
        assert!(out.contains("agent-*"));
    }

    #[test]
    fn test_json_exporter_batch() {
        let exp = JsonMemoryExporter;
        let out = exp
            .export_batch(&[sample_entry()], &[sample_scope()], &[sample_retention_policy()])
            .unwrap();
        assert!(out.contains("memory_governance_batch"));
    }

    #[test]
    fn test_retention_compliance_exporter() {
        let exp = MemoryRetentionComplianceExporter;
        let out = exp
            .export_retention_report(&[sample_retention_policy()], &[sample_entry()])
            .unwrap();
        assert!(out.contains("Retention Compliance Report"));
        assert!(out.contains("rp-1"));
        assert_eq!(exp.format_name(), "RetentionCompliance");
        assert_eq!(exp.content_type(), "text/markdown");
    }

    #[test]
    fn test_isolation_report_exporter() {
        let exp = MemoryIsolationReportExporter;
        let out = exp
            .export_isolation_report(&[sample_boundary()], &[sample_violation()])
            .unwrap();
        assert!(out.contains("Memory Isolation Report"));
        assert!(out.contains("ib-1"));
        assert!(out.contains("iv-1"));
        assert_eq!(exp.format_name(), "IsolationReport");
    }

    #[test]
    fn test_gdpr_exporter() {
        let exp = GdprMemoryDeletionExporter;
        let out = exp
            .export_memory_inventory(&[sample_entry()], &[sample_scope()])
            .unwrap();
        assert!(out.contains("GDPR Article 17"));
        assert!(out.contains("e1"));
        assert_eq!(exp.format_name(), "GdprDeletion");
    }

    #[test]
    fn test_gdpr_exporter_isolation() {
        let exp = GdprMemoryDeletionExporter;
        let out = exp
            .export_isolation_report(&[sample_boundary()], &[sample_violation()])
            .unwrap();
        assert!(out.contains("GDPR"));
        assert!(out.contains("Data separation"));
    }

    #[test]
    fn test_retrieval_audit_exporter() {
        let exp = RetrievalAuditExporter;
        let out = exp
            .export_retrieval_audit(&[sample_retrieval_policy()])
            .unwrap();
        assert!(out.contains("retrieval_governance_audit"));
        assert!(out.contains("agent-*"));
        assert_eq!(exp.format_name(), "RetrievalAudit");
        assert_eq!(exp.content_type(), "application/json");
    }

    #[test]
    fn test_all_exporters_format_and_content_type() {
        let exporters: Vec<Box<dyn MemoryGovernanceExporter>> = vec![
            Box::new(JsonMemoryExporter),
            Box::new(MemoryRetentionComplianceExporter),
            Box::new(MemoryIsolationReportExporter),
            Box::new(GdprMemoryDeletionExporter),
            Box::new(RetrievalAuditExporter),
        ];
        for e in &exporters {
            assert!(!e.format_name().is_empty());
            assert!(!e.content_type().is_empty());
        }
        assert_eq!(exporters.len(), 5);
    }

    #[test]
    fn test_retention_compliance_inventory() {
        let exp = MemoryRetentionComplianceExporter;
        let mut entry = sample_entry();
        entry.retention_policy_ref = Some("rp-1".into());
        let out = exp
            .export_memory_inventory(&[entry], &[sample_scope()])
            .unwrap();
        assert!(out.contains("Entries with retention policy"));
        assert!(out.contains("1/1"));
    }

    #[test]
    fn test_gdpr_retrieval_audit() {
        let exp = GdprMemoryDeletionExporter;
        let out = exp
            .export_retrieval_audit(&[sample_retrieval_policy()])
            .unwrap();
        assert!(out.contains("GDPR — Retrieval Audit"));
    }
}
