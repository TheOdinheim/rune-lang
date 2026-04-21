// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — MemoryGovernanceMetricsCollector trait for computing
// memory governance metrics: retention compliance rate, redaction
// coverage, isolation violation rate, retrieval denial rate, memory
// utilization, scope listing. All computed values are String for Eq
// derivation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::backend::{StoredMemoryEntry, StoredMemoryScope};
use crate::error::MemoryError;

// ── MemoryGovernanceMetricSnapshot ─────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGovernanceMetricSnapshot {
    pub snapshot_id: String,
    pub scope_id: String,
    pub computed_at: i64,
    pub retention_compliance_rate: String,
    pub redaction_coverage: String,
    pub isolation_violation_rate: String,
    pub retrieval_denial_rate: String,
    pub memory_utilization: String,
    pub metadata: HashMap<String, String>,
}

// ── RetentionComplianceRecord ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionComplianceRecord {
    pub scope_id: String,
    pub compliant_entries: usize,
    pub total_entries: usize,
    pub evaluated_at: i64,
}

// ── IsolationViolationRecord ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IsolationViolationMetricRecord {
    pub scope_id: String,
    pub violation_count: usize,
    pub check_count: usize,
    pub evaluated_at: i64,
}

// ── RetrievalDenialRecord ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetrievalDenialRecord {
    pub scope_id: String,
    pub denied_count: usize,
    pub total_requests: usize,
    pub evaluated_at: i64,
}

// ── MemoryGovernanceMetricsCollector trait ──────────────────────────

pub trait MemoryGovernanceMetricsCollector {
    fn compute_retention_compliance_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError>;

    fn compute_redaction_coverage(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError>;

    fn compute_isolation_violation_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError>;

    fn compute_retrieval_denial_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError>;

    fn compute_memory_utilization(
        &self,
        scope_id: &str,
    ) -> Result<String, MemoryError>;

    fn list_scopes_by_entry_count(
        &self,
        limit: usize,
    ) -> Vec<(String, usize)>;

    fn collector_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryMemoryGovernanceMetricsCollector ────────────────────────

pub struct InMemoryMemoryGovernanceMetricsCollector {
    id: String,
    retention_records: Vec<RetentionComplianceRecord>,
    redaction_counts: HashMap<String, (usize, usize)>,
    violation_records: Vec<IsolationViolationMetricRecord>,
    denial_records: Vec<RetrievalDenialRecord>,
    entries: Vec<StoredMemoryEntry>,
    scopes: Vec<StoredMemoryScope>,
}

impl InMemoryMemoryGovernanceMetricsCollector {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            retention_records: Vec::new(),
            redaction_counts: HashMap::new(),
            violation_records: Vec::new(),
            denial_records: Vec::new(),
            entries: Vec::new(),
            scopes: Vec::new(),
        }
    }

    pub fn add_retention_record(&mut self, record: RetentionComplianceRecord) {
        self.retention_records.push(record);
    }

    pub fn set_redaction_counts(
        &mut self,
        scope_id: impl Into<String>,
        redacted: usize,
        total: usize,
    ) {
        self.redaction_counts.insert(scope_id.into(), (redacted, total));
    }

    pub fn add_violation_record(&mut self, record: IsolationViolationMetricRecord) {
        self.violation_records.push(record);
    }

    pub fn add_denial_record(&mut self, record: RetrievalDenialRecord) {
        self.denial_records.push(record);
    }

    pub fn add_entry(&mut self, entry: StoredMemoryEntry) {
        self.entries.push(entry);
    }

    pub fn add_scope(&mut self, scope: StoredMemoryScope) {
        self.scopes.push(scope);
    }
}

impl MemoryGovernanceMetricsCollector for InMemoryMemoryGovernanceMetricsCollector {
    fn compute_retention_compliance_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError> {
        if window_end <= window_start {
            return Err(MemoryError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let records: Vec<&RetentionComplianceRecord> = self
            .retention_records
            .iter()
            .filter(|r| {
                r.scope_id == scope_id
                    && r.evaluated_at >= window_start
                    && r.evaluated_at <= window_end
            })
            .collect();
        if records.is_empty() {
            return Ok("1.0000".into());
        }
        let total_compliant: usize = records.iter().map(|r| r.compliant_entries).sum();
        let total_entries: usize = records.iter().map(|r| r.total_entries).sum();
        if total_entries == 0 {
            return Ok("1.0000".into());
        }
        let rate = total_compliant as f64 / total_entries as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_redaction_coverage(
        &self,
        scope_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, MemoryError> {
        match self.redaction_counts.get(scope_id) {
            Some(&(redacted, total)) if total > 0 => {
                let rate = redacted as f64 / total as f64;
                Ok(format!("{:.4}", rate))
            }
            _ => Ok("0.0000".into()),
        }
    }

    fn compute_isolation_violation_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError> {
        if window_end <= window_start {
            return Err(MemoryError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let records: Vec<&IsolationViolationMetricRecord> = self
            .violation_records
            .iter()
            .filter(|r| {
                r.scope_id == scope_id
                    && r.evaluated_at >= window_start
                    && r.evaluated_at <= window_end
            })
            .collect();
        if records.is_empty() {
            return Ok("0.0000".into());
        }
        let total_violations: usize = records.iter().map(|r| r.violation_count).sum();
        let total_checks: usize = records.iter().map(|r| r.check_count).sum();
        if total_checks == 0 {
            return Ok("0.0000".into());
        }
        let rate = total_violations as f64 / total_checks as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_retrieval_denial_rate(
        &self,
        scope_id: &str,
        window_start: i64,
        window_end: i64,
    ) -> Result<String, MemoryError> {
        if window_end <= window_start {
            return Err(MemoryError::InvalidOperation(
                "window_end must be after window_start".into(),
            ));
        }
        let records: Vec<&RetrievalDenialRecord> = self
            .denial_records
            .iter()
            .filter(|r| {
                r.scope_id == scope_id
                    && r.evaluated_at >= window_start
                    && r.evaluated_at <= window_end
            })
            .collect();
        if records.is_empty() {
            return Ok("0.0000".into());
        }
        let total_denied: usize = records.iter().map(|r| r.denied_count).sum();
        let total_requests: usize = records.iter().map(|r| r.total_requests).sum();
        if total_requests == 0 {
            return Ok("0.0000".into());
        }
        let rate = total_denied as f64 / total_requests as f64;
        Ok(format!("{:.4}", rate))
    }

    fn compute_memory_utilization(
        &self,
        scope_id: &str,
    ) -> Result<String, MemoryError> {
        let count = self
            .entries
            .iter()
            .filter(|e| e.scope_id == scope_id)
            .count();
        Ok(count.to_string())
    }

    fn list_scopes_by_entry_count(
        &self,
        limit: usize,
    ) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            *counts.entry(e.scope_id.clone()).or_default() += 1;
        }
        let mut pairs: Vec<(String, usize)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(limit);
        pairs
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn is_active(&self) -> bool {
        true
    }
}

// ── NullMemoryGovernanceMetricsCollector ────────────────────────────

pub struct NullMemoryGovernanceMetricsCollector;

impl MemoryGovernanceMetricsCollector for NullMemoryGovernanceMetricsCollector {
    fn compute_retention_compliance_rate(
        &self,
        _scope_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, MemoryError> {
        Ok("1.0000".into())
    }

    fn compute_redaction_coverage(
        &self,
        _scope_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, MemoryError> {
        Ok("0.0000".into())
    }

    fn compute_isolation_violation_rate(
        &self,
        _scope_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, MemoryError> {
        Ok("0.0000".into())
    }

    fn compute_retrieval_denial_rate(
        &self,
        _scope_id: &str,
        _window_start: i64,
        _window_end: i64,
    ) -> Result<String, MemoryError> {
        Ok("0.0000".into())
    }

    fn compute_memory_utilization(
        &self,
        _scope_id: &str,
    ) -> Result<String, MemoryError> {
        Ok("0".into())
    }

    fn list_scopes_by_entry_count(
        &self,
        _limit: usize,
    ) -> Vec<(String, usize)> {
        Vec::new()
    }

    fn collector_id(&self) -> &str {
        "null-memory-metrics-collector"
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
    use crate::memory::MemoryContentType;
    use crate::memory::MemorySensitivity;

    fn sample_entry(scope: &str) -> StoredMemoryEntry {
        StoredMemoryEntry::new(
            format!("e-{scope}"), scope, "content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal,
            "agent-1", 1000, 1001, "hash",
        )
    }

    #[test]
    fn test_retention_compliance_rate() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        c.add_retention_record(RetentionComplianceRecord {
            scope_id: "s1".into(),
            compliant_entries: 8,
            total_entries: 10,
            evaluated_at: 500,
        });
        let rate = c
            .compute_retention_compliance_rate("s1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "0.8000");
    }

    #[test]
    fn test_retention_compliance_no_records() {
        let c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        let rate = c
            .compute_retention_compliance_rate("s1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "1.0000");
    }

    #[test]
    fn test_redaction_coverage() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        c.set_redaction_counts("s1", 3, 10);
        let rate = c.compute_redaction_coverage("s1", 0, 1000).unwrap();
        assert_eq!(rate, "0.3000");
    }

    #[test]
    fn test_redaction_coverage_no_data() {
        let c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        let rate = c.compute_redaction_coverage("s1", 0, 1000).unwrap();
        assert_eq!(rate, "0.0000");
    }

    #[test]
    fn test_isolation_violation_rate() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        c.add_violation_record(IsolationViolationMetricRecord {
            scope_id: "s1".into(),
            violation_count: 2,
            check_count: 20,
            evaluated_at: 500,
        });
        let rate = c
            .compute_isolation_violation_rate("s1", 0, 1000)
            .unwrap();
        assert_eq!(rate, "0.1000");
    }

    #[test]
    fn test_retrieval_denial_rate() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        c.add_denial_record(RetrievalDenialRecord {
            scope_id: "s1".into(),
            denied_count: 1,
            total_requests: 5,
            evaluated_at: 500,
        });
        let rate = c.compute_retrieval_denial_rate("s1", 0, 1000).unwrap();
        assert_eq!(rate, "0.2000");
    }

    #[test]
    fn test_memory_utilization() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        c.add_entry(sample_entry("s1"));
        c.add_entry(sample_entry("s1"));
        c.add_entry(sample_entry("s2"));
        let util = c.compute_memory_utilization("s1").unwrap();
        assert_eq!(util, "2");
    }

    #[test]
    fn test_list_scopes_by_entry_count() {
        let mut c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        let mut e1 = sample_entry("s1");
        e1.entry_id = "e1".into();
        c.add_entry(e1);
        let mut e2 = sample_entry("s1");
        e2.entry_id = "e2".into();
        c.add_entry(e2);
        let mut e3 = sample_entry("s2");
        e3.entry_id = "e3".into();
        c.add_entry(e3);
        let top = c.list_scopes_by_entry_count(2);
        assert_eq!(top[0].0, "s1");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_null_collector() {
        let c = NullMemoryGovernanceMetricsCollector;
        assert!(!c.is_active());
        assert_eq!(
            c.compute_retention_compliance_rate("s1", 0, 1000).unwrap(),
            "1.0000"
        );
        assert_eq!(
            c.compute_redaction_coverage("s1", 0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(
            c.compute_isolation_violation_rate("s1", 0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(
            c.compute_retrieval_denial_rate("s1", 0, 1000).unwrap(),
            "0.0000"
        );
        assert_eq!(c.compute_memory_utilization("s1").unwrap(), "0");
        assert!(c.list_scopes_by_entry_count(5).is_empty());
    }

    #[test]
    fn test_collector_id() {
        let c = InMemoryMemoryGovernanceMetricsCollector::new("my-metrics");
        assert_eq!(c.collector_id(), "my-metrics");
        assert!(c.is_active());
    }

    #[test]
    fn test_snapshot_eq() {
        let s = MemoryGovernanceMetricSnapshot {
            snapshot_id: "snap-1".into(),
            scope_id: "s1".into(),
            computed_at: 5000,
            retention_compliance_rate: "0.9500".into(),
            redaction_coverage: "0.3000".into(),
            isolation_violation_rate: "0.0100".into(),
            retrieval_denial_rate: "0.0500".into(),
            memory_utilization: "42".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(s, s.clone());
    }

    #[test]
    fn test_invalid_window() {
        let c = InMemoryMemoryGovernanceMetricsCollector::new("m1");
        assert!(c
            .compute_retention_compliance_rate("s1", 1000, 500)
            .is_err());
        assert!(c
            .compute_isolation_violation_rate("s1", 1000, 500)
            .is_err());
        assert!(c
            .compute_retrieval_denial_rate("s1", 1000, 500)
            .is_err());
    }
}
