// ═══════════════════════════════════════════════════════════════════════
// Detection Backend — Storage trait for findings, rules, and baselines.
//
// Layer 3 extracts the storage contract for detection findings,
// rules, and baselines into a trait so customers can provide their
// own persistence backend. RUNE provides the contract — the customer
// provides the transport and storage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::SecuritySeverity;

use crate::alert::Alert;
use crate::error::DetectionError;
use crate::rule::DetectionRule;

// ── DetectionFinding ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub category: String,
    pub source: String,
    pub timestamp: i64,
    pub evidence: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl DetectionFinding {
    pub fn new(id: &str, title: &str, severity: SecuritySeverity, timestamp: i64) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            description: String::new(),
            severity,
            category: String::new(),
            source: String::new(),
            timestamp,
            evidence: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_category(mut self, cat: &str) -> Self {
        self.category = cat.to_string();
        self
    }

    pub fn with_source(mut self, src: &str) -> Self {
        self.source = src.to_string();
        self
    }

    pub fn with_evidence(mut self, ev: &str) -> Self {
        self.evidence.push(ev.to_string());
        self
    }
}

// ── StoredBaseline ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredBaseline {
    pub id: String,
    pub name: String,
    pub mean: String,
    pub std_dev: String,
    pub sample_count: u64,
    pub trained_at: i64,
    pub window_description: String,
}

// ── BackendInfo ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub backend_type: String,
    pub supports_versioning: bool,
    pub supports_persistence: bool,
    pub max_findings: Option<usize>,
    pub max_rules: Option<usize>,
}

// ── DetectionBackend trait ───────────────────────────────────────

pub trait DetectionBackend {
    fn store_finding(&mut self, finding: &DetectionFinding) -> Result<(), DetectionError>;
    fn retrieve_finding(&self, id: &str) -> Option<&DetectionFinding>;
    fn delete_finding(&mut self, id: &str) -> Result<bool, DetectionError>;
    fn list_findings(&self) -> Vec<&str>;
    fn finding_count(&self) -> usize;
    fn findings_by_severity(&self, severity: SecuritySeverity) -> Vec<&DetectionFinding>;
    fn findings_in_time_range(&self, start: i64, end: i64) -> Vec<&DetectionFinding>;
    fn store_detection_rule(&mut self, rule: &DetectionRule) -> Result<(), DetectionError>;
    fn retrieve_detection_rule(&self, id: &str) -> Option<&DetectionRule>;
    fn list_detection_rules(&self) -> Vec<&str>;
    fn store_baseline(&mut self, baseline: &StoredBaseline) -> Result<(), DetectionError>;
    fn retrieve_baseline(&self, id: &str) -> Option<&StoredBaseline>;
    fn list_baselines(&self) -> Vec<&str>;
    fn baseline_count(&self) -> usize;
    fn flush(&mut self) -> Result<(), DetectionError>;
    fn backend_info(&self) -> BackendInfo;
}

// ── InMemoryDetectionBackend ────────────────────────────────────

pub struct InMemoryDetectionBackend {
    findings: HashMap<String, DetectionFinding>,
    rules: HashMap<String, DetectionRule>,
    baselines: HashMap<String, StoredBaseline>,
}

impl InMemoryDetectionBackend {
    pub fn new() -> Self {
        Self {
            findings: HashMap::new(),
            rules: HashMap::new(),
            baselines: HashMap::new(),
        }
    }
}

impl Default for InMemoryDetectionBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionBackend for InMemoryDetectionBackend {
    fn store_finding(&mut self, finding: &DetectionFinding) -> Result<(), DetectionError> {
        if self.findings.contains_key(&finding.id) {
            return Err(DetectionError::InvalidOperation(format!(
                "finding already exists: {}",
                finding.id
            )));
        }
        self.findings.insert(finding.id.clone(), finding.clone());
        Ok(())
    }

    fn retrieve_finding(&self, id: &str) -> Option<&DetectionFinding> {
        self.findings.get(id)
    }

    fn delete_finding(&mut self, id: &str) -> Result<bool, DetectionError> {
        Ok(self.findings.remove(id).is_some())
    }

    fn list_findings(&self) -> Vec<&str> {
        self.findings.keys().map(|k| k.as_str()).collect()
    }

    fn finding_count(&self) -> usize {
        self.findings.len()
    }

    fn findings_by_severity(&self, severity: SecuritySeverity) -> Vec<&DetectionFinding> {
        self.findings.values().filter(|f| f.severity == severity).collect()
    }

    fn findings_in_time_range(&self, start: i64, end: i64) -> Vec<&DetectionFinding> {
        self.findings
            .values()
            .filter(|f| f.timestamp >= start && f.timestamp <= end)
            .collect()
    }

    fn store_detection_rule(&mut self, rule: &DetectionRule) -> Result<(), DetectionError> {
        if self.rules.contains_key(&rule.id) {
            return Err(DetectionError::RuleAlreadyExists(rule.id.clone()));
        }
        self.rules.insert(rule.id.clone(), rule.clone());
        Ok(())
    }

    fn retrieve_detection_rule(&self, id: &str) -> Option<&DetectionRule> {
        self.rules.get(id)
    }

    fn list_detection_rules(&self) -> Vec<&str> {
        self.rules.keys().map(|k| k.as_str()).collect()
    }

    fn store_baseline(&mut self, baseline: &StoredBaseline) -> Result<(), DetectionError> {
        self.baselines.insert(baseline.id.clone(), baseline.clone());
        Ok(())
    }

    fn retrieve_baseline(&self, id: &str) -> Option<&StoredBaseline> {
        self.baselines.get(id)
    }

    fn list_baselines(&self) -> Vec<&str> {
        self.baselines.keys().map(|k| k.as_str()).collect()
    }

    fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    fn flush(&mut self) -> Result<(), DetectionError> {
        Ok(())
    }

    fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend_type: "in-memory".to_string(),
            supports_versioning: false,
            supports_persistence: false,
            max_findings: None,
            max_rules: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rune_security::SecuritySeverity;

    fn make_finding(id: &str, ts: i64) -> DetectionFinding {
        DetectionFinding::new(id, "Test Finding", SecuritySeverity::High, ts)
            .with_category("injection")
            .with_source("test")
    }

    fn make_baseline(id: &str) -> StoredBaseline {
        StoredBaseline {
            id: id.to_string(),
            name: format!("baseline-{id}"),
            mean: "10.5".to_string(),
            std_dev: "2.1".to_string(),
            sample_count: 100,
            trained_at: 1000,
            window_description: "24h".to_string(),
        }
    }

    #[test]
    fn test_store_and_retrieve_finding() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        let f = b.retrieve_finding("f1");
        assert!(f.is_some());
        assert_eq!(f.unwrap().title, "Test Finding");
    }

    #[test]
    fn test_delete_finding() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        assert!(b.delete_finding("f1").unwrap());
        assert!(!b.delete_finding("f1").unwrap());
    }

    #[test]
    fn test_finding_count_and_list() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        b.store_finding(&make_finding("f2", 200)).unwrap();
        assert_eq!(b.finding_count(), 2);
        assert_eq!(b.list_findings().len(), 2);
    }

    #[test]
    fn test_findings_by_severity() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        b.store_finding(&DetectionFinding::new("f2", "Low", SecuritySeverity::Low, 200)).unwrap();
        assert_eq!(b.findings_by_severity(SecuritySeverity::High).len(), 1);
    }

    #[test]
    fn test_findings_in_time_range() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        b.store_finding(&make_finding("f2", 500)).unwrap();
        b.store_finding(&make_finding("f3", 900)).unwrap();
        assert_eq!(b.findings_in_time_range(200, 800).len(), 1);
    }

    #[test]
    fn test_duplicate_finding_rejected() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_finding(&make_finding("f1", 100)).unwrap();
        assert!(b.store_finding(&make_finding("f1", 200)).is_err());
    }

    #[test]
    fn test_store_and_retrieve_rule() {
        let mut b = InMemoryDetectionBackend::new();
        let rule = crate::rule::DetectionRule::prompt_injection();
        b.store_detection_rule(&rule).unwrap();
        assert!(b.retrieve_detection_rule("builtin-prompt-injection").is_some());
    }

    #[test]
    fn test_duplicate_rule_rejected() {
        let mut b = InMemoryDetectionBackend::new();
        let rule = crate::rule::DetectionRule::prompt_injection();
        b.store_detection_rule(&rule).unwrap();
        assert!(b.store_detection_rule(&rule).is_err());
    }

    #[test]
    fn test_store_and_retrieve_baseline() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_baseline(&make_baseline("b1")).unwrap();
        let bl = b.retrieve_baseline("b1");
        assert!(bl.is_some());
        assert_eq!(bl.unwrap().mean, "10.5");
    }

    #[test]
    fn test_baseline_count_and_list() {
        let mut b = InMemoryDetectionBackend::new();
        b.store_baseline(&make_baseline("b1")).unwrap();
        b.store_baseline(&make_baseline("b2")).unwrap();
        assert_eq!(b.baseline_count(), 2);
        assert_eq!(b.list_baselines().len(), 2);
    }

    #[test]
    fn test_backend_info() {
        let b = InMemoryDetectionBackend::new();
        let info = b.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(!info.supports_persistence);
    }

    #[test]
    fn test_flush_succeeds() {
        let mut b = InMemoryDetectionBackend::new();
        assert!(b.flush().is_ok());
    }
}
