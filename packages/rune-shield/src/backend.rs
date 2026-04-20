// ═══════════════════════════════════════════════════════════════════════
// Backend — Detection rule backend trait and in-memory reference
// implementation.
//
// Layer 3 extracts the storage contract for detection rules,
// signatures, and verdicts into a trait so customers can provide
// their own persistence backend. RUNE provides the contract —
// the customer provides the transport and storage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::ShieldError;
use crate::response::ShieldVerdict;

// ── DetectionRule ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

// ── DetectionSignature ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionSignature {
    pub id: String,
    pub name: String,
    pub signature_data: Vec<u8>,
    pub version: u32,
    pub category: String,
}

// ── StoredVerdict ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredVerdict {
    pub id: String,
    pub verdict: ShieldVerdict,
    pub timestamp: i64,
    pub rule_id: Option<String>,
    pub input_hash: Option<String>,
}

// ── BackendInfo ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub backend_type: String,
    pub supports_versioning: bool,
    pub supports_persistence: bool,
    pub max_rules: Option<usize>,
    pub max_signatures: Option<usize>,
}

// ── DetectionRuleBackend trait ────────────────────────────────────

pub trait DetectionRuleBackend {
    fn store_rule(&mut self, rule: &DetectionRule) -> Result<(), ShieldError>;
    fn retrieve_rule(&self, id: &str) -> Option<&DetectionRule>;
    fn delete_rule(&mut self, id: &str) -> Result<bool, ShieldError>;
    fn list_rules(&self) -> Vec<&str>;
    fn rule_count(&self) -> usize;
    fn rule_exists(&self, id: &str) -> bool;
    fn store_signature(&mut self, sig: &DetectionSignature) -> Result<(), ShieldError>;
    fn retrieve_signature(&self, id: &str) -> Option<&DetectionSignature>;
    fn list_signatures(&self) -> Vec<&str>;
    fn store_verdict(&mut self, verdict: &StoredVerdict) -> Result<(), ShieldError>;
    fn retrieve_verdict(&self, id: &str) -> Option<&StoredVerdict>;
    fn query_verdicts(&self, since: i64) -> Vec<&StoredVerdict>;
    fn flush(&mut self) -> Result<(), ShieldError>;
    fn backend_info(&self) -> BackendInfo;
}

// ── InMemoryShieldBackend ────────────────────────────────────────

pub struct InMemoryShieldBackend {
    rules: HashMap<String, DetectionRule>,
    signatures: HashMap<String, DetectionSignature>,
    verdicts: HashMap<String, StoredVerdict>,
}

impl InMemoryShieldBackend {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            signatures: HashMap::new(),
            verdicts: HashMap::new(),
        }
    }
}

impl Default for InMemoryShieldBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRuleBackend for InMemoryShieldBackend {
    fn store_rule(&mut self, rule: &DetectionRule) -> Result<(), ShieldError> {
        if self.rules.contains_key(&rule.id) {
            return Err(ShieldError::InvalidConfiguration(format!(
                "rule already exists: {}",
                rule.id
            )));
        }
        self.rules.insert(rule.id.clone(), rule.clone());
        Ok(())
    }

    fn retrieve_rule(&self, id: &str) -> Option<&DetectionRule> {
        self.rules.get(id)
    }

    fn delete_rule(&mut self, id: &str) -> Result<bool, ShieldError> {
        Ok(self.rules.remove(id).is_some())
    }

    fn list_rules(&self) -> Vec<&str> {
        self.rules.keys().map(|k| k.as_str()).collect()
    }

    fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn rule_exists(&self, id: &str) -> bool {
        self.rules.contains_key(id)
    }

    fn store_signature(&mut self, sig: &DetectionSignature) -> Result<(), ShieldError> {
        self.signatures.insert(sig.id.clone(), sig.clone());
        Ok(())
    }

    fn retrieve_signature(&self, id: &str) -> Option<&DetectionSignature> {
        self.signatures.get(id)
    }

    fn list_signatures(&self) -> Vec<&str> {
        self.signatures.keys().map(|k| k.as_str()).collect()
    }

    fn store_verdict(&mut self, verdict: &StoredVerdict) -> Result<(), ShieldError> {
        self.verdicts.insert(verdict.id.clone(), verdict.clone());
        Ok(())
    }

    fn retrieve_verdict(&self, id: &str) -> Option<&StoredVerdict> {
        self.verdicts.get(id)
    }

    fn query_verdicts(&self, since: i64) -> Vec<&StoredVerdict> {
        self.verdicts
            .values()
            .filter(|v| v.timestamp >= since)
            .collect()
    }

    fn flush(&mut self) -> Result<(), ShieldError> {
        Ok(())
    }

    fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend_type: "in-memory".to_string(),
            supports_versioning: false,
            supports_persistence: false,
            max_rules: None,
            max_signatures: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::ShieldVerdict;
    use rune_security::SecuritySeverity;

    fn make_rule(id: &str) -> DetectionRule {
        DetectionRule {
            id: id.to_string(),
            name: format!("Rule {id}"),
            pattern: "test.*pattern".to_string(),
            severity: "High".to_string(),
            category: "injection".to_string(),
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    fn make_signature(id: &str) -> DetectionSignature {
        DetectionSignature {
            id: id.to_string(),
            name: format!("Sig {id}"),
            signature_data: vec![0xDE, 0xAD],
            version: 1,
            category: "malware".to_string(),
        }
    }

    fn make_verdict(id: &str, ts: i64) -> StoredVerdict {
        StoredVerdict {
            id: id.to_string(),
            verdict: ShieldVerdict::block("test", SecuritySeverity::High, 0.9),
            timestamp: ts,
            rule_id: Some("r1".to_string()),
            input_hash: None,
        }
    }

    #[test]
    fn test_store_and_retrieve_rule() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_rule(&make_rule("r1")).unwrap();
        let rule = backend.retrieve_rule("r1");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name, "Rule r1");
    }

    #[test]
    fn test_delete_rule() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_rule(&make_rule("r1")).unwrap();
        assert!(backend.delete_rule("r1").unwrap());
        assert!(!backend.rule_exists("r1"));
        assert!(!backend.delete_rule("r1").unwrap());
    }

    #[test]
    fn test_list_rules_and_count() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_rule(&make_rule("r1")).unwrap();
        backend.store_rule(&make_rule("r2")).unwrap();
        assert_eq!(backend.rule_count(), 2);
        let mut ids = backend.list_rules();
        ids.sort();
        assert_eq!(ids, vec!["r1", "r2"]);
    }

    #[test]
    fn test_rule_exists() {
        let mut backend = InMemoryShieldBackend::new();
        assert!(!backend.rule_exists("r1"));
        backend.store_rule(&make_rule("r1")).unwrap();
        assert!(backend.rule_exists("r1"));
    }

    #[test]
    fn test_store_and_retrieve_signature() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_signature(&make_signature("s1")).unwrap();
        let sig = backend.retrieve_signature("s1");
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().version, 1);
    }

    #[test]
    fn test_list_signatures() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_signature(&make_signature("s1")).unwrap();
        assert_eq!(backend.list_signatures().len(), 1);
    }

    #[test]
    fn test_store_and_query_verdicts() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_verdict(&make_verdict("v1", 100)).unwrap();
        backend.store_verdict(&make_verdict("v2", 200)).unwrap();
        let retrieved = backend.retrieve_verdict("v1");
        assert!(retrieved.is_some());
        let recent = backend.query_verdicts(150);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_flush_succeeds() {
        let mut backend = InMemoryShieldBackend::new();
        assert!(backend.flush().is_ok());
    }

    #[test]
    fn test_backend_info() {
        let backend = InMemoryShieldBackend::new();
        let info = backend.backend_info();
        assert_eq!(info.backend_type, "in-memory");
        assert!(!info.supports_persistence);
    }

    #[test]
    fn test_duplicate_rule_rejected() {
        let mut backend = InMemoryShieldBackend::new();
        backend.store_rule(&make_rule("r1")).unwrap();
        let result = backend.store_rule(&make_rule("r1"));
        assert!(result.is_err());
    }
}
