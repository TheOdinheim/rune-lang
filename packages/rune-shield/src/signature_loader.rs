// ═══════════════════════════════════════════════════════════════════════
// Signature Loader — Rule pack loading and integrity validation.
//
// Layer 3 defines the contract for loading detection rule packs
// with integrity validation (SHA3-256). Validates hash before
// installation. RUNE provides the loading contract — the customer
// provides the transport.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::backend::DetectionRule;
use crate::error::ShieldError;

// ── RulePackValidationError ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulePackValidationError {
    IntegrityMismatch { expected: String, actual: String },
    EmptyRuleset,
    InvalidFormat(String),
    MissingField(String),
}

impl std::fmt::Display for RulePackValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntegrityMismatch { expected, actual } => {
                write!(f, "integrity mismatch: expected {expected}, got {actual}")
            }
            Self::EmptyRuleset => f.write_str("rule pack contains no rules"),
            Self::InvalidFormat(s) => write!(f, "invalid format: {s}"),
            Self::MissingField(s) => write!(f, "missing field: {s}"),
        }
    }
}

impl std::error::Error for RulePackValidationError {}

// ── RulePack ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RulePack {
    pub name: String,
    pub version: u32,
    pub ruleset_hash: String,
    pub rules: Vec<DetectionRule>,
    pub metadata: HashMap<String, String>,
}

impl RulePack {
    pub fn new(name: &str, version: u32, rules: Vec<DetectionRule>) -> Self {
        let hash = Self::compute_hash(&rules);
        Self {
            name: name.to_string(),
            version,
            ruleset_hash: hash,
            rules,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Compute SHA3-256 hash over rule ids and patterns (sorted for determinism).
    pub fn compute_hash(rules: &[DetectionRule]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        let mut entries: Vec<String> = rules
            .iter()
            .map(|r| format!("{}:{}", r.id, r.pattern))
            .collect();
        entries.sort();
        for entry in &entries {
            hasher.update(entry.as_bytes());
        }
        let result = hasher.finalize();
        result.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Validate that the stored hash matches the computed hash.
    pub fn validate_integrity(&self) -> Result<(), RulePackValidationError> {
        if self.rules.is_empty() {
            return Err(RulePackValidationError::EmptyRuleset);
        }
        let computed = Self::compute_hash(&self.rules);
        if computed != self.ruleset_hash {
            return Err(RulePackValidationError::IntegrityMismatch {
                expected: self.ruleset_hash.clone(),
                actual: computed,
            });
        }
        Ok(())
    }
}

// ── SignatureLoader trait ────────────────────────────────────────

pub trait SignatureLoader {
    fn load_pack(&mut self, pack: RulePack) -> Result<(), ShieldError>;
    fn validate_pack(&self, pack: &RulePack) -> Result<(), RulePackValidationError>;
    fn list_loaded_packs(&self) -> Vec<&str>;
    fn pack_metadata(&self, name: &str) -> Option<&HashMap<String, String>>;
    fn supported_pack_format(&self) -> &str;
}

// ── InMemorySignatureLoader ─────────────────────────────────────

pub struct InMemorySignatureLoader {
    packs: HashMap<String, RulePack>,
}

impl InMemorySignatureLoader {
    pub fn new() -> Self {
        Self {
            packs: HashMap::new(),
        }
    }

    pub fn loaded_rules(&self) -> Vec<&DetectionRule> {
        self.packs.values().flat_map(|p| &p.rules).collect()
    }

    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }
}

impl Default for InMemorySignatureLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureLoader for InMemorySignatureLoader {
    fn load_pack(&mut self, pack: RulePack) -> Result<(), ShieldError> {
        pack.validate_integrity()
            .map_err(|e| ShieldError::InvalidConfiguration(format!("pack validation: {e}")))?;
        self.packs.insert(pack.name.clone(), pack);
        Ok(())
    }

    fn validate_pack(&self, pack: &RulePack) -> Result<(), RulePackValidationError> {
        pack.validate_integrity()
    }

    fn list_loaded_packs(&self) -> Vec<&str> {
        self.packs.keys().map(|k| k.as_str()).collect()
    }

    fn pack_metadata(&self, name: &str) -> Option<&HashMap<String, String>> {
        self.packs.get(name).map(|p| &p.metadata)
    }

    fn supported_pack_format(&self) -> &str {
        "in-memory"
    }
}

// ── JsonSignatureLoader ─────────────────────────────────────────

/// Parses rule packs from JSON bytes. No file I/O — the customer
/// provides the bytes.
pub struct JsonSignatureLoader {
    packs: HashMap<String, RulePack>,
}

impl JsonSignatureLoader {
    pub fn new() -> Self {
        Self {
            packs: HashMap::new(),
        }
    }

    /// Parse a RulePack from JSON bytes.
    pub fn parse_pack(data: &[u8]) -> Result<RulePack, ShieldError> {
        let json: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| ShieldError::InvalidConfiguration(format!("JSON parse: {e}")))?;

        let name = json["name"]
            .as_str()
            .ok_or_else(|| ShieldError::InvalidConfiguration("missing 'name'".into()))?;
        let version = json["version"]
            .as_u64()
            .ok_or_else(|| ShieldError::InvalidConfiguration("missing 'version'".into()))?
            as u32;

        let rules_arr = json["rules"]
            .as_array()
            .ok_or_else(|| ShieldError::InvalidConfiguration("missing 'rules' array".into()))?;

        let mut rules = Vec::new();
        for r in rules_arr {
            let id = r["id"]
                .as_str()
                .ok_or_else(|| ShieldError::InvalidConfiguration("rule missing 'id'".into()))?;
            let rule_name = r["name"].as_str().unwrap_or(id);
            let pattern = r["pattern"]
                .as_str()
                .ok_or_else(|| {
                    ShieldError::InvalidConfiguration("rule missing 'pattern'".into())
                })?;
            let severity = r["severity"].as_str().unwrap_or("Medium");
            let category = r["category"].as_str().unwrap_or("general");
            let enabled = r["enabled"].as_bool().unwrap_or(true);

            rules.push(DetectionRule {
                id: id.to_string(),
                name: rule_name.to_string(),
                pattern: pattern.to_string(),
                severity: severity.to_string(),
                category: category.to_string(),
                enabled,
                metadata: HashMap::new(),
            });
        }

        let mut pack = RulePack::new(name, version, rules);

        // If a hash is provided in JSON, use it (for pre-signed packs).
        if let Some(hash) = json["ruleset_hash"].as_str() {
            pack.ruleset_hash = hash.to_string();
        }

        Ok(pack)
    }

    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }
}

impl Default for JsonSignatureLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureLoader for JsonSignatureLoader {
    fn load_pack(&mut self, pack: RulePack) -> Result<(), ShieldError> {
        pack.validate_integrity()
            .map_err(|e| ShieldError::InvalidConfiguration(format!("pack validation: {e}")))?;
        self.packs.insert(pack.name.clone(), pack);
        Ok(())
    }

    fn validate_pack(&self, pack: &RulePack) -> Result<(), RulePackValidationError> {
        pack.validate_integrity()
    }

    fn list_loaded_packs(&self) -> Vec<&str> {
        self.packs.keys().map(|k| k.as_str()).collect()
    }

    fn pack_metadata(&self, name: &str) -> Option<&HashMap<String, String>> {
        self.packs.get(name).map(|p| &p.metadata)
    }

    fn supported_pack_format(&self) -> &str {
        "json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_rule_pack_integrity_valid() {
        let pack = RulePack::new("test-pack", 1, vec![make_rule("r1"), make_rule("r2")]);
        assert!(pack.validate_integrity().is_ok());
    }

    #[test]
    fn test_rule_pack_integrity_tampered() {
        let mut pack = RulePack::new("test-pack", 1, vec![make_rule("r1")]);
        pack.ruleset_hash = "deadbeef".to_string();
        let err = pack.validate_integrity().unwrap_err();
        assert!(matches!(err, RulePackValidationError::IntegrityMismatch { .. }));
    }

    #[test]
    fn test_rule_pack_empty_rejected() {
        let pack = RulePack::new("empty", 1, vec![]);
        // Empty pack gets a hash but validate_integrity rejects it
        let err = pack.validate_integrity().unwrap_err();
        assert!(matches!(err, RulePackValidationError::EmptyRuleset));
    }

    #[test]
    fn test_in_memory_loader() {
        let mut loader = InMemorySignatureLoader::new();
        let pack = RulePack::new("pack1", 1, vec![make_rule("r1")]);
        loader.load_pack(pack).unwrap();
        assert_eq!(loader.pack_count(), 1);
        assert_eq!(loader.loaded_rules().len(), 1);
        assert!(loader.list_loaded_packs().contains(&"pack1"));
    }

    #[test]
    fn test_in_memory_loader_rejects_bad_hash() {
        let mut loader = InMemorySignatureLoader::new();
        let mut pack = RulePack::new("pack1", 1, vec![make_rule("r1")]);
        pack.ruleset_hash = "bad".to_string();
        assert!(loader.load_pack(pack).is_err());
    }

    #[test]
    fn test_pack_metadata() {
        let mut loader = InMemorySignatureLoader::new();
        let pack = RulePack::new("pack1", 1, vec![make_rule("r1")])
            .with_metadata("author", "rune");
        loader.load_pack(pack).unwrap();
        let meta = loader.pack_metadata("pack1").unwrap();
        assert_eq!(meta.get("author").unwrap(), "rune");
    }

    #[test]
    fn test_json_parse_pack() {
        let json = serde_json::json!({
            "name": "json-pack",
            "version": 2,
            "rules": [
                {
                    "id": "r1",
                    "name": "Rule 1",
                    "pattern": "ignore.*instructions",
                    "severity": "High",
                    "category": "injection",
                    "enabled": true
                }
            ]
        });
        let data = serde_json::to_vec(&json).unwrap();
        let pack = JsonSignatureLoader::parse_pack(&data).unwrap();
        assert_eq!(pack.name, "json-pack");
        assert_eq!(pack.version, 2);
        assert_eq!(pack.rules.len(), 1);
        // Hash was computed, so integrity should be valid
        assert!(pack.validate_integrity().is_ok());
    }

    #[test]
    fn test_json_loader_load() {
        let mut loader = JsonSignatureLoader::new();
        let json = serde_json::json!({
            "name": "jp",
            "version": 1,
            "rules": [{"id": "r1", "pattern": "test"}]
        });
        let data = serde_json::to_vec(&json).unwrap();
        let pack = JsonSignatureLoader::parse_pack(&data).unwrap();
        loader.load_pack(pack).unwrap();
        assert_eq!(loader.pack_count(), 1);
        assert_eq!(loader.supported_pack_format(), "json");
    }

    #[test]
    fn test_json_parse_missing_name() {
        let json = serde_json::json!({ "version": 1, "rules": [] });
        let data = serde_json::to_vec(&json).unwrap();
        assert!(JsonSignatureLoader::parse_pack(&data).is_err());
    }

    #[test]
    fn test_validation_error_display() {
        let errs = vec![
            RulePackValidationError::IntegrityMismatch {
                expected: "abc".into(),
                actual: "def".into(),
            },
            RulePackValidationError::EmptyRuleset,
            RulePackValidationError::InvalidFormat("bad".into()),
            RulePackValidationError::MissingField("name".into()),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }
}
