// ═══════════════════════════════════════════════════════════════════════
// Redaction Engine — Pluggable data redaction strategies.
//
// Defines how personal data is transformed to remove or mask PII.
// RedactionEngine composes multiple strategies by field classification,
// routing to the appropriate strategy based on PII category and policy.
//
// HMAC-SHA3-256 tokenization provides deterministic, reversible-with-key
// tokens. SHA3-256 hashing is one-way and irreversible.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};

use crate::backend::SubjectRef;
use crate::error::PrivacyError;
use crate::pii::PiiCategory;

type HmacSha3_256 = Hmac<Sha3_256>;

// ── StrategyType ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategyType {
    Mask,
    Truncate,
    Hash,
    Tokenize,
    Pseudonymize,
    Remove,
}

impl fmt::Display for StrategyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RedactionContext ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RedactionContext {
    pub field_classification: PiiCategory,
    pub jurisdiction: String,
    pub subject_ref: Option<SubjectRef>,
}

impl RedactionContext {
    pub fn new(classification: PiiCategory, jurisdiction: &str) -> Self {
        Self {
            field_classification: classification,
            jurisdiction: jurisdiction.to_string(),
            subject_ref: None,
        }
    }

    pub fn with_subject(mut self, subject: SubjectRef) -> Self {
        self.subject_ref = Some(subject);
        self
    }
}

// ── RedactionStrategy trait ─────────────────────────────────────────

pub trait RedactionStrategy {
    fn redact(&self, input: &[u8], context: &RedactionContext) -> Result<Vec<u8>, PrivacyError>;
    fn strategy_id(&self) -> &str;
    fn strategy_type(&self) -> StrategyType;
    fn is_reversible(&self) -> bool;
}

// ── MaskRedactionStrategy ───────────────────────────────────────────

pub struct MaskRedactionStrategy {
    id: String,
    visible_tail: usize,
    mask_char: u8,
}

impl MaskRedactionStrategy {
    pub fn new(id: &str, visible_tail: usize, mask_char: char) -> Self {
        Self {
            id: id.to_string(),
            visible_tail,
            mask_char: mask_char as u8,
        }
    }
}

impl RedactionStrategy for MaskRedactionStrategy {
    fn redact(&self, input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        if input.len() <= self.visible_tail {
            return Ok(vec![self.mask_char; input.len()]);
        }
        let mask_len = input.len() - self.visible_tail;
        let mut output = vec![self.mask_char; mask_len];
        output.extend_from_slice(&input[mask_len..]);
        Ok(output)
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Mask }
    fn is_reversible(&self) -> bool { false }
}

// ── TruncateRedactionStrategy ───────────────────────────────────────

pub struct TruncateRedactionStrategy {
    id: String,
    keep_first: usize,
}

impl TruncateRedactionStrategy {
    pub fn new(id: &str, keep_first: usize) -> Self {
        Self { id: id.to_string(), keep_first }
    }
}

impl RedactionStrategy for TruncateRedactionStrategy {
    fn redact(&self, input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        let end = self.keep_first.min(input.len());
        Ok(input[..end].to_vec())
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Truncate }
    fn is_reversible(&self) -> bool { false }
}

// ── Sha3HashRedactionStrategy ───────────────────────────────────────

pub struct Sha3HashRedactionStrategy {
    id: String,
}

impl Sha3HashRedactionStrategy {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl RedactionStrategy for Sha3HashRedactionStrategy {
    fn redact(&self, input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        let mut hasher = Sha3_256::new();
        hasher.update(input);
        Ok(hex::encode(hasher.finalize()).into_bytes())
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Hash }
    fn is_reversible(&self) -> bool { false }
}

// ── TokenizeRedactionStrategy ───────────────────────────────────────

pub struct TokenizeRedactionStrategy {
    id: String,
    key: Vec<u8>,
}

impl TokenizeRedactionStrategy {
    pub fn new(id: &str, key: &[u8]) -> Self {
        Self { id: id.to_string(), key: key.to_vec() }
    }
}

impl RedactionStrategy for TokenizeRedactionStrategy {
    fn redact(&self, input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        let mut mac = HmacSha3_256::new_from_slice(&self.key)
            .expect("HMAC key can be any length");
        mac.update(input);
        let token = hex::encode(mac.finalize().into_bytes());
        Ok(format!("tok:{token}").into_bytes())
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Tokenize }
    fn is_reversible(&self) -> bool { true }
}

// ── PseudonymizeRedactionStrategy ───────────────────────────────────

pub struct PseudonymizeRedactionStrategy {
    id: String,
    key: Vec<u8>,
    key_reference: String,
}

impl PseudonymizeRedactionStrategy {
    pub fn new(id: &str, key: &[u8], key_reference: &str) -> Self {
        Self {
            id: id.to_string(),
            key: key.to_vec(),
            key_reference: key_reference.to_string(),
        }
    }
}

impl RedactionStrategy for PseudonymizeRedactionStrategy {
    fn redact(&self, input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        let mut mac = HmacSha3_256::new_from_slice(&self.key)
            .expect("HMAC key can be any length");
        mac.update(input);
        let token = hex::encode(mac.finalize().into_bytes());
        Ok(format!("pseudo:{}:{}", self.key_reference, token).into_bytes())
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Pseudonymize }
    fn is_reversible(&self) -> bool { true }
}

// ── RemoveRedactionStrategy ─────────────────────────────────────────

pub struct RemoveRedactionStrategy {
    id: String,
}

impl RemoveRedactionStrategy {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl RedactionStrategy for RemoveRedactionStrategy {
    fn redact(&self, _input: &[u8], _context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        Ok(Vec::new())
    }

    fn strategy_id(&self) -> &str { &self.id }
    fn strategy_type(&self) -> StrategyType { StrategyType::Remove }
    fn is_reversible(&self) -> bool { false }
}

// ── RedactionEngine ─────────────────────────────────────────────────

pub struct RedactionEngine {
    strategies: HashMap<String, Box<dyn RedactionStrategy>>,
    category_mapping: HashMap<String, String>,
}

impl RedactionEngine {
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
            category_mapping: HashMap::new(),
        }
    }

    pub fn register_strategy(&mut self, strategy: Box<dyn RedactionStrategy>) {
        let id = strategy.strategy_id().to_string();
        self.strategies.insert(id, strategy);
    }

    pub fn map_category(&mut self, category: &PiiCategory, strategy_id: &str) {
        self.category_mapping.insert(format!("{category}"), strategy_id.to_string());
    }

    pub fn redact(&self, input: &[u8], context: &RedactionContext) -> Result<Vec<u8>, PrivacyError> {
        let cat_key = format!("{}", context.field_classification);
        let strategy_id = self.category_mapping.get(&cat_key)
            .ok_or_else(|| PrivacyError::InvalidOperation(
                format!("no redaction strategy mapped for category {cat_key}")
            ))?;
        let strategy = self.strategies.get(strategy_id)
            .ok_or_else(|| PrivacyError::InvalidOperation(
                format!("redaction strategy {strategy_id} not found")
            ))?;
        strategy.redact(input, context)
    }

    pub fn strategy_count(&self) -> usize {
        self.strategies.len()
    }
}

impl Default for RedactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cat: PiiCategory) -> RedactionContext {
        RedactionContext::new(cat, "EU")
    }

    #[test]
    fn test_mask_strategy() {
        let s = MaskRedactionStrategy::new("mask-1", 4, '*');
        let result = s.redact(b"alice@example.com", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(result.len(), b"alice@example.com".len());
        assert!(result.ends_with(b".com"));
        assert!(!s.is_reversible());
    }

    #[test]
    fn test_mask_short_input() {
        let s = MaskRedactionStrategy::new("mask-1", 10, '*');
        let result = s.redact(b"hi", &ctx(PiiCategory::Name)).unwrap();
        assert_eq!(result, b"**");
    }

    #[test]
    fn test_truncate_strategy() {
        let s = TruncateRedactionStrategy::new("trunc-1", 3);
        let result = s.redact(b"alice@example.com", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(result, b"ali");
        assert!(!s.is_reversible());
    }

    #[test]
    fn test_sha3_hash_strategy() {
        let s = Sha3HashRedactionStrategy::new("hash-1");
        let result = s.redact(b"alice@example.com", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(result.len(), 64); // hex-encoded SHA3-256
        assert!(!s.is_reversible());
    }

    #[test]
    fn test_sha3_hash_deterministic() {
        let s = Sha3HashRedactionStrategy::new("hash-1");
        let r1 = s.redact(b"test", &ctx(PiiCategory::Email)).unwrap();
        let r2 = s.redact(b"test", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_tokenize_strategy() {
        let s = TokenizeRedactionStrategy::new("tok-1", b"secret-key");
        let result = s.redact(b"alice@example.com", &ctx(PiiCategory::Email)).unwrap();
        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.starts_with("tok:"));
        assert!(s.is_reversible());
    }

    #[test]
    fn test_tokenize_deterministic() {
        let s = TokenizeRedactionStrategy::new("tok-1", b"key");
        let r1 = s.redact(b"test", &ctx(PiiCategory::Email)).unwrap();
        let r2 = s.redact(b"test", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_pseudonymize_strategy() {
        let s = PseudonymizeRedactionStrategy::new("pseudo-1", b"key", "kr-2024");
        let result = s.redact(b"alice", &ctx(PiiCategory::Name)).unwrap();
        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.starts_with("pseudo:kr-2024:"));
        assert!(s.is_reversible());
    }

    #[test]
    fn test_remove_strategy() {
        let s = RemoveRedactionStrategy::new("rm-1");
        let result = s.redact(b"sensitive data", &ctx(PiiCategory::Ssn)).unwrap();
        assert!(result.is_empty());
        assert!(!s.is_reversible());
    }

    #[test]
    fn test_redaction_engine_routes_by_category() {
        let mut engine = RedactionEngine::new();
        engine.register_strategy(Box::new(MaskRedactionStrategy::new("mask-1", 4, '*')));
        engine.register_strategy(Box::new(RemoveRedactionStrategy::new("rm-1")));
        engine.map_category(&PiiCategory::Email, "mask-1");
        engine.map_category(&PiiCategory::Ssn, "rm-1");

        let masked = engine.redact(b"alice@example.com", &ctx(PiiCategory::Email)).unwrap();
        assert_eq!(masked.len(), b"alice@example.com".len());

        let removed = engine.redact(b"123-45-6789", &ctx(PiiCategory::Ssn)).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn test_redaction_engine_unknown_category() {
        let engine = RedactionEngine::new();
        assert!(engine.redact(b"test", &ctx(PiiCategory::Phone)).is_err());
    }

    #[test]
    fn test_strategy_type_display() {
        assert_eq!(StrategyType::Mask.to_string(), "Mask");
        assert_eq!(StrategyType::Tokenize.to_string(), "Tokenize");
        assert_eq!(StrategyType::Pseudonymize.to_string(), "Pseudonymize");
    }

    #[test]
    fn test_redaction_context_with_subject() {
        let ctx = RedactionContext::new(PiiCategory::Email, "EU")
            .with_subject(SubjectRef::new("alice"));
        assert!(ctx.subject_ref.is_some());
    }

    #[test]
    fn test_engine_strategy_count() {
        let mut engine = RedactionEngine::new();
        engine.register_strategy(Box::new(MaskRedactionStrategy::new("m1", 4, '*')));
        engine.register_strategy(Box::new(RemoveRedactionStrategy::new("r1")));
        assert_eq!(engine.strategy_count(), 2);
    }
}
