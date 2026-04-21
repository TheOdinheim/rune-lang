// ═════════���════════════════════════════════���════════════════════════════
// Layer 2 — Memory content integrity via SHA3-256 hashing. Provides
// content hashing, entry fingerprinting, hash verification with
// constant-time comparison, retrieval result hashing, and an
// append-only hash chain for tamper detection.
// ════════���══════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

use crate::memory::MemoryEntry;
use crate::retrieval::RetrievalResult;

// ── Hashing functions ───────────���──────────────────────────────────

pub fn hash_memory_content(content: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_memory_entry(entry: &MemoryEntry) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(entry.content.as_bytes());
    hasher.update(b":");
    hasher.update(entry.scope_id.as_bytes());
    hasher.update(b":");
    hasher.update(entry.content_type.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(entry.sensitivity_level.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(entry.created_by.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_memory_hash(content: &str, expected_hash: &str) -> bool {
    let computed = hash_memory_content(content);
    constant_time_eq(computed.as_bytes(), expected_hash.as_bytes())
}

pub fn hash_retrieval_result(result: &RetrievalResult) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(result.collection_id.as_bytes());
    hasher.update(b":");
    hasher.update(result.result_count.to_string().as_bytes());
    for pref in &result.provenance_refs {
        hasher.update(b":");
        hasher.update(pref.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── MemoryHashChain ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HashChainLink {
    pub content_hash: String,
    pub previous_hash: String,
    pub chain_hash: String,
    pub index: usize,
}

pub struct MemoryHashChain {
    links: Vec<HashChainLink>,
}

impl MemoryHashChain {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    pub fn append(&mut self, content: &str) -> HashChainLink {
        let content_hash = hash_memory_content(content);
        let previous_hash = self
            .links
            .last()
            .map(|l| l.chain_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let mut hasher = Sha3_256::new();
        hasher.update(content_hash.as_bytes());
        hasher.update(b":");
        hasher.update(previous_hash.as_bytes());
        let chain_hash = hex::encode(hasher.finalize());
        let link = HashChainLink {
            content_hash,
            previous_hash,
            chain_hash,
            index: self.links.len(),
        };
        self.links.push(link.clone());
        link
    }

    pub fn verify_chain(&self) -> bool {
        let zero_hash = "0".repeat(64);
        for (i, link) in self.links.iter().enumerate() {
            let expected_prev = if i == 0 {
                &zero_hash
            } else {
                &self.links[i - 1].chain_hash
            };
            if link.previous_hash != *expected_prev {
                return false;
            }
            let mut hasher = Sha3_256::new();
            hasher.update(link.content_hash.as_bytes());
            hasher.update(b":");
            hasher.update(link.previous_hash.as_bytes());
            let recomputed = hex::encode(hasher.finalize());
            if !constant_time_eq(recomputed.as_bytes(), link.chain_hash.as_bytes()) {
                return false;
            }
        }
        true
    }

    pub fn chain_length(&self) -> usize {
        self.links.len()
    }

    pub fn latest_hash(&self) -> Option<&str> {
        self.links.last().map(|l| l.chain_hash.as_str())
    }

    pub fn links(&self) -> &[HashChainLink] {
        &self.links
    }
}

impl Default for MemoryHashChain {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════���════════════════════════════
// Tests
// ════════���══════════════���══════════════════════════════��════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryContentType, MemorySensitivity};

    #[test]
    fn test_hash_memory_content() {
        let hash = hash_memory_content("hello world");
        assert_eq!(hash.len(), 64);
        let hash2 = hash_memory_content("hello world");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_different_content() {
        let h1 = hash_memory_content("hello");
        let h2 = hash_memory_content("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_memory_entry() {
        let entry = MemoryEntry::new(
            "e1", "scope-1", "test content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal, "agent-1", 1000,
        );
        let hash = hash_memory_entry(&entry);
        assert_eq!(hash.len(), 64);
        let hash2 = hash_memory_entry(&entry);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_entry_differs_by_scope() {
        let e1 = MemoryEntry::new(
            "e1", "scope-a", "content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Public, "agent-1", 1000,
        );
        let e2 = MemoryEntry::new(
            "e1", "scope-b", "content",
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Public, "agent-1", 1000,
        );
        assert_ne!(hash_memory_entry(&e1), hash_memory_entry(&e2));
    }

    #[test]
    fn test_verify_memory_hash_valid() {
        let content = "test data";
        let hash = hash_memory_content(content);
        assert!(verify_memory_hash(content, &hash));
    }

    #[test]
    fn test_verify_memory_hash_invalid() {
        assert!(!verify_memory_hash("test data", "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_verify_memory_hash_wrong_length() {
        assert!(!verify_memory_hash("test", "abc"));
    }

    #[test]
    fn test_hash_retrieval_result() {
        let mut result = RetrievalResult::new(
            "res-1", "rr-1", "docs", 5,
            MemorySensitivity::Public, 2000,
        );
        result.add_provenance_ref("attest-1");
        let hash = hash_retrieval_result(&result);
        assert_eq!(hash.len(), 64);
        let hash2 = hash_retrieval_result(&result);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_retrieval_result_differs_by_provenance() {
        let mut r1 = RetrievalResult::new(
            "res-1", "rr-1", "docs", 5,
            MemorySensitivity::Public, 2000,
        );
        r1.add_provenance_ref("attest-1");
        let mut r2 = RetrievalResult::new(
            "res-1", "rr-1", "docs", 5,
            MemorySensitivity::Public, 2000,
        );
        r2.add_provenance_ref("attest-2");
        assert_ne!(hash_retrieval_result(&r1), hash_retrieval_result(&r2));
    }

    #[test]
    fn test_hash_chain_empty() {
        let chain = MemoryHashChain::new();
        assert_eq!(chain.chain_length(), 0);
        assert!(chain.latest_hash().is_none());
        assert!(chain.verify_chain());
    }

    #[test]
    fn test_hash_chain_append() {
        let mut chain = MemoryHashChain::new();
        let link = chain.append("first entry");
        assert_eq!(link.index, 0);
        assert_eq!(chain.chain_length(), 1);
        assert!(chain.latest_hash().is_some());
    }

    #[test]
    fn test_hash_chain_multiple_appends() {
        let mut chain = MemoryHashChain::new();
        chain.append("first");
        chain.append("second");
        chain.append("third");
        assert_eq!(chain.chain_length(), 3);
        assert!(chain.verify_chain());
    }

    #[test]
    fn test_hash_chain_links_are_connected() {
        let mut chain = MemoryHashChain::new();
        let l1 = chain.append("first");
        let l2 = chain.append("second");
        assert_eq!(l2.previous_hash, l1.chain_hash);
    }

    #[test]
    fn test_hash_chain_tamper_detection() {
        let mut chain = MemoryHashChain::new();
        chain.append("first");
        chain.append("second");
        chain.append("third");
        assert!(chain.verify_chain());
        // Tamper with a link
        chain.links[1].content_hash = "tampered".into();
        assert!(!chain.verify_chain());
    }

    #[test]
    fn test_hash_chain_first_link_previous_is_zeros() {
        let mut chain = MemoryHashChain::new();
        let link = chain.append("first");
        assert_eq!(link.previous_hash, "0".repeat(64));
    }

    #[test]
    fn test_hash_chain_default() {
        let chain = MemoryHashChain::default();
        assert_eq!(chain.chain_length(), 0);
    }
}
