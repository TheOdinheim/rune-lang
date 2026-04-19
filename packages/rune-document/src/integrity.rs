// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — SHA3-256 document integrity verification.
//
// Cryptographic hashing for document content and metadata,
// integrity verification with constant-time comparison,
// integrity record store, and hash chain for tamper detection.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

// ── Hashing functions ───────────────────────────────────────────────

pub fn hash_document_content(content: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

pub fn hash_document_metadata(doc_id: &str, title: &str, version: u32, created_at: i64) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{doc_id}:{title}:{version}:{created_at}").as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_document_hash(content: &[u8], expected_hash: &str) -> bool {
    let computed = hash_document_content(content);
    constant_time_eq(computed.as_bytes(), expected_hash.as_bytes())
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

// ── IntegrityVerification ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IntegrityVerification {
    pub doc_id: String,
    pub version: u32,
    pub content_matches: bool,
    pub record_found: bool,
}

// ── DocumentIntegrityRecord ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocumentIntegrityRecord {
    pub doc_id: String,
    pub content_hash: String,
    pub metadata_hash: String,
    pub version: u32,
    pub verified_at: i64,
    pub tampered: bool,
}

// ── DocumentIntegrityStore ──────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DocumentIntegrityStore {
    pub records: HashMap<String, Vec<DocumentIntegrityRecord>>,
}

impl DocumentIntegrityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_integrity(
        &mut self,
        doc_id: &str,
        content: &[u8],
        title: &str,
        version: u32,
        now: i64,
    ) -> DocumentIntegrityRecord {
        let content_hash = hash_document_content(content);
        let metadata_hash = hash_document_metadata(doc_id, title, version, now);
        let record = DocumentIntegrityRecord {
            doc_id: doc_id.into(),
            content_hash,
            metadata_hash,
            version,
            verified_at: now,
            tampered: false,
        };
        self.records
            .entry(doc_id.into())
            .or_default()
            .push(record.clone());
        record
    }

    pub fn verify_integrity(
        &self,
        doc_id: &str,
        version: u32,
        content: &[u8],
    ) -> IntegrityVerification {
        let records = self.records.get(doc_id);
        let record = records
            .and_then(|rs| rs.iter().find(|r| r.version == version));
        match record {
            Some(rec) => {
                let matches = verify_document_hash(content, &rec.content_hash);
                IntegrityVerification {
                    doc_id: doc_id.into(),
                    version,
                    content_matches: matches,
                    record_found: true,
                }
            }
            None => IntegrityVerification {
                doc_id: doc_id.into(),
                version,
                content_matches: false,
                record_found: false,
            },
        }
    }

    pub fn integrity_history(&self, doc_id: &str) -> Vec<&DocumentIntegrityRecord> {
        self.records
            .get(doc_id)
            .map(|rs| rs.iter().collect())
            .unwrap_or_default()
    }
}

// ── ChainVerification ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<usize>,
}

// ── HashChainEntry ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HashChainEntry {
    pub doc_id: String,
    pub version: u32,
    pub content_hash: String,
    pub previous_hash: Option<String>,
    pub entry_hash: String,
    pub timestamp: i64,
}

fn compute_entry_hash(
    doc_id: &str,
    version: u32,
    content_hash: &str,
    previous_hash: &Option<String>,
) -> String {
    let prev = previous_hash.as_deref().unwrap_or("none");
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{doc_id}:{version}:{content_hash}:{prev}").as_bytes());
    hex::encode(hasher.finalize())
}

// ── DocumentHashChain ───────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct DocumentHashChain {
    pub entries: Vec<HashChainEntry>,
}

impl DocumentHashChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(
        &mut self,
        doc_id: &str,
        version: u32,
        content_hash: &str,
        now: i64,
    ) -> &HashChainEntry {
        let previous_hash = self.entries.last().map(|e| e.entry_hash.clone());
        let entry_hash = compute_entry_hash(doc_id, version, content_hash, &previous_hash);
        self.entries.push(HashChainEntry {
            doc_id: doc_id.into(),
            version,
            content_hash: content_hash.into(),
            previous_hash,
            entry_hash,
            timestamp: now,
        });
        self.entries.last().unwrap()
    }

    pub fn verify_chain(&self) -> ChainVerification {
        if self.entries.is_empty() {
            return ChainVerification {
                valid: true,
                verified_links: 0,
                broken_at: None,
            };
        }

        for (i, entry) in self.entries.iter().enumerate() {
            // Verify previous_hash linkage
            if i == 0 {
                if entry.previous_hash.is_some() {
                    return ChainVerification {
                        valid: false,
                        verified_links: 0,
                        broken_at: Some(0),
                    };
                }
            } else {
                let expected_prev = &self.entries[i - 1].entry_hash;
                if entry.previous_hash.as_ref() != Some(expected_prev) {
                    return ChainVerification {
                        valid: false,
                        verified_links: i,
                        broken_at: Some(i),
                    };
                }
            }

            // Verify entry_hash is correctly computed
            let expected_hash = compute_entry_hash(
                &entry.doc_id,
                entry.version,
                &entry.content_hash,
                &entry.previous_hash,
            );
            if entry.entry_hash != expected_hash {
                return ChainVerification {
                    valid: false,
                    verified_links: i,
                    broken_at: Some(i),
                };
            }
        }

        ChainVerification {
            valid: true,
            verified_links: self.entries.len(),
            broken_at: None,
        }
    }

    pub fn chain_length(&self) -> usize {
        self.entries.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_document_content_produces_64_char_hex() {
        let hash = hash_document_content(b"hello world");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_document_content_deterministic() {
        let h1 = hash_document_content(b"test content");
        let h2 = hash_document_content(b"test content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_document_content_different_content() {
        let h1 = hash_document_content(b"content A");
        let h2 = hash_document_content(b"content B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_document_metadata_includes_all_fields() {
        let h1 = hash_document_metadata("doc1", "Title", 1, 1000);
        let h2 = hash_document_metadata("doc1", "Title", 1, 2000);
        assert_ne!(h1, h2); // different timestamp
        let h3 = hash_document_metadata("doc1", "Title", 2, 1000);
        assert_ne!(h1, h3); // different version
    }

    #[test]
    fn test_verify_document_hash_correct() {
        let content = b"important document";
        let hash = hash_document_content(content);
        assert!(verify_document_hash(content, &hash));
    }

    #[test]
    fn test_verify_document_hash_tampered() {
        let content = b"important document";
        let hash = hash_document_content(content);
        assert!(!verify_document_hash(b"tampered document", &hash));
    }

    #[test]
    fn test_integrity_store_record_and_verify() {
        let mut store = DocumentIntegrityStore::new();
        let content = b"document content";
        store.record_integrity("doc1", content, "Test Doc", 1, 1000);
        let verification = store.verify_integrity("doc1", 1, content);
        assert!(verification.record_found);
        assert!(verification.content_matches);
    }

    #[test]
    fn test_integrity_store_verify_mismatch() {
        let mut store = DocumentIntegrityStore::new();
        store.record_integrity("doc1", b"original", "Test", 1, 1000);
        let verification = store.verify_integrity("doc1", 1, b"modified");
        assert!(verification.record_found);
        assert!(!verification.content_matches);
    }

    #[test]
    fn test_integrity_store_history() {
        let mut store = DocumentIntegrityStore::new();
        store.record_integrity("doc1", b"v1", "Test", 1, 1000);
        store.record_integrity("doc1", b"v2", "Test", 2, 2000);
        let history = store.integrity_history("doc1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[1].version, 2);
    }

    #[test]
    fn test_hash_chain_append_creates_links() {
        let mut chain = DocumentHashChain::new();
        chain.append("doc1", 1, "hash1", 1000);
        chain.append("doc1", 2, "hash2", 2000);
        assert_eq!(chain.chain_length(), 2);
        assert!(chain.entries[0].previous_hash.is_none());
        assert!(chain.entries[1].previous_hash.is_some());
        assert_eq!(
            chain.entries[1].previous_hash.as_ref().unwrap(),
            &chain.entries[0].entry_hash
        );
    }

    #[test]
    fn test_hash_chain_verify_valid() {
        let mut chain = DocumentHashChain::new();
        chain.append("doc1", 1, "hash1", 1000);
        chain.append("doc1", 2, "hash2", 2000);
        chain.append("doc2", 1, "hash3", 3000);
        let verification = chain.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.verified_links, 3);
        assert!(verification.broken_at.is_none());
    }

    #[test]
    fn test_hash_chain_verify_tampered() {
        let mut chain = DocumentHashChain::new();
        chain.append("doc1", 1, "hash1", 1000);
        chain.append("doc1", 2, "hash2", 2000);
        // Tamper with the first entry's hash
        chain.entries[0].entry_hash = "tampered".into();
        let verification = chain.verify_chain();
        assert!(!verification.valid);
        assert!(verification.broken_at.is_some());
    }
}
