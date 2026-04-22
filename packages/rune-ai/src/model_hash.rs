// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Model and dataset integrity hashing via SHA3-256.
// Provides deterministic fingerprinting of model records, dataset
// records, constant-time hash verification, and an append-only
// hash chain for model registry integrity tracking.
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

use crate::model_registry::ModelRecord;
use crate::training_data::DatasetRecord;

// ── Hashing functions ───────────────────────────────────────────────

pub fn hash_model_record(record: &ModelRecord) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(record.model_id.as_bytes());
    hasher.update(b":");
    hasher.update(record.model_name.as_bytes());
    hasher.update(b":");
    hasher.update(record.model_version.as_bytes());
    hasher.update(b":");
    hasher.update(record.architecture.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(record.task_type.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(record.framework.as_bytes());
    hasher.update(b":");
    hasher.update(record.created_by.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_dataset_record(record: &DatasetRecord) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(record.dataset_id.as_bytes());
    hasher.update(b":");
    hasher.update(record.dataset_name.as_bytes());
    hasher.update(b":");
    hasher.update(record.version.as_bytes());
    hasher.update(b":");
    hasher.update(record.source.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(record.format.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(record.created_by.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_model_hash(record: &ModelRecord, expected_hash: &str) -> bool {
    let computed = hash_model_record(record);
    constant_time_eq(computed.as_bytes(), expected_hash.as_bytes())
}

pub fn verify_dataset_hash(record: &DatasetRecord, expected_hash: &str) -> bool {
    let computed = hash_dataset_record(record);
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

// ── ModelHashChain ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelHashChainLink {
    pub content_hash: String,
    pub previous_hash: String,
    pub chain_hash: String,
    pub index: usize,
}

pub struct ModelHashChain {
    links: Vec<ModelHashChainLink>,
}

impl ModelHashChain {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    pub fn append(&mut self, record: &ModelRecord) -> ModelHashChainLink {
        let content_hash = hash_model_record(record);
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
        let link = ModelHashChainLink {
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
}

impl Default for ModelHashChain {
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
    use crate::model_registry::{ModelArchitecture, ModelTaskType};
    use crate::training_data::{DatasetFormat, DatasetSource};

    fn make_model(id: &str, name: &str, version: &str) -> ModelRecord {
        ModelRecord::new(
            id, name, version,
            ModelArchitecture::Transformer,
            ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        )
    }

    fn make_dataset(id: &str, name: &str) -> DatasetRecord {
        DatasetRecord::new(
            id, name, "1.0",
            DatasetSource::Public { url: "https://example.com".into() },
            DatasetFormat::Csv,
            1000, "alice",
        )
    }

    #[test]
    fn test_hash_model_record_deterministic() {
        let record = make_model("m1", "GPT", "1.0");
        let h1 = hash_model_record(&record);
        let h2 = hash_model_record(&record);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_model_record_differs_by_id() {
        let r1 = make_model("m1", "GPT", "1.0");
        let r2 = make_model("m2", "GPT", "1.0");
        assert_ne!(hash_model_record(&r1), hash_model_record(&r2));
    }

    #[test]
    fn test_hash_model_record_differs_by_version() {
        let r1 = make_model("m1", "GPT", "1.0");
        let r2 = make_model("m1", "GPT", "2.0");
        assert_ne!(hash_model_record(&r1), hash_model_record(&r2));
    }

    #[test]
    fn test_hash_model_record_differs_by_name() {
        let r1 = make_model("m1", "GPT", "1.0");
        let r2 = make_model("m1", "BERT", "1.0");
        assert_ne!(hash_model_record(&r1), hash_model_record(&r2));
    }

    #[test]
    fn test_hash_model_record_differs_by_architecture() {
        let r1 = make_model("m1", "GPT", "1.0");
        let mut r2 = make_model("m1", "GPT", "1.0");
        r2.architecture = ModelArchitecture::Cnn;
        assert_ne!(hash_model_record(&r1), hash_model_record(&r2));
    }

    #[test]
    fn test_hash_dataset_record_deterministic() {
        let record = make_dataset("ds1", "ImageNet");
        let h1 = hash_dataset_record(&record);
        let h2 = hash_dataset_record(&record);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_dataset_record_differs_by_id() {
        let r1 = make_dataset("ds1", "ImageNet");
        let r2 = make_dataset("ds2", "ImageNet");
        assert_ne!(hash_dataset_record(&r1), hash_dataset_record(&r2));
    }

    #[test]
    fn test_hash_dataset_record_differs_by_format() {
        let r1 = make_dataset("ds1", "ImageNet");
        let mut r2 = make_dataset("ds1", "ImageNet");
        r2.format = DatasetFormat::Parquet;
        assert_ne!(hash_dataset_record(&r1), hash_dataset_record(&r2));
    }

    #[test]
    fn test_verify_model_hash_valid() {
        let record = make_model("m1", "GPT", "1.0");
        let hash = hash_model_record(&record);
        assert!(verify_model_hash(&record, &hash));
    }

    #[test]
    fn test_verify_model_hash_invalid() {
        let record = make_model("m1", "GPT", "1.0");
        let bad_hash = "0".repeat(64);
        assert!(!verify_model_hash(&record, &bad_hash));
    }

    #[test]
    fn test_verify_model_hash_wrong_length() {
        let record = make_model("m1", "GPT", "1.0");
        assert!(!verify_model_hash(&record, "abc"));
    }

    #[test]
    fn test_verify_dataset_hash_valid() {
        let record = make_dataset("ds1", "COCO");
        let hash = hash_dataset_record(&record);
        assert!(verify_dataset_hash(&record, &hash));
    }

    #[test]
    fn test_verify_dataset_hash_invalid() {
        let record = make_dataset("ds1", "COCO");
        assert!(!verify_dataset_hash(&record, &"f".repeat(64)));
    }

    #[test]
    fn test_chain_empty() {
        let chain = ModelHashChain::new();
        assert_eq!(chain.chain_length(), 0);
        assert!(chain.latest_hash().is_none());
        assert!(chain.verify_chain());
    }

    #[test]
    fn test_chain_append_single() {
        let mut chain = ModelHashChain::new();
        let record = make_model("m1", "GPT", "1.0");
        let link = chain.append(&record);
        assert_eq!(link.index, 0);
        assert_eq!(link.previous_hash, "0".repeat(64));
        assert_eq!(chain.chain_length(), 1);
        assert!(chain.latest_hash().is_some());
    }

    #[test]
    fn test_chain_multiple_appends() {
        let mut chain = ModelHashChain::new();
        chain.append(&make_model("m1", "GPT", "1.0"));
        chain.append(&make_model("m2", "BERT", "1.0"));
        chain.append(&make_model("m3", "T5", "1.0"));
        assert_eq!(chain.chain_length(), 3);
        assert!(chain.verify_chain());
    }

    #[test]
    fn test_chain_links_connected() {
        let mut chain = ModelHashChain::new();
        let l1 = chain.append(&make_model("m1", "GPT", "1.0"));
        let l2 = chain.append(&make_model("m2", "BERT", "1.0"));
        assert_eq!(l2.previous_hash, l1.chain_hash);
    }

    #[test]
    fn test_chain_tamper_detection() {
        let mut chain = ModelHashChain::new();
        chain.append(&make_model("m1", "GPT", "1.0"));
        chain.append(&make_model("m2", "BERT", "1.0"));
        chain.append(&make_model("m3", "T5", "1.0"));
        assert!(chain.verify_chain());
        chain.links[1].content_hash = "tampered".into();
        assert!(!chain.verify_chain());
    }

    #[test]
    fn test_chain_default() {
        let chain = ModelHashChain::default();
        assert_eq!(chain.chain_length(), 0);
    }
}
