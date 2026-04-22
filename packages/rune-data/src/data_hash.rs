// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Dataset and schema integrity hashing. SHA3-256
// fingerprinting for governed dataset identity, schema records,
// and lineage records. DataHashChain for append-only integrity
// tracking of the data catalog over time.
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

use crate::lineage::LineageRecord;
use crate::schema::SchemaRecord;

// ── Hash functions ───────────────────────────────────────────────────

pub fn hash_dataset_ref(
    dataset_ref: &str,
    schema_version: &str,
    classification_sensitivity: &str,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(dataset_ref.as_bytes());
    hasher.update(b":");
    hasher.update(schema_version.as_bytes());
    hasher.update(b":");
    hasher.update(classification_sensitivity.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_schema_record(record: &SchemaRecord) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(record.schema_id.as_bytes());
    hasher.update(b":");
    hasher.update(record.dataset_ref.as_bytes());
    hasher.update(b":");
    hasher.update(record.version.as_bytes());
    hasher.update(b":");
    hasher.update(record.format.to_string().as_bytes());
    hasher.update(b":");
    let mut field_parts: Vec<String> = record
        .fields
        .iter()
        .map(|f| format!("{}:{}", f.field_name, f.field_type))
        .collect();
    field_parts.sort();
    hasher.update(field_parts.join(",").as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_lineage_record(record: &LineageRecord) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(record.record_id.as_bytes());
    hasher.update(b":");
    hasher.update(record.dataset_ref.as_bytes());
    hasher.update(b":");
    hasher.update(record.stage.to_string().as_bytes());
    hasher.update(b":");
    let mut preds = record.predecessor_refs.clone();
    preds.sort();
    hasher.update(preds.join(",").as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_hash(content: &str, expected_hash: &str) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(content.as_bytes());
    let computed = hex::encode(hasher.finalize());
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

// ── DataHashChain ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHashChainLink {
    pub content_hash: String,
    pub previous_hash: String,
    pub chain_hash: String,
    pub index: usize,
}

pub struct DataHashChain {
    links: Vec<DataHashChainLink>,
}

impl DataHashChain {
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    pub fn append(&mut self, content_hash: &str) {
        let previous_hash = if let Some(last) = self.links.last() {
            last.chain_hash.clone()
        } else {
            "0".repeat(64)
        };
        let mut hasher = Sha3_256::new();
        hasher.update(content_hash.as_bytes());
        hasher.update(b":");
        hasher.update(previous_hash.as_bytes());
        let chain_hash = hex::encode(hasher.finalize());
        let index = self.links.len();
        self.links.push(DataHashChainLink {
            content_hash: content_hash.to_string(),
            previous_hash,
            chain_hash,
            index,
        });
    }

    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = "0".repeat(64);
        for link in &self.links {
            if link.previous_hash != expected_prev {
                return false;
            }
            let mut hasher = Sha3_256::new();
            hasher.update(link.content_hash.as_bytes());
            hasher.update(b":");
            hasher.update(link.previous_hash.as_bytes());
            let computed = hex::encode(hasher.finalize());
            if !constant_time_eq(computed.as_bytes(), link.chain_hash.as_bytes()) {
                return false;
            }
            expected_prev = link.chain_hash.clone();
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

impl Default for DataHashChain {
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
    use crate::lineage::LineageStage;
    use crate::schema::{SchemaField, SchemaFormat};
    use std::collections::HashMap;

    #[test]
    fn test_hash_dataset_ref_deterministic() {
        let h1 = hash_dataset_ref("ds-users", "1.0.0", "Restricted");
        let h2 = hash_dataset_ref("ds-users", "1.0.0", "Restricted");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_dataset_ref_different_inputs() {
        let h1 = hash_dataset_ref("ds-users", "1.0.0", "Restricted");
        let h2 = hash_dataset_ref("ds-users", "2.0.0", "Restricted");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_schema_record() {
        let record = SchemaRecord {
            schema_id: "sch-1".into(),
            dataset_ref: "ds-users".into(),
            version: "1.0.0".into(),
            fields: vec![
                SchemaField {
                    field_name: "id".into(),
                    field_type: "string".into(),
                    nullable: false,
                    description: None,
                    sensitivity_label: None,
                    constraints: Vec::new(),
                },
                SchemaField {
                    field_name: "email".into(),
                    field_type: "string".into(),
                    nullable: true,
                    description: None,
                    sensitivity_label: None,
                    constraints: Vec::new(),
                },
            ],
            format: SchemaFormat::JsonSchema,
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
        };
        let hash = hash_schema_record(&record);
        assert_eq!(hash.len(), 64);
        let hash2 = hash_schema_record(&record);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_schema_record_field_order_independent() {
        let record1 = SchemaRecord {
            schema_id: "sch-1".into(),
            dataset_ref: "ds-1".into(),
            version: "1.0.0".into(),
            fields: vec![
                SchemaField { field_name: "a".into(), field_type: "string".into(), nullable: false, description: None, sensitivity_label: None, constraints: Vec::new() },
                SchemaField { field_name: "b".into(), field_type: "int64".into(), nullable: false, description: None, sensitivity_label: None, constraints: Vec::new() },
            ],
            format: SchemaFormat::Avro,
            registered_at: 1000,
            registered_by: "admin".into(),
            metadata: HashMap::new(),
        };
        let record2 = SchemaRecord {
            schema_id: "sch-1".into(),
            dataset_ref: "ds-1".into(),
            version: "1.0.0".into(),
            fields: vec![
                SchemaField { field_name: "b".into(), field_type: "int64".into(), nullable: false, description: None, sensitivity_label: None, constraints: Vec::new() },
                SchemaField { field_name: "a".into(), field_type: "string".into(), nullable: false, description: None, sensitivity_label: None, constraints: Vec::new() },
            ],
            format: SchemaFormat::Avro,
            registered_at: 2000,
            registered_by: "other".into(),
            metadata: HashMap::new(),
        };
        assert_eq!(hash_schema_record(&record1), hash_schema_record(&record2));
    }

    #[test]
    fn test_hash_lineage_record() {
        let record = LineageRecord {
            record_id: "lr-1".into(),
            dataset_ref: "ds-orders".into(),
            stage: LineageStage::Transform { operation: "agg".into(), input_refs: vec!["lr-0".into()] },
            predecessor_refs: vec!["lr-0".into()],
            successor_refs: Vec::new(),
            transformation_metadata: HashMap::new(),
            attestation_ref: None,
            recorded_at: 1000,
            recorded_by: "agent".into(),
            metadata: HashMap::new(),
        };
        let hash = hash_lineage_record(&record);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_verify_hash_valid() {
        let content = "test-content";
        let mut hasher = Sha3_256::new();
        hasher.update(content.as_bytes());
        let expected = hex::encode(hasher.finalize());
        assert!(verify_hash(content, &expected));
    }

    #[test]
    fn test_verify_hash_invalid() {
        assert!(!verify_hash("content", "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_verify_hash_different_length() {
        assert!(!verify_hash("content", "short"));
    }

    #[test]
    fn test_hash_chain_append_and_verify() {
        let mut chain = DataHashChain::new();
        chain.append("hash-a");
        chain.append("hash-b");
        chain.append("hash-c");
        assert_eq!(chain.chain_length(), 3);
        assert!(chain.verify_chain());
        assert!(chain.latest_hash().is_some());
    }

    #[test]
    fn test_hash_chain_empty() {
        let chain = DataHashChain::new();
        assert_eq!(chain.chain_length(), 0);
        assert!(chain.verify_chain());
        assert!(chain.latest_hash().is_none());
    }

    #[test]
    fn test_hash_chain_tamper_detection() {
        let mut chain = DataHashChain::new();
        chain.append("hash-a");
        chain.append("hash-b");
        assert!(chain.verify_chain());
        chain.links[0].content_hash = "tampered".into();
        assert!(!chain.verify_chain());
    }

    #[test]
    fn test_hash_chain_default() {
        let chain = DataHashChain::default();
        assert_eq!(chain.chain_length(), 0);
    }

    #[test]
    fn test_hash_chain_genesis_previous_hash() {
        let mut chain = DataHashChain::new();
        chain.append("first");
        assert_eq!(chain.links[0].previous_hash, "0".repeat(64));
        assert_eq!(chain.links[0].index, 0);
    }
}
