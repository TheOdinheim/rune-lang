// ═══════════════════════════════════════════════════════════════════════
// Document Backend — Trait for pluggable document storage with
// versioning, content blobs, and retention record management.
//
// StoredDocumentCategory is distinct from the L2 DocumentCategory
// (classification.rs).  L2's enum classifies sensitivity domains
// (PersonalData, HealthData, etc.); L3's enum classifies document
// functional purpose (Contract, Policy, Procedure, etc.).
//
// ClassificationLevel is distinct from the L2 SensitivityLevel
// (classification.rs).  L2's SensitivityLevel has Ord derivation for
// scoring; L3's ClassificationLevel is a storage-layer label.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::DocumentError;

// ── StoredDocumentCategory ─────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StoredDocumentCategory {
    Contract,
    Policy,
    Procedure,
    Report,
    Specification,
    Correspondence,
    EvidenceRecord,
    IncidentReport,
    Other,
}

impl fmt::Display for StoredDocumentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract => write!(f, "contract"),
            Self::Policy => write!(f, "policy"),
            Self::Procedure => write!(f, "procedure"),
            Self::Report => write!(f, "report"),
            Self::Specification => write!(f, "specification"),
            Self::Correspondence => write!(f, "correspondence"),
            Self::EvidenceRecord => write!(f, "evidence-record"),
            Self::IncidentReport => write!(f, "incident-report"),
            Self::Other => write!(f, "other"),
        }
    }
}

// ── ClassificationLevel ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClassificationLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

impl fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Internal => write!(f, "internal"),
            Self::Confidential => write!(f, "confidential"),
            Self::Restricted => write!(f, "restricted"),
            Self::TopSecret => write!(f, "top-secret"),
        }
    }
}

// ── StoredDocumentRecord ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentRecord {
    pub document_id: String,
    pub title: String,
    pub description: String,
    pub author: String,
    pub category: StoredDocumentCategory,
    pub classification_level: ClassificationLevel,
    pub current_version: String,
    pub created_at: i64,
    pub last_modified_at: i64,
    pub content_sha3_hash: String,
    pub metadata: HashMap<String, String>,
    pub attestation_refs: Vec<String>,
    pub retention_policy_ref: Option<String>,
}

// ── StoredDocumentVersion ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentVersion {
    pub version_id: String,
    pub document_id: String,
    pub version_number: String,
    pub content_blob_ref: String,
    pub content_sha3_hash: String,
    pub author: String,
    pub commit_message: String,
    pub created_at: i64,
    pub supersedes: Option<String>,
    pub metadata: HashMap<String, String>,
}

// ── StoredContentBlob ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContentBlob {
    pub blob_id: String,
    pub content_bytes: Vec<u8>,
    pub content_type: String,
    pub byte_length: usize,
    pub created_at: i64,
}

// ── StoredDocumentRetentionRecord ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentRetentionRecord {
    pub record_id: String,
    pub document_id: String,
    pub retention_policy_ref: String,
    pub linked_at: i64,
    pub expires_at: Option<i64>,
    pub disposed_at: Option<i64>,
    pub disposal_method: Option<String>,
    pub on_legal_hold: bool,
}

// ── DocumentBackendInfo ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentBackendInfo {
    pub backend_name: String,
    pub backend_version: String,
    pub document_count: usize,
    pub version_count: usize,
    pub blob_count: usize,
}

// ── DocumentBackend trait ──────────────────────────────────────

pub trait DocumentBackend {
    fn store_document(&mut self, record: StoredDocumentRecord) -> Result<(), DocumentError>;
    fn retrieve_document(&self, document_id: &str) -> Result<StoredDocumentRecord, DocumentError>;
    fn delete_document(&mut self, document_id: &str) -> Result<(), DocumentError>;
    fn list_documents_by_category(&self, category: &StoredDocumentCategory) -> Vec<StoredDocumentRecord>;
    fn list_documents_by_classification(&self, level: &ClassificationLevel) -> Vec<StoredDocumentRecord>;
    fn list_documents_by_author(&self, author: &str) -> Vec<StoredDocumentRecord>;
    fn search_documents_by_metadata(&self, key: &str, value: &str) -> Vec<StoredDocumentRecord>;
    fn document_count(&self) -> usize;

    fn store_document_version(&mut self, version: StoredDocumentVersion) -> Result<(), DocumentError>;
    fn retrieve_document_version(&self, version_id: &str) -> Result<StoredDocumentVersion, DocumentError>;
    fn list_versions_for_document(&self, document_id: &str) -> Vec<StoredDocumentVersion>;
    fn list_all_versions_for_document(&self, document_id: &str) -> Vec<StoredDocumentVersion>;

    fn store_content_blob(&mut self, blob: StoredContentBlob) -> Result<(), DocumentError>;
    fn retrieve_content_blob(&self, blob_id: &str) -> Result<StoredContentBlob, DocumentError>;
    fn delete_content_blob(&mut self, blob_id: &str) -> Result<(), DocumentError>;
    fn content_blob_size(&self, blob_id: &str) -> Result<usize, DocumentError>;

    fn store_retention_record(&mut self, record: StoredDocumentRetentionRecord) -> Result<(), DocumentError>;
    fn retrieve_retention_record(&self, record_id: &str) -> Result<StoredDocumentRetentionRecord, DocumentError>;
    fn list_retention_records_by_document(&self, document_id: &str) -> Vec<StoredDocumentRetentionRecord>;

    fn flush(&mut self) -> Result<(), DocumentError>;
    fn backend_info(&self) -> DocumentBackendInfo;
}

// ── InMemoryDocumentBackend ────────────────────────────────────

pub struct InMemoryDocumentBackend {
    documents: HashMap<String, StoredDocumentRecord>,
    versions: HashMap<String, StoredDocumentVersion>,
    blobs: HashMap<String, StoredContentBlob>,
    retention_records: HashMap<String, StoredDocumentRetentionRecord>,
}

impl InMemoryDocumentBackend {
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
            versions: HashMap::new(),
            blobs: HashMap::new(),
            retention_records: HashMap::new(),
        }
    }
}

impl Default for InMemoryDocumentBackend {
    fn default() -> Self { Self::new() }
}

impl DocumentBackend for InMemoryDocumentBackend {
    fn store_document(&mut self, record: StoredDocumentRecord) -> Result<(), DocumentError> {
        if self.documents.contains_key(&record.document_id) {
            return Err(DocumentError::DocumentAlreadyExists(record.document_id.clone()));
        }
        self.documents.insert(record.document_id.clone(), record);
        Ok(())
    }

    fn retrieve_document(&self, document_id: &str) -> Result<StoredDocumentRecord, DocumentError> {
        self.documents.get(document_id).cloned()
            .ok_or_else(|| DocumentError::DocumentNotFound(document_id.to_string()))
    }

    fn delete_document(&mut self, document_id: &str) -> Result<(), DocumentError> {
        self.documents.remove(document_id)
            .map(|_| ())
            .ok_or_else(|| DocumentError::DocumentNotFound(document_id.to_string()))
    }

    fn list_documents_by_category(&self, category: &StoredDocumentCategory) -> Vec<StoredDocumentRecord> {
        self.documents.values().filter(|d| &d.category == category).cloned().collect()
    }

    fn list_documents_by_classification(&self, level: &ClassificationLevel) -> Vec<StoredDocumentRecord> {
        self.documents.values().filter(|d| &d.classification_level == level).cloned().collect()
    }

    fn list_documents_by_author(&self, author: &str) -> Vec<StoredDocumentRecord> {
        self.documents.values().filter(|d| d.author == author).cloned().collect()
    }

    fn search_documents_by_metadata(&self, key: &str, value: &str) -> Vec<StoredDocumentRecord> {
        self.documents.values()
            .filter(|d| d.metadata.get(key).is_some_and(|v| v == value))
            .cloned().collect()
    }

    fn document_count(&self) -> usize { self.documents.len() }

    fn store_document_version(&mut self, version: StoredDocumentVersion) -> Result<(), DocumentError> {
        if self.versions.contains_key(&version.version_id) {
            return Err(DocumentError::DocumentAlreadyExists(version.version_id.clone()));
        }
        self.versions.insert(version.version_id.clone(), version);
        Ok(())
    }

    fn retrieve_document_version(&self, version_id: &str) -> Result<StoredDocumentVersion, DocumentError> {
        self.versions.get(version_id).cloned()
            .ok_or_else(|| DocumentError::VersionNotFound(version_id.to_string()))
    }

    fn list_versions_for_document(&self, document_id: &str) -> Vec<StoredDocumentVersion> {
        let mut versions: Vec<_> = self.versions.values()
            .filter(|v| v.document_id == document_id)
            .cloned().collect();
        versions.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        versions
    }

    fn list_all_versions_for_document(&self, document_id: &str) -> Vec<StoredDocumentVersion> {
        self.list_versions_for_document(document_id)
    }

    fn store_content_blob(&mut self, blob: StoredContentBlob) -> Result<(), DocumentError> {
        if self.blobs.contains_key(&blob.blob_id) {
            return Err(DocumentError::DocumentAlreadyExists(blob.blob_id.clone()));
        }
        self.blobs.insert(blob.blob_id.clone(), blob);
        Ok(())
    }

    fn retrieve_content_blob(&self, blob_id: &str) -> Result<StoredContentBlob, DocumentError> {
        self.blobs.get(blob_id).cloned()
            .ok_or_else(|| DocumentError::DocumentNotFound(blob_id.to_string()))
    }

    fn delete_content_blob(&mut self, blob_id: &str) -> Result<(), DocumentError> {
        self.blobs.remove(blob_id)
            .map(|_| ())
            .ok_or_else(|| DocumentError::DocumentNotFound(blob_id.to_string()))
    }

    fn content_blob_size(&self, blob_id: &str) -> Result<usize, DocumentError> {
        self.blobs.get(blob_id)
            .map(|b| b.byte_length)
            .ok_or_else(|| DocumentError::DocumentNotFound(blob_id.to_string()))
    }

    fn store_retention_record(&mut self, record: StoredDocumentRetentionRecord) -> Result<(), DocumentError> {
        if self.retention_records.contains_key(&record.record_id) {
            return Err(DocumentError::DocumentAlreadyExists(record.record_id.clone()));
        }
        self.retention_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_retention_record(&self, record_id: &str) -> Result<StoredDocumentRetentionRecord, DocumentError> {
        self.retention_records.get(record_id).cloned()
            .ok_or_else(|| DocumentError::DocumentNotFound(record_id.to_string()))
    }

    fn list_retention_records_by_document(&self, document_id: &str) -> Vec<StoredDocumentRetentionRecord> {
        self.retention_records.values()
            .filter(|r| r.document_id == document_id)
            .cloned().collect()
    }

    fn flush(&mut self) -> Result<(), DocumentError> {
        self.documents.clear();
        self.versions.clear();
        self.blobs.clear();
        self.retention_records.clear();
        Ok(())
    }

    fn backend_info(&self) -> DocumentBackendInfo {
        DocumentBackendInfo {
            backend_name: "in-memory".to_string(),
            backend_version: "1.0.0".to_string(),
            document_count: self.documents.len(),
            version_count: self.versions.len(),
            blob_count: self.blobs.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc(id: &str) -> StoredDocumentRecord {
        StoredDocumentRecord {
            document_id: id.to_string(),
            title: "Test Document".to_string(),
            description: "A test document".to_string(),
            author: "alice".to_string(),
            category: StoredDocumentCategory::Report,
            classification_level: ClassificationLevel::Internal,
            current_version: "1".to_string(),
            created_at: 1000,
            last_modified_at: 1000,
            content_sha3_hash: "abc123".to_string(),
            metadata: HashMap::from([("dept".into(), "engineering".into())]),
            attestation_refs: vec!["att-1".into()],
            retention_policy_ref: Some("rp-1".into()),
        }
    }

    #[test]
    fn test_category_display() {
        assert_eq!(StoredDocumentCategory::Contract.to_string(), "contract");
        assert_eq!(StoredDocumentCategory::EvidenceRecord.to_string(), "evidence-record");
        assert_eq!(StoredDocumentCategory::IncidentReport.to_string(), "incident-report");
    }

    #[test]
    fn test_classification_level_display() {
        assert_eq!(ClassificationLevel::Public.to_string(), "public");
        assert_eq!(ClassificationLevel::Restricted.to_string(), "restricted");
        assert_eq!(ClassificationLevel::TopSecret.to_string(), "top-secret");
    }

    #[test]
    fn test_store_and_retrieve_document() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        let doc = backend.retrieve_document("d1").unwrap();
        assert_eq!(doc.title, "Test Document");
        assert_eq!(backend.document_count(), 1);
    }

    #[test]
    fn test_store_duplicate_document() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        assert!(backend.store_document(sample_doc("d1")).is_err());
    }

    #[test]
    fn test_delete_document() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        backend.delete_document("d1").unwrap();
        assert!(backend.retrieve_document("d1").is_err());
    }

    #[test]
    fn test_list_by_category() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        let mut doc2 = sample_doc("d2");
        doc2.category = StoredDocumentCategory::Contract;
        backend.store_document(doc2).unwrap();
        assert_eq!(backend.list_documents_by_category(&StoredDocumentCategory::Report).len(), 1);
    }

    #[test]
    fn test_list_by_classification() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        assert_eq!(backend.list_documents_by_classification(&ClassificationLevel::Internal).len(), 1);
        assert_eq!(backend.list_documents_by_classification(&ClassificationLevel::Public).len(), 0);
    }

    #[test]
    fn test_list_by_author() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        assert_eq!(backend.list_documents_by_author("alice").len(), 1);
        assert_eq!(backend.list_documents_by_author("bob").len(), 0);
    }

    #[test]
    fn test_search_by_metadata() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        assert_eq!(backend.search_documents_by_metadata("dept", "engineering").len(), 1);
        assert_eq!(backend.search_documents_by_metadata("dept", "sales").len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_version() {
        let mut backend = InMemoryDocumentBackend::new();
        let version = StoredDocumentVersion {
            version_id: "v1".to_string(),
            document_id: "d1".to_string(),
            version_number: "1".to_string(),
            content_blob_ref: "blob-1".to_string(),
            content_sha3_hash: "hash".to_string(),
            author: "alice".to_string(),
            commit_message: "initial".to_string(),
            created_at: 1000,
            supersedes: None,
            metadata: HashMap::new(),
        };
        backend.store_document_version(version).unwrap();
        let retrieved = backend.retrieve_document_version("v1").unwrap();
        assert_eq!(retrieved.commit_message, "initial");
    }

    #[test]
    fn test_list_versions_for_document() {
        let mut backend = InMemoryDocumentBackend::new();
        for i in 0..3 {
            backend.store_document_version(StoredDocumentVersion {
                version_id: format!("v{i}"),
                document_id: "d1".to_string(),
                version_number: format!("{i}"),
                content_blob_ref: format!("blob-{i}"),
                content_sha3_hash: "hash".to_string(),
                author: "alice".to_string(),
                commit_message: format!("version {i}"),
                created_at: 1000 + i,
                supersedes: None,
                metadata: HashMap::new(),
            }).unwrap();
        }
        assert_eq!(backend.list_versions_for_document("d1").len(), 3);
    }

    #[test]
    fn test_store_and_retrieve_blob() {
        let mut backend = InMemoryDocumentBackend::new();
        let blob = StoredContentBlob {
            blob_id: "b1".to_string(),
            content_bytes: b"hello world".to_vec(),
            content_type: "text/plain".to_string(),
            byte_length: 11,
            created_at: 1000,
        };
        backend.store_content_blob(blob).unwrap();
        let retrieved = backend.retrieve_content_blob("b1").unwrap();
        assert_eq!(retrieved.byte_length, 11);
        assert_eq!(backend.content_blob_size("b1").unwrap(), 11);
    }

    #[test]
    fn test_delete_blob() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_content_blob(StoredContentBlob {
            blob_id: "b1".into(), content_bytes: vec![], content_type: "text/plain".into(),
            byte_length: 0, created_at: 1000,
        }).unwrap();
        backend.delete_content_blob("b1").unwrap();
        assert!(backend.retrieve_content_blob("b1").is_err());
    }

    #[test]
    fn test_store_and_retrieve_retention_record() {
        let mut backend = InMemoryDocumentBackend::new();
        let record = StoredDocumentRetentionRecord {
            record_id: "r1".into(), document_id: "d1".into(),
            retention_policy_ref: "rp-1".into(), linked_at: 1000,
            expires_at: Some(2000), disposed_at: None,
            disposal_method: None, on_legal_hold: false,
        };
        backend.store_retention_record(record).unwrap();
        let retrieved = backend.retrieve_retention_record("r1").unwrap();
        assert_eq!(retrieved.document_id, "d1");
    }

    #[test]
    fn test_list_retention_records_by_document() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_retention_record(StoredDocumentRetentionRecord {
            record_id: "r1".into(), document_id: "d1".into(),
            retention_policy_ref: "rp-1".into(), linked_at: 1000,
            expires_at: None, disposed_at: None, disposal_method: None, on_legal_hold: false,
        }).unwrap();
        backend.store_retention_record(StoredDocumentRetentionRecord {
            record_id: "r2".into(), document_id: "d2".into(),
            retention_policy_ref: "rp-1".into(), linked_at: 1000,
            expires_at: None, disposed_at: None, disposal_method: None, on_legal_hold: false,
        }).unwrap();
        assert_eq!(backend.list_retention_records_by_document("d1").len(), 1);
    }

    #[test]
    fn test_flush_and_backend_info() {
        let mut backend = InMemoryDocumentBackend::new();
        backend.store_document(sample_doc("d1")).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.document_count, 1);
        assert_eq!(info.backend_name, "in-memory");
        backend.flush().unwrap();
        assert_eq!(backend.document_count(), 0);
    }
}
