// ═══════════════════════════════════════════════════════════════════════
// Privacy Backend — Pluggable storage for privacy artifacts.
//
// Layer 3 defines the storage contract for PII classifications, data
// subject records, data subject requests, processing records, and
// retention policy definitions. ConsentStore is a separate trait
// (consent_store.rs) because consent has a distinct lifecycle and
// hot-path access pattern.
//
// SubjectRef is a thin newtype decoupling from rune-identity's
// IdentityId, following the IdentityRef pattern from rune-permissions.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::PrivacyError;
use crate::pii::PiiCategory;
use crate::purpose::LegalBasis;

// ── SubjectRef ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectRef(String);

impl SubjectRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<rune_identity::IdentityId> for SubjectRef {
    fn from(id: rune_identity::IdentityId) -> Self {
        Self(id.to_string())
    }
}

// ── StoredPiiClassification ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPiiClassification {
    pub classification_id: String,
    pub field_name: String,
    pub category: PiiCategory,
    pub confidence: String,
    pub classifier_id: String,
    pub classified_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── StoredDataSubjectRecord ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredDataSubjectRecord {
    pub subject_ref: SubjectRef,
    pub display_name: String,
    pub jurisdiction: String,
    pub registered_at: i64,
    pub metadata: HashMap<String, String>,
}

// ── RequestType ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestType {
    Access,
    Rectification,
    Erasure,
    Portability,
    Restriction,
    Objection,
}

impl fmt::Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── StoredDataSubjectRequest ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredDataSubjectRequest {
    pub request_id: String,
    pub subject_ref: SubjectRef,
    pub request_type: RequestType,
    pub submitted_at: i64,
    pub deadline_at: i64,
    pub status: String,
    pub completed_at: Option<i64>,
    pub notes: Vec<String>,
}

// ── StoredProcessingRecord ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredProcessingRecord {
    pub record_id: String,
    pub subject_ref: SubjectRef,
    pub purpose: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<String>,
    pub processors: Vec<String>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

// ── StoredRetentionPolicyDefinition ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredRetentionPolicyDefinition {
    pub policy_id: String,
    pub name: String,
    pub applies_to: String,
    pub minimum_retention_days: u64,
    pub maximum_retention_days: u64,
    pub deletion_strategy: DeletionStrategy,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionStrategy {
    Soft,
    Hard,
    Anonymize,
}

impl fmt::Display for DeletionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── PrivacyBackendInfo ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PrivacyBackendInfo {
    pub backend_name: String,
    pub classification_count: usize,
    pub subject_count: usize,
    pub request_count: usize,
    pub processing_record_count: usize,
    pub retention_policy_count: usize,
}

// ── PrivacyBackend trait ────────────────────────────────────────────

pub trait PrivacyBackend {
    fn store_pii_classification(&mut self, classification: StoredPiiClassification) -> Result<(), PrivacyError>;
    fn retrieve_pii_classification(&self, classification_id: &str) -> Result<Option<StoredPiiClassification>, PrivacyError>;
    fn list_pii_classifications(&self) -> Result<Vec<StoredPiiClassification>, PrivacyError>;

    fn store_data_subject_record(&mut self, record: StoredDataSubjectRecord) -> Result<(), PrivacyError>;
    fn retrieve_data_subject_record(&self, subject_ref: &SubjectRef) -> Result<Option<StoredDataSubjectRecord>, PrivacyError>;
    fn list_data_subject_records(&self) -> Result<Vec<StoredDataSubjectRecord>, PrivacyError>;

    fn store_data_subject_request(&mut self, request: StoredDataSubjectRequest) -> Result<(), PrivacyError>;
    fn retrieve_data_subject_request(&self, request_id: &str) -> Result<Option<StoredDataSubjectRequest>, PrivacyError>;
    fn list_data_subject_requests_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<StoredDataSubjectRequest>, PrivacyError>;
    fn update_data_subject_request_status(&mut self, request_id: &str, status: &str, completed_at: Option<i64>) -> Result<(), PrivacyError>;

    fn store_processing_record(&mut self, record: StoredProcessingRecord) -> Result<(), PrivacyError>;
    fn retrieve_processing_record(&self, record_id: &str) -> Result<Option<StoredProcessingRecord>, PrivacyError>;
    fn list_processing_records_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<StoredProcessingRecord>, PrivacyError>;

    fn store_retention_policy_definition(&mut self, policy: StoredRetentionPolicyDefinition) -> Result<(), PrivacyError>;
    fn retrieve_retention_policy_definition(&self, policy_id: &str) -> Result<Option<StoredRetentionPolicyDefinition>, PrivacyError>;
    fn list_retention_policy_definitions(&self) -> Result<Vec<StoredRetentionPolicyDefinition>, PrivacyError>;

    fn flush(&mut self) -> Result<(), PrivacyError>;
    fn backend_info(&self) -> PrivacyBackendInfo;
}

// ── InMemoryPrivacyBackend ──────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryPrivacyBackend {
    classifications: HashMap<String, StoredPiiClassification>,
    subjects: HashMap<String, StoredDataSubjectRecord>,
    requests: HashMap<String, StoredDataSubjectRequest>,
    processing_records: HashMap<String, StoredProcessingRecord>,
    retention_policies: HashMap<String, StoredRetentionPolicyDefinition>,
}

impl InMemoryPrivacyBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PrivacyBackend for InMemoryPrivacyBackend {
    fn store_pii_classification(&mut self, c: StoredPiiClassification) -> Result<(), PrivacyError> {
        if self.classifications.contains_key(&c.classification_id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "classification {} already exists", c.classification_id
            )));
        }
        self.classifications.insert(c.classification_id.clone(), c);
        Ok(())
    }

    fn retrieve_pii_classification(&self, id: &str) -> Result<Option<StoredPiiClassification>, PrivacyError> {
        Ok(self.classifications.get(id).cloned())
    }

    fn list_pii_classifications(&self) -> Result<Vec<StoredPiiClassification>, PrivacyError> {
        Ok(self.classifications.values().cloned().collect())
    }

    fn store_data_subject_record(&mut self, record: StoredDataSubjectRecord) -> Result<(), PrivacyError> {
        let key = record.subject_ref.as_str().to_string();
        self.subjects.insert(key, record);
        Ok(())
    }

    fn retrieve_data_subject_record(&self, subject_ref: &SubjectRef) -> Result<Option<StoredDataSubjectRecord>, PrivacyError> {
        Ok(self.subjects.get(subject_ref.as_str()).cloned())
    }

    fn list_data_subject_records(&self) -> Result<Vec<StoredDataSubjectRecord>, PrivacyError> {
        Ok(self.subjects.values().cloned().collect())
    }

    fn store_data_subject_request(&mut self, request: StoredDataSubjectRequest) -> Result<(), PrivacyError> {
        if self.requests.contains_key(&request.request_id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "request {} already exists", request.request_id
            )));
        }
        self.requests.insert(request.request_id.clone(), request);
        Ok(())
    }

    fn retrieve_data_subject_request(&self, request_id: &str) -> Result<Option<StoredDataSubjectRequest>, PrivacyError> {
        Ok(self.requests.get(request_id).cloned())
    }

    fn list_data_subject_requests_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<StoredDataSubjectRequest>, PrivacyError> {
        Ok(self.requests.values()
            .filter(|r| r.subject_ref == *subject_ref)
            .cloned()
            .collect())
    }

    fn update_data_subject_request_status(&mut self, request_id: &str, status: &str, completed_at: Option<i64>) -> Result<(), PrivacyError> {
        let req = self.requests.get_mut(request_id)
            .ok_or_else(|| PrivacyError::RightsRequestNotFound(request_id.to_string()))?;
        req.status = status.to_string();
        if let Some(ts) = completed_at {
            req.completed_at = Some(ts);
        }
        Ok(())
    }

    fn store_processing_record(&mut self, record: StoredProcessingRecord) -> Result<(), PrivacyError> {
        if self.processing_records.contains_key(&record.record_id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "processing record {} already exists", record.record_id
            )));
        }
        self.processing_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn retrieve_processing_record(&self, record_id: &str) -> Result<Option<StoredProcessingRecord>, PrivacyError> {
        Ok(self.processing_records.get(record_id).cloned())
    }

    fn list_processing_records_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<StoredProcessingRecord>, PrivacyError> {
        Ok(self.processing_records.values()
            .filter(|r| r.subject_ref == *subject_ref)
            .cloned()
            .collect())
    }

    fn store_retention_policy_definition(&mut self, policy: StoredRetentionPolicyDefinition) -> Result<(), PrivacyError> {
        if self.retention_policies.contains_key(&policy.policy_id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "retention policy {} already exists", policy.policy_id
            )));
        }
        self.retention_policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn retrieve_retention_policy_definition(&self, policy_id: &str) -> Result<Option<StoredRetentionPolicyDefinition>, PrivacyError> {
        Ok(self.retention_policies.get(policy_id).cloned())
    }

    fn list_retention_policy_definitions(&self) -> Result<Vec<StoredRetentionPolicyDefinition>, PrivacyError> {
        Ok(self.retention_policies.values().cloned().collect())
    }

    fn flush(&mut self) -> Result<(), PrivacyError> {
        self.classifications.clear();
        self.subjects.clear();
        self.requests.clear();
        self.processing_records.clear();
        self.retention_policies.clear();
        Ok(())
    }

    fn backend_info(&self) -> PrivacyBackendInfo {
        PrivacyBackendInfo {
            backend_name: "InMemoryPrivacyBackend".to_string(),
            classification_count: self.classifications.len(),
            subject_count: self.subjects.len(),
            request_count: self.requests.len(),
            processing_record_count: self.processing_records.len(),
            retention_policy_count: self.retention_policies.len(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_classification(id: &str) -> StoredPiiClassification {
        StoredPiiClassification {
            classification_id: id.to_string(),
            field_name: "email".to_string(),
            category: PiiCategory::Email,
            confidence: "0.95".to_string(),
            classifier_id: "regex-1".to_string(),
            classified_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_subject(id: &str) -> StoredDataSubjectRecord {
        StoredDataSubjectRecord {
            subject_ref: SubjectRef::new(id),
            display_name: "Alice".to_string(),
            jurisdiction: "EU".to_string(),
            registered_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn make_request(id: &str, subject: &str) -> StoredDataSubjectRequest {
        StoredDataSubjectRequest {
            request_id: id.to_string(),
            subject_ref: SubjectRef::new(subject),
            request_type: RequestType::Access,
            submitted_at: 1000,
            deadline_at: 5000,
            status: "Received".to_string(),
            completed_at: None,
            notes: Vec::new(),
        }
    }

    fn make_processing_record(id: &str, subject: &str) -> StoredProcessingRecord {
        StoredProcessingRecord {
            record_id: id.to_string(),
            subject_ref: SubjectRef::new(subject),
            purpose: "analytics".to_string(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec!["email".to_string()],
            processors: vec!["internal".to_string()],
            started_at: 1000,
            ended_at: None,
        }
    }

    fn make_retention_policy(id: &str) -> StoredRetentionPolicyDefinition {
        StoredRetentionPolicyDefinition {
            policy_id: id.to_string(),
            name: "Test Policy".to_string(),
            applies_to: "email".to_string(),
            minimum_retention_days: 30,
            maximum_retention_days: 365,
            deletion_strategy: DeletionStrategy::Anonymize,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_subject_ref_from_identity_id() {
        let id = rune_identity::IdentityId::new("alice");
        let sr = SubjectRef::from(id);
        assert_eq!(sr.as_str(), "alice");
    }

    #[test]
    fn test_store_and_retrieve_classification() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_pii_classification(make_classification("c1")).unwrap();
        let c = backend.retrieve_pii_classification("c1").unwrap().unwrap();
        assert_eq!(c.classification_id, "c1");
    }

    #[test]
    fn test_duplicate_classification_rejected() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_pii_classification(make_classification("c1")).unwrap();
        assert!(backend.store_pii_classification(make_classification("c1")).is_err());
    }

    #[test]
    fn test_store_and_retrieve_subject() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_data_subject_record(make_subject("alice")).unwrap();
        let s = backend.retrieve_data_subject_record(&SubjectRef::new("alice")).unwrap().unwrap();
        assert_eq!(s.display_name, "Alice");
    }

    #[test]
    fn test_store_and_list_requests() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_data_subject_request(make_request("r1", "alice")).unwrap();
        backend.store_data_subject_request(make_request("r2", "alice")).unwrap();
        backend.store_data_subject_request(make_request("r3", "bob")).unwrap();
        let alice_reqs = backend.list_data_subject_requests_for_subject(&SubjectRef::new("alice")).unwrap();
        assert_eq!(alice_reqs.len(), 2);
    }

    #[test]
    fn test_update_request_status() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_data_subject_request(make_request("r1", "alice")).unwrap();
        backend.update_data_subject_request_status("r1", "Completed", Some(5000)).unwrap();
        let r = backend.retrieve_data_subject_request("r1").unwrap().unwrap();
        assert_eq!(r.status, "Completed");
        assert_eq!(r.completed_at, Some(5000));
    }

    #[test]
    fn test_store_and_list_processing_records() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_processing_record(make_processing_record("pr1", "alice")).unwrap();
        backend.store_processing_record(make_processing_record("pr2", "alice")).unwrap();
        let records = backend.list_processing_records_for_subject(&SubjectRef::new("alice")).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_store_and_retrieve_retention_policy() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_retention_policy_definition(make_retention_policy("rp1")).unwrap();
        let p = backend.retrieve_retention_policy_definition("rp1").unwrap().unwrap();
        assert_eq!(p.maximum_retention_days, 365);
    }

    #[test]
    fn test_flush_clears_all() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_pii_classification(make_classification("c1")).unwrap();
        backend.store_data_subject_record(make_subject("alice")).unwrap();
        backend.flush().unwrap();
        assert_eq!(backend.backend_info().classification_count, 0);
        assert_eq!(backend.backend_info().subject_count, 0);
    }

    #[test]
    fn test_backend_info() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_pii_classification(make_classification("c1")).unwrap();
        backend.store_data_subject_record(make_subject("alice")).unwrap();
        backend.store_data_subject_request(make_request("r1", "alice")).unwrap();
        backend.store_processing_record(make_processing_record("pr1", "alice")).unwrap();
        backend.store_retention_policy_definition(make_retention_policy("rp1")).unwrap();
        let info = backend.backend_info();
        assert_eq!(info.classification_count, 1);
        assert_eq!(info.subject_count, 1);
        assert_eq!(info.request_count, 1);
        assert_eq!(info.processing_record_count, 1);
        assert_eq!(info.retention_policy_count, 1);
    }

    #[test]
    fn test_request_type_display() {
        assert_eq!(RequestType::Access.to_string(), "Access");
        assert_eq!(RequestType::Erasure.to_string(), "Erasure");
        assert_eq!(RequestType::Portability.to_string(), "Portability");
    }

    #[test]
    fn test_deletion_strategy_display() {
        assert_eq!(DeletionStrategy::Soft.to_string(), "Soft");
        assert_eq!(DeletionStrategy::Hard.to_string(), "Hard");
        assert_eq!(DeletionStrategy::Anonymize.to_string(), "Anonymize");
    }

    #[test]
    fn test_list_classifications() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_pii_classification(make_classification("c1")).unwrap();
        backend.store_pii_classification(make_classification("c2")).unwrap();
        assert_eq!(backend.list_pii_classifications().unwrap().len(), 2);
    }

    #[test]
    fn test_list_retention_policies() {
        let mut backend = InMemoryPrivacyBackend::new();
        backend.store_retention_policy_definition(make_retention_policy("rp1")).unwrap();
        backend.store_retention_policy_definition(make_retention_policy("rp2")).unwrap();
        assert_eq!(backend.list_retention_policy_definitions().unwrap().len(), 2);
    }
}
