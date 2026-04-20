// ═══════════════════════════════════════════════════════════════════════
// Consent Record Store — Pluggable consent lifecycle storage.
//
// Consent is separated from PrivacyBackend because it has a distinct
// lifecycle (granted → active → expired/withdrawn/superseded) and
// distinct access patterns (high-frequency reads on the hot path,
// infrequent writes). This matches the BaselineStore/DetectionBackend
// and CredentialMaterialStore/IdentityBackend separations.
//
// ConsentRecord uses a ConsentLegalBasis enum covering GDPR Article 6
// bases so that consent legitimacy can be reasoned about structurally.
// The consent_text_hash field (SHA3-256) records the actual language
// the subject saw, because regulator audit of consent validity
// requires proving what the subject was shown, not merely that consent
// was recorded.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use sha3::{Digest, Sha3_256};

use crate::backend::SubjectRef;
use crate::error::PrivacyError;

// ── ConsentLegalBasis ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentLegalBasis {
    Consent,
    Contract,
    LegalObligation,
    VitalInterests,
    PublicTask,
    LegitimateInterest,
}

impl fmt::Display for ConsentLegalBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consent => write!(f, "Consent (Art. 6(1)(a))"),
            Self::Contract => write!(f, "Contract (Art. 6(1)(b))"),
            Self::LegalObligation => write!(f, "LegalObligation (Art. 6(1)(c))"),
            Self::VitalInterests => write!(f, "VitalInterests (Art. 6(1)(d))"),
            Self::PublicTask => write!(f, "PublicTask (Art. 6(1)(e))"),
            Self::LegitimateInterest => write!(f, "LegitimateInterest (Art. 6(1)(f))"),
        }
    }
}

// ── StoredConsentStatus ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredConsentStatus {
    Active,
    Withdrawn,
    Expired,
    Superseded,
    NotFound,
}

impl fmt::Display for StoredConsentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ConsentRecord ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConsentRecord {
    pub consent_id: String,
    pub subject_ref: SubjectRef,
    pub purpose: String,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub withdrawn_at: Option<i64>,
    pub legal_basis: ConsentLegalBasis,
    pub scope: Vec<String>,
    pub consent_text_hash: String,
    pub status: StoredConsentStatus,
}

impl ConsentRecord {
    pub fn new(
        consent_id: &str,
        subject_ref: SubjectRef,
        purpose: &str,
        granted_at: i64,
        legal_basis: ConsentLegalBasis,
        consent_text: &str,
    ) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(consent_text.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            consent_id: consent_id.to_string(),
            subject_ref,
            purpose: purpose.to_string(),
            granted_at,
            expires_at: None,
            withdrawn_at: None,
            legal_basis,
            scope: Vec::new(),
            consent_text_hash: hash,
            status: StoredConsentStatus::Active,
        }
    }

    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_scope(mut self, scope: Vec<String>) -> Self {
        self.scope = scope;
        self
    }
}

// ── ConsentStoreInfo ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConsentStoreInfo {
    pub store_name: String,
    pub total_records: usize,
    pub active_count: usize,
}

// ── ConsentRecordStore trait ────────────────────────────────────────

pub trait ConsentRecordStore {
    fn record_consent(&mut self, record: ConsentRecord) -> Result<(), PrivacyError>;
    fn retrieve_consent(&self, consent_id: &str) -> Result<Option<ConsentRecord>, PrivacyError>;
    fn list_consents_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<ConsentRecord>, PrivacyError>;
    fn list_consents_for_purpose(&self, purpose: &str) -> Result<Vec<ConsentRecord>, PrivacyError>;
    fn withdraw_consent(&mut self, consent_id: &str, withdrawn_at: i64) -> Result<(), PrivacyError>;
    fn consent_is_active_for(&self, subject_ref: &SubjectRef, purpose: &str, now: i64) -> Result<bool, PrivacyError>;
    fn consent_expires_between(&self, from: i64, to: i64) -> Result<Vec<ConsentRecord>, PrivacyError>;
    fn supersede_consent(&mut self, old_consent_id: &str, new_record: ConsentRecord) -> Result<(), PrivacyError>;
    fn flush(&mut self) -> Result<(), PrivacyError>;
    fn store_info(&self) -> ConsentStoreInfo;
}

// ── InMemoryConsentStore ────────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryConsentRecordStore {
    records: HashMap<String, ConsentRecord>,
}

impl InMemoryConsentRecordStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConsentRecordStore for InMemoryConsentRecordStore {
    fn record_consent(&mut self, record: ConsentRecord) -> Result<(), PrivacyError> {
        if self.records.contains_key(&record.consent_id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "consent {} already exists", record.consent_id
            )));
        }
        self.records.insert(record.consent_id.clone(), record);
        Ok(())
    }

    fn retrieve_consent(&self, consent_id: &str) -> Result<Option<ConsentRecord>, PrivacyError> {
        Ok(self.records.get(consent_id).cloned())
    }

    fn list_consents_for_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<ConsentRecord>, PrivacyError> {
        Ok(self.records.values()
            .filter(|r| r.subject_ref == *subject_ref)
            .cloned()
            .collect())
    }

    fn list_consents_for_purpose(&self, purpose: &str) -> Result<Vec<ConsentRecord>, PrivacyError> {
        Ok(self.records.values()
            .filter(|r| r.purpose == purpose)
            .cloned()
            .collect())
    }

    fn withdraw_consent(&mut self, consent_id: &str, withdrawn_at: i64) -> Result<(), PrivacyError> {
        let record = self.records.get_mut(consent_id)
            .ok_or_else(|| PrivacyError::ConsentNotFound(consent_id.to_string()))?;
        if record.status == StoredConsentStatus::Withdrawn {
            return Err(PrivacyError::ConsentAlreadyWithdrawn(consent_id.to_string()));
        }
        record.status = StoredConsentStatus::Withdrawn;
        record.withdrawn_at = Some(withdrawn_at);
        Ok(())
    }

    fn consent_is_active_for(&self, subject_ref: &SubjectRef, purpose: &str, now: i64) -> Result<bool, PrivacyError> {
        Ok(self.records.values().any(|r| {
            r.subject_ref == *subject_ref
                && r.purpose == purpose
                && r.status == StoredConsentStatus::Active
                && r.expires_at.map_or(true, |exp| now < exp)
        }))
    }

    fn consent_expires_between(&self, from: i64, to: i64) -> Result<Vec<ConsentRecord>, PrivacyError> {
        Ok(self.records.values()
            .filter(|r| {
                r.status == StoredConsentStatus::Active
                    && r.expires_at.is_some_and(|exp| exp >= from && exp <= to)
            })
            .cloned()
            .collect())
    }

    fn supersede_consent(&mut self, old_consent_id: &str, new_record: ConsentRecord) -> Result<(), PrivacyError> {
        let old = self.records.get_mut(old_consent_id)
            .ok_or_else(|| PrivacyError::ConsentNotFound(old_consent_id.to_string()))?;
        old.status = StoredConsentStatus::Superseded;
        let new_id = new_record.consent_id.clone();
        self.records.insert(new_id, new_record);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), PrivacyError> {
        self.records.clear();
        Ok(())
    }

    fn store_info(&self) -> ConsentStoreInfo {
        let active = self.records.values()
            .filter(|r| r.status == StoredConsentStatus::Active)
            .count();
        ConsentStoreInfo {
            store_name: "InMemoryConsentRecordStore".to_string(),
            total_records: self.records.len(),
            active_count: active,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: &str, subject: &str, purpose: &str) -> ConsentRecord {
        ConsentRecord::new(id, SubjectRef::new(subject), purpose, 1000, ConsentLegalBasis::Consent, "I agree to the terms")
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        let r = store.retrieve_consent("c1").unwrap().unwrap();
        assert_eq!(r.purpose, "analytics");
        assert!(!r.consent_text_hash.is_empty());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        assert!(store.record_consent(make_record("c1", "alice", "analytics")).is_err());
    }

    #[test]
    fn test_withdraw_consent() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        store.withdraw_consent("c1", 5000).unwrap();
        let r = store.retrieve_consent("c1").unwrap().unwrap();
        assert_eq!(r.status, StoredConsentStatus::Withdrawn);
        assert_eq!(r.withdrawn_at, Some(5000));
    }

    #[test]
    fn test_withdraw_already_withdrawn() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        store.withdraw_consent("c1", 5000).unwrap();
        assert!(store.withdraw_consent("c1", 6000).is_err());
    }

    #[test]
    fn test_consent_is_active_for() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        assert!(store.consent_is_active_for(&SubjectRef::new("alice"), "analytics", 2000).unwrap());
        assert!(!store.consent_is_active_for(&SubjectRef::new("alice"), "marketing", 2000).unwrap());
    }

    #[test]
    fn test_consent_is_active_respects_expiry() {
        let mut store = InMemoryConsentRecordStore::new();
        let record = make_record("c1", "alice", "analytics").with_expires_at(3000);
        store.record_consent(record).unwrap();
        assert!(store.consent_is_active_for(&SubjectRef::new("alice"), "analytics", 2000).unwrap());
        assert!(!store.consent_is_active_for(&SubjectRef::new("alice"), "analytics", 4000).unwrap());
    }

    #[test]
    fn test_list_consents_for_subject() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        store.record_consent(make_record("c2", "alice", "marketing")).unwrap();
        store.record_consent(make_record("c3", "bob", "analytics")).unwrap();
        let alice = store.list_consents_for_subject(&SubjectRef::new("alice")).unwrap();
        assert_eq!(alice.len(), 2);
    }

    #[test]
    fn test_list_consents_for_purpose() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        store.record_consent(make_record("c2", "bob", "analytics")).unwrap();
        store.record_consent(make_record("c3", "alice", "marketing")).unwrap();
        let analytics = store.list_consents_for_purpose("analytics").unwrap();
        assert_eq!(analytics.len(), 2);
    }

    #[test]
    fn test_consent_expires_between() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "a").with_expires_at(5000)).unwrap();
        store.record_consent(make_record("c2", "bob", "b").with_expires_at(8000)).unwrap();
        store.record_consent(make_record("c3", "carol", "c")).unwrap(); // no expiry
        let expiring = store.consent_expires_between(4000, 6000).unwrap();
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].consent_id, "c1");
    }

    #[test]
    fn test_supersede_consent() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "analytics")).unwrap();
        let new_record = make_record("c2", "alice", "analytics");
        store.supersede_consent("c1", new_record).unwrap();
        let old = store.retrieve_consent("c1").unwrap().unwrap();
        assert_eq!(old.status, StoredConsentStatus::Superseded);
        assert!(store.retrieve_consent("c2").unwrap().is_some());
    }

    #[test]
    fn test_flush() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "a")).unwrap();
        store.flush().unwrap();
        assert_eq!(store.store_info().total_records, 0);
    }

    #[test]
    fn test_store_info() {
        let mut store = InMemoryConsentRecordStore::new();
        store.record_consent(make_record("c1", "alice", "a")).unwrap();
        store.record_consent(make_record("c2", "bob", "b")).unwrap();
        store.withdraw_consent("c2", 5000).unwrap();
        let info = store.store_info();
        assert_eq!(info.total_records, 2);
        assert_eq!(info.active_count, 1);
    }

    #[test]
    fn test_consent_text_hash_deterministic() {
        let r1 = make_record("c1", "alice", "a");
        let r2 = ConsentRecord::new("c2", SubjectRef::new("bob"), "b", 2000, ConsentLegalBasis::Contract, "I agree to the terms");
        assert_eq!(r1.consent_text_hash, r2.consent_text_hash);
    }

    #[test]
    fn test_legal_basis_display() {
        assert!(ConsentLegalBasis::Consent.to_string().contains("Art. 6(1)(a)"));
        assert!(ConsentLegalBasis::LegitimateInterest.to_string().contains("Art. 6(1)(f)"));
    }

    #[test]
    fn test_stored_consent_status_display() {
        assert_eq!(StoredConsentStatus::Active.to_string(), "Active");
        assert_eq!(StoredConsentStatus::Withdrawn.to_string(), "Withdrawn");
        assert_eq!(StoredConsentStatus::Superseded.to_string(), "Superseded");
    }

    #[test]
    fn test_consent_record_with_scope() {
        let record = make_record("c1", "alice", "a")
            .with_scope(vec!["email".to_string(), "phone".to_string()]);
        assert_eq!(record.scope.len(), 2);
    }
}
