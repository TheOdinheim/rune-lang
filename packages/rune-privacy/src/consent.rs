// ═══════════════════════════════════════════════════════════════════════
// Consent Management — Lifecycle, Withdrawal, Evidence
//
// Track who consented to what processing for which purpose,
// under which legal basis, with full audit-worthy evidence.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_identity::IdentityId;

use crate::error::PrivacyError;
use crate::pii::PiiCategory;
use crate::purpose::Purpose;

// ── ConsentId ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConsentId(String);

impl ConsentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConsentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── ConsentScope ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConsentScope {
    Specific(Vec<String>),
    Category(Vec<PiiCategory>),
    AllData,
}

impl fmt::Display for ConsentScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Specific(fields) => write!(f, "Specific({} fields)", fields.len()),
            Self::Category(cats) => write!(f, "Category({} categories)", cats.len()),
            Self::AllData => write!(f, "AllData"),
        }
    }
}

// ── ConsentStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConsentStatus {
    Active,
    Withdrawn,
    Expired,
    Superseded { by: ConsentId },
}

impl fmt::Display for ConsentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Withdrawn => write!(f, "Withdrawn"),
            Self::Expired => write!(f, "Expired"),
            Self::Superseded { by } => write!(f, "Superseded(by {by})"),
        }
    }
}

// ── ConsentMethod ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConsentMethod {
    ExplicitOptIn,
    WrittenAgreement,
    VerbalConfirmation,
    ImpliedByContract,
    LegitimateInterest,
    LegalObligation,
}

impl fmt::Display for ConsentMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── ConsentEvidence ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConsentEvidence {
    pub method: ConsentMethod,
    pub timestamp: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub document_version: Option<String>,
    pub signature: Option<String>,
}

// ── Consent ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Consent {
    pub id: ConsentId,
    pub data_subject: IdentityId,
    pub purpose: Purpose,
    pub scope: ConsentScope,
    pub status: ConsentStatus,
    pub given_at: i64,
    pub expires_at: Option<i64>,
    pub withdrawn_at: Option<i64>,
    pub evidence: ConsentEvidence,
    pub version: u32,
    pub metadata: HashMap<String, String>,
}

impl Consent {
    pub fn is_active(&self, now: i64) -> bool {
        if !matches!(self.status, ConsentStatus::Active) {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if now >= exp {
                return false;
            }
        }
        true
    }
}

// ── ConsentStore ──────────────────────────────────────────────────────

#[derive(Default)]
pub struct ConsentStore {
    pub consents: HashMap<ConsentId, Consent>,
    pub subject_index: HashMap<IdentityId, Vec<ConsentId>>,
}

impl ConsentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_consent(&mut self, consent: Consent) -> Result<(), PrivacyError> {
        if self.consents.contains_key(&consent.id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "consent {} already exists",
                consent.id
            )));
        }
        let subject = consent.data_subject.clone();
        let id = consent.id.clone();
        self.consents.insert(id.clone(), consent);
        self.subject_index.entry(subject).or_default().push(id);
        Ok(())
    }

    pub fn withdraw_consent(
        &mut self,
        id: &ConsentId,
        withdrawn_at: i64,
    ) -> Result<(), PrivacyError> {
        let consent = self
            .consents
            .get_mut(id)
            .ok_or_else(|| PrivacyError::ConsentNotFound(id.to_string()))?;
        if matches!(consent.status, ConsentStatus::Withdrawn) {
            return Err(PrivacyError::ConsentAlreadyWithdrawn(id.to_string()));
        }
        consent.status = ConsentStatus::Withdrawn;
        consent.withdrawn_at = Some(withdrawn_at);
        Ok(())
    }

    pub fn get_consent(&self, id: &ConsentId) -> Option<&Consent> {
        self.consents.get(id)
    }

    pub fn consents_for_subject(&self, subject: &IdentityId) -> Vec<&Consent> {
        self.subject_index
            .get(subject)
            .map(|ids| ids.iter().filter_map(|i| self.consents.get(i)).collect())
            .unwrap_or_default()
    }

    pub fn active_consents(&self, subject: &IdentityId) -> Vec<&Consent> {
        let now = i64::MAX / 2; // "now" placeholder; callers can override via has_consent variant
        self.consents_for_subject(subject)
            .into_iter()
            .filter(|c| c.is_active(now))
            .collect()
    }

    pub fn has_consent(
        &self,
        subject: &IdentityId,
        purpose: &Purpose,
    ) -> bool {
        self.active_consents(subject)
            .iter()
            .any(|c| c.purpose == *purpose)
    }

    pub fn expired_consents(&self) -> Vec<&Consent> {
        self.consents.values().filter(|c| matches!(c.status, ConsentStatus::Expired)).collect()
    }

    pub fn cleanup_expired(&mut self, now: i64) -> usize {
        let mut count = 0;
        for consent in self.consents.values_mut() {
            if matches!(consent.status, ConsentStatus::Active) {
                if let Some(exp) = consent.expires_at {
                    if now >= exp {
                        consent.status = ConsentStatus::Expired;
                        count += 1;
                    }
                }
            }
        }
        count
    }

    pub fn consent_history(&self, subject: &IdentityId) -> Vec<&Consent> {
        self.consents_for_subject(subject)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::purpose::LegalBasis;

    fn test_evidence() -> ConsentEvidence {
        ConsentEvidence {
            method: ConsentMethod::ExplicitOptIn,
            timestamp: 1000,
            ip_address: Some("1.2.3.4".into()),
            user_agent: None,
            document_version: Some("v1".into()),
            signature: None,
        }
    }

    fn test_consent(id: &str, subject: &str, purpose_id: &str) -> Consent {
        Consent {
            id: ConsentId::new(id),
            data_subject: IdentityId::new(subject),
            purpose: Purpose::new(purpose_id, "p", LegalBasis::Consent),
            scope: ConsentScope::AllData,
            status: ConsentStatus::Active,
            given_at: 1000,
            expires_at: None,
            withdrawn_at: None,
            evidence: test_evidence(),
            version: 1,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        assert!(store.get_consent(&ConsentId::new("c1")).is_some());
    }

    #[test]
    fn test_withdraw_consent() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        store.withdraw_consent(&ConsentId::new("c1"), 2000).unwrap();
        let c = store.get_consent(&ConsentId::new("c1")).unwrap();
        assert_eq!(c.status, ConsentStatus::Withdrawn);
        assert_eq!(c.withdrawn_at, Some(2000));
    }

    #[test]
    fn test_active_consents_filter() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        let mut c2 = test_consent("c2", "user:alice", "p2");
        c2.status = ConsentStatus::Withdrawn;
        store.record_consent(c2).unwrap();
        let active = store.active_consents(&IdentityId::new("user:alice"));
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_has_consent() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        let purpose = Purpose::new("p1", "p", LegalBasis::Consent);
        let other = Purpose::new("p2", "p", LegalBasis::Consent);
        assert!(store.has_consent(&IdentityId::new("user:alice"), &purpose));
        assert!(!store.has_consent(&IdentityId::new("user:alice"), &other));
    }

    #[test]
    fn test_expired_consents() {
        let mut store = ConsentStore::new();
        let mut c = test_consent("c1", "user:alice", "p1");
        c.expires_at = Some(1500);
        store.record_consent(c).unwrap();
        store.cleanup_expired(2000);
        assert_eq!(store.expired_consents().len(), 1);
    }

    #[test]
    fn test_consent_history_includes_withdrawn() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        store.withdraw_consent(&ConsentId::new("c1"), 2000).unwrap();
        let history = store.consent_history(&IdentityId::new("user:alice"));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_consent_with_expiration_inactive() {
        let mut c = test_consent("c1", "user:alice", "p1");
        c.expires_at = Some(1500);
        assert!(c.is_active(1200));
        assert!(!c.is_active(2000));
    }

    #[test]
    fn test_consent_method_display() {
        assert_eq!(ConsentMethod::ExplicitOptIn.to_string(), "ExplicitOptIn");
        assert_eq!(ConsentMethod::WrittenAgreement.to_string(), "WrittenAgreement");
    }

    #[test]
    fn test_legal_basis_display_coverage() {
        assert!(LegalBasis::Consent.to_string().contains("Art. 6"));
        assert!(LegalBasis::LegalObligation.to_string().contains("Art. 6"));
    }
}
