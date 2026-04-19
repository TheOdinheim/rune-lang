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
// Layer 2: Consent Lifecycle Enhancement
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Sha3_256};

/// A versioned consent record with policy hash for change detection.
#[derive(Debug, Clone)]
pub struct ConsentVersion {
    pub consent_id: ConsentId,
    pub version: u32,
    pub policy_text: String,
    pub policy_hash: String,
    pub created_at: i64,
    pub supersedes: Option<u32>,
}

impl ConsentVersion {
    fn compute_hash(text: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Result of a cascade withdrawal.
#[derive(Debug, Clone)]
pub struct WithdrawalResult {
    pub withdrawn_consent_id: ConsentId,
    pub dependent_purposes_withdrawn: Vec<String>,
    pub total_withdrawn: usize,
}

/// Cryptographic proof of consent for audit/legal purposes.
#[derive(Debug, Clone)]
pub struct ConsentProof {
    pub consent_id: ConsentId,
    pub subject_id: String,
    pub purpose: String,
    pub given_at: i64,
    pub policy_hash: String,
    pub proof_hash: String,
}

/// Graph of purpose dependencies for cascade operations.
#[derive(Debug, Clone, Default)]
pub struct PurposeDependencyGraph {
    /// Maps purpose → list of purposes that depend on it
    pub dependencies: HashMap<String, Vec<String>>,
}

impl PurposeDependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_dependency(&mut self, purpose: &str, depends_on: &str) {
        self.dependencies
            .entry(depends_on.to_string())
            .or_default()
            .push(purpose.to_string());
    }

    /// Get all purposes that directly depend on the given purpose.
    pub fn dependents_of(&self, purpose: &str) -> Vec<String> {
        self.dependencies.get(purpose).cloned().unwrap_or_default()
    }

    /// Get all purposes transitively required when withdrawing the given purpose.
    pub fn all_required_for(&self, purpose: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut stack = vec![purpose.to_string()];
        let mut visited = std::collections::HashSet::new();
        while let Some(p) = stack.pop() {
            if !visited.insert(p.clone()) {
                continue;
            }
            if let Some(deps) = self.dependencies.get(&p) {
                for dep in deps {
                    result.push(dep.clone());
                    stack.push(dep.clone());
                }
            }
        }
        result
    }
}

/// Consent version store — manages versioned consent records.
#[derive(Default)]
pub struct ConsentVersionStore {
    pub versions: HashMap<ConsentId, Vec<ConsentVersion>>,
}

impl ConsentVersionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_version(
        &mut self,
        consent_id: &ConsentId,
        policy_text: &str,
        created_at: i64,
    ) -> ConsentVersion {
        let existing = self.versions.entry(consent_id.clone()).or_default();
        let version_num = existing.len() as u32 + 1;
        let supersedes = if existing.is_empty() { None } else { Some(version_num - 1) };
        let version = ConsentVersion {
            consent_id: consent_id.clone(),
            version: version_num,
            policy_text: policy_text.to_string(),
            policy_hash: ConsentVersion::compute_hash(policy_text),
            created_at,
            supersedes,
        };
        existing.push(version.clone());
        version
    }

    pub fn current_version(&self, consent_id: &ConsentId) -> Option<&ConsentVersion> {
        self.versions.get(consent_id).and_then(|v| v.last())
    }

    pub fn is_consent_current(&self, consent_id: &ConsentId, policy_text: &str) -> bool {
        if let Some(current) = self.current_version(consent_id) {
            current.policy_hash == ConsentVersion::compute_hash(policy_text)
        } else {
            false
        }
    }

    pub fn version_history(&self, consent_id: &ConsentId) -> Vec<&ConsentVersion> {
        self.versions.get(consent_id).map(|v| v.iter().collect()).unwrap_or_default()
    }
}

impl ConsentStore {
    /// Withdraw consent and cascade to dependent purposes.
    pub fn withdraw_consent_cascade(
        &mut self,
        id: &ConsentId,
        withdrawn_at: i64,
        dep_graph: &PurposeDependencyGraph,
    ) -> Result<WithdrawalResult, PrivacyError> {
        let consent = self
            .consents
            .get(id)
            .ok_or_else(|| PrivacyError::ConsentNotFound(id.to_string()))?;
        let purpose_id = consent.purpose.id.clone();
        let subject = consent.data_subject.clone();

        // Withdraw the primary consent
        self.withdraw_consent(id, withdrawn_at)?;

        // Find dependent purposes
        let dependent_purposes = dep_graph.all_required_for(&purpose_id);

        // Withdraw consents for dependent purposes
        let mut withdrawn_ids = Vec::new();
        for dep_purpose in &dependent_purposes {
            let ids_to_withdraw: Vec<ConsentId> = self
                .consents_for_subject(&subject)
                .iter()
                .filter(|c| {
                    c.purpose.id == *dep_purpose && matches!(c.status, ConsentStatus::Active)
                })
                .map(|c| c.id.clone())
                .collect();
            for cid in ids_to_withdraw {
                let _ = self.withdraw_consent(&cid, withdrawn_at);
                withdrawn_ids.push(cid);
            }
        }

        Ok(WithdrawalResult {
            withdrawn_consent_id: id.clone(),
            dependent_purposes_withdrawn: dependent_purposes,
            total_withdrawn: 1 + withdrawn_ids.len(),
        })
    }

    /// Generate a cryptographic proof of consent.
    pub fn generate_consent_proof(
        &self,
        id: &ConsentId,
    ) -> Result<ConsentProof, PrivacyError> {
        let consent = self
            .consents
            .get(id)
            .ok_or_else(|| PrivacyError::ConsentNotFound(id.to_string()))?;

        let proof_input = format!(
            "{}:{}:{}:{}",
            consent.id,
            consent.data_subject,
            consent.purpose.id,
            consent.given_at
        );
        let mut hasher = Sha3_256::new();
        hasher.update(proof_input.as_bytes());
        let proof_hash = hex::encode(hasher.finalize());

        let mut policy_hasher = Sha3_256::new();
        policy_hasher.update(consent.purpose.id.as_bytes());
        let policy_hash = hex::encode(policy_hasher.finalize());

        Ok(ConsentProof {
            consent_id: id.clone(),
            subject_id: consent.data_subject.to_string(),
            purpose: consent.purpose.id.clone(),
            given_at: consent.given_at,
            policy_hash,
            proof_hash,
        })
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

    // ── Layer 2 tests ────────────────────────────────────────────────

    #[test]
    fn test_consent_version_create() {
        let mut vs = ConsentVersionStore::new();
        let v1 = vs.create_version(&ConsentId::new("c1"), "Privacy Policy v1", 1000);
        assert_eq!(v1.version, 1);
        assert!(v1.supersedes.is_none());
        assert!(!v1.policy_hash.is_empty());
    }

    #[test]
    fn test_consent_version_supersedes() {
        let mut vs = ConsentVersionStore::new();
        vs.create_version(&ConsentId::new("c1"), "Policy v1", 1000);
        let v2 = vs.create_version(&ConsentId::new("c1"), "Policy v2", 2000);
        assert_eq!(v2.version, 2);
        assert_eq!(v2.supersedes, Some(1));
    }

    #[test]
    fn test_consent_version_current() {
        let mut vs = ConsentVersionStore::new();
        vs.create_version(&ConsentId::new("c1"), "Policy v1", 1000);
        vs.create_version(&ConsentId::new("c1"), "Policy v2", 2000);
        let current = vs.current_version(&ConsentId::new("c1")).unwrap();
        assert_eq!(current.version, 2);
    }

    #[test]
    fn test_is_consent_current_matches() {
        let mut vs = ConsentVersionStore::new();
        vs.create_version(&ConsentId::new("c1"), "Policy v1", 1000);
        assert!(vs.is_consent_current(&ConsentId::new("c1"), "Policy v1"));
        assert!(!vs.is_consent_current(&ConsentId::new("c1"), "Policy v2"));
    }

    #[test]
    fn test_consent_version_hash_deterministic() {
        let mut vs = ConsentVersionStore::new();
        let v1 = vs.create_version(&ConsentId::new("c1"), "Same policy", 1000);
        let mut vs2 = ConsentVersionStore::new();
        let v2 = vs2.create_version(&ConsentId::new("c2"), "Same policy", 2000);
        assert_eq!(v1.policy_hash, v2.policy_hash);
    }

    #[test]
    fn test_purpose_dependency_graph() {
        let mut graph = PurposeDependencyGraph::new();
        graph.add_dependency("marketing", "analytics");
        graph.add_dependency("profiling", "analytics");
        let deps = graph.dependents_of("analytics");
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&"marketing".to_string()));
        assert!(deps.contains(&"profiling".to_string()));
    }

    #[test]
    fn test_purpose_dependency_transitive() {
        let mut graph = PurposeDependencyGraph::new();
        graph.add_dependency("marketing", "analytics");
        graph.add_dependency("ads", "marketing");
        let all = graph.all_required_for("analytics");
        assert!(all.contains(&"marketing".to_string()));
        assert!(all.contains(&"ads".to_string()));
    }

    #[test]
    fn test_withdraw_consent_cascade() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "analytics")).unwrap();
        store.record_consent(test_consent("c2", "user:alice", "marketing")).unwrap();

        let mut graph = PurposeDependencyGraph::new();
        graph.add_dependency("marketing", "analytics");

        let result = store.withdraw_consent_cascade(&ConsentId::new("c1"), 2000, &graph).unwrap();
        assert_eq!(result.total_withdrawn, 2);
        assert_eq!(result.dependent_purposes_withdrawn.len(), 1);

        let c1 = store.get_consent(&ConsentId::new("c1")).unwrap();
        assert_eq!(c1.status, ConsentStatus::Withdrawn);
        let c2 = store.get_consent(&ConsentId::new("c2")).unwrap();
        assert_eq!(c2.status, ConsentStatus::Withdrawn);
    }

    #[test]
    fn test_generate_consent_proof() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        let proof = store.generate_consent_proof(&ConsentId::new("c1")).unwrap();
        assert_eq!(proof.consent_id, ConsentId::new("c1"));
        assert!(!proof.proof_hash.is_empty());
        assert!(!proof.policy_hash.is_empty());
        assert_eq!(proof.purpose, "p1");
    }

    #[test]
    fn test_consent_proof_deterministic() {
        let mut store = ConsentStore::new();
        store.record_consent(test_consent("c1", "user:alice", "p1")).unwrap();
        let proof1 = store.generate_consent_proof(&ConsentId::new("c1")).unwrap();
        let proof2 = store.generate_consent_proof(&ConsentId::new("c1")).unwrap();
        assert_eq!(proof1.proof_hash, proof2.proof_hash);
    }
}
