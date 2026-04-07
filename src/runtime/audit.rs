// ═══════════════════════════════════════════════════════════════════════
// Cryptographic Audit Trail
//
// Every policy decision, capability exercise, and model invocation is
// recorded in an append-only hash chain with cryptographic signatures.
//
// Current implementation uses placeholder primitives:
//   - SHA-256 (stand-in for SHA-3 / FIPS 202)
//   - HMAC-SHA256 (stand-in for ML-DSA / FIPS 204)
//
// Swapping to real PQC primitives is a single-function change in the
// `crypto` module at the bottom of this file.
//
// Pillar: Security Baked In — audit instrumentation is compiler-inserted,
// not optional. Every governance decision is recorded.
//
// Pillar: Assumed Breach — the hash chain detects tampering. If any
// record is modified after creation, verification fails.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;
use std::time::SystemTime;

use crate::runtime::evaluator::PolicyDecision;

// ── Event types ───────────────────────────────────────────────────────

/// The type of governance event being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// A policy decision was made (permit, deny, escalate, quarantine).
    PolicyDecision,
    /// A function was entered.
    FunctionEntry,
    /// A function was exited.
    FunctionExit,
    /// A capability was exercised.
    CapabilityExercise,
    /// A model was invoked.
    ModelInvocation,
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditEventType::PolicyDecision => write!(f, "PolicyDecision"),
            AuditEventType::FunctionEntry => write!(f, "FunctionEntry"),
            AuditEventType::FunctionExit => write!(f, "FunctionExit"),
            AuditEventType::CapabilityExercise => write!(f, "CapabilityExercise"),
            AuditEventType::ModelInvocation => write!(f, "ModelInvocation"),
        }
    }
}

// ── Audit record ──────────────────────────────────────────────────────

/// A single record in the cryptographic audit trail.
///
/// Each record contains a hash of its contents and a link to the
/// previous record's hash, forming an append-only hash chain.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Monotonically increasing record identifier.
    pub record_id: u64,
    /// When this event occurred.
    pub timestamp: SystemTime,
    /// What type of governance event this records.
    pub event_type: AuditEventType,
    /// Name or hash of the policy module that produced this event.
    pub policy_module: String,
    /// Which function or rule produced this event.
    pub function_name: String,
    /// The policy decision, if this is a PolicyDecision event.
    pub decision: Option<PolicyDecision>,
    /// Hash of the evaluation inputs.
    pub input_hash: String,
    /// Hash of the previous record in the chain.
    pub previous_hash: String,
    /// Hash of this record's contents.
    pub record_hash: String,
    /// Cryptographic signature of the record hash.
    /// Currently HMAC-SHA256; will be ML-DSA (FIPS 204) post-M10.
    pub signature: String,
}

// ── Verification errors ───────────────────────────────────────────────

/// Errors detected during audit trail verification.
#[derive(Debug, Clone, PartialEq)]
pub enum AuditVerificationError {
    /// A record's previous_hash does not match the preceding record's hash.
    BrokenChain {
        record_id: u64,
        expected_hash: String,
        actual_hash: String,
    },
    /// A record's signature does not verify against the record hash.
    InvalidSignature { record_id: u64 },
    /// The audit trail is empty.
    EmptyTrail,
}

impl fmt::Display for AuditVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditVerificationError::BrokenChain { record_id, expected_hash, actual_hash } => {
                write!(
                    f,
                    "broken hash chain at record {record_id}: expected {expected_hash}, got {actual_hash}"
                )
            }
            AuditVerificationError::InvalidSignature { record_id } => {
                write!(f, "invalid signature at record {record_id}")
            }
            AuditVerificationError::EmptyTrail => write!(f, "audit trail is empty"),
        }
    }
}

impl std::error::Error for AuditVerificationError {}

// ── Audit trail ───────────────────────────────────────────────────────

/// The genesis hash — the previous_hash for the first record.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An append-only cryptographic audit trail.
///
/// Records are linked by hash: each record contains the hash of the
/// preceding record. Tampering with any record breaks the chain.
pub struct AuditTrail {
    records: Vec<AuditRecord>,
    current_hash: String,
    signing_key: Vec<u8>,
    record_counter: u64,
}

impl AuditTrail {
    /// Create a new empty audit trail with the given signing key.
    pub fn new(signing_key: Vec<u8>) -> Self {
        Self {
            records: Vec::new(),
            current_hash: GENESIS_HASH.to_string(),
            signing_key,
            record_counter: 0,
        }
    }

    /// Record a policy decision event.
    pub fn record_decision(
        &mut self,
        module: &str,
        function: &str,
        decision: PolicyDecision,
        input_hash: &str,
    ) -> &AuditRecord {
        self.append_record(
            AuditEventType::PolicyDecision,
            module,
            function,
            Some(decision),
            input_hash,
        )
    }

    /// Record a non-decision governance event (entry, exit, capability, model).
    pub fn record_event(
        &mut self,
        module: &str,
        function: &str,
        event_type: AuditEventType,
    ) -> &AuditRecord {
        self.append_record(event_type, module, function, None, "")
    }

    /// Verify that the hash chain is intact.
    ///
    /// Walks every record and confirms that each record's previous_hash
    /// matches the preceding record's record_hash. Also recomputes each
    /// record's hash to detect content tampering.
    pub fn verify_chain(&self) -> Result<(), AuditVerificationError> {
        if self.records.is_empty() {
            return Err(AuditVerificationError::EmptyTrail);
        }

        let mut expected_prev = GENESIS_HASH.to_string();

        for record in &self.records {
            // Check the chain link.
            if record.previous_hash != expected_prev {
                return Err(AuditVerificationError::BrokenChain {
                    record_id: record.record_id,
                    expected_hash: expected_prev,
                    actual_hash: record.previous_hash.clone(),
                });
            }

            // Recompute the record hash to detect content tampering.
            let recomputed = compute_record_hash(record);
            if record.record_hash != recomputed {
                return Err(AuditVerificationError::BrokenChain {
                    record_id: record.record_id,
                    expected_hash: recomputed,
                    actual_hash: record.record_hash.clone(),
                });
            }

            expected_prev = record.record_hash.clone();
        }

        Ok(())
    }

    /// Verify all signatures in the chain.
    pub fn verify_signatures(
        &self,
        verification_key: &[u8],
    ) -> Result<(), AuditVerificationError> {
        if self.records.is_empty() {
            return Err(AuditVerificationError::EmptyTrail);
        }

        for record in &self.records {
            let expected_sig = crypto::sign(verification_key, &record.record_hash);
            if record.signature != expected_sig {
                return Err(AuditVerificationError::InvalidSignature {
                    record_id: record.record_id,
                });
            }
        }

        Ok(())
    }

    /// Number of records in the trail.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the trail is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get a record by index.
    pub fn get(&self, index: usize) -> Option<&AuditRecord> {
        self.records.get(index)
    }

    /// Get the most recent record.
    pub fn latest(&self) -> Option<&AuditRecord> {
        self.records.last()
    }

    /// Export all records (cloned).
    pub fn export(&self) -> Vec<AuditRecord> {
        self.records.clone()
    }

    // ── Internal ──────────────────────────────────────────────────

    fn append_record(
        &mut self,
        event_type: AuditEventType,
        module: &str,
        function: &str,
        decision: Option<PolicyDecision>,
        input_hash: &str,
    ) -> &AuditRecord {
        let record_id = self.record_counter;
        self.record_counter += 1;

        let mut record = AuditRecord {
            record_id,
            timestamp: SystemTime::now(),
            event_type,
            policy_module: module.to_string(),
            function_name: function.to_string(),
            decision,
            input_hash: input_hash.to_string(),
            previous_hash: self.current_hash.clone(),
            record_hash: String::new(),
            signature: String::new(),
        };

        // Compute the record hash.
        record.record_hash = compute_record_hash(&record);

        // Sign the record hash.
        record.signature = crypto::sign(&self.signing_key, &record.record_hash);

        // Update chain head.
        self.current_hash = record.record_hash.clone();

        self.records.push(record);
        self.records.last().unwrap()
    }
}

impl fmt::Debug for AuditTrail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditTrail")
            .field("len", &self.records.len())
            .field("current_hash", &self.current_hash)
            .finish()
    }
}

// ── Record hashing ────────────────────────────────────────────────────

/// Compute the hash of an audit record's contents.
///
/// Hash = SHA256(record_id || timestamp || event_type || policy_module
///               || function_name || decision || input_hash || previous_hash)
fn compute_record_hash(record: &AuditRecord) -> String {
    let decision_str = match record.decision {
        Some(d) => d.to_i32().to_string(),
        None => "none".to_string(),
    };

    let timestamp_str = record
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());

    let payload = format!(
        "{}||{}||{}||{}||{}||{}||{}||{}",
        record.record_id,
        timestamp_str,
        record.event_type,
        record.policy_module,
        record.function_name,
        decision_str,
        record.input_hash,
        record.previous_hash,
    );

    crypto::hash(&payload)
}

// ═══════════════════════════════════════════════════════════════════════
// Cryptographic primitives — placeholder module
//
// Currently uses SHA-256 and HMAC-SHA256 as stand-ins for:
//   - SHA-3 (FIPS 202) for hashing
//   - ML-DSA (FIPS 204) for signatures
//
// To swap to real PQC primitives, replace the two functions below.
// No other code in this file needs to change.
// ═══════════════════════════════════════════════════════════════════════

mod crypto {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Hash a string payload. Currently SHA-256; will be SHA-3 post-M10.
    pub fn hash(payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign a record hash. Currently HMAC-SHA256; will be ML-DSA post-M10.
    pub fn sign(key: &[u8], record_hash: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(record_hash.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Compute a SHA-256 hash of arbitrary input bytes. Utility for callers
/// that need to hash evaluation inputs.
pub fn hash_input(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
