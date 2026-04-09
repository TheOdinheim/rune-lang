// ═══════════════════════════════════════════════════════════════════════
// RUNE Standard Library
//
// Provides runtime-accessible modules for RUNE programs via FFI.
// Each module corresponds to a rune:: namespace that RUNE source code
// can call through extern declarations.
//
// PQC-first: cryptographic primitives default to post-quantum algorithms
// (SHA-3 for hashing, ML-DSA for signatures). Classical algorithms are
// explicit fallbacks, not defaults.
// ═══════════════════════════════════════════════════════════════════════

pub mod crypto;
pub mod io;
pub mod net;
pub mod env;
pub mod time;
pub mod collections;
pub mod attestation;
pub mod policy;
pub mod audit;

#[cfg(test)]
mod integration_tests;

// ── Prelude ────────────────────────────────────────────────────────
//
// Re-exports the most commonly used types and functions from all
// stdlib modules. Usage: `use rune_lang::stdlib::prelude::*;`

pub mod prelude {
    // Crypto
    pub use super::crypto::{
        default_hash, default_sign, default_verify,
        HashAlgorithm, SignatureAlgorithm,
    };
    // Policy
    pub use super::policy::{
        Decision, PolicyRequest,
        first_non_permit, most_severe, all_permit, any_deny,
        RiskLevel, risk_level,
    };
    // Attestation
    pub use super::attestation::{
        ModelCard, TrustPolicy, TrustVerifier, TrustResult,
        sign_model, verify_signed_model,
    };
    // Audit
    pub use super::audit::{
        AuditEntry, AuditTrailView, DecisionSummary,
        AuditEventKind, verify_chain, verify_integrity,
    };
    // IO
    pub use super::io::{read_file, write_file, read_file_string, IoError};
    // Time
    pub use super::time::{now_unix_ms, now_unix_secs, elapsed_ms};
    // Collections
    pub use super::collections::{sort_i64, unique_i64, contains_i64, min_i64, max_i64, sum_i64};
}
