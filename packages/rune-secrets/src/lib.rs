// ═══════════════════════════════════════════════════════════════════════
// rune-secrets — Secret Lifecycle Management
//
// Sensitive data storage, encryption, key derivation, rotation,
// sharing, and classification for the RUNE governance ecosystem.
//
// Design principles:
//   - Security Baked In: zeroization on drop, envelope encryption,
//     PQC-first HKDF, classification-driven handling rules
//   - Assumed Breach: every access is audit-logged, integrity hashes
//     on all encrypted data, Shamir sharing for key escrow
//   - Zero Trust Throughout: Bell-LaPadula clearance checks,
//     transit encryption with 5-minute expiry, usage limits
//   - No Single Points of Failure: DEK/KEK separation, versioned
//     rotation, K-of-N secret sharing
//
// Architecture:
//   secret.rs         — SecretValue (zeroized), SecretEntry, VersionedSecret
//   vault.rs          — In-memory vault with access control and audit
//   envelope.rs       — DEK/KEK envelope encryption
//   derivation.rs     — HKDF key derivation, password hashing
//   rotation.rs       — Rotation policies and status tracking
//   sharing.rs        — Shamir's Secret Sharing over GF(256)
//   classification.rs — Handling rules per classification level
//   transit.rs        — Cross-boundary transit encryption
//   audit.rs          — Secret operation event logging
//   error.rs          — SecretError variants
// ═══════════════════════════════════════════════════════════════════════

pub mod secret;
pub mod vault;
pub mod envelope;
pub mod derivation;
pub mod rotation;
pub mod sharing;
pub mod classification;
pub mod transit;
pub mod audit;
pub mod error;

pub use secret::{
    SecretEntry, SecretId, SecretMetadata, SecretState, SecretType, SecretValue, VersionedSecret,
};
pub use vault::{SecretVault, VaultAccessPolicy, VaultHealth};
pub use envelope::{EncryptedSecret, decrypt_secret, encrypt_secret, generate_dek, re_encrypt_with_new_kek};
pub use derivation::{derive_key, derive_subkeys, hash_password, hkdf_expand, hkdf_extract, verify_password};
pub use rotation::{RotationPolicy, RotationResult, RotationStatus, check_rotation_status};
pub use sharing::{Share, reconstruct, split};
pub use classification::{
    HandlingRules, HandlingViolation, LoggingLevel, ViolationSeverity,
    rules_for_classification, validate_handling,
};
pub use transit::{TransitPackage, package_for_transit, unpackage_transit, TRANSIT_EXPIRY_SECS};
pub use audit::{SecretAuditLog, SecretEvent, SecretEventType};
pub use error::SecretError;
