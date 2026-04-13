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
// Layer 2: real ChaCha20-Poly1305 AEAD, strengthened zeroization
// via zeroize crate, key rotation versioning, secret lifecycle
// management, enhanced Shamir GF(256) helpers.
//
// Architecture:
//   secret.rs         — SecretValue (zeroized), SensitiveBytes, SecretEntry, VersionedSecret
//   vault.rs          — In-memory vault with access control, lifecycle, and audit
//   envelope.rs       — DEK/KEK envelope encryption (ChaCha20-Poly1305 AEAD)
//   derivation.rs     — HKDF key derivation, password hashing
//   rotation.rs       — Rotation policies, status tracking, key version management
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
    SecretEntry, SecretId, SecretMetadata, SecretState, SecretType, SecretValue,
    SensitiveBytes, VersionedSecret,
};
pub use vault::{ExpirationStatus, SecretVault, VaultAccessPolicy, VaultHealth};
pub use envelope::{EncryptedSecret, decrypt_secret, encrypt_secret, generate_dek, re_encrypt_with_new_kek};
pub use derivation::{
    derive_key, derive_subkeys, hash_password, hkdf_derive, hkdf_expand, hkdf_extract,
    verify_password,
};
pub use rotation::{
    KeyRotationManager, KeyVersion, KeyVersionStatus, RotationPolicy, RotationResult,
    RotationStatus, check_rotation_status,
};
pub use sharing::{
    Share, evaluate_polynomial, gf256_add, gf256_div, gf256_inv, gf256_mul,
    lagrange_basis_at_zero, lagrange_interpolate, reconstruct, split,
};
pub use classification::{
    HandlingRules, HandlingViolation, LoggingLevel, ViolationSeverity,
    rules_for_classification, validate_handling,
};
pub use transit::{TransitPackage, package_for_transit, unpackage_transit, TRANSIT_EXPIRY_SECS};
pub use audit::{SecretAuditLog, SecretEvent, SecretEventType};
pub use error::SecretError;
