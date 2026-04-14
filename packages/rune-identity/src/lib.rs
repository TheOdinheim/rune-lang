// ═══════════════════════════════════════════════════════════════════════
// rune-identity — Identity Lifecycle, Authentication, Sessions & Trust
//
// Provides identity management for the RUNE governance ecosystem:
// identity types, credential storage, authentication flows, session
// management, continuous trust scoring, attestation chains, verifiable
// claims, federation interfaces, and audit logging.
// ═══════════════════════════════════════════════════════════════════════

pub mod identity;
pub mod identity_type;
pub mod credential;
pub mod authn;
pub mod session;
pub mod trust;
pub mod attestation;
pub mod claims;
pub mod federation;
pub mod audit;
pub mod error;

// ── Re-exports ───────────────────────────────────────────────────────

pub use identity::{Identity, IdentityBuilder, IdentityId, IdentityStatus, IdentityStore};
pub use identity_type::{
    AutonomyLevel, DeviceClass, GovernanceLevel, IdentityType, PasswordPolicy, PasswordViolation,
};
pub use credential::{
    Credential, CredentialId, CredentialStatus, CredentialStore, CredentialType, TokenType,
    // Layer 2
    HashedCredential, CredentialStrengthResult, CredentialHistory,
    verify_credential, validate_credential_strength, validate_credential_strength_with_username,
};
pub use authn::{
    AuthnFailureReason, AuthnMethod, AuthnRequest, AuthnResult, Authenticator, MfaMethod,
    // Layer 2
    TotpConfig, BackupCodeSet, MfaPolicy,
    generate_totp_code, verify_totp_code,
};
pub use session::{
    Session, SessionConfig, SessionId, SessionManager, SessionStatus, SessionValidation,
    // Layer 2
    SessionFingerprint,
};
pub use trust::{
    TrustCalculator, TrustEvaluation, TrustFactor, TrustFactorType, TrustLevel, TrustPolicy,
    TrustScore,
    // Layer 2
    TrustAdjustment, TrustAdjustmentReason, TrustScoreManager, TrustTrend,
    required_trust_level,
};
pub use attestation::{
    AttestationChain, AttestationType, IdentityAttestation,
    // Layer 2
    ChainVerificationResult, ChainAnchor,
    verify_attestation_chain, anchor_chain,
};
pub use claims::{Claim, ClaimSet, ClaimType};
pub use federation::{
    FederationProtocol, FederationProvider, OidcClaims, SamlAssertion,
    // Layer 2
    FederatedIdentity, FederatedIdentityStore, FederationTrustPolicy,
};
pub use audit::{IdentityAuditEvent, IdentityAuditLog, IdentityEventType};
pub use error::IdentityError;
