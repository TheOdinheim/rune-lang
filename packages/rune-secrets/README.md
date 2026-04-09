# rune-secrets

Secret lifecycle management for the RUNE governance ecosystem.

## Overview

`rune-secrets` provides secure storage, encryption, key derivation, rotation, sharing, and classification-based handling for sensitive data. Every operation is audit-logged and enforces the four RUNE pillars.

## Modules

| Module | Purpose |
|--------|---------|
| `secret` | `SecretValue` with zeroization on Drop, metadata, versioning |
| `vault` | In-memory secret store with Bell-LaPadula access control |
| `envelope` | DEK/KEK envelope encryption (HMAC-SHA3-256 XOR placeholder) |
| `derivation` | HKDF (RFC 5869) key derivation using HMAC-SHA3-256 |
| `rotation` | Rotation policies (aggressive/standard/relaxed/token), status tracking |
| `sharing` | Shamir's Secret Sharing over GF(256) |
| `classification` | Handling rules per classification level, violation detection |
| `transit` | Cross-boundary transit encryption with 5-minute expiry |
| `audit` | Secret operation event logging with filtering and export |
| `error` | `SecretError` with 17 typed variants |

## Four-Pillar Alignment

- **Security Baked In**: Zeroization on drop, envelope encryption, PQC-first HKDF, classification-driven handling rules
- **Assumed Breach**: Every access is audit-logged, integrity hashes on all encrypted data, Shamir sharing for key escrow
- **Zero Trust Throughout**: Bell-LaPadula clearance checks, transit encryption with 5-minute expiry, usage limits
- **No Single Points of Failure**: DEK/KEK separation, versioned rotation, K-of-N secret sharing

## Usage

```rust
use rune_secrets::*;
use rune_permissions::ClassificationLevel;

// Create a vault
let mut vault = SecretVault::new(vec![0xAA; 32]);

// Store a secret
let meta = SecretMetadata::new(
    SecretType::ApiKey,
    ClassificationLevel::Confidential,
    "admin",
);
vault.store(
    SecretId::new("my-api-key"),
    SecretValue::from_str("sk_live_abc123"),
    meta,
    "admin",
    1000,
).unwrap();

// Retrieve with clearance check
let policy = VaultAccessPolicy::new(ClassificationLevel::TopSecret);
let value = vault.retrieve(&SecretId::new("my-api-key"), &policy, "user", 1100).unwrap();
value.expose_for(|bytes| {
    // Use the secret bytes within this scope
});
```
