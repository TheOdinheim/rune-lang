# RUNE Build Log 12

> Previous file: [BUILD_LOG_11.md](BUILD_LOG_11.md)

---

## rune-secrets — Layer 2 Upgrade

**Date:** 2026-04-13
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 166 (131 existing + 35 new)
**Dependencies added:** chacha20poly1305 = "0.10", rand = "0.8", zeroize = { version = "1", features = ["derive"] }

### Overview

Upgraded `rune-secrets` from placeholder cryptographic primitives to
production-grade implementations while maintaining full backward
compatibility with the existing public API.

### Changes by Module

#### envelope.rs — ChaCha20-Poly1305 AEAD (PART 2)

Replaced the XOR stream cipher placeholder with ChaCha20-Poly1305
authenticated encryption:

- **Random DEK generation**: `encrypt_secret` now generates a random
  32-byte DEK via `rand::thread_rng()` instead of deriving deterministically
  from nonce + id
- **AEAD nonce derivation**: `derive_aead_nonce(input_nonce, label)` hashes
  input nonce + label via SHA3-256, truncated to 12 bytes. Separate nonces
  for data encryption ("data") and DEK wrapping ("dek")
- **Key normalization**: `normalize_key(key)` hashes any-length key to
  32 bytes via SHA3-256, ensuring ChaCha20-Poly1305 always gets a valid key
- **DEK zeroization**: DEK bytes are zeroized after use via `zeroize` crate
- **Ciphertext format**: ciphertext now includes 16-byte Poly1305 auth tag
  (ciphertext.len() == plaintext.len() + 16)
- **Wrong-key behavior**: wrong KEK now produces AEAD authentication error
  instead of garbage output (strictly stronger security)
- `generate_dek(seed)` public function unchanged (SHA3-256 of seed)

Tests updated:
- `test_xor_cipher_roundtrip` → replaced with `test_aead_nonce_derivation`
- `test_re_encrypt_old_kek_produces_wrong_data` → now asserts error
  (AEAD correctly rejects wrong key)
- Added: `test_wrong_kek_rejected_by_aead`, `test_ciphertext_includes_auth_tag`,
  `test_dek_zeroized_after_encrypt`

#### transit.rs — AEAD compatibility update

- `test_transit_wrong_key_produces_wrong_data` → renamed to
  `test_transit_wrong_key_rejected`, asserts error instead of garbage
  (AEAD correctly rejects wrong transit key)

#### secret.rs — SensitiveBytes & zeroize (PART 6)

- **SecretValue Drop**: replaced manual `write_volatile` loop with
  `data.zeroize()` from the `zeroize` crate
- **SensitiveBytes**: new general-purpose wrapper type for sensitive byte
  data, derives `Zeroize` and `ZeroizeOnDrop`
  - `new(data)`, `len()`, `is_empty()`, `expose()`, `expose_for(f)`
  - Debug impl: `[SENSITIVE N bytes]` (never leaks content)
  - Constant-time PartialEq/Eq

7 new tests for SensitiveBytes.

#### sharing.rs — Public GF(256) helpers (PART 3)

Made GF(256) arithmetic functions public:
- `gf256_add`, `gf256_mul`, `gf256_inv`, `gf256_div`

Added named public functions:
- `evaluate_polynomial(coefficients, x)` — evaluate polynomial at point x
  in GF(256)
- `lagrange_basis_at_zero(x_coords, i)` — Lagrange basis coefficient for
  share i evaluated at x=0
- `lagrange_interpolate(points)` — Lagrange interpolation at x=0 given
  (x, y) points

5 new tests for polynomial evaluation and Lagrange interpolation.

#### rotation.rs — Key version management (PART 4)

Added key rotation versioning types:

- **KeyVersionStatus**: `Active` / `DecryptOnly` / `Retired` / `Destroyed`
  with `can_encrypt()`, `can_decrypt()`, `is_usable()` predicates
- **KeyVersion**: version number, status, timestamps (created_at,
  retired_at, destroyed_at), key_id. State machine transitions enforced:
  Active → DecryptOnly → Retired → Destroyed
- **KeyRotationManager**: manages a sequence of key versions
  - `create_version(now)` — creates new Active version, demotes current
    Active to DecryptOnly
  - `active_version()`, `version(n)`, `decryptable_versions()`
  - `retire_version(n, now)`, `destroy_version(n, now)`

10 new tests for key version lifecycle.

#### vault.rs — Secret lifecycle management (PART 5)

Added lifecycle management to SecretVault:

- **ExpirationStatus**: `NoExpiry` / `Active` / `ExpiringSoon` / `Expired`
  with `is_expired()`, `is_expiring_soon()` predicates and Display
- `set_expiration(id, expires_at, actor, now)` — update secret expiration
- `check_expiration(id, now, threshold)` — check expiration status with
  configurable "expiring soon" threshold
- `expired_secrets(now)` — list all expired secret IDs
- `cleanup_expired(actor, now)` — mark expired Active secrets as Expired state
- `access_count(id)` — get usage count for a secret
- `last_accessed(id)` — get last-updated timestamp

11 new tests for lifecycle management.

#### derivation.rs — HKDF alias (PART 1)

- `hkdf_derive(salt, ikm, info, length)` — alias for `derive_key()`
  (HKDF implementation was already real HMAC-SHA3-256 from Layer 1)

1 new test.

#### audit.rs — New event types (PART 7)

Added 6 new SecretEventType variants:
- `KeyRotated`, `SecretExpired`, `Zeroized`, `KeyDerived`,
  `DecryptionFailed`, `ShamirReconstructed`

#### lib.rs — Updated re-exports

New public exports:
- `SensitiveBytes`, `ExpirationStatus`
- `KeyVersion`, `KeyVersionStatus`, `KeyRotationManager`
- `hkdf_derive`
- `gf256_add`, `gf256_mul`, `gf256_inv`, `gf256_div`
- `evaluate_polynomial`, `lagrange_basis_at_zero`, `lagrange_interpolate`

### Test Summary

| Module | Existing | New | Total |
|---|---|---|---|
| secret.rs | 28 | 7 | 35 |
| envelope.rs | 9* | 3 | 12 |
| sharing.rs | 17 | 5 | 22 |
| rotation.rs | 11 | 10 | 21 |
| vault.rs | 14 | 11 | 25 |
| derivation.rs | 15 | 1 | 16 |
| transit.rs | 7* | 0 | 7 |
| audit.rs | 11 | 0 | 11 |
| classification.rs | 12 | 0 | 12 |
| error.rs | 1 | 0 | 1 |
| **Total** | **125** | **37** | **166** |

*Note: 3 tests updated to reflect AEAD behavior (wrong key → error instead
of garbage). These test the same scenarios with strictly stronger assertions.

### Backward Compatibility

- All public function signatures unchanged
- All public type names unchanged
- EncryptedSecret struct fields unchanged
- Envelope encryption is stronger (AEAD vs XOR) — same API, better security
- 3 tests updated to assert AEAD error rejection instead of XOR garbage
  output (the correct behavior for an authenticated cipher)

### Dependencies

```toml
chacha20poly1305 = "0.10"  # AEAD cipher for envelope encryption
rand = "0.8"               # Random DEK generation
zeroize = { version = "1", features = ["derive"] }  # Memory zeroization
```
