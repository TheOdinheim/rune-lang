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

---

## rune-shield — Layer 2 Upgrade

**Date:** 2026-04-13
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 164 (98 existing + 66 new)
**Dependencies added:** regex = "1"

### Overview

Upgraded `rune-shield` from keyword-based heuristics to production-grade
regex-based pattern matching, token classification, content fingerprinting,
and enhanced exfiltration analysis. All 98 existing tests continue to pass
unchanged. All existing public APIs preserved.

### Changes by Module

#### pattern.rs — Regex Injection Detection (NEW, PART 1)

New module for configurable regex-based injection detection:

- **InjectionCategory** enum: PromptInjection, JailbreakAttempt,
  IndirectInjection, SqlInjection, CommandInjection, TemplateInjection
- **InjectionPattern** struct: id, name, compiled Regex, category,
  severity (f64), description, false_positive_rate
- **Built-in pattern sets**: `prompt_injection_patterns()` (12 patterns),
  `jailbreak_patterns()` (6 patterns), `indirect_injection_patterns()`
  (3 patterns) — 21 total regex patterns
- **InjectionScorer**: accumulates severity of matching patterns, caps at
  1.0, `is_injection = score >= threshold`
- **InjectionScore**: score, matched_patterns, category_scores breakdown,
  is_injection flag, detail string

16 tests for pattern matching, scoring, categories, custom patterns.

#### token.rs — Token Classification (NEW, PART 2)

New module for regex-based PII and secret token detection:

- **PiiTokenType** enum: Email, PhoneNumber, SocialSecurityNumber,
  CreditCardNumber, IpAddress, DateOfBirth, StreetAddress, Name, Custom
- **SecretTokenType** enum: ApiKey, AwsAccessKey, AwsSecretKey,
  GitHubToken, JwtToken, PrivateKey, Password, ConnectionString, Custom
- **TokenClassifier**: 5 PII patterns + 4 secret patterns built-in
- Methods: classify, contains_pii, contains_secrets, pii_types_found,
  secret_types_found, redact_pii, redact_secrets, redact_all

17 tests for detection, redaction, clean text, sorted classification.

#### fingerprint.rs — Content Fingerprinting (NEW, PART 3)

New module for SHA3-256 content fingerprinting and entropy analysis:

- **ContentFingerprint**: hash, normalized_length, token_count, entropy
- **fingerprint()**: normalize (lowercase, collapse whitespace, remove
  punctuation) then SHA3-256 hash
- **shannon_entropy()**: byte-level Shannon entropy calculation
- **FingerprintStore**: record/seen_count/is_known/record_attack/
  is_known_attack/known_attack_patterns tracking

12 tests for determinism, normalization, entropy, store operations.

#### exfiltration.rs — Enhanced Exfiltration Detection (PART 4)

Added encoded data detection and ExfiltrationAnalyzer:

- **contains_base64_block()**: regex for 32+ char base64 blocks
- **contains_hex_block()**: regex for 32+ char hex blocks
- **contains_sensitive_json_keys()**: checks for password/secret/token/
  api_key/authorization/credential/ssn JSON keys
- **ExfiltrationAnalysis**: pii_found, secrets_found, encoded_data_found,
  sensitive_json_found, pii_types, secret_types, risk_score, detail
- **ExfiltrationAnalyzer**: wraps TokenClassifier + encoded data helpers,
  produces risk_score (PII=0.3, secrets=0.5, encoded=0.2, json=0.2,
  capped at 1.0)

9 new tests (13 existing unchanged).

#### memory.rs — Immune Memory Enhancement (PART 5)

Added fingerprint recording and attack statistics:

- **record_fingerprint()**: records fingerprint hash as `fp:{hash}` attack
- **attack_frequency(window_ms, now)**: count attacks within time window
- **top_attack_categories(n)**: top N categories by frequency
- **unique_attack_fingerprints()**: count fp:-prefixed signatures

4 new tests (7 existing unchanged).

#### audit.rs — New Event Types (PART 7)

Added 6 new ShieldEventType variants:

- `InjectionPatternMatched { pattern_id, score }`
- `PiiDetected { pii_type, count }`
- `SecretDetected { secret_type }`
- `ExfiltrationAttempt { risk_score, detail }`
- `FingerprintRecorded { hash }`
- `AttackPatternRecognized { fingerprint, seen_count }`

Updated Display, kind(), existing display-all test expanded. 1 new test
(5 existing unchanged).

#### shield.rs — Shield Verdict Enhancement (PART 6)

Integrated Layer 2 components into Shield engine:

- 4 new pub fields: injection_scorer, token_classifier,
  exfiltration_analyzer, fingerprint_store
- **Input pipeline**: InjectionScorer runs alongside existing
  InjectionDetector; confidence = max(original, regex_score); pattern
  matches logged to audit; content fingerprinted for attack tracking
- **Output pipeline**: ExfiltrationAnalyzer runs before OutputFilter;
  PII/secret/exfiltration events logged to audit
- All existing 13 tests pass unchanged

7 new tests (13 existing unchanged).

#### lib.rs — Updated Module Declarations and Re-exports

3 new module declarations: `pub mod pattern`, `pub mod token`,
`pub mod fingerprint`

New public exports: InjectionCategory, InjectionPattern, InjectionScore,
InjectionScorer, prompt_injection_patterns, jailbreak_patterns,
indirect_injection_patterns, PiiTokenType, SecretTokenType,
TokenClassification, TokenClassifier, TokenType, ContentFingerprint,
FingerprintStore, shannon_entropy, fingerprint, ExfiltrationAnalysis,
ExfiltrationAnalyzer, contains_base64_block, contains_hex_block,
contains_sensitive_json_keys

### Test Summary

| Module | Existing | New | Total |
|---|---|---|---|
| pattern.rs | 0 | 16 | 16 |
| token.rs | 0 | 17 | 17 |
| fingerprint.rs | 0 | 12 | 12 |
| exfiltration.rs | 13 | 9 | 22 |
| memory.rs | 7 | 4 | 11 |
| audit.rs | 5 | 1 | 6 |
| shield.rs | 13 | 7 | 20 |
| adversarial.rs | 7 | 0 | 7 |
| injection.rs | 13 | 0 | 13 |
| input.rs | 11 | 0 | 11 |
| quarantine.rs | 10 | 0 | 10 |
| output.rs | 6 | 0 | 6 |
| policy.rs | 6 | 0 | 6 |
| response.rs | 6 | 0 | 6 |
| error.rs | 1 | 0 | 1 |
| **Total** | **98** | **66** | **164** |

### Backward Compatibility

- All 98 existing tests pass unchanged
- All public function signatures unchanged
- All public type names unchanged
- Existing InjectionDetector, ExfiltrationDetector, ImmuneMemory APIs
  fully preserved
- Shield struct gains 4 new pub fields (additive only)
- New components enhance detection without altering existing behavior:
  confidence = max(original, regex_scorer) ensures strictly better
  detection

### Dependencies

```toml
regex = "1"  # Regex-based pattern matching for injection/token detection
```
