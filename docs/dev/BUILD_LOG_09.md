# Build Log 09

## 2026-04-09 — M10 Layer 1: rune::crypto — PQC-First Cryptographic Primitives

### What was built

Standard library cryptographic module (`src/stdlib/crypto/`) implementing PQC-first design: SHA-3 (FIPS 202) for hashing, ML-DSA-65 placeholder (FIPS 204 interface) for signatures, HMAC-SHA3-256 for symmetric MAC, and ML-KEM-768 placeholder (FIPS 203 interface) for key encapsulation. Classical algorithms (SHA-256, HMAC-SHA256) are explicit fallbacks, not defaults. Backward compatible with M5 audit trail.

### Four-pillar alignment

- **Security Baked In**: PQC is the default — SHA-3 and ML-DSA, not SHA-256 and HMAC. Classical requires explicit opt-in.
- **Assumed Breach**: Constant-time comparison for MAC verification prevents timing side channels
- **Zero Trust Throughout**: All crypto operations carry the `crypto` effect — calling without declaring the effect is a compile-time error
- **No Single Points of Failure**: Multiple algorithm choices per operation; single-file swap when stable PQC crates arrive

### Files created / modified

| File | Purpose | Changes |
|------|---------|---------|
| src/stdlib/mod.rs | Standard library root module | New (14 lines) |
| src/stdlib/crypto/mod.rs | Crypto module: re-exports, defaults, effect docs, interop tests | New (~155 lines) |
| src/stdlib/crypto/hash.rs | SHA-3 (FIPS 202) + SHA-256 hashing with generic interface | New (~120 lines) |
| src/stdlib/crypto/sign.rs | ML-DSA-65 placeholder, HMAC-SHA3-256, HMAC-SHA256, generic sign/verify | New (~175 lines) |
| src/stdlib/crypto/verify.rs | Hash verification, signed hash verification | New (~60 lines) |
| src/stdlib/crypto/kem.rs | ML-KEM-768 placeholder (FIPS 203 interface, returns NotImplemented) | New (~65 lines) |
| src/stdlib/crypto/error.rs | CryptoError enum with Display/Error impls | New (~50 lines) |
| src/lib.rs | Register `pub mod stdlib` | +1 line |
| Cargo.toml | Add `sha3 = "0.10"` dependency | +1 line |

### Architecture

**PQC-first design:**
- Default hash: SHA3-256 (FIPS 202), not SHA-256
- Default signature: ML-DSA-65 (FIPS 204), not HMAC-SHA256
- Default KEM: ML-KEM-768 (FIPS 203), not X25519
- Classical algorithms behind explicit enum variants, not default paths

**ML-DSA placeholder strategy:**
- Function signatures match real ML-DSA-65 (key, data → signature)
- Internally uses HMAC-SHA3-256 as deterministic stand-in
- When stable `ml-dsa` crate arrives: replace `sign.rs` bodies only
- Interface, tests, and all callers remain unchanged

**Backward compatibility:**
- `hmac_sha256()` output matches M5 `audit::crypto::sign()` exactly
- `sha256_hex()` output matches M5 `audit::crypto::hash()` exactly
- Verified by explicit interoperability tests comparing byte-for-byte

**Effect enforcement:**
- CryptoEffects struct documents that all operations require `effects { crypto }`
- Enforcement via existing FFI effect system from M8 Layer 1
- When called via extern declarations, the type checker enforces the effect

### Test summary

40 new tests (856 total, all passing):

| Area | Tests | What's covered |
|------|-------|----------------|
| Hash | 11 | SHA3-256 (size, determinism, uniqueness, hex, NIST vector), SHA3-512, SHA-256 (size, NIST vector), generic dispatch, default |
| Signatures | 11 | HMAC-SHA3-256 (consistency, key diff, verify ok/fail), HMAC-SHA256, ML-DSA (sign, verify ok/fail, dispatch), default |
| Verification | 3 | verify_hash correct/wrong, verify_signed_hash |
| KEM | 3 | keygen/encapsulate/decapsulate all return NotImplemented |
| Errors | 6 | All CryptoError variants: Display messages with correct content |
| Interop | 2 | hmac_sha256 matches audit::crypto::sign, sha256 matches audit::crypto::hash |
| Defaults | 4 | default_hash/sign/verify use PQC algorithms |

### Decisions

- **sha3 crate (non-optional)**: SHA-3 is the PQC-default hash. Small dependency, always available. No feature gate needed.
- **No ed25519-dalek yet**: Classical Ed25519 deferred to when actually needed. HMAC-SHA3-256 handles all current signing needs.
- **Placeholder over stub**: ML-DSA and ML-KEM have correct interfaces that will work with real implementations. Better than empty functions.
- **Constant-time MAC comparison**: Prevents timing attacks on verification. Uses XOR-accumulate pattern.
- **No changes to audit.rs**: Existing M5 audit trail untouched. Swap happens in Layer 4.
