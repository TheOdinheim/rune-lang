# RUNE Build Log 13

> Previous file: [BUILD_LOG_12.md](BUILD_LOG_12.md)

---

## rune-audit-ext — Layer 2 Upgrade

**Date:** 2026-04-13
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 136 (87 existing + 49 new)
**Dependencies added:** hmac = "0.12"

### Overview

Upgraded `rune-audit-ext` with HMAC-SHA3-256 chain authentication,
storage abstraction, retention hardening with archive capability,
HashMap-based query indexing, condition-based event enrichment,
export format hardening with NDJSON/ECS support, and 7 new
meta-audit event types.

### Changes by Module

#### integrity.rs — HMAC Chain Authentication (PART 1)

- Added `ChainAuthenticator` struct with `chain_key: Vec<u8>`
- `compute_authenticated_hash()`: computes SHA3-256 base hash then
  applies HMAC-SHA3-256 with the chain key
- `verify_authenticated_chain()`: recomputes full chain with HMAC,
  returns `ChainStatus`
- `sign_chain_segment()`: signs a slice of events, returns Vec of
  HMAC signatures
- `verify_chain_segment()`: verifies signatures match events
- Uses `hmac::Hmac<Sha3_256>` type alias `HmacSha3_256`
- Different keys produce different hashes (prevents chain forgery)
- 7 new tests

#### store.rs — Storage Abstraction + Event Indexing (PARTS 2 & 4)

- Added `EventIndex` struct with `by_source`, `by_category`,
  `by_correlation`, `by_actor` HashMap<Key, Vec<usize>> fields
- `EventIndex::build()` and `EventIndex::add()` for construction
- `StorageStats` struct: total_events, unique_sources/categories/
  actors/correlations, oldest/newest timestamp, memory_estimate_bytes
- `AuditStore::storage_stats()`: aggregated statistics
- `AuditStore::memory_estimate()`: approximate memory usage in bytes
- `AuditStore::compact()`: shrinks internal allocations
- `AuditStore::snapshot()` / `restore()`: clone and rebuild
- `AuditStore::merge()`: merge another store, skip duplicates
- `AuditStore::rebuild_index()`: full reindex
- `AuditStore::archive_where()`: move events to archive instead of
  deleting (Critical+ events never archived)
- `AuditStore::archived_events()` / `archived_count()`: access archive
- `events_by_source/category/actor/correlation` now use EventIndex
  for O(1) lookup instead of linear scan
- Enricher integration: `with_enricher()` / `set_enricher()`, applied
  during `ingest()` before chain hashing
- 12 new tests

#### retention.rs — Retention Hardening (PART 3)

- `validate_policies()` -> `RetentionValidation`: checks non-positive
  max_age, empty names, duplicate names
- `RetentionValidation::is_valid()` predicate
- `dry_run()` -> `RetentionPreview`: total_affected, affected_sources
  HashMap, space_to_free_estimate
- `apply_with_archive()` -> `Vec<ArchiveResult>`: respects
  RetentionAction (Archive uses store.archive_where, Delete uses
  store.remove_where)
- `ArchiveResult` struct: policy_name, action, events_archived,
  events_deleted
- 7 new tests

#### enrichment.rs — Event Enrichment (PART 5, new module)

- `EnrichmentCondition` enum: SourceIs, CategoryIs, SeverityAtLeast,
  TagExists, Always
- `Enrichment` enum: AddTag (no duplicates), SetCorrelationId
  (no overwrite), EscalateSeverity (no downgrade), AddDetail (append)
- `EnrichmentRule`: name + condition + enrichments, returns count
  of applied enrichments
- `EventEnricher`: holds rules, `enrich()` applies all matching rules
- Integrated into `AuditStore::ingest()` — enrichment runs before
  chain hash computation
- 13 new tests

#### export.rs — Export Format Hardening (PART 6)

- CEF header: `CEF:0|RUNE|rune-audit-ext|1.0|action|detail|sev|ext`
  with proper pipe escaping via `cef_escape()`
- CEF correlation: `cs1Label=correlationId cs1=<id>` when present
- JSON Lines: `schema_version: "1.0"` and `export_timestamp` (ISO 8601)
  injected into each line
- NDJSON/ECS format: `@timestamp`, `event` (kind/category/outcome/
  action/severity), `source.component`, `user.name`, `message`,
  `labels` (rune_event_id/rune_subject), `tags`
- `ExportFormat::Ndjson` variant added
- `ExportValidation` struct: format, event_count, output_bytes, valid,
  issues
- `AuditExporter::validate_export()`: validates JSON parsability,
  CSV column consistency, CEF header presence
- `iso8601_from_epoch()` and `epoch_days_to_date()` civil calendar
  conversion helpers
- 10 new tests

#### audit.rs — New Meta-Audit Event Types (PART 7)

- 7 new `AuditExtEventType` variants: ChainAuthenticated,
  StorageCompacted, IndexRebuilt, EventEnriched, ArchiveCompleted,
  RetentionValidated, ExportValidated
- Display and type_name implementations for all 15 variants
- Existing test updated from 8 to 15 variant count
- 1 new test covering all 7 new event types

### README.md Fix

- Changed "21 Governance Libraries" to "19 Governance Libraries" in
  badge and status line (rune-rs and rune-python are FFI bridges, not
  governance libraries)

### Test Summary

```
cargo test -p rune-audit-ext
  136 passed; 0 failed

cargo test --workspace
  3,110 passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | HMAC chain auth prevents hash chain forgery without key; event enrichment auto-tags security events |
| Assumed Breach | Chain authentication detects tampered audit trails; archive preserves evidence |
| No Single Points of Failure | Storage snapshot/restore enables audit store replication; merge supports distributed collection |
| Zero Trust Throughout | HMAC requires explicit key; enrichment conditions are declarative and auditable |

---

## rune-web — Layer 2 Upgrade

**Date:** 2026-04-14
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 163 (114 existing + 49 new)
**Dependencies added:** (already present from Layer 1: sha3, hmac, rand, hex, regex)

### Overview

Upgraded `rune-web` with real HMAC-SHA3-256 request signing, cryptographic
session IDs with token hashing, regex-based request validation patterns,
sliding window rate limiting, regex-based data leakage scanning, CORS
hardening with preflight caching, gateway middleware and health metrics,
and 8 new audit event types.

### Changes by Module

#### signing.rs — Real HMAC-SHA3-256 Signing (PART 1)

- Replaced DJB2-based `simple_hash()` with real SHA3-256 via `Sha3_256`
- Replaced placeholder `hmac_sign()` with real `HmacSha3_256` HMAC
- Added `SignatureMetadata` struct (algorithm, signed_headers, timestamp,
  key_id, body_hash)
- Added `sign_with_metadata()` returning `(SignedRequest, SignatureMetadata)`
- Added `derive_signing_key()` for purpose-specific HMAC key derivation
- Canonical string: headers now lowercased/trimmed, duplicates concatenated
- 7 new tests

#### session.rs — Cryptographic Session IDs (PART 2)

- `generate_session_id()`: 32 crypto-random bytes, hex-encoded with `sess_` prefix
- `SessionTokenHasher::hash_token()`: SHA3-256 hash for storage
- Sessions stored by hashed key internally, raw ID returned to caller
- `resolve_key()` for transparent raw-or-hashed lookup
- `SessionBinding` struct with `bind_to_ip()` / `bind_to_user_agent()`
- `validate_with_binding()` checks IP and User-Agent bindings
- `record_request()` / `session_request_count()` / `session_request_rate()`
- Fixed `invalidate_all_for_identity` and `cleanup_expired` to use HashMap keys
- 10 new tests

#### request.rs — Regex Request Validation (PART 3)

- Added `blocked_patterns: Vec<(String, Regex)>` to `RequestValidator`
- `with_default_blocked_patterns()`: null byte, unicode normalization,
  HTTP response splitting, SSTI
- `add_blocked_pattern()` / `check_blocked_patterns()`
- `validate_body_content_type()` with allowed types list
- `validate_body_size_by_method()` (GET/HEAD/DELETE/OPTIONS reject bodies)
- `is_valid_ipv4()` / `is_private_ip()` / `is_loopback()` helpers
- 10 new tests

#### gateway.rs — Sliding Window Rate Limiting & Middleware (PARTS 4 & 7)

- `SlidingWindowLimiter`: timestamp-based sliding window with `check()`/`reset()`
- `RateLimitHeaders`: X-RateLimit-Limit/Remaining/Reset, Retry-After
- `EndpointRateLimiter`: per-endpoint overrides with default fallback
- `RateLimiterStats` struct
- `MiddlewareFn` type alias, `MiddlewareResult` enum, `GatewayContext` struct
- `GatewayTiming` struct (request_received/auth_check/rate_limit/validation/total)
- `GatewayHealthMetrics` with `p50_latency_us()`, `p99_latency_us()`,
  `requests_per_second()`
- 14 new tests

#### response.rs — Regex Data Leakage Scanner (PART 5)

- `DataLeakageScanner` with 9 compiled regex patterns: internal IPs,
  stack traces, file paths, secrets, debug info, database connection
  strings, AWS credentials, private keys, error details
- 4 new `DataLeakageType` variants: DatabaseConnectionString, AwsCredential,
  PrivateKey, ErrorDetail
- Made `is_internal_ip` public
- 9 new tests (including existing display test updated 5→9 variants)

#### cors.rs — CORS Hardening (PART 6)

- `is_valid_origin()`: validates scheme, no path/query/fragment
- `PreflightCache` with TTL-based expiry, `get()`/`put()`/`cleanup_expired()`
- `CorsViolation` struct for logging
- `vary_origin_header()`: returns `Vary: Origin` for non-wildcard policies
- 8 new tests

#### audit.rs — New Audit Event Types (PART 8)

- 8 new `WebEventType` variants: HmacSignatureVerified, SessionTokenHashed,
  RegexPatternBlocked, SlidingWindowLimited, DataLeakageRegexMatch,
  CorsViolationLogged, MiddlewareExecuted, GatewayTimingRecorded
- Display implementations for all 23 variants
- Existing variant count test updated from 15 to 23

### Test Summary

```
cargo test -p rune-web
  163 passed; 0 failed

cargo test --workspace
  3,159 passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | Real HMAC-SHA3-256 replaces placeholder hashing; regex patterns catch injection at the gate |
| Assumed Breach | Session token hashing prevents stolen-database replay; IP/UA binding detects hijacking |
| No Single Points of Failure | Sliding window + endpoint rate limiting provide layered throttling; preflight caching reduces CORS overhead |
| Zero Trust Throughout | Cryptographic session IDs resist guessing; data leakage scanner with 9 regex patterns catches secrets before they leave |

---

## rune-identity — Layer 2 Upgrade

**Date:** 2026-04-14
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 188 (120 existing + 68 new)
**Dependencies added:** sha3 = "0.10", hmac = "0.12", rand = "0.8" (hex already present)

### Overview

Upgraded `rune-identity` with SHA3-256 credential hashing, cryptographic
session tokens with token-hash storage, enhanced trust scoring with
exponential decay, attestation chain verification with detailed results,
TOTP MFA with backup codes, identity federation with trust policies,
and 15 new audit event types.

### Changes by Module

#### credential.rs — SHA3-256 Credential Hashing (PART 1)

- `HashedCredential` struct: hash/salt/algorithm/created_at
- `from_password()`: 16-byte crypto random salt, SHA3-256(salt||password)
- `hash_credential_sha3()`: internal SHA3-256 helper
- `verify_credential()`: constant-time XOR comparison
- `CredentialStrengthResult`: score 0-100, meets_minimum, issues
- `validate_credential_strength()` / `validate_credential_strength_with_username()`
  with 8 checks: length≥12, uppercase, lowercase, digit, special, repeated
  chars (>3), common password list (30 entries), username containment
- `CredentialHistory`: previous_hashes, is_reused, record_change,
  days_since_change, needs_rotation, max_history enforcement
- 16 new tests

#### session.rs — Cryptographic Session Tokens (PART 2)

- `generate_session_token()`: 32 crypto-random bytes, hex with `idt_` prefix
- `hash_session_token()`: SHA3-256 for storage keying
- `session_key()`: transparent hash-or-legacy lookup
- Sessions stored by token hash internally, raw token returned to caller
- `SessionFingerprint`: SHA3-256 hashed IP + User-Agent, never stores raw
- `set_fingerprint()` / `validate_fingerprint()` on SessionManager
- `concurrent_session_count()` / `revoke_oldest_sessions()` /
  `sessions_by_identity()`
- 14 new tests

#### trust.rs — Enhanced Trust Scoring (PART 3)

- `TrustAdjustmentReason` enum: 8 variants with `default_impact()`
  (SuccessfulAuthentication +0.05, SuspiciousActivity -0.20, MfaVerified +0.15, etc.)
- `TrustAdjustment` struct: reason, delta, timestamp, old/new score
- `TrustScoreManager`: score, exponential decay `score * e^(-rate * hours)`,
  adjust_trust, trust_history, trust_trend (Improving/Stable/Degrading via
  half-split average comparison with ±0.02 threshold)
- `TrustTrend` enum: Improving/Stable/Degrading
- `required_trust_level()`: read→Low, write→Medium, admin→High, critical→Full
- 11 new tests

#### attestation.rs — Attestation Chain Verification (PART 4)

- `ChainVerificationResult`: valid, verified_links, broken_at, timestamps
- `verify_attestation_chain()`: returns detailed result instead of bool
- `ChainAnchor`: root_hash, tip_hash, chain_length
- `anchor_chain()`: compact external verification summary
- 4 new `AttestationType` variants: BiometricVerification, HardwareToken,
  CertificateChain, CrossReferenceAttestation
- 5 new tests

#### authn.rs — TOTP MFA & Backup Codes (PART 5)

- `TotpConfig`: secret, digits (default 6), period_seconds (default 30)
- `generate_totp_code()`: HMAC-SHA3-256 with RFC 6238 truncation
- `verify_totp_code()`: clock skew window (past + future)
- `BackupCodeSet`: 8-char alphanumeric codes stored as SHA3-256 hashes,
  single-use verify with remaining count
- `MfaPolicy`: required_for operations, grace_period_ms, allowed_methods
- 14 new tests

#### federation.rs — Identity Federation (PART 6)

- `FederatedIdentity`: local_identity_id, provider, external_id,
  linked_at, last_synced_at, trust_modifier
- `FederatedIdentityStore`: link/unlink/find_by_external_id/identities_for
- `FederationTrustPolicy`: trusted_providers map with trust levels
- 7 new tests

#### audit.rs — New Audit Event Types (PART 7)

- 15 new `IdentityEventType` variants: CredentialHashed, CredentialVerified,
  CredentialStrengthChecked, CredentialRotated, SessionTokenHashed,
  SessionFingerprintCreated, SessionFingerprintMismatch, TrustScoreAdjusted,
  TrustDecayApplied, AttestationChainVerified, TotpVerified, BackupCodeUsed,
  FederatedIdentityLinked, FederatedIdentityUnlinked, MfaPolicyEnforced
- Display implementations for all 34 variants (19 original + 15 new)
- SessionFingerprintMismatch and TrustDecayApplied added to is_security_event()
- 2 new tests

### Test Summary

```
cargo test -p rune-identity
  188 passed; 0 failed

cargo test --workspace
  all passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | SHA3-256 credential hashing with constant-time verify; TOTP MFA with backup codes; MFA policy enforcement |
| Assumed Breach | Session tokens stored as hashes prevent stolen-DB replay; SessionFingerprint detects session hijacking; credential history prevents reuse |
| No Single Points of Failure | Federation supports multiple identity providers; trust scoring combines multiple adjustment signals |
| Zero Trust Throughout | Cryptographic session tokens resist guessing; exponential trust decay requires continuous verification; attestation chain verification with detailed break detection |
