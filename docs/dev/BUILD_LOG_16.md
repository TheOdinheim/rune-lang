# RUNE Build Log 16

> Previous file: [BUILD_LOG_15.md](BUILD_LOG_15.md)

---

## rune-shield Layer 3

**Test count**: 164 → 233 (+69 tests, zero failures)

**Clippy**: Zero rune-shield-specific warnings

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~180 | 10 | DetectionRuleBackend trait + InMemoryShieldBackend |
| `threat_feed.rs` | ~140 | 9 | ThreatFeedSource trait + InMemoryThreatFeed |
| `export_format.rs` | ~340 | 11 | VerdictExporter trait + 5 format implementations |
| `verdict_stream.rs` | ~250 | 9 | VerdictSubscriber trait + registry + filtering |
| `enforcement.rs` | ~230 | 10 | EnforcementHook trait + recording + chaining |
| `signature_loader.rs` | ~270 | 10 | SignatureLoader trait + JSON parsing + SHA3-256 integrity |
| `metrics_export.rs` | ~280 | 10 | ShieldMetricsExporter trait + Prometheus + OTel |

### Trait Contracts

- **DetectionRuleBackend**: 14 methods — store/retrieve/delete/list rules, signatures, verdicts, flush, backend_info. InMemoryShieldBackend reference implementation with duplicate-rule rejection.
- **ThreatFeedSource**: 7 methods — fetch_indicators/refresh/indicator_count/source_name/last_refreshed/supported_indicator_types/is_active. InMemoryThreatFeed with TTL-aware expiration (purge_expired, active_indicators).
- **VerdictExporter**: 4 methods — export_verdict/export_batch/format_name/content_type. Five implementations: JsonVerdictExporter (native JSON with governance_decision), StixVerdictExporter (STIX 2.1 sighting, confidence 0-100), OcsfVerdictExporter (class_uid 2004, severity_id 1-6), MispVerdictExporter (MISP event with Attribute array), SigmaRuleExporter (Sigma rule JSON for DetectionRules).
- **VerdictSubscriber**: 3 methods — on_verdict/subscriber_id/is_active. VerdictSubscriberRegistry with register/notify/notify_batch/active_count/remove_inactive. VerdictCollector records all verdicts. FilteredVerdictSubscriber filters by min severity, action type, or rule id.
- **EnforcementHook**: 4 methods — on_action/hook_id/supported_actions/is_active. MitigationAction enum (Allow, Deny, Quarantine, Redact, Rewrite, Escalate with reason+verdict_ref). RecordingEnforcementHook stores all routed actions. ChainedEnforcementHook priority-ordered chain, short-circuits on error.
- **SignatureLoader**: 5 methods — load_pack/validate_pack/list_loaded_packs/pack_metadata/supported_pack_format. RulePack with SHA3-256 integrity hash over sorted rule ids+patterns. InMemorySignatureLoader and JsonSignatureLoader (parse from bytes, no file I/O). Validates integrity before installation.
- **ShieldMetricsExporter**: 5 methods — export_counters/export_histograms/export_gauges/format_name/content_type. PrometheusMetricsExporter (text exposition format). OtelMetricsExporter (OpenTelemetry JSON data model). ShieldMetricsStore collects CounterMetric/HistogramMetric/GaugeMetric (f64 stored as String for Eq).

### Audit Enhancement

17 new ShieldEventType variants added: RuleBackendChanged, SignaturePackLoaded, SignaturePackRejected, VerdictExported, VerdictExportFailed, VerdictSubscriberRegistered, VerdictSubscriberRemoved, VerdictPublished, ThreatFeedRefreshed, ThreatFeedFailed, IndicatorAdded, IndicatorExpired, EnforcementHookRegistered, EnforcementActionRouted, EnforcementActionRejected, MetricsExported, MetricsExportFailed. Updated kind() and Display implementations with full test coverage.

### Dependencies Added

- `sha3 = "0.10"` — SHA3-256 integrity hashing for signature packs

### Design Decisions

- **VerdictExporter is one-way:** All five exporters produce bytes from verdicts — none parse external formats. STIX/OCSF/MISP shapes match their specifications without requiring their parsers.
- **EnforcementHook routes, does not execute:** The hook receives a MitigationAction and records/routes it. The customer implements actual enforcement — RUNE provides the decision routing contract.
- **SignatureLoader validates before install:** RulePack.validate_integrity() checks SHA3-256 hash of sorted(rule_id:pattern) entries before any load_pack() call succeeds. Empty rulesets are also rejected.
- **Metrics use String for f64 values:** CounterMetric/HistogramMetric/GaugeMetric store numeric values as String to satisfy Eq/PartialEq derive requirements. PrometheusMetricsExporter formats labels deterministically (sorted key=value pairs).
- **FilteredVerdictSubscriber composes a VerdictCollector:** Filtering logic wraps an inner VerdictCollector, keeping the pattern consistent with the base subscriber implementation.
- **ChainedEnforcementHook short-circuits on error:** If any hook in the chain returns an error, the chain stops. Inactive hooks are skipped.

### Four-Pillar Alignment

| Pillar | How Layer 3 Serves It |
|--------|----------------------|
| Security/Privacy/Governance Baked In | DetectionRuleBackend trait ensures all rule storage satisfies governance contracts; VerdictExporter formats embed governance_decision in every output; EnforcementHook routes decisions without executing mitigation |
| Assumed Breach | ThreatFeedSource enables real-time threat intelligence ingestion; VerdictSubscriber enables streaming verdict monitoring; metrics exporters track per-rule hit rates and false-positive rates |
| No Single Points of Failure | All 7 traits decouple from implementations; 5 export formats prevent vendor lock-in; ChainedEnforcementHook enables multi-hook pipelines |
| Zero Trust Throughout | SHA3-256 integrity validation on signature packs before installation; sorted deterministic hashing; VerdictSubscriber filtering enforces need-to-know verdict visibility |

---

## rune-detection Layer 3

**Test count**: 155 → 228 (+73 tests, zero failures)

**Clippy**: Zero new warnings (pre-existing Layer 1/2 warnings only)

### New Modules (7)

| Module | Lines | Tests | Purpose |
|--------|-------|-------|---------|
| `backend.rs` | ~225 | 12 | DetectionBackend trait + InMemoryDetectionBackend |
| `model_adapter.rs` | ~200 | 10 | DetectionModelAdapter trait + NullDetectionModel + RulesOnlyModel |
| `alert_export.rs` | ~280 | 9 | AlertExporter trait + 5 format implementations |
| `finding_stream.rs` | ~250 | 10 | FindingSubscriber trait + registry + filtering |
| `correlation.rs` | ~240 | 12 | FindingCorrelator trait + TimeWindowCorrelator + AttributeCorrelator |
| `baseline_store.rs` | ~190 | 10 | BaselineStore trait + InMemoryBaselineStore |
| `timeseries_ingest.rs` | ~180 | 10 | TimeSeriesIngestor trait + InMemoryTimeSeriesIngestor |

### Trait Contracts

- **DetectionBackend**: 16 methods — store/retrieve/delete/list findings, store/retrieve/list rules, store/retrieve/list/count baselines, findings_by_severity/findings_in_time_range, flush, backend_info. InMemoryDetectionBackend with duplicate-finding rejection.
- **DetectionModelAdapter**: 6 methods — load_model/predict/batch_predict/model_info/is_loaded/unload. NullDetectionModel (always-zero, SHA3-256 attestation hash). RulesOnlyModel (threshold on specific feature index).
- **AlertExporter**: 4 methods — export_finding/export_batch/format_name/content_type. Five implementations: JsonAlertExporter, CefAlertExporter (CEF:0|Odin's LLC|RUNE-Detection|1.0), OcsfAlertExporter (class_uid 2004), EcsAlertExporter (Elastic Common Schema), SplunkNotableExporter (notable event JSON with urgency mapping).
- **FindingSubscriber**: 3 methods — on_finding/subscriber_id/is_active. FindingSubscriberRegistry with register/notify/notify_batch/active_count/remove_inactive. FindingCollector records all findings. FilteredFindingSubscriber filters by min severity, category, or source.
- **FindingCorrelator**: 4 methods — correlate/correlation_rule_id/supported_correlation_types/is_active. Named FindingCorrelator (not AlertCorrelator) to avoid collision with existing Layer 2 AlertCorrelator struct. TimeWindowCorrelator groups findings within time window by source. AttributeCorrelator groups by shared category.
- **BaselineStore**: 7 methods — store/retrieve/update/delete/list/count/metadata. Separate from DetectionBackend because baselines have retrain/rollback lifecycle. InMemoryBaselineStore with duplicate rejection and update-requires-existence.
- **TimeSeriesIngestor**: 7 methods — ingest_metric/ingest_batch/query_range/last_ingest_at/source_name/supported_metric_types/is_active. One-way ingestion; retrieval protocols belong in adapter crates. InMemoryTimeSeriesIngestor with configurable retention and purge_expired.

### Audit Enhancement

19 new DetectionEventType variants: DetectionBackendChanged, FindingPersisted, FindingQueried, DetectionModelLoaded, DetectionModelUnloaded, ModelPredictionMade, ModelLoadFailed, AlertExported, AlertExportFailed, FindingSubscriberRegistered, FindingSubscriberRemoved, FindingPublished, CorrelationExecuted, CorrelationRuleRegistered, BaselineStored, BaselineUpdated, BaselineRetrieved, TimeSeriesIngested, TimeSeriesIngestFailed. New classification methods: is_backend(), is_model(), is_streaming(), is_baseline(), is_timeseries(). Updated kind() and Display with full test coverage.

### Dependencies Added

- `sha3 = "0.10"` — SHA3-256 attestation hashing for detection model integrity

### Design Decisions

- **FindingCorrelator avoids name collision**: Existing AlertCorrelator struct in alert.rs is a Layer 2 concrete correlator for alerts. Layer 3 trait uses FindingCorrelator name to distinguish the pluggable boundary from the existing implementation.
- **BaselineStore is separate from DetectionBackend**: Baselines have retrain/rollback lifecycle distinct from finding persistence. BaselineStore adds update_baseline, delete_baseline, and baseline_metadata.
- **TimeSeriesIngestor is one-way**: Ingestion and retrieval are separate concerns. The trait defines ingest_metric and query_range for local use; full retrieval protocols belong in downstream adapter crates.
- **OCSF class_uid 2004 overlaps with rune-shield**: Deliberate schema convergence — both crates produce Detection Finding events.
- **CorrelationResult.confidence uses String**: f64 cannot derive Eq; confidence stored as formatted string (e.g., "0.900").
- **FilteredFindingSubscriber composes FindingCollector**: Same pattern as rune-shield's FilteredVerdictSubscriber.

### Four-Pillar Alignment

| Pillar | How Layer 3 Serves It |
|--------|----------------------|
| Security/Privacy/Governance Baked In | DetectionBackend trait ensures all finding storage satisfies governance contracts; AlertExporter formats produce standards-compliant output (CEF, OCSF 2004, ECS, Splunk) |
| Assumed Breach | FindingSubscriber enables real-time streaming of detection findings; TimeSeriesIngestor ingests metrics for anomaly detection; FindingCorrelator discovers multi-finding attack patterns |
| No Single Points of Failure | All 7 traits decouple from implementations; 5 export formats prevent vendor lock-in; BaselineStore separates baseline lifecycle from finding storage |
| Zero Trust Throughout | SHA3-256 attestation hash on model load verifies model integrity; DetectionModelAdapter contracts enforce loaded-before-predict; inactive ingestors reject writes |

---

## rune-web Layer 3

**Test count**: 163 → 252 (+89 tests, zero failures)
**Clippy**: no new warnings (24 pre-existing from L1/L2 code)
**Workspace**: all crates pass

### New Modules (7)

| Module | Purpose | Tests |
|--------|---------|-------|
| `backend.rs` | WebBackend trait — pluggable session/route/API-key storage with InMemoryWebBackend reference impl; RoutePolicy, ApiKeyBinding (SHA3-256 hash_key) | 16 |
| `http_adapter.rs` | HttpAdapter trait — framework-neutral HTTP interception; InterceptResult (Continue/Modified/Reject); RecordingHttpAdapter, PassThroughHttpAdapter | 9 |
| `rate_limit.rs` | RateLimitBackend trait — token bucket, leaky bucket, sliding window; RateLimitDecision (Allowed/Throttled); BucketStatus | 18 |
| `request_log_export.rs` | RequestLogExporter trait — 5 formats (JSON, CLF, Combined, ECS, OTEL); RequestLogEntry with Authorization header auto-redaction | 10 |
| `request_stream.rs` | RequestSubscriber trait — event streaming registry; RequestCollector, FilteredRequestSubscriber (method/status/route filters); 10 RequestLifecycleEventType variants | 10 |
| `cors_policy.rs` | CorsPolicyStore trait — CORS policy storage with wildcard matching; StoredCorsPolicy, CorsDecision (Allow/Deny); exact-match-wins-over-wildcard | 11 |
| `auth_validator.rs` | TokenValidator trait — token shape/binding validation (NOT identity auth); ApiKeyValidator (SHA3-256 constant-time), JwtStructureValidator (structure+claims, NOT signature), SessionCookieValidator | 14 |

### Audit Additions (23 new WebEventType variants → 46 total)

WebBackendChanged, BackendSessionCreated, SessionExpired, SessionRevoked, RoutePolicyStored, RoutePolicyUpdated, HttpRequestIntercepted, HttpResponseEmitted, RateLimitAllowed, RateLimitThrottled, RateLimitBucketReset, RequestLogExported, RequestLogExportFailed, RequestSubscriberRegistered, RequestSubscriberRemoved, RequestEventPublished, CorsPolicyStored, CorsPreflightAllowed, CorsPreflightDenied, TokenValidationSucceeded, TokenValidationFailed, ApiKeyBindingCreated, ApiKeyBindingRevoked

New classification methods: `request_events()`, `auth_events()`, `cors_events()` (existing `session_events()` updated to include L3 session variants).

### Design Decisions

- **StoredCorsPolicy avoids name collision**: Existing cors.rs has `CorsPolicy` struct. Layer 3 uses `StoredCorsPolicy` in cors_policy.rs. Similarly `CorsDecision` avoids colliding with existing `CorsResult`.
- **BackendSessionCreated avoids SessionCreated collision**: Existing L1 audit.rs has `SessionCreated { session_id }`. Layer 3 uses `BackendSessionCreated` for the backend-tracked variant; `SessionExpired` and `SessionRevoked` added directly (no collision).
- **TokenValidator scope**: Validates token shape/binding only. JwtStructureValidator validates structure + required claims but NOT the signing key (rune-identity's job).
- **Authorization header redaction**: RequestLogEntry.from_request() auto-redacts Authorization headers to "[REDACTED]" — defense in depth regardless of exporter format.
- **API key SHA3-256 hashing**: ApiKeyBinding.hash_key() and ApiKeyValidator use SHA3-256 digests with constant_time_eq — raw keys never stored or compared directly.
- **Rate limit backends are in-memory only**: Distributed backends (Redis, Memcached) belong in adapter crates, not the trait boundary layer.

### Four-Pillar Alignment

| Pillar | How Layer 3 Serves It |
|--------|----------------------|
| Security/Privacy/Governance Baked In | TokenValidator enforces shape/binding without identity coupling; Authorization header redaction in all 5 export formats; CORS policy store with wildcard matching |
| Assumed Breach | RequestSubscriber enables real-time request event streaming; FilteredRequestSubscriber isolates error/admin traffic; rate limit backends provide throttling contracts |
| No Single Points of Failure | All 7 traits decouple from implementations; 5 request log export formats prevent vendor lock-in; WebBackend abstracts session/route/key storage |
| Zero Trust Throughout | SHA3-256 constant-time API key comparison; JWT structure validation without trusting signatures; session cookie validation checks existence + expiry |

---

## rune-identity Layer 3 — External Integration Trait Boundaries

**Test count**: 279 (188→279, +91 new tests)

### New Modules (7)

1. **backend.rs** — `IdentityBackend` trait (16 methods: store/retrieve/delete/list/count/exists for identities, credential records, MFA enrollments, flush, backend_info), `InMemoryIdentityBackend` reference implementation, `CredentialRecord` (metadata pointer not material), `MfaEnrollment`, `IdentityBackendInfo`. 15 tests.

2. **credential_material_store.rs** — `CredentialMaterialStore` trait (13 methods), `InMemoryCredentialMaterialStore`, `PasswordHashRecord`, `TotpSecretHashRecord`, `WebAuthnPublicKeyRecord`, `StoredRecoveryCodeSet`. SHA3-256 hashing, constant-time comparison for recovery codes. Separate from IdentityBackend (different lifecycle/access patterns). 13 tests.

3. **authentication_provider.rs** — `AuthenticationProvider` trait (authenticate/authenticator_id/authentication_factor_type/supported_credential_types/is_active), `FactorType` (Knowledge/Possession/Inherence per NIST SP 800-63B), `AuthenticationChallenge`, `AuthenticationResult` (Succeeded/Failed/Locked/MfaRequired), `PasswordAuthenticator` (SHA3-256 salt+password), `TotpAuthenticator` (HMAC-SHA3-256 RFC 6238), `RecoveryCodeAuthenticator`, `NullAuthenticator`. 15 tests.

4. **jwt_signing.rs** — `JwtSigner`/`JwtSignatureVerifier` traits (complement rune-web's JwtStructureValidator: structure vs signature), `JwtAlgorithm` (9 variants), `JwtClaims`, `SignatureVerification` (Valid/Invalid/AlgorithmMismatch/Expired), `HmacSha3Sha256JwtSigner`/`HmacSha3Sha256JwtSignatureVerifier` reference implementations, `NullJwtSigner`/`NullJwtSignatureVerifier`. Base64url encode/decode, constant-time signature comparison. 14 tests.

5. **federation_provider.rs** — `FederationAuthProvider` trait (begin_authentication_flow/complete_authentication_flow/provider_id/provider_type/supported_assertion_formats/is_active), `ProviderType` (Oidc/Saml/Ldap), `FlowContext` with SHA3-256 state token, `ExternalIdentity` with SHA3-256 assertion hash. `InMemoryOidcFederationStub`, `InMemorySamlFederationStub`, `InMemoryLdapFederationStub` — stubs exercise trait interface. 11 tests.

6. **identity_stream.rs** — `IdentityEventSubscriber` trait (on_event/subscriber_id/is_active), `IdentityEventSubscriberRegistry` (register/unregister/publish), `IdentityEventCollector`, `FilteredIdentityEventSubscriber`, `IdentityLifecycleEvent`, `IdentityLifecycleEventType` (15 variants). 12 tests.

7. **identity_export.rs** — `IdentityExporter` trait (export_identity/export_format/exporter_id), `ExportFormat` (Scim/OcsfIam/Ecs/Ldif/Json), `ScimIdentityExporter`, `OcsfIamExporter`, `EcsUserExporter`, `LdifExporter`, `JsonIdentityExporter`. All 5 formats verified to exclude credential material (defense in depth). 11 tests.

### Audit Enhancements

23 new `IdentityEventType` variants: IdentityBackendChanged, IdentityPersisted, IdentityQueried, IdentityExported, IdentityExportFailed, CredentialStoreChanged, PasswordHashStored, PasswordHashUpdated, TotpSecretEnrolled, WebAuthnKeyEnrolled, RecoveryCodesGenerated, RecoveryCodeConsumedEvent, AuthenticatorInvoked, AuthenticationOutcomeRecorded, JwtSigned, JwtSignatureVerified, JwtSignatureRejected, FederationFlowStarted, FederationFlowCompleted, FederationFlowFailed, IdentitySubscriberRegistered, IdentitySubscriberRemoved, IdentityEventPublished.

New classification methods: `is_credential_event()`, `is_authentication_event()`, `is_federation_event()`, `is_export_event()`.

### Design Decisions

- **CredentialMaterialStore separates from IdentityBackend**: Different lifecycle and access patterns — credential material is write-heavy with stricter access controls, identity metadata is read-heavy.
- **CredentialMaterialStore avoids name collision**: Existing credential.rs has `CredentialStore` struct. Layer 3 uses `CredentialMaterialStore` trait.
- **AuthenticationProvider avoids name collision**: Existing authn.rs has `Authenticator` struct. Layer 3 uses `AuthenticationProvider` trait.
- **FederationAuthProvider avoids name collision**: Existing federation.rs has `FederationProvider` struct. Layer 3 uses `FederationAuthProvider` trait in `federation_provider.rs`.
- **NIST SP 800-63B factor types**: Knowledge/Possession/Inherence — the three standard authentication factor categories.
- **Only HMAC-SHA3-256 reference implementations**: Asymmetric JWT (RS256/ES256/EdDSA) requires adapter crates — the trait boundary accepts all 9 algorithm variants.
- **WebAuthn cryptographic verification deferred**: webauthn-rs is too substantial for a trait boundary layer — the trait defines the contract, adapters implement the crypto.
- **Federation stubs exercise trait interface**: Not actual OIDC/SAML/LDAP flows — stubs demonstrate the contract pattern.
- **RecoveryCodeAuthenticator immutability**: AuthenticationProvider.authenticate takes `&dyn CredentialMaterialStore` (immutable); code consumption deferred to caller via mutable store.

### Four-Pillar Alignment

| Pillar | How Layer 3 Serves It |
|--------|----------------------|
| Security/Privacy/Governance Baked In | All 5 export formats exclude credential material; SHA3-256 hashing for passwords/TOTP/recovery codes; constant-time comparison everywhere |
| Assumed Breach | IdentityEventSubscriber enables real-time identity lifecycle streaming; filtered subscribers isolate security events; federation flow state tokens are SHA3-256 hashed |
| No Single Points of Failure | All 7 traits decouple from implementations; 5 identity export formats prevent vendor lock-in; IdentityBackend and CredentialMaterialStore separate storage concerns |
| Zero Trust Throughout | NIST SP 800-63B factor type classification; JWT signing/verification split from structure validation; federation flows require state token + assertion hash verification |

---

## rune-permissions Layer 3 — External Integration Trait Boundaries

**Test count**: 227 (151→227, +76 new tests)

**Clippy**: Zero new warnings in Layer 3 files

### New Modules (7)

| Module | Tests | Purpose |
|--------|-------|---------|
| `backend.rs` | 14 | PermissionBackend trait (17 methods), IdentityRef/RoleRef newtypes, StoredPolicyDefinition, StoredRoleDefinition, PermissionGrantRecord, InMemoryPermissionBackend |
| `decision_engine.rs` | 12 | AuthorizationDecisionEngine trait with XACML four-outcome model (Permit/Deny/Indeterminate/NotApplicable), RbacDecisionEngine, AbacDecisionEngine with AttributeRule, DenyAll/AllowAll |
| `policy_export.rs` | 7 | PolicyExporter trait + 5 formats: Rego, Cedar, XACML, OPA Bundle, JSON |
| `decision_stream.rs` | 11 | DecisionSubscriber trait, registry, collector, filtered subscriber, 17 DecisionLifecycleEventType variants |
| `external_evaluator.rs` | 5 | ExternalPolicyEvaluator trait, NullExternalEvaluator (Indeterminate not Deny), RecordingExternalEvaluator |
| `role_provider.rs` | 11 | RoleProvider trait, InMemoryRoleProvider, CachedRoleProvider with TTL cache and RefCell interior mutability |
| `capability_verifier.rs` | 12 | CapabilityVerifier trait, HMAC-SHA3-256 signing with constant-time comparison, ExpiryAwareCapabilityVerifier composable wrapper, NullCapabilityVerifier |

### Trait Contracts

- **PermissionBackend**: 17 methods — store/retrieve/delete/list policies, roles, grants, flush, backend_info. IdentityRef decouples from rune-identity's SubjectId (From<SubjectId> conversion provided). RoleRef parallel newtype for role identifiers.
- **AuthorizationDecisionEngine**: XACML four-outcome decision model (Permit/Deny/Indeterminate/NotApplicable) — the most architecturally significant trait because Layer 5 formal verification will target this interface. EngineType enum (Rbac/Abac/Rebac/Hybrid). AbacDecisionEngine supports composable AttributeRules.
- **PolicyExporter**: One-way export only (round-trip parsing requires dedicated parser crates). Five formats: Rego (OPA), Cedar (AWS Verified Permissions), XACML 3.0, OPA Bundle, JSON.
- **DecisionSubscriber**: Streaming decision lifecycle events. FilteredDecisionSubscriber filters by decision type. DecisionCollector reference implementation.
- **ExternalPolicyEvaluator**: Integration point for OPA/Cedar/AuthZed. NullExternalEvaluator returns Indeterminate (not Deny) so unavailability does not silently become denial. RecordingExternalEvaluator wraps + records all calls via RefCell.
- **RoleProvider**: External role membership source (LDAP/AD/SCIM). CachedRoleProvider is first-class architectural component — role lookups against external directories are the classic authorization bottleneck. TTL-aware cache with invalidate/invalidate_all.
- **CapabilityVerifier**: Runtime capability token verification complementing compile-time types. HMAC-SHA3-256 signing with constant-time comparison. ExpiryAwareCapabilityVerifier wraps another verifier (composable, not baked into base trait).

### Audit Enhancement

23 new PermissionEventType variants: PermissionBackendChanged, PolicyDefinitionStored, PolicyDefinitionRemoved, RoleDefinitionStored, RoleDefinitionRemoved, PermissionGrantRecordCreated, PermissionGrantRecordRevoked, AuthorizationDecisionMade, AuthorizationPermit, AuthorizationDeny, AuthorizationIndeterminate, AuthorizationNotApplicable, DecisionEngineInvoked, PolicyExported, PolicyExportFailed, DecisionSubscriberRegistered, DecisionSubscriberRemoved, DecisionEventPublished, ExternalEvaluatorInvoked, ExternalEvaluatorFailed, RoleProviderQueried, CapabilityTokenVerified, CapabilityTokenRejected. New classification methods: is_backend_event, is_decision_event, is_export_event, is_external_event, is_capability_event.

### Dependencies Added

- `sha3 = "0.10"`, `hex = "0.4"`, `hmac = "0.12"` — HMAC-SHA3-256 capability token signing

### Design Decisions

- **XACML four-outcome model**: Permit/Deny/Indeterminate/NotApplicable specifically chosen for formal verification alignment at Layer 5. Indeterminate means the engine cannot decide (external system down, policy error); NotApplicable means no policy matched.
- **IdentityRef decouples from rune-identity**: rune-permissions defines its own IdentityRef newtype to avoid tight coupling with rune-identity's IdentityId. From<SubjectId> conversion provided for internal use.
- **NullExternalEvaluator returns Indeterminate**: External evaluator unavailability must not silently become denial — Indeterminate flows through the decision engine's fallback logic.
- **CachedRoleProvider as first-class component**: Role lookups against LDAP/AD directories are the classic performance bottleneck in authorization systems. TTL-aware cache with per-identity and bulk invalidation.
- **ExpiryAwareCapabilityVerifier is composable**: Wraps another verifier rather than baking expiry into the base trait — customers may apply expiry checks selectively.
- **Policy exports are one-way**: All five exporters produce text from policies. Round-trip parsing (Rego→Policy, Cedar→Policy) requires dedicated parser crates.
- **Naming collision resolution**: StoredPolicyDefinition (vs Permission), StoredRoleDefinition (vs Role), AuthorizationDecision (vs AccessDecision), AuthorizationDecisionEngine (vs RbacEngine), PermissionGrantRecord (vs Grant), PermissionBackendInfo (vs existing types).
- **evaluation_latency_us as String**: f64 cannot derive Eq; latency stored as formatted string for Eq compatibility.

### Four-Pillar Alignment

| Pillar | How Layer 3 Serves It |
|--------|----------------------|
| Security/Privacy/Governance Baked In | AuthorizationDecisionEngine enforces four-outcome XACML model for formal verification; PermissionBackend ensures all policy/role/grant storage satisfies governance contracts; PolicyExporter formats embed governance metadata |
| Assumed Breach | DecisionSubscriber enables real-time authorization decision streaming; ExternalPolicyEvaluator integrates external engines; RecordingExternalEvaluator provides complete audit trail of all external calls |
| No Single Points of Failure | All 7 traits decouple from implementations; 5 policy export formats prevent vendor lock-in; CachedRoleProvider prevents external directory failures from blocking authorization |
| Zero Trust Throughout | HMAC-SHA3-256 capability token signing with constant-time comparison; NullExternalEvaluator returns Indeterminate not Deny; CapabilityVerifier requires explicit token verification at runtime |
