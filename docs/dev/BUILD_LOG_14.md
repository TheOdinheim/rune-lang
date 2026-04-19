# RUNE Build Log 14

> Previous file: [BUILD_LOG_13.md](BUILD_LOG_13.md)

---

## rune-permissions — Layer 2 Upgrade

**Date:** 2026-04-14
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 151 (97 existing + 54 new)
**Dependencies added:** (none — serde_json already present from Layer 1)

### Overview

Upgraded `rune-permissions` with permission snapshot/restore with JSON
export/import, evaluation optimization with grant indexing and decision
caching, policy simulation with least privilege analysis, delegation
hardening with temporal delegations and cascade revocation, role
hierarchy conflict detection and comparison, enhanced Separation of
Duties with dynamic policy enforcement, and 15 new audit event types.

### Changes by Module

#### rbac.rs — Engine Accessors (Layer 2 support)

- `all_assignments()` / `replace_assignments()`: snapshot/restore of
  role assignments
- `hierarchy()` / `hierarchy_mut()`: access to RoleHierarchy for
  role analysis, snapshot/restore
- `all_permissions()` / `replace_permissions()`: permission map access
- Cache invalidation on assign_role/revoke_role/add_grant

#### store.rs — Permission Persistence (PART 1)

- `PermissionSnapshot` struct: grants/roles/assignments/policies/
  snapshot_at/version
- `snapshot()` / `restore()` → `RestoreResult` (grants/roles/
  assignments/policies restored counts + warnings)
- `export_json()` / `import_json()`: JSON serialization roundtrip
- `GrantRequest` / `BulkGrantResult` for `bulk_grant()` batch operations
- `cleanup_expired_grants()`: removes expired grants with cache
  invalidation
- `expiring_soon()`: grants expiring within a time window
- 8 new tests

#### store.rs — Evaluation Optimization (PART 2)

- `GrantIndex` with `by_subject`/`by_permission`/`by_resource`
  HashMap<String, Vec<usize>> fields, `build()`/`add()`/`clear()`
- `EvaluationCache`: HashMap<String, CachedDecision>, max_entries with
  LRU eviction, TTL-based expiry, hit/miss tracking
- `cache_key()` / `get()` / `put()` / `invalidate_for_subject()` /
  `invalidate_all()` / `hit_rate()`
- `EvaluationStats`: cache_entries/hits/misses/hit_rate
- `rebuild_index()` / `invalidate_cache()` / `cache_stats()` /
  `cached_check()`
- 10 new tests

#### store.rs — Policy Simulation (PART 3)

- `simulate_grant()` → `SimulationResult` (would_conflict,
  conflict_reasons, effective_permissions_after, sod_violations,
  risk_assessment: SimulationRisk)
- `SimulationRisk` enum: Low/Medium/High/Critical
- `effective_permissions()` → Vec<EffectivePermission> with
  `PermissionSource` enum (Direct/RoleInherited/Delegated)
- `analyze_least_privilege()` → `LeastPrivilegeReport` (total,
  used, unused, recommendation)
- 8 new tests

#### store.rs — Delegation Hardening (PART 4)

- `TemporalDelegation` struct: id/delegator/delegate/permission_id/
  starts_at/ends_at/reason/active/parent_delegation, `is_active_at()`
- `grant_temporal_delegation()` with duplicate/time validation
- `active_temporal_delegations()` time-windowed query
- `delegation_chain_depth()`: walks parent chain with cycle protection
- `validate_delegation_depth()`: enforces max depth
- `revoke_delegation_cascade()` → `CascadeResult` (revoked_count/
  revoked_ids): BFS cascade through children
- `delegation_tree()` → `DelegationNode` recursive tree
- 9 new tests

#### store.rs — Role Hierarchy Enhancement (PART 5)

- `detect_role_conflicts()` → Vec<RoleConflict> with
  `RoleConflictType` (MutuallyExclusive/RedundantInclusion/
  PermissionOverlap)
- `compare_roles()` → `RoleComparison` (shared/only_a/only_b/
  is_subset/is_superset)
- `role_assignment_count()` / `most_assigned_roles()` /
  `unassigned_roles()`
- 6 new tests

#### store.rs — SoD Enhancement (PART 6)

- `SodPolicy` struct: name/enforcement/conflicting_permissions/
  conflicting_roles/description
- `SodEnforcement` enum: Static/Dynamic
- `add_sod_policy()` with duplicate detection
- `check_dynamic_sod()` → `SodCheckResult` (passed/violations):
  checks both permission-based and role-based SoD policies
- `detect_sod_violations()` → Vec<SodViolation>: scans all subjects
- `SodViolation` struct: policy_name/subject_id/detail
- 6 new tests

#### store.rs — Audit Enhancement (PART 7)

- 15 new `PermissionEventType` variants: PermissionSnapshotCreated,
  PermissionSnapshotRestored, BulkGrantExecuted, ExpiredGrantsCleaned,
  GrantIndexRebuilt, CacheInvalidated, PermissionSimulated,
  EffectivePermissionsQueried, LeastPrivilegeAnalyzed,
  DelegationCascadeRevoked, DelegationDepthChecked,
  TemporalDelegationCreated, RoleConflictDetected,
  SodViolationDetected, SodPolicyAdded
- Display and type_name implementations for all 23 variants
  (8 original + 15 new)
- 5 new tests (event types, display coverage)

#### role.rs — Accessors (from previous step)

- `all_roles()` / `replace_roles()` on RoleHierarchy

#### grant.rs — Accessors (from previous step)

- `all_grants()` / `replace_grants()` on GrantStore

### Test Summary

```
cargo test -p rune-permissions
  151 passed; 0 failed

cargo test --workspace
  3,288 passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | SoD policies enforce separation of conflicting permissions; least privilege analysis identifies unnecessary access |
| Assumed Breach | Snapshot/restore enables permission state recovery; cascade revocation limits blast radius of compromised delegations |
| No Single Points of Failure | Temporal delegations provide time-bounded backup access; bulk grants enable rapid recovery from access loss |
| Zero Trust Throughout | Dynamic SoD checks enforce constraints at runtime; delegation depth limits prevent unbounded trust chains; cache invalidation ensures fresh evaluations |

---

## rune-privacy — Layer 2 Upgrade

**Date:** 2026-04-14
**Type:** Layer 2 (internal upgrade, backward-compatible)
**Tests:** 178 (104 existing + 74 new)
**Dependencies added:** sha3 = "0.10", regex = "1" (added in Layer 1 prep)

### Overview

Upgraded `rune-privacy` with regex-based PII detection (12 compiled
patterns), Gaussian differential privacy mechanism with budget tracking
and composition theorems, anonymization hardening (standalone l-diversity/
t-closeness, re-identification risk, generalization hierarchies),
consent versioning with SHA3-256 policy hashing, cascade withdrawal with
purpose dependency graphs, consent proof generation, data subject request
automation with analytics, data inventory, PIA scoring with weighted
components, structured recommendations, regulatory mapping, and 15 new
audit event types.

### Changes by Module

#### pii.rs — Regex PII Detection (PART 1)

- `PiiConfidence` enum (Low/Medium/High with Ord)
- `PiiMatch` struct: pii_type/pattern_name/confidence/matched_text_redacted/
  field_name/byte_offset
- `PiiFieldMatch` struct: field_name/matches
- `PiiRegexScanner` with 12 built-in compiled regex patterns (email, SSN,
  phone, credit card, IPv4, DOB, passport, AWS key, private key, JWT, ZIP)
- `scan()` / `scan_structured()` / `scan_above_confidence()` /
  `add_pattern()` / `pattern_count()`
- `redact_match()` helper
- 14 new tests

#### differential.rs — Enhanced Differential Privacy (PART 2)

- `gaussian_noise()` with Box-Muller transform
- `calibrate_laplace()` / `calibrate_gaussian()` scale/sigma calculators
- `BudgetQuery` struct for query tracking
- `PrivacyBudgetTracker`: new/can_afford/spend/remaining_epsilon/
  remaining_delta/utilization/reset/sequential_composition_epsilon/
  advanced_composition_epsilon
- Made `deterministic_uniform`/`seed_from_value` pub(crate) in anonymize.rs
- 17 new tests

#### anonymize.rs — Anonymization Hardening (PART 3)

- `AnonymizationGroup` struct for pre-built groups
- `check_l_diversity()` standalone function
- `check_t_closeness()` standalone function with EMD
- `RiskLevel` enum (Negligible/Low/Medium/High/Critical)
- `ReidentificationRisk` struct with score/recommendations
- `reidentification_risk()` assessment function
- `GeneralizationHierarchy` with closures, built-in hierarchies:
  `age()` (5yr/10yr/*), `zip_code()` (3-digit/1-digit/*),
  `date()` (year-month/year/*)
- 11 new tests

#### consent.rs — Consent Lifecycle Enhancement (PART 4)

- `ConsentVersion` struct with SHA3-256 policy_hash
- `ConsentVersionStore`: create_version/current_version/is_consent_current/
  version_history
- `WithdrawalResult` struct
- `withdraw_consent_cascade()` on ConsentStore with PurposeDependencyGraph
- `ConsentProof` struct with proof_hash
- `generate_consent_proof()` on ConsentStore
- `PurposeDependencyGraph`: add_dependency/dependents_of/all_required_for
- 11 new tests

#### rights.rs — Data Subject Rights Automation (PART 5)

- `DataSubjectRequest` struct with regulation tracking
- `DataSubjectRequestTracker`: submit_request (auto-deadline GDPR 30d /
  CCPA 45d) / update_status / complete_request / overdue_requests /
  requests_for_subject / average_completion_time_ms
- `DataInventoryEntry` struct
- `DataInventory`: add_entry / categories / entries_for_category /
  total_retention_exposure
- 11 new tests

#### impact.rs — PIA Enhancement (PART 6)

- `PiaScore` struct (data_sensitivity 0.35 / processing_risk 0.25 /
  cross_border 0.20 / volume 0.20)
- `calculate_pia_score()` with weighted components
- `RecommendationPriority` enum (Low/Medium/High/Critical)
- `PiaRecommendation` struct (category/priority/description/
  regulatory_reference)
- `generate_pia_recommendations()` based on score thresholds
- `RegulatoryRequirement` struct
- `map_to_regulations()` mapping PIA to GDPR articles
- 8 new tests

#### audit.rs — Audit Enhancement (PART 7)

- 15 new `PrivacyEventType` variants: PiiRegexScanCompleted,
  PiiHighConfidenceMatch, PrivacyBudgetSpent, PrivacyBudgetExhausted,
  GaussianNoiseApplied, LDiversityChecked, TClosenessChecked,
  ReidentificationRiskAssessed, ConsentVersionCreated,
  ConsentWithdrawnCascade, ConsentProofGenerated,
  DataSubjectRequestSubmitted, DataSubjectRequestCompleted,
  DataSubjectRequestOverdue, PiaScoreCalculated
- Extended `is_violation()` and `is_consent_event()` for new variants
- Display and kind() for all 26 variants (11 original + 15 new)
- 5 new tests

### Test Summary

```
cargo test -p rune-privacy
  178 passed; 0 failed

cargo test --workspace
  3,362 passed; 0 failed
```

### Four-Pillar Alignment

| Pillar | How This Upgrade Serves It |
|--------|---------------------------|
| Security/Privacy/Governance Baked In | Regex PII scanning catches real-world data leaks; PIA scoring provides quantitative risk assessment; consent versioning ensures policy compliance |
| Assumed Breach | Re-identification risk assessment identifies vulnerable records; cascade consent withdrawal limits exposure when consent is revoked |
| No Single Points of Failure | Privacy budget tracking prevents epsilon exhaustion; data inventory provides complete visibility of data holdings |
| Zero Trust Throughout | Advanced composition theorems enforce mathematically sound privacy guarantees; l-diversity and t-closeness hardening prevents inference attacks |
