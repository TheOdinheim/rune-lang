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
