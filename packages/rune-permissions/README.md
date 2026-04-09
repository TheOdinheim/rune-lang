# rune-permissions

Capability-based permission system for the RUNE governance ecosystem. Type-safe,
compile-time-aware, and auditable by construction.

## Architecture

| Module | Purpose |
|--------|---------|
| `types` | Permission, Action, Resource, Subject, Classification, Condition |
| `role` | Role definitions, role hierarchies with multiple inheritance |
| `rbac` | Role-based access control engine with evaluation |
| `grant` | Direct permission grants with conditions and usage tracking |
| `context` | Evaluation context (who, when, where, risk level) |
| `decision` | Access decisions with reasoning and evaluation trace |
| `error` | Permission error types |
| `store` | Unified store composing roles, grants, subjects, audit log |

## Quick Start

```rust
use rune_permissions::*;

// Create a store.
let mut store = PermissionStore::new();

// Add roles and permissions.
store.add_role(Role::viewer()).unwrap();
store.register_permission(Permission::new(
    "docs:read", ResourcePattern::Prefix("docs/".into()), vec![Action::Read],
)).unwrap();

// Register a subject and assign a role.
store.register_subject(Subject::new("alice", SubjectType::User, "Alice")).unwrap();
store.assign_role(
    SubjectId::new("alice"), RoleId::new("viewer"),
    SubjectId::new("system"), "onboarding".into(),
).unwrap();

// Check access.
assert!(store.can(&SubjectId::new("alice"), Action::Read, "docs/readme"));
```

## Four-Pillar Alignment

- **Zero Trust Throughout**: all access requires explicit permission grant
- **Security Baked In**: classification levels enforce Bell-LaPadula "no read up"
- **Assumed Breach**: audit log records every access check and role change
- **No Single Points of Failure**: multiple evaluation paths (roles + direct grants)
