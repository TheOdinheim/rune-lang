// ═══════════════════════════════════════════════════════════════════════
// Permission Grants
//
// Direct bindings between subjects and permissions, with conditions,
// expiration, and usage tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::context::EvalContext;
use crate::error::PermissionError;
use crate::types::{Condition, PermissionId, SubjectId};

// ── GrantId ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrantId(String);

impl GrantId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Grant ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub subject_id: SubjectId,
    pub permission_id: PermissionId,
    pub granted_by: SubjectId,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
    pub conditions: Vec<Condition>,
    pub reason: String,
    pub active: bool,
    pub usage_count: u64,
    pub max_usage: Option<u64>,
}

impl Grant {
    pub fn new(
        id: impl Into<String>,
        subject_id: SubjectId,
        permission_id: PermissionId,
        granted_by: SubjectId,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: GrantId::new(id),
            subject_id,
            permission_id,
            granted_by,
            granted_at: 0,
            expires_at: None,
            conditions: Vec::new(),
            reason: reason.into(),
            active: true,
            usage_count: 0,
            max_usage: None,
        }
    }

    pub fn expires_at(mut self, ts: i64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    pub fn condition(mut self, cond: Condition) -> Self {
        self.conditions.push(cond);
        self
    }

    pub fn max_usage(mut self, max: u64) -> Self {
        self.max_usage = Some(max);
        self
    }

    pub fn granted_at(mut self, ts: i64) -> Self {
        self.granted_at = ts;
        self
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map_or(false, |exp| now > exp)
    }

    pub fn is_usage_exceeded(&self) -> bool {
        self.max_usage.map_or(false, |max| self.usage_count >= max)
    }
}

// ── GrantStore ─────────────────────────────────────────────────────

pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
        }
    }

    pub fn add_grant(&mut self, grant: Grant) -> Result<(), PermissionError> {
        self.grants.push(grant);
        Ok(())
    }

    pub fn revoke_grant(&mut self, id: &GrantId) -> Result<(), PermissionError> {
        for grant in &mut self.grants {
            if grant.id == *id {
                grant.active = false;
                return Ok(());
            }
        }
        Err(PermissionError::GrantNotFound(id.clone()))
    }

    pub fn active_grants(&self, subject_id: &SubjectId) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|g| g.subject_id == *subject_id && g.active && !g.is_usage_exceeded())
            .collect()
    }

    pub fn grants_for_permission(&self, permission_id: &PermissionId) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|g| g.permission_id == *permission_id && g.active)
            .collect()
    }

    /// Check if a subject has an active, non-expired, condition-passing grant.
    pub fn is_granted(
        &self,
        subject_id: &SubjectId,
        permission_id: &PermissionId,
        context: &EvalContext,
    ) -> bool {
        self.grants.iter().any(|g| {
            g.subject_id == *subject_id
                && g.permission_id == *permission_id
                && g.active
                && !g.is_expired(context.timestamp)
                && !g.is_usage_exceeded()
                && g.conditions.iter().all(|c| c.evaluate(context))
        })
    }

    pub fn record_usage(&mut self, grant_id: &GrantId) -> Result<(), PermissionError> {
        for grant in &mut self.grants {
            if grant.id == *grant_id {
                if grant.is_usage_exceeded() {
                    return Err(PermissionError::InvalidOperation(
                        format!("grant {} usage limit exceeded", grant_id),
                    ));
                }
                grant.usage_count += 1;
                return Ok(());
            }
        }
        Err(PermissionError::GrantNotFound(grant_id.clone()))
    }

    pub fn all_grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn replace_grants(&mut self, grants: Vec<Grant>) {
        self.grants = grants;
    }

    pub fn cleanup_expired(&mut self, now: i64) -> usize {
        let mut count = 0;
        for grant in &mut self.grants {
            if grant.active && grant.is_expired(now) {
                grant.active = false;
                count += 1;
            }
        }
        count
    }
}

impl Default for GrantStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Subject, SubjectType};

    fn test_grant() -> Grant {
        Grant::new(
            "grant-1",
            SubjectId::new("user1"),
            PermissionId::new("file:read"),
            SubjectId::new("admin"),
            "access needed",
        )
    }

    fn test_ctx(ts: i64) -> EvalContext {
        EvalContext::for_subject(
            Subject::new("user1", SubjectType::User, "User 1"),
        ).timestamp(ts).build()
    }

    #[test]
    fn test_grant_creation() {
        let g = test_grant();
        assert_eq!(g.subject_id, SubjectId::new("user1"));
        assert_eq!(g.permission_id, PermissionId::new("file:read"));
        assert!(g.active);
        assert_eq!(g.usage_count, 0);
    }

    #[test]
    fn test_active_grants() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant()).unwrap();
        store.add_grant(
            Grant::new("grant-2", SubjectId::new("user2"), PermissionId::new("x"), SubjectId::new("admin"), "r")
        ).unwrap();

        assert_eq!(store.active_grants(&SubjectId::new("user1")).len(), 1);
        assert_eq!(store.active_grants(&SubjectId::new("user2")).len(), 1);
        assert_eq!(store.active_grants(&SubjectId::new("user3")).len(), 0);
    }

    #[test]
    fn test_is_granted_valid() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant()).unwrap();
        let ctx = test_ctx(50);
        assert!(store.is_granted(&SubjectId::new("user1"), &PermissionId::new("file:read"), &ctx));
    }

    #[test]
    fn test_is_granted_expired() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant().expires_at(100)).unwrap();
        let ctx = test_ctx(200);
        assert!(!store.is_granted(&SubjectId::new("user1"), &PermissionId::new("file:read"), &ctx));
    }

    #[test]
    fn test_is_granted_condition_fails() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant().condition(Condition::RequiresMfa)).unwrap();
        let ctx = test_ctx(50); // mfa_verified = false by default
        assert!(!store.is_granted(&SubjectId::new("user1"), &PermissionId::new("file:read"), &ctx));
    }

    #[test]
    fn test_record_usage() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant().max_usage(2)).unwrap();
        assert!(store.record_usage(&GrantId::new("grant-1")).is_ok());
        assert!(store.record_usage(&GrantId::new("grant-1")).is_ok());
        // Third usage exceeds max.
        assert!(store.record_usage(&GrantId::new("grant-1")).is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant().expires_at(100)).unwrap();
        store.add_grant(
            Grant::new("grant-2", SubjectId::new("u2"), PermissionId::new("x"), SubjectId::new("a"), "r")
                .expires_at(500),
        ).unwrap();

        let cleaned = store.cleanup_expired(200);
        assert_eq!(cleaned, 1);
        assert_eq!(store.active_grants(&SubjectId::new("user1")).len(), 0);
        assert_eq!(store.active_grants(&SubjectId::new("u2")).len(), 1);
    }

    #[test]
    fn test_revoke_grant() {
        let mut store = GrantStore::new();
        store.add_grant(test_grant()).unwrap();
        assert!(store.revoke_grant(&GrantId::new("grant-1")).is_ok());
        assert_eq!(store.active_grants(&SubjectId::new("user1")).len(), 0);
    }
}
