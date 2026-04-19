// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Policy versioning with SHA3-256 integrity.
//
// Cryptographic hash chains for policy versions with tamper detection
// and version lifecycle management.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use hex;
use sha3::{Digest, Sha3_256};

// ── PolicyVersionStatus ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2PolicyVersionStatus {
    Draft,
    Active,
    Deprecated,
    Revoked,
}

impl fmt::Display for L2PolicyVersionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Draft => "Draft",
            Self::Active => "Active",
            Self::Deprecated => "Deprecated",
            Self::Revoked => "Revoked",
        };
        f.write_str(s)
    }
}

// ── compute_policy_hash ────────────────────────────────────────────

pub fn compute_policy_hash(
    policy_id: &str,
    version: u32,
    content: &str,
    previous_hash: Option<&str>,
) -> String {
    let mut hasher = Sha3_256::new();
    let input = format!(
        "{}:{}:{}:{}",
        policy_id,
        version,
        content,
        previous_hash.unwrap_or("")
    );
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── PolicyVersion ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct L2PolicyVersion {
    pub policy_id: String,
    pub version: u32,
    pub content_hash: String,
    pub previous_version_hash: Option<String>,
    pub created_by: String,
    pub created_at: i64,
    pub change_summary: String,
    pub status: L2PolicyVersionStatus,
}

// ── VersionChainVerification ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VersionChainVerification {
    pub policy_id: String,
    pub valid: bool,
    pub verified_links: usize,
    pub broken_at: Option<u32>,
}

// ── PolicyVersionStore ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct L2PolicyVersionStore {
    versions: HashMap<String, Vec<L2PolicyVersion>>,
}

impl L2PolicyVersionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_version(&mut self, version: L2PolicyVersion) {
        self.versions
            .entry(version.policy_id.clone())
            .or_default()
            .push(version);
    }

    pub fn current_version(&self, policy_id: &str) -> Option<&L2PolicyVersion> {
        self.versions.get(policy_id).and_then(|vs| vs.last())
    }

    pub fn version_history(&self, policy_id: &str) -> Vec<&L2PolicyVersion> {
        self.versions
            .get(policy_id)
            .map(|vs| vs.iter().collect())
            .unwrap_or_default()
    }

    pub fn verify_version_chain(&self, policy_id: &str) -> VersionChainVerification {
        let versions = match self.versions.get(policy_id) {
            Some(vs) => vs,
            None => {
                return VersionChainVerification {
                    policy_id: policy_id.to_string(),
                    valid: true,
                    verified_links: 0,
                    broken_at: None,
                };
            }
        };

        if versions.len() <= 1 {
            return VersionChainVerification {
                policy_id: policy_id.to_string(),
                valid: true,
                verified_links: versions.len(),
                broken_at: None,
            };
        }

        let mut verified = 0;
        for i in 1..versions.len() {
            let expected_prev = &versions[i - 1].content_hash;
            match &versions[i].previous_version_hash {
                Some(prev_hash) if prev_hash == expected_prev => {
                    verified += 1;
                }
                _ => {
                    return VersionChainVerification {
                        policy_id: policy_id.to_string(),
                        valid: false,
                        verified_links: verified,
                        broken_at: Some(versions[i].version),
                    };
                }
            }
        }

        VersionChainVerification {
            policy_id: policy_id.to_string(),
            valid: true,
            verified_links: verified + 1, // include the first version
            broken_at: None,
        }
    }

    pub fn active_versions(&self) -> Vec<&L2PolicyVersion> {
        self.versions
            .values()
            .flatten()
            .filter(|v| v.status == L2PolicyVersionStatus::Active)
            .collect()
    }

    pub fn deprecate_version(&mut self, policy_id: &str, version: u32) -> bool {
        if let Some(versions) = self.versions.get_mut(policy_id) {
            if let Some(v) = versions.iter_mut().find(|v| v.version == version) {
                v.status = L2PolicyVersionStatus::Deprecated;
                return true;
            }
        }
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_policy_hash_produces_64_char_hex() {
        let hash = compute_policy_hash("p1", 1, "content here", None);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_policy_hash_is_deterministic() {
        let h1 = compute_policy_hash("p1", 1, "same content", None);
        let h2 = compute_policy_hash("p1", 1, "same content", None);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_policy_version_store_add_and_current_version() {
        let mut store = L2PolicyVersionStore::new();
        let hash = compute_policy_hash("p1", 1, "v1 content", None);
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: hash,
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "initial".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let current = store.current_version("p1").unwrap();
        assert_eq!(current.version, 1);
    }

    #[test]
    fn test_policy_version_store_version_history_returns_ordered() {
        let mut store = L2PolicyVersionStore::new();
        let h1 = compute_policy_hash("p1", 1, "v1", None);
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: h1.clone(),
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let h2 = compute_policy_hash("p1", 2, "v2", Some(&h1));
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 2,
            content_hash: h2,
            previous_version_hash: Some(h1),
            created_by: "bob".into(),
            created_at: 2000,
            change_summary: "v2".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let history = store.version_history("p1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[1].version, 2);
    }

    #[test]
    fn test_policy_version_store_verify_version_chain_valid() {
        let mut store = L2PolicyVersionStore::new();
        let h1 = compute_policy_hash("p1", 1, "v1", None);
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: h1.clone(),
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let h2 = compute_policy_hash("p1", 2, "v2", Some(&h1));
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 2,
            content_hash: h2,
            previous_version_hash: Some(h1),
            created_by: "bob".into(),
            created_at: 2000,
            change_summary: "v2".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let verification = store.verify_version_chain("p1");
        assert!(verification.valid);
        assert_eq!(verification.verified_links, 2);
    }

    #[test]
    fn test_policy_version_store_verify_version_chain_detects_tamper() {
        let mut store = L2PolicyVersionStore::new();
        let h1 = compute_policy_hash("p1", 1, "v1", None);
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: h1,
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Active,
        });
        // v2 with wrong previous hash
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 2,
            content_hash: "fake_hash".into(),
            previous_version_hash: Some("wrong_hash".into()),
            created_by: "bob".into(),
            created_at: 2000,
            change_summary: "v2".into(),
            status: L2PolicyVersionStatus::Active,
        });
        let verification = store.verify_version_chain("p1");
        assert!(!verification.valid);
        assert_eq!(verification.broken_at, Some(2));
    }

    #[test]
    fn test_policy_version_store_deprecate_version_changes_status() {
        let mut store = L2PolicyVersionStore::new();
        let hash = compute_policy_hash("p1", 1, "v1", None);
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: hash,
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Active,
        });
        assert!(store.deprecate_version("p1", 1));
        assert_eq!(
            store.current_version("p1").unwrap().status,
            L2PolicyVersionStatus::Deprecated
        );
    }

    #[test]
    fn test_policy_version_store_active_versions_filters_correctly() {
        let mut store = L2PolicyVersionStore::new();
        store.add_version(L2PolicyVersion {
            policy_id: "p1".into(),
            version: 1,
            content_hash: "h1".into(),
            previous_version_hash: None,
            created_by: "alice".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Active,
        });
        store.add_version(L2PolicyVersion {
            policy_id: "p2".into(),
            version: 1,
            content_hash: "h2".into(),
            previous_version_hash: None,
            created_by: "bob".into(),
            created_at: 1000,
            change_summary: "v1".into(),
            status: L2PolicyVersionStatus::Draft,
        });
        let active = store.active_versions();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].policy_id, "p1");
    }
}
