// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Document version diffing.
//
// VersionSnapshot captures a point-in-time document state.
// VersionDiff computes structural differences between snapshots.
// VersionHistoryStore manages ordered version histories with diff.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};

use crate::integrity::hash_document_content;

// ── MetadataChangeType ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum MetadataChangeType {
    Added { value: String },
    Removed { value: String },
    Modified { old: String, new: String },
}

// ── MetadataChange ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetadataChange {
    pub key: String,
    pub change_type: MetadataChangeType,
}

// ── VersionSnapshot ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VersionSnapshot {
    pub doc_id: String,
    pub version: u32,
    pub title: String,
    pub content: String,
    pub metadata: HashMap<String, String>,
    pub content_hash: String,
    pub created_at: i64,
    pub created_by: String,
}

impl VersionSnapshot {
    pub fn new(
        doc_id: impl Into<String>,
        version: u32,
        title: impl Into<String>,
        content: impl Into<String>,
        created_by: impl Into<String>,
        created_at: i64,
    ) -> Self {
        let content_str: String = content.into();
        let content_hash = hash_document_content(content_str.as_bytes());
        Self {
            doc_id: doc_id.into(),
            version,
            title: title.into(),
            content: content_str,
            metadata: HashMap::new(),
            content_hash,
            created_at,
            created_by: created_by.into(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ── VersionDiff ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VersionDiff {
    pub doc_id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub title_changed: bool,
    pub content_changed: bool,
    pub metadata_changes: Vec<MetadataChange>,
    pub lines_added: usize,
    pub lines_removed: usize,
    pub change_ratio: f64,
}

pub fn diff_versions(a: &VersionSnapshot, b: &VersionSnapshot) -> VersionDiff {
    let title_changed = a.title != b.title;
    let content_changed = a.content_hash != b.content_hash;

    // Line-level diff
    let a_lines: HashSet<&str> = a.content.lines().collect();
    let b_lines: HashSet<&str> = b.content.lines().collect();

    let lines_removed = a_lines.difference(&b_lines).count();
    let lines_added = b_lines.difference(&a_lines).count();

    let total_lines = a.content.lines().count().max(1);
    let change_ratio = (lines_added + lines_removed) as f64 / total_lines as f64;

    // Metadata diff
    let mut metadata_changes = Vec::new();
    let all_keys: HashSet<&String> = a.metadata.keys().chain(b.metadata.keys()).collect();
    for key in all_keys {
        match (a.metadata.get(key), b.metadata.get(key)) {
            (None, Some(v)) => {
                metadata_changes.push(MetadataChange {
                    key: key.clone(),
                    change_type: MetadataChangeType::Added { value: v.clone() },
                });
            }
            (Some(v), None) => {
                metadata_changes.push(MetadataChange {
                    key: key.clone(),
                    change_type: MetadataChangeType::Removed { value: v.clone() },
                });
            }
            (Some(old), Some(new)) if old != new => {
                metadata_changes.push(MetadataChange {
                    key: key.clone(),
                    change_type: MetadataChangeType::Modified {
                        old: old.clone(),
                        new: new.clone(),
                    },
                });
            }
            _ => {}
        }
    }

    VersionDiff {
        doc_id: a.doc_id.clone(),
        from_version: a.version,
        to_version: b.version,
        title_changed,
        content_changed,
        metadata_changes,
        lines_added,
        lines_removed,
        change_ratio,
    }
}

// ── VersionHistoryStore ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct VersionHistoryStore {
    pub versions: HashMap<String, Vec<VersionSnapshot>>,
}

impl VersionHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_version(&mut self, snapshot: VersionSnapshot) {
        self.versions
            .entry(snapshot.doc_id.clone())
            .or_default()
            .push(snapshot);
    }

    pub fn get_version(&self, doc_id: &str, version: u32) -> Option<&VersionSnapshot> {
        self.versions
            .get(doc_id)
            .and_then(|vs| vs.iter().find(|v| v.version == version))
    }

    pub fn latest_version(&self, doc_id: &str) -> Option<&VersionSnapshot> {
        self.versions
            .get(doc_id)
            .and_then(|vs| vs.iter().max_by_key(|v| v.version))
    }

    pub fn version_count(&self, doc_id: &str) -> usize {
        self.versions.get(doc_id).map(|vs| vs.len()).unwrap_or(0)
    }

    pub fn diff_latest_two(&self, doc_id: &str) -> Option<VersionDiff> {
        let vs = self.versions.get(doc_id)?;
        if vs.len() < 2 {
            return None;
        }
        let mut sorted: Vec<&VersionSnapshot> = vs.iter().collect();
        sorted.sort_by_key(|v| v.version);
        let len = sorted.len();
        Some(diff_versions(sorted[len - 2], sorted[len - 1]))
    }

    pub fn full_changelog(&self, doc_id: &str) -> Vec<VersionDiff> {
        let vs = match self.versions.get(doc_id) {
            Some(vs) if vs.len() >= 2 => vs,
            _ => return Vec::new(),
        };
        let mut sorted: Vec<&VersionSnapshot> = vs.iter().collect();
        sorted.sort_by_key(|v| v.version);
        sorted
            .windows(2)
            .map(|pair| diff_versions(pair[0], pair[1]))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_snapshot_construction() {
        let snap = VersionSnapshot::new("doc1", 1, "Title", "content", "author", 1000);
        assert_eq!(snap.doc_id, "doc1");
        assert_eq!(snap.content_hash.len(), 64);
    }

    #[test]
    fn test_diff_versions_detects_title_change() {
        let a = VersionSnapshot::new("doc1", 1, "Title A", "content", "author", 1000);
        let b = VersionSnapshot::new("doc1", 2, "Title B", "content", "author", 2000);
        let diff = diff_versions(&a, &b);
        assert!(diff.title_changed);
        assert!(!diff.content_changed);
    }

    #[test]
    fn test_diff_versions_detects_content_changes() {
        let a = VersionSnapshot::new("doc1", 1, "Title", "line one\nline two", "author", 1000);
        let b = VersionSnapshot::new(
            "doc1",
            2,
            "Title",
            "line one\nline three\nline four",
            "author",
            2000,
        );
        let diff = diff_versions(&a, &b);
        assert!(diff.content_changed);
        assert!(diff.lines_added > 0);
        assert!(diff.lines_removed > 0);
    }

    #[test]
    fn test_diff_versions_counts_lines() {
        let a = VersionSnapshot::new("doc1", 1, "T", "a\nb\nc", "auth", 1000);
        let b = VersionSnapshot::new("doc1", 2, "T", "a\nb\nd\ne", "auth", 2000);
        let diff = diff_versions(&a, &b);
        // removed: "c", added: "d", "e"
        assert_eq!(diff.lines_removed, 1);
        assert_eq!(diff.lines_added, 2);
    }

    #[test]
    fn test_diff_versions_detects_metadata_changes() {
        let a = VersionSnapshot::new("doc1", 1, "T", "c", "auth", 1000)
            .with_metadata("author", "alice")
            .with_metadata("status", "draft");
        let b = VersionSnapshot::new("doc1", 2, "T", "c", "auth", 2000)
            .with_metadata("author", "bob")
            .with_metadata("tag", "new");
        let diff = diff_versions(&a, &b);
        assert!(diff.metadata_changes.len() >= 2); // author modified, status removed, tag added
    }

    #[test]
    fn test_version_history_store_add_and_retrieve() {
        let mut store = VersionHistoryStore::new();
        store.add_version(VersionSnapshot::new("doc1", 1, "T", "c1", "auth", 1000));
        store.add_version(VersionSnapshot::new("doc1", 2, "T", "c2", "auth", 2000));
        assert_eq!(store.version_count("doc1"), 2);
        assert!(store.get_version("doc1", 1).is_some());
        assert!(store.get_version("doc1", 2).is_some());
    }

    #[test]
    fn test_version_history_store_latest() {
        let mut store = VersionHistoryStore::new();
        store.add_version(VersionSnapshot::new("doc1", 1, "T", "c1", "auth", 1000));
        store.add_version(VersionSnapshot::new("doc1", 3, "T", "c3", "auth", 3000));
        store.add_version(VersionSnapshot::new("doc1", 2, "T", "c2", "auth", 2000));
        let latest = store.latest_version("doc1").unwrap();
        assert_eq!(latest.version, 3);
    }

    #[test]
    fn test_version_history_store_diff_latest_two() {
        let mut store = VersionHistoryStore::new();
        store.add_version(VersionSnapshot::new("doc1", 1, "Title A", "content", "auth", 1000));
        store.add_version(VersionSnapshot::new("doc1", 2, "Title B", "content", "auth", 2000));
        let diff = store.diff_latest_two("doc1").unwrap();
        assert!(diff.title_changed);
        assert_eq!(diff.from_version, 1);
        assert_eq!(diff.to_version, 2);
    }

    #[test]
    fn test_version_history_store_full_changelog() {
        let mut store = VersionHistoryStore::new();
        store.add_version(VersionSnapshot::new("doc1", 1, "T1", "a", "auth", 1000));
        store.add_version(VersionSnapshot::new("doc1", 2, "T2", "b", "auth", 2000));
        store.add_version(VersionSnapshot::new("doc1", 3, "T3", "c", "auth", 3000));
        let changelog = store.full_changelog("doc1");
        assert_eq!(changelog.len(), 2);
        assert_eq!(changelog[0].from_version, 1);
        assert_eq!(changelog[0].to_version, 2);
        assert_eq!(changelog[1].from_version, 2);
        assert_eq!(changelog[1].to_version, 3);
    }
}
