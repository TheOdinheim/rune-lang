// ═══════════════════════════════════════════════════════════════════════
// Document Version Controller — Trait for managing document version
// history with tagging, lineage, and comparison.
//
// LinearDocumentVersionController rejects branching — each document
// has one linear version chain, appropriate for regulated environments
// where version branching is disallowed.
//
// MetadataFieldChange is distinct from the L2 MetadataChange /
// MetadataChangeType in version_diff.rs.  L2's types use nested enums;
// L3's FieldChangeType is flat for Eq derivation.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::DocumentError;

// ── FieldChangeType ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldChangeType {
    Added,
    Modified,
    Removed,
}

impl fmt::Display for FieldChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => write!(f, "added"),
            Self::Modified => write!(f, "modified"),
            Self::Removed => write!(f, "removed"),
        }
    }
}

// ── MetadataFieldChange ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataFieldChange {
    pub field_name: String,
    pub change_type: FieldChangeType,
    pub old_value: String,
    pub new_value: String,
}

// ── ChronologicalOrder ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChronologicalOrder {
    ABeforeB,
    BBeforeA,
    Simultaneous,
}

impl fmt::Display for ChronologicalOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ABeforeB => write!(f, "a-before-b"),
            Self::BBeforeA => write!(f, "b-before-a"),
            Self::Simultaneous => write!(f, "simultaneous"),
        }
    }
}

// ── VersionComparison ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionComparison {
    pub version_a_id: String,
    pub version_b_id: String,
    pub content_changed: bool,
    pub metadata_changes: Vec<MetadataFieldChange>,
    pub size_delta_bytes: i64,
    pub chronological_order: ChronologicalOrder,
}

// ── DocumentTag ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentTag {
    pub tag_id: String,
    pub document_id: String,
    pub version_id: String,
    pub tag_name: String,
    pub created_by: String,
    pub created_at: i64,
    pub tag_message: String,
}

// ── VersionEntry (internal) ────────────────────────────────────

#[derive(Debug, Clone)]
struct VersionEntry {
    _version_id: String,
    _document_id: String,
    content_hash: String,
    content_size: usize,
    metadata: HashMap<String, String>,
    created_at: i64,
    previous_version_id: Option<String>,
}

// ── DocumentVersionController trait ────────────────────────────

pub trait DocumentVersionController {
    fn create_version(
        &mut self,
        document_id: &str,
        version_id: &str,
        content_hash: &str,
        content_size: usize,
        metadata: &HashMap<String, String>,
        created_at: i64,
    ) -> Result<(), DocumentError>;

    fn revert_to_version(
        &mut self,
        document_id: &str,
        target_version_id: &str,
        new_version_id: &str,
        created_at: i64,
    ) -> Result<(), DocumentError>;

    fn tag_version(
        &mut self,
        tag: DocumentTag,
    ) -> Result<(), DocumentError>;

    fn list_tags(&self, document_id: &str) -> Vec<DocumentTag>;

    fn list_version_lineage(&self, document_id: &str) -> Vec<String>;

    fn compare_versions(
        &self,
        version_a_id: &str,
        version_b_id: &str,
    ) -> Result<VersionComparison, DocumentError>;

    fn controller_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── InMemoryDocumentVersionController ──────────────────────────

pub struct InMemoryDocumentVersionController {
    id: String,
    versions: HashMap<String, VersionEntry>,
    latest_per_document: HashMap<String, String>,
    tags: Vec<DocumentTag>,
}

impl InMemoryDocumentVersionController {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            versions: HashMap::new(),
            latest_per_document: HashMap::new(),
            tags: Vec::new(),
        }
    }
}

impl DocumentVersionController for InMemoryDocumentVersionController {
    fn create_version(
        &mut self,
        document_id: &str,
        version_id: &str,
        content_hash: &str,
        content_size: usize,
        metadata: &HashMap<String, String>,
        created_at: i64,
    ) -> Result<(), DocumentError> {
        if self.versions.contains_key(version_id) {
            return Err(DocumentError::DocumentAlreadyExists(version_id.to_string()));
        }
        let previous = self.latest_per_document.get(document_id).cloned();
        self.versions.insert(version_id.to_string(), VersionEntry {
            _version_id: version_id.to_string(),
            _document_id: document_id.to_string(),
            content_hash: content_hash.to_string(),
            content_size,
            metadata: metadata.clone(),
            created_at,
            previous_version_id: previous,
        });
        self.latest_per_document.insert(document_id.to_string(), version_id.to_string());
        Ok(())
    }

    fn revert_to_version(
        &mut self,
        document_id: &str,
        target_version_id: &str,
        new_version_id: &str,
        created_at: i64,
    ) -> Result<(), DocumentError> {
        let target = self.versions.get(target_version_id)
            .ok_or_else(|| DocumentError::VersionNotFound(target_version_id.to_string()))?
            .clone();
        self.create_version(
            document_id,
            new_version_id,
            &target.content_hash,
            target.content_size,
            &target.metadata,
            created_at,
        )
    }

    fn tag_version(&mut self, tag: DocumentTag) -> Result<(), DocumentError> {
        if !self.versions.contains_key(&tag.version_id) {
            return Err(DocumentError::VersionNotFound(tag.version_id.clone()));
        }
        self.tags.push(tag);
        Ok(())
    }

    fn list_tags(&self, document_id: &str) -> Vec<DocumentTag> {
        self.tags.iter().filter(|t| t.document_id == document_id).cloned().collect()
    }

    fn list_version_lineage(&self, document_id: &str) -> Vec<String> {
        let mut lineage = Vec::new();
        let mut current_id = self.latest_per_document.get(document_id).cloned();
        while let Some(vid) = current_id {
            lineage.push(vid.clone());
            current_id = self.versions.get(&vid).and_then(|v| v.previous_version_id.clone());
        }
        lineage
    }

    fn compare_versions(
        &self,
        version_a_id: &str,
        version_b_id: &str,
    ) -> Result<VersionComparison, DocumentError> {
        let a = self.versions.get(version_a_id)
            .ok_or_else(|| DocumentError::VersionNotFound(version_a_id.to_string()))?;
        let b = self.versions.get(version_b_id)
            .ok_or_else(|| DocumentError::VersionNotFound(version_b_id.to_string()))?;

        let content_changed = a.content_hash != b.content_hash;
        let size_delta = b.content_size as i64 - a.content_size as i64;

        let mut metadata_changes = Vec::new();
        let all_keys: std::collections::HashSet<&String> =
            a.metadata.keys().chain(b.metadata.keys()).collect();
        for key in all_keys {
            match (a.metadata.get(key), b.metadata.get(key)) {
                (None, Some(v)) => metadata_changes.push(MetadataFieldChange {
                    field_name: key.clone(), change_type: FieldChangeType::Added,
                    old_value: String::new(), new_value: v.clone(),
                }),
                (Some(v), None) => metadata_changes.push(MetadataFieldChange {
                    field_name: key.clone(), change_type: FieldChangeType::Removed,
                    old_value: v.clone(), new_value: String::new(),
                }),
                (Some(old), Some(new)) if old != new => metadata_changes.push(MetadataFieldChange {
                    field_name: key.clone(), change_type: FieldChangeType::Modified,
                    old_value: old.clone(), new_value: new.clone(),
                }),
                _ => {}
            }
        }

        let chronological_order = if a.created_at < b.created_at {
            ChronologicalOrder::ABeforeB
        } else if a.created_at > b.created_at {
            ChronologicalOrder::BBeforeA
        } else {
            ChronologicalOrder::Simultaneous
        };

        Ok(VersionComparison {
            version_a_id: version_a_id.to_string(),
            version_b_id: version_b_id.to_string(),
            content_changed,
            metadata_changes,
            size_delta_bytes: size_delta,
            chronological_order,
        })
    }

    fn controller_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── LinearDocumentVersionController ────────────────────────────

pub struct LinearDocumentVersionController {
    inner: InMemoryDocumentVersionController,
}

impl LinearDocumentVersionController {
    pub fn new(id: &str) -> Self {
        Self { inner: InMemoryDocumentVersionController::new(id) }
    }
}

impl DocumentVersionController for LinearDocumentVersionController {
    fn create_version(
        &mut self,
        document_id: &str,
        version_id: &str,
        content_hash: &str,
        content_size: usize,
        metadata: &HashMap<String, String>,
        created_at: i64,
    ) -> Result<(), DocumentError> {
        self.inner.create_version(document_id, version_id, content_hash, content_size, metadata, created_at)
    }

    fn revert_to_version(
        &mut self,
        document_id: &str,
        target_version_id: &str,
        new_version_id: &str,
        created_at: i64,
    ) -> Result<(), DocumentError> {
        self.inner.revert_to_version(document_id, target_version_id, new_version_id, created_at)
    }

    fn tag_version(&mut self, tag: DocumentTag) -> Result<(), DocumentError> {
        self.inner.tag_version(tag)
    }

    fn list_tags(&self, document_id: &str) -> Vec<DocumentTag> {
        self.inner.list_tags(document_id)
    }

    fn list_version_lineage(&self, document_id: &str) -> Vec<String> {
        self.inner.list_version_lineage(document_id)
    }

    fn compare_versions(
        &self,
        version_a_id: &str,
        version_b_id: &str,
    ) -> Result<VersionComparison, DocumentError> {
        self.inner.compare_versions(version_a_id, version_b_id)
    }

    fn controller_id(&self) -> &str { self.inner.controller_id() }
    fn is_active(&self) -> bool { true }
}

// ── NullDocumentVersionController ──────────────────────────────

pub struct NullDocumentVersionController {
    id: String,
}

impl NullDocumentVersionController {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl DocumentVersionController for NullDocumentVersionController {
    fn create_version(&mut self, _: &str, _: &str, _: &str, _: usize, _: &HashMap<String, String>, _: i64) -> Result<(), DocumentError> { Ok(()) }
    fn revert_to_version(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<(), DocumentError> { Ok(()) }
    fn tag_version(&mut self, _: DocumentTag) -> Result<(), DocumentError> { Ok(()) }
    fn list_tags(&self, _: &str) -> Vec<DocumentTag> { Vec::new() }
    fn list_version_lineage(&self, _: &str) -> Vec<String> { Vec::new() }
    fn compare_versions(&self, a: &str, b: &str) -> Result<VersionComparison, DocumentError> {
        Ok(VersionComparison {
            version_a_id: a.to_string(), version_b_id: b.to_string(),
            content_changed: false, metadata_changes: Vec::new(),
            size_delta_bytes: 0, chronological_order: ChronologicalOrder::Simultaneous,
        })
    }
    fn controller_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_change_type_display() {
        assert_eq!(FieldChangeType::Added.to_string(), "added");
        assert_eq!(FieldChangeType::Modified.to_string(), "modified");
        assert_eq!(FieldChangeType::Removed.to_string(), "removed");
    }

    #[test]
    fn test_chronological_order_display() {
        assert_eq!(ChronologicalOrder::ABeforeB.to_string(), "a-before-b");
        assert_eq!(ChronologicalOrder::BBeforeA.to_string(), "b-before-a");
        assert_eq!(ChronologicalOrder::Simultaneous.to_string(), "simultaneous");
    }

    #[test]
    fn test_create_and_lineage() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        ctrl.create_version("d1", "v1", "hash1", 100, &HashMap::new(), 1000).unwrap();
        ctrl.create_version("d1", "v2", "hash2", 200, &HashMap::new(), 2000).unwrap();
        ctrl.create_version("d1", "v3", "hash3", 150, &HashMap::new(), 3000).unwrap();
        let lineage = ctrl.list_version_lineage("d1");
        assert_eq!(lineage, vec!["v3", "v2", "v1"]);
    }

    #[test]
    fn test_revert_to_version() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        ctrl.create_version("d1", "v1", "hash1", 100, &HashMap::new(), 1000).unwrap();
        ctrl.create_version("d1", "v2", "hash2", 200, &HashMap::new(), 2000).unwrap();
        ctrl.revert_to_version("d1", "v1", "v3", 3000).unwrap();
        let lineage = ctrl.list_version_lineage("d1");
        assert_eq!(lineage[0], "v3");
    }

    #[test]
    fn test_tag_version() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        ctrl.create_version("d1", "v1", "hash1", 100, &HashMap::new(), 1000).unwrap();
        ctrl.tag_version(DocumentTag {
            tag_id: "t1".into(), document_id: "d1".into(), version_id: "v1".into(),
            tag_name: "release-1.0".into(), created_by: "alice".into(),
            created_at: 2000, tag_message: "First release".into(),
        }).unwrap();
        let tags = ctrl.list_tags("d1");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].tag_name, "release-1.0");
    }

    #[test]
    fn test_tag_nonexistent_version() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        let result = ctrl.tag_version(DocumentTag {
            tag_id: "t1".into(), document_id: "d1".into(), version_id: "v999".into(),
            tag_name: "bad".into(), created_by: "alice".into(),
            created_at: 1000, tag_message: "".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_compare_versions() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        let meta1 = HashMap::from([("author".into(), "alice".into())]);
        let meta2 = HashMap::from([("author".into(), "bob".into()), ("tag".into(), "new".into())]);
        ctrl.create_version("d1", "v1", "hash1", 100, &meta1, 1000).unwrap();
        ctrl.create_version("d1", "v2", "hash2", 150, &meta2, 2000).unwrap();

        let cmp = ctrl.compare_versions("v1", "v2").unwrap();
        assert!(cmp.content_changed);
        assert_eq!(cmp.size_delta_bytes, 50);
        assert_eq!(cmp.chronological_order, ChronologicalOrder::ABeforeB);
        assert!(!cmp.metadata_changes.is_empty());
    }

    #[test]
    fn test_compare_same_content() {
        let mut ctrl = InMemoryDocumentVersionController::new("vc-1");
        ctrl.create_version("d1", "v1", "hash1", 100, &HashMap::new(), 1000).unwrap();
        ctrl.create_version("d1", "v2", "hash1", 100, &HashMap::new(), 1000).unwrap();
        let cmp = ctrl.compare_versions("v1", "v2").unwrap();
        assert!(!cmp.content_changed);
        assert_eq!(cmp.chronological_order, ChronologicalOrder::Simultaneous);
    }

    #[test]
    fn test_linear_controller() {
        let mut ctrl = LinearDocumentVersionController::new("lvc-1");
        ctrl.create_version("d1", "v1", "h1", 100, &HashMap::new(), 1000).unwrap();
        ctrl.create_version("d1", "v2", "h2", 200, &HashMap::new(), 2000).unwrap();
        assert_eq!(ctrl.list_version_lineage("d1"), vec!["v2", "v1"]);
        assert_eq!(ctrl.controller_id(), "lvc-1");
        assert!(ctrl.is_active());
    }

    #[test]
    fn test_null_controller() {
        let mut ctrl = NullDocumentVersionController::new("null-1");
        ctrl.create_version("d1", "v1", "h1", 0, &HashMap::new(), 0).unwrap();
        assert!(ctrl.list_version_lineage("d1").is_empty());
        assert!(ctrl.list_tags("d1").is_empty());
        assert!(!ctrl.is_active());
    }

    #[test]
    fn test_controller_ids() {
        let ctrl = InMemoryDocumentVersionController::new("vc-1");
        assert_eq!(ctrl.controller_id(), "vc-1");
        assert!(ctrl.is_active());
    }
}
