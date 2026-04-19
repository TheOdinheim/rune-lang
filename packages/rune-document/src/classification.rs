// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Document classification and sensitivity scoring.
//
// Multi-dimensional document classification with sensitivity levels,
// category-based scoring, keyword auto-classification, and a
// classification store with review tracking.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

// ── SensitivityLevel ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

impl fmt::Display for SensitivityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Internal => f.write_str("internal"),
            Self::Confidential => f.write_str("confidential"),
            Self::Secret => f.write_str("secret"),
            Self::TopSecret => f.write_str("top-secret"),
        }
    }
}

// ── DocumentCategory ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentCategory {
    PersonalData,
    FinancialData,
    HealthData,
    LegalPrivilege,
    TradeSecret,
    GovernmentClassified,
    Regulatory,
    Operational,
}

impl fmt::Display for DocumentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PersonalData => f.write_str("personal-data"),
            Self::FinancialData => f.write_str("financial-data"),
            Self::HealthData => f.write_str("health-data"),
            Self::LegalPrivilege => f.write_str("legal-privilege"),
            Self::TradeSecret => f.write_str("trade-secret"),
            Self::GovernmentClassified => f.write_str("government-classified"),
            Self::Regulatory => f.write_str("regulatory"),
            Self::Operational => f.write_str("operational"),
        }
    }
}

// ── DocumentClassification ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocumentClassification {
    pub doc_id: String,
    pub sensitivity_level: SensitivityLevel,
    pub categories: Vec<DocumentCategory>,
    pub handling_instructions: Vec<String>,
    pub classified_by: String,
    pub classified_at: i64,
    pub review_due_at: Option<i64>,
}

impl DocumentClassification {
    pub fn new(
        doc_id: impl Into<String>,
        sensitivity_level: SensitivityLevel,
        classified_by: impl Into<String>,
        classified_at: i64,
    ) -> Self {
        Self {
            doc_id: doc_id.into(),
            sensitivity_level,
            categories: Vec::new(),
            handling_instructions: Vec::new(),
            classified_by: classified_by.into(),
            classified_at,
            review_due_at: None,
        }
    }

    pub fn with_category(mut self, cat: DocumentCategory) -> Self {
        self.categories.push(cat);
        self
    }

    pub fn with_handling(mut self, instruction: impl Into<String>) -> Self {
        self.handling_instructions.push(instruction.into());
        self
    }

    pub fn with_review_due(mut self, due_at: i64) -> Self {
        self.review_due_at = Some(due_at);
        self
    }
}

// ── SensitivityScore ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SensitivityScore {
    pub overall: f64,
    pub dimensions: HashMap<String, f64>,
    pub recommended_level: SensitivityLevel,
}

pub fn score_sensitivity(classification: &DocumentClassification) -> SensitivityScore {
    let base = match &classification.sensitivity_level {
        SensitivityLevel::Public => 0.0,
        SensitivityLevel::Internal => 20.0,
        SensitivityLevel::Confidential => 40.0,
        SensitivityLevel::Secret => 60.0,
        SensitivityLevel::TopSecret => 80.0,
    };

    let mut dimensions = HashMap::new();
    dimensions.insert("base_level".into(), base);

    let mut category_score = 0.0;
    for cat in &classification.categories {
        let modifier = match cat {
            DocumentCategory::PersonalData => 15.0,
            DocumentCategory::HealthData => 20.0,
            DocumentCategory::TradeSecret => 10.0,
            DocumentCategory::GovernmentClassified => 25.0,
            DocumentCategory::FinancialData => 12.0,
            DocumentCategory::LegalPrivilege => 10.0,
            DocumentCategory::Regulatory => 5.0,
            DocumentCategory::Operational => 3.0,
        };
        category_score += modifier;
    }
    dimensions.insert("category_modifier".into(), category_score);

    let overall = f64::min(base + category_score, 100.0);

    let recommended_level = if overall >= 80.0 {
        SensitivityLevel::TopSecret
    } else if overall >= 60.0 {
        SensitivityLevel::Secret
    } else if overall >= 40.0 {
        SensitivityLevel::Confidential
    } else if overall >= 20.0 {
        SensitivityLevel::Internal
    } else {
        SensitivityLevel::Public
    };

    SensitivityScore {
        overall,
        dimensions,
        recommended_level,
    }
}

pub fn auto_classify(content: &str, metadata: &HashMap<String, String>) -> SensitivityLevel {
    let lower_content = content.to_lowercase();
    let all_text: String = metadata
        .values()
        .map(|v| v.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let combined = format!("{lower_content} {all_text}");

    if combined.contains("top secret") || combined.contains("top-secret") {
        SensitivityLevel::TopSecret
    } else if combined.contains("secret") || combined.contains("classified") {
        SensitivityLevel::Secret
    } else if combined.contains("confidential")
        || combined.contains("pii")
        || combined.contains("hipaa")
        || combined.contains("trade secret")
    {
        SensitivityLevel::Confidential
    } else {
        SensitivityLevel::Internal
    }
}

// ── ClassificationStore ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ClassificationStore {
    pub classifications: HashMap<String, DocumentClassification>,
}

impl ClassificationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn classify(&mut self, classification: DocumentClassification) {
        self.classifications
            .insert(classification.doc_id.clone(), classification);
    }

    pub fn get(&self, doc_id: &str) -> Option<&DocumentClassification> {
        self.classifications.get(doc_id)
    }

    pub fn documents_at_level(&self, level: &SensitivityLevel) -> Vec<&str> {
        self.classifications
            .values()
            .filter(|c| c.sensitivity_level == *level)
            .map(|c| c.doc_id.as_str())
            .collect()
    }

    pub fn overdue_reviews(&self, now: i64) -> Vec<&DocumentClassification> {
        self.classifications
            .values()
            .filter(|c| c.review_due_at.is_some_and(|due| due <= now))
            .collect()
    }

    pub fn reclassify(
        &mut self,
        doc_id: &str,
        new_level: SensitivityLevel,
        by: &str,
        now: i64,
    ) -> bool {
        if let Some(classification) = self.classifications.get_mut(doc_id) {
            classification.sensitivity_level = new_level;
            classification.classified_by = by.into();
            classification.classified_at = now;
            true
        } else {
            false
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_construction() {
        let cls = DocumentClassification::new("doc1", SensitivityLevel::Confidential, "alice", 1000)
            .with_category(DocumentCategory::PersonalData)
            .with_handling("encrypt at rest");
        assert_eq!(cls.sensitivity_level, SensitivityLevel::Confidential);
        assert_eq!(cls.categories.len(), 1);
        assert_eq!(cls.handling_instructions.len(), 1);
    }

    #[test]
    fn test_sensitivity_level_ordering() {
        assert!(SensitivityLevel::Public < SensitivityLevel::Internal);
        assert!(SensitivityLevel::Internal < SensitivityLevel::Confidential);
        assert!(SensitivityLevel::Confidential < SensitivityLevel::Secret);
        assert!(SensitivityLevel::Secret < SensitivityLevel::TopSecret);
    }

    #[test]
    fn test_score_sensitivity_computes() {
        let cls =
            DocumentClassification::new("doc1", SensitivityLevel::Confidential, "alice", 1000)
                .with_category(DocumentCategory::PersonalData);
        let score = score_sensitivity(&cls);
        // base 40 + personal_data 15 = 55
        assert!((score.overall - 55.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_sensitivity_recommends_level() {
        let cls = DocumentClassification::new("doc1", SensitivityLevel::Secret, "alice", 1000)
            .with_category(DocumentCategory::GovernmentClassified);
        let score = score_sensitivity(&cls);
        // base 60 + govt 25 = 85 → TopSecret
        assert_eq!(score.recommended_level, SensitivityLevel::TopSecret);
    }

    #[test]
    fn test_auto_classify_confidential() {
        let level = auto_classify(
            "This document contains confidential PII data",
            &HashMap::new(),
        );
        assert_eq!(level, SensitivityLevel::Confidential);
    }

    #[test]
    fn test_auto_classify_default_internal() {
        let level = auto_classify("A regular document", &HashMap::new());
        assert_eq!(level, SensitivityLevel::Internal);
    }

    #[test]
    fn test_classification_store_classify_and_get() {
        let mut store = ClassificationStore::new();
        store.classify(DocumentClassification::new(
            "doc1",
            SensitivityLevel::Confidential,
            "alice",
            1000,
        ));
        assert!(store.get("doc1").is_some());
        assert_eq!(
            store.get("doc1").unwrap().sensitivity_level,
            SensitivityLevel::Confidential
        );
    }

    #[test]
    fn test_classification_store_documents_at_level() {
        let mut store = ClassificationStore::new();
        store.classify(DocumentClassification::new(
            "doc1",
            SensitivityLevel::Confidential,
            "alice",
            1000,
        ));
        store.classify(DocumentClassification::new(
            "doc2",
            SensitivityLevel::Public,
            "bob",
            1000,
        ));
        store.classify(DocumentClassification::new(
            "doc3",
            SensitivityLevel::Confidential,
            "alice",
            1000,
        ));
        let confidential = store.documents_at_level(&SensitivityLevel::Confidential);
        assert_eq!(confidential.len(), 2);
    }

    #[test]
    fn test_classification_store_overdue_reviews() {
        let mut store = ClassificationStore::new();
        store.classify(
            DocumentClassification::new("doc1", SensitivityLevel::Internal, "alice", 1000)
                .with_review_due(5000),
        );
        store.classify(
            DocumentClassification::new("doc2", SensitivityLevel::Internal, "bob", 1000)
                .with_review_due(10000),
        );
        let overdue = store.overdue_reviews(6000);
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].doc_id, "doc1");
    }

    #[test]
    fn test_classification_store_reclassify() {
        let mut store = ClassificationStore::new();
        store.classify(DocumentClassification::new(
            "doc1",
            SensitivityLevel::Internal,
            "alice",
            1000,
        ));
        assert!(store.reclassify("doc1", SensitivityLevel::Secret, "bob", 2000));
        assert_eq!(
            store.get("doc1").unwrap().sensitivity_level,
            SensitivityLevel::Secret
        );
        assert_eq!(store.get("doc1").unwrap().classified_by, "bob");
    }
}
