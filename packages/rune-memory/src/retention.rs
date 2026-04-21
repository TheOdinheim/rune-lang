// ═══════════════════════════════════════════════════════════════════════
// Retention — Memory retention policies, redaction policies,
// conversation window policies, and supporting types for memory
// lifecycle management.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::memory::{MemoryContentType, MemorySensitivity};

// ── ExpiryAction ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExpiryAction {
    Delete,
    Archive,
    Redact,
    Summarize,
}

impl fmt::Display for ExpiryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Delete => "Delete",
            Self::Archive => "Archive",
            Self::Redact => "Redact",
            Self::Summarize => "Summarize",
        };
        f.write_str(s)
    }
}

// ── SummarizationStrategy ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SummarizationStrategy {
    TruncateOldest,
    SlidingWindow,
    SummarizeAndCompact,
    Custom { name: String },
}

impl fmt::Display for SummarizationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncateOldest => write!(f, "TruncateOldest"),
            Self::SlidingWindow => write!(f, "SlidingWindow"),
            Self::SummarizeAndCompact => write!(f, "SummarizeAndCompact"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── RedactionPatternType ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactionPatternType {
    Regex { expression: String },
    KeywordList { keywords: Vec<String> },
    SensitivityBased { min_level: MemorySensitivity },
    Custom { name: String },
}

impl fmt::Display for RedactionPatternType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regex { expression } => write!(f, "Regex({expression})"),
            Self::KeywordList { keywords } => {
                write!(f, "KeywordList(count={})", keywords.len())
            }
            Self::SensitivityBased { min_level } => {
                write!(f, "SensitivityBased(min={min_level})")
            }
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── RedactionPattern ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPattern {
    pub pattern_id: String,
    pub pattern_type: RedactionPatternType,
    pub replacement: String,
    pub description: String,
}

impl RedactionPattern {
    pub fn new(
        pattern_id: impl Into<String>,
        pattern_type: RedactionPatternType,
        replacement: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            pattern_id: pattern_id.into(),
            pattern_type,
            replacement: replacement.into(),
            description: description.into(),
        }
    }
}

// ── MemoryRetentionPolicy ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetentionPolicy {
    pub policy_id: String,
    pub scope_pattern: String,
    pub max_age_seconds: Option<i64>,
    pub max_entries: Option<usize>,
    pub content_type_filter: Option<Vec<MemoryContentType>>,
    pub sensitivity_threshold: Option<MemorySensitivity>,
    pub on_expiry: ExpiryAction,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl MemoryRetentionPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        scope_pattern: impl Into<String>,
        on_expiry: ExpiryAction,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            scope_pattern: scope_pattern.into(),
            max_age_seconds: None,
            max_entries: None,
            content_type_filter: None,
            sensitivity_threshold: None,
            on_expiry,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn with_max_age(mut self, seconds: i64) -> Self {
        self.max_age_seconds = Some(seconds);
        self
    }

    pub fn with_max_entries(mut self, count: usize) -> Self {
        self.max_entries = Some(count);
        self
    }

    pub fn with_sensitivity_threshold(mut self, threshold: MemorySensitivity) -> Self {
        self.sensitivity_threshold = Some(threshold);
        self
    }
}

// ── MemoryRedactionPolicy ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRedactionPolicy {
    pub policy_id: String,
    pub redaction_patterns: Vec<RedactionPattern>,
    pub applies_to_content_types: Option<Vec<MemoryContentType>>,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl MemoryRedactionPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            redaction_patterns: Vec::new(),
            applies_to_content_types: None,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn add_pattern(&mut self, pattern: RedactionPattern) {
        self.redaction_patterns.push(pattern);
    }
}

// ── ConversationWindowPolicy ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationWindowPolicy {
    pub policy_id: String,
    pub max_turns: Option<usize>,
    pub max_tokens_estimate: Option<usize>,
    pub summarization_strategy: SummarizationStrategy,
    pub preserve_system_messages: bool,
    pub preserve_pinned_entries: bool,
    pub created_at: i64,
    pub metadata: HashMap<String, String>,
}

impl ConversationWindowPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        summarization_strategy: SummarizationStrategy,
        created_at: i64,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            max_turns: None,
            max_tokens_estimate: None,
            summarization_strategy,
            preserve_system_messages: true,
            preserve_pinned_entries: true,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn with_max_turns(mut self, turns: usize) -> Self {
        self.max_turns = Some(turns);
        self
    }

    pub fn with_max_tokens_estimate(mut self, tokens: usize) -> Self {
        self.max_tokens_estimate = Some(tokens);
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expiry_action_display() {
        let actions = vec![
            ExpiryAction::Delete,
            ExpiryAction::Archive,
            ExpiryAction::Redact,
            ExpiryAction::Summarize,
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
        assert_eq!(actions.len(), 4);
    }

    #[test]
    fn test_summarization_strategy_display() {
        let strategies = vec![
            SummarizationStrategy::TruncateOldest,
            SummarizationStrategy::SlidingWindow,
            SummarizationStrategy::SummarizeAndCompact,
            SummarizationStrategy::Custom {
                name: "recursive".into(),
            },
        ];
        for s in &strategies {
            assert!(!s.to_string().is_empty());
        }
        assert_eq!(strategies.len(), 4);
    }

    #[test]
    fn test_redaction_pattern_type_display() {
        let types = vec![
            RedactionPatternType::Regex {
                expression: r"\d{3}-\d{2}-\d{4}".into(),
            },
            RedactionPatternType::KeywordList {
                keywords: vec!["password".into(), "secret".into()],
            },
            RedactionPatternType::SensitivityBased {
                min_level: MemorySensitivity::Sensitive,
            },
            RedactionPatternType::Custom {
                name: "pii-detector".into(),
            },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 4);
    }

    #[test]
    fn test_redaction_pattern_construction() {
        let pattern = RedactionPattern::new(
            "rp-1",
            RedactionPatternType::Regex {
                expression: r"\b\d{9}\b".into(),
            },
            "[REDACTED]",
            "Redact 9-digit numbers",
        );
        assert_eq!(pattern.pattern_id, "rp-1");
        assert_eq!(pattern.replacement, "[REDACTED]");
    }

    #[test]
    fn test_retention_policy_construction() {
        let policy = MemoryRetentionPolicy::new("rp-1", "scope-*", ExpiryAction::Delete, 1000);
        assert_eq!(policy.policy_id, "rp-1");
        assert_eq!(policy.scope_pattern, "scope-*");
        assert_eq!(policy.on_expiry, ExpiryAction::Delete);
        assert!(policy.max_age_seconds.is_none());
        assert!(policy.max_entries.is_none());
    }

    #[test]
    fn test_retention_policy_builders() {
        let policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Archive, 1000)
            .with_max_age(86400)
            .with_max_entries(1000)
            .with_sensitivity_threshold(MemorySensitivity::Sensitive);
        assert_eq!(policy.max_age_seconds, Some(86400));
        assert_eq!(policy.max_entries, Some(1000));
        assert_eq!(
            policy.sensitivity_threshold,
            Some(MemorySensitivity::Sensitive)
        );
    }

    #[test]
    fn test_redaction_policy_construction() {
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(RedactionPattern::new(
            "rp-1",
            RedactionPatternType::KeywordList {
                keywords: vec!["ssn".into()],
            },
            "[REDACTED]",
            "Redact SSNs",
        ));
        assert_eq!(policy.policy_id, "rdp-1");
        assert_eq!(policy.redaction_patterns.len(), 1);
    }

    #[test]
    fn test_conversation_window_policy_construction() {
        let policy = ConversationWindowPolicy::new(
            "cwp-1",
            SummarizationStrategy::SlidingWindow,
            1000,
        );
        assert_eq!(policy.policy_id, "cwp-1");
        assert!(policy.preserve_system_messages);
        assert!(policy.preserve_pinned_entries);
        assert!(policy.max_turns.is_none());
    }

    #[test]
    fn test_conversation_window_policy_builders() {
        let policy = ConversationWindowPolicy::new(
            "cwp-1",
            SummarizationStrategy::TruncateOldest,
            1000,
        )
        .with_max_turns(50)
        .with_max_tokens_estimate(128000);
        assert_eq!(policy.max_turns, Some(50));
        assert_eq!(policy.max_tokens_estimate, Some(128000));
    }

    #[test]
    fn test_retention_policy_eq() {
        let p1 = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Delete, 1000);
        assert_eq!(p1, p1.clone());
    }

    #[test]
    fn test_conversation_window_policy_eq() {
        let p1 = ConversationWindowPolicy::new(
            "cwp-1",
            SummarizationStrategy::SummarizeAndCompact,
            1000,
        );
        assert_eq!(p1, p1.clone());
    }

    #[test]
    fn test_retention_policy_with_content_type_filter() {
        let mut policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Redact, 1000);
        policy.content_type_filter = Some(vec![
            MemoryContentType::ConversationTurn,
            MemoryContentType::RetrievalResult,
        ]);
        assert_eq!(policy.content_type_filter.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_redaction_policy_with_content_types() {
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.applies_to_content_types = Some(vec![MemoryContentType::ConversationTurn]);
        assert!(policy.applies_to_content_types.is_some());
    }

    #[test]
    fn test_custom_summarization_strategy() {
        let s = SummarizationStrategy::Custom {
            name: "hierarchical".into(),
        };
        assert_eq!(s.to_string(), "Custom(hierarchical)");
    }

    #[test]
    fn test_retention_policy_metadata() {
        let mut policy = MemoryRetentionPolicy::new("rp-1", "*", ExpiryAction::Archive, 1000);
        policy.metadata.insert("owner".into(), "admin".into());
        assert_eq!(policy.metadata.get("owner"), Some(&"admin".to_string()));
    }
}
