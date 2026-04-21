// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Redaction engine for memory content. Applies keyword-based
// and sensitivity-based redaction patterns. Regex patterns are stored
// but require an adapter crate — attempting to apply them returns an
// error explaining this limitation.
// ═══════════════════════════════════════════════════════════════════════

use crate::error::MemoryError;
use crate::memory::{MemoryEntry, MemorySensitivity};
use crate::retention::{MemoryRedactionPolicy, RedactionPattern, RedactionPatternType};

// ── RedactionAction ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionAction {
    pub pattern_id: String,
    pub original_span: String,
    pub replacement: String,
}

// ── RedactionReport ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RedactionReport {
    pub entry_id: String,
    pub policy_id: String,
    pub actions: Vec<RedactionAction>,
    pub original_content: String,
    pub redacted_content: String,
    pub fully_redacted: bool,
}

impl RedactionReport {
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn was_modified(&self) -> bool {
        !self.actions.is_empty()
    }
}

// ── RedactedContent ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedContent {
    pub content: String,
    pub actions: Vec<RedactionAction>,
}

// ── MemoryRedactionEngine ─────────────────────────────────────────

pub struct MemoryRedactionEngine;

impl MemoryRedactionEngine {
    pub fn new() -> Self {
        Self
    }

    /// Redact content string using a single pattern. Returns the redacted
    /// text and all actions taken.
    pub fn apply_pattern(
        &self,
        content: &str,
        pattern: &RedactionPattern,
    ) -> Result<RedactedContent, MemoryError> {
        match &pattern.pattern_type {
            RedactionPatternType::KeywordList { keywords } => {
                let mut result = content.to_string();
                let mut actions = Vec::new();
                for keyword in keywords {
                    let lower_content = result.to_lowercase();
                    let lower_keyword = keyword.to_lowercase();
                    // Find all occurrences (case-insensitive)
                    let mut offset = 0;
                    while let Some(pos) = lower_content[offset..].find(&lower_keyword) {
                        let abs_pos = offset + pos;
                        let original = &result[abs_pos..abs_pos + keyword.len()];
                        actions.push(RedactionAction {
                            pattern_id: pattern.pattern_id.clone(),
                            original_span: original.to_string(),
                            replacement: pattern.replacement.clone(),
                        });
                        offset = abs_pos + keyword.len();
                    }
                    // Now do the actual replacement
                    let mut new_result = String::new();
                    let mut search_start = 0;
                    let lower_result = result.to_lowercase();
                    while let Some(pos) = lower_result[search_start..].find(&lower_keyword) {
                        let abs_pos = search_start + pos;
                        new_result.push_str(&result[search_start..abs_pos]);
                        new_result.push_str(&pattern.replacement);
                        search_start = abs_pos + keyword.len();
                    }
                    new_result.push_str(&result[search_start..]);
                    result = new_result;
                }
                Ok(RedactedContent {
                    content: result,
                    actions,
                })
            }
            RedactionPatternType::SensitivityBased { .. } => {
                // Sensitivity-based redaction replaces entire content
                let actions = vec![RedactionAction {
                    pattern_id: pattern.pattern_id.clone(),
                    original_span: content.to_string(),
                    replacement: pattern.replacement.clone(),
                }];
                Ok(RedactedContent {
                    content: pattern.replacement.clone(),
                    actions,
                })
            }
            RedactionPatternType::Regex { expression } => Err(MemoryError::InvalidOperation(
                format!(
                    "regex pattern '{}' requires an adapter crate — \
                     rune-memory does not include a regex dependency",
                    expression
                ),
            )),
            RedactionPatternType::Custom { name } => Err(MemoryError::InvalidOperation(
                format!(
                    "custom redaction pattern '{}' requires an adapter implementation",
                    name
                ),
            )),
        }
    }

    /// Redact raw content string against all patterns in a policy.
    pub fn redact_content(
        &self,
        content: &str,
        policy: &MemoryRedactionPolicy,
    ) -> Result<RedactedContent, MemoryError> {
        let mut current = content.to_string();
        let mut all_actions = Vec::new();

        for pattern in &policy.redaction_patterns {
            let result = self.apply_pattern(&current, pattern)?;
            all_actions.extend(result.actions);
            current = result.content;
        }

        Ok(RedactedContent {
            content: current,
            actions: all_actions,
        })
    }

    /// Redact a MemoryEntry, returning a full report. If the policy has a
    /// content-type filter and the entry doesn't match, no redaction is
    /// performed.
    pub fn redact_entry(
        &self,
        entry: &MemoryEntry,
        policy: &MemoryRedactionPolicy,
    ) -> Result<RedactionReport, MemoryError> {
        // Check content-type applicability
        if let Some(ref types) = policy.applies_to_content_types
            && !types.contains(&entry.content_type)
        {
            return Ok(RedactionReport {
                entry_id: entry.entry_id.clone(),
                policy_id: policy.policy_id.clone(),
                actions: Vec::new(),
                original_content: entry.content.clone(),
                redacted_content: entry.content.clone(),
                fully_redacted: false,
            });
        }

        let result = self.redact_content(&entry.content, policy)?;
        let fully_redacted = !result.actions.is_empty()
            && result.content == policy
                .redaction_patterns
                .first()
                .map(|p| p.replacement.as_str())
                .unwrap_or("[REDACTED]");

        Ok(RedactionReport {
            entry_id: entry.entry_id.clone(),
            policy_id: policy.policy_id.clone(),
            actions: result.actions,
            original_content: entry.content.clone(),
            redacted_content: result.content,
            fully_redacted,
        })
    }

    /// Check whether a sensitivity-based redaction should apply.
    pub fn should_redact_by_sensitivity(
        &self,
        entry: &MemoryEntry,
        min_level: &MemorySensitivity,
    ) -> bool {
        entry.sensitivity_level >= *min_level
    }
}

impl Default for MemoryRedactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryContentType;

    fn make_entry(id: &str, content: &str) -> MemoryEntry {
        MemoryEntry::new(
            id, "scope-1", content,
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Internal, "agent-1", 1000,
        )
    }

    fn keyword_pattern(keywords: Vec<&str>) -> RedactionPattern {
        RedactionPattern::new(
            "rp-kw",
            RedactionPatternType::KeywordList {
                keywords: keywords.into_iter().map(String::from).collect(),
            },
            "[REDACTED]",
            "keyword redaction",
        )
    }

    #[test]
    fn test_apply_keyword_pattern_single() {
        let engine = MemoryRedactionEngine::new();
        let pattern = keyword_pattern(vec!["password"]);
        let result = engine.apply_pattern("my password is secret", &pattern).unwrap();
        assert_eq!(result.content, "my [REDACTED] is secret");
        assert_eq!(result.actions.len(), 1);
    }

    #[test]
    fn test_apply_keyword_pattern_multiple_keywords() {
        let engine = MemoryRedactionEngine::new();
        let pattern = keyword_pattern(vec!["password", "secret"]);
        let result = engine.apply_pattern("my password is secret", &pattern).unwrap();
        assert_eq!(result.content, "my [REDACTED] is [REDACTED]");
        assert_eq!(result.actions.len(), 2);
    }

    #[test]
    fn test_apply_keyword_case_insensitive() {
        let engine = MemoryRedactionEngine::new();
        let pattern = keyword_pattern(vec!["password"]);
        let result = engine.apply_pattern("my PASSWORD is here", &pattern).unwrap();
        assert_eq!(result.content, "my [REDACTED] is here");
    }

    #[test]
    fn test_apply_keyword_multiple_occurrences() {
        let engine = MemoryRedactionEngine::new();
        let pattern = keyword_pattern(vec!["ssn"]);
        let result = engine.apply_pattern("ssn: 123 and ssn: 456", &pattern).unwrap();
        assert_eq!(result.content, "[REDACTED]: 123 and [REDACTED]: 456");
        assert_eq!(result.actions.len(), 2);
    }

    #[test]
    fn test_apply_keyword_no_match() {
        let engine = MemoryRedactionEngine::new();
        let pattern = keyword_pattern(vec!["password"]);
        let result = engine.apply_pattern("nothing to redact here", &pattern).unwrap();
        assert_eq!(result.content, "nothing to redact here");
        assert!(result.actions.is_empty());
    }

    #[test]
    fn test_apply_sensitivity_pattern() {
        let engine = MemoryRedactionEngine::new();
        let pattern = RedactionPattern::new(
            "rp-sens",
            RedactionPatternType::SensitivityBased {
                min_level: MemorySensitivity::Sensitive,
            },
            "[SENSITIVE-REDACTED]",
            "sensitivity redaction",
        );
        let result = engine.apply_pattern("full content here", &pattern).unwrap();
        assert_eq!(result.content, "[SENSITIVE-REDACTED]");
        assert_eq!(result.actions.len(), 1);
    }

    #[test]
    fn test_apply_regex_pattern_returns_error() {
        let engine = MemoryRedactionEngine::new();
        let pattern = RedactionPattern::new(
            "rp-re",
            RedactionPatternType::Regex {
                expression: r"\d{3}-\d{2}-\d{4}".into(),
            },
            "[REDACTED]",
            "SSN regex",
        );
        let result = engine.apply_pattern("ssn: 123-45-6789", &pattern);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_custom_pattern_returns_error() {
        let engine = MemoryRedactionEngine::new();
        let pattern = RedactionPattern::new(
            "rp-custom",
            RedactionPatternType::Custom {
                name: "pii-detector".into(),
            },
            "[REDACTED]",
            "custom PII",
        );
        let result = engine.apply_pattern("some content", &pattern);
        assert!(result.is_err());
    }

    #[test]
    fn test_redact_content_multiple_patterns() {
        let engine = MemoryRedactionEngine::new();
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(keyword_pattern(vec!["password"]));
        policy.add_pattern(keyword_pattern(vec!["token"]));
        let result = engine
            .redact_content("password and token", &policy)
            .unwrap();
        assert_eq!(result.content, "[REDACTED] and [REDACTED]");
    }

    #[test]
    fn test_redact_entry_basic() {
        let engine = MemoryRedactionEngine::new();
        let entry = make_entry("e1", "my password is secret");
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(keyword_pattern(vec!["password"]));
        let report = engine.redact_entry(&entry, &policy).unwrap();
        assert_eq!(report.entry_id, "e1");
        assert_eq!(report.redacted_content, "my [REDACTED] is secret");
        assert!(report.was_modified());
    }

    #[test]
    fn test_redact_entry_content_type_filter_skip() {
        let engine = MemoryRedactionEngine::new();
        let entry = make_entry("e1", "password");
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(keyword_pattern(vec!["password"]));
        policy.applies_to_content_types = Some(vec![MemoryContentType::Embedding]);
        let report = engine.redact_entry(&entry, &policy).unwrap();
        assert!(!report.was_modified());
        assert_eq!(report.redacted_content, "password");
    }

    #[test]
    fn test_redact_entry_content_type_filter_match() {
        let engine = MemoryRedactionEngine::new();
        let entry = make_entry("e1", "password");
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(keyword_pattern(vec!["password"]));
        policy.applies_to_content_types = Some(vec![MemoryContentType::ConversationTurn]);
        let report = engine.redact_entry(&entry, &policy).unwrap();
        assert!(report.was_modified());
    }

    #[test]
    fn test_redaction_report_action_count() {
        let report = RedactionReport {
            entry_id: "e1".into(),
            policy_id: "p1".into(),
            actions: vec![
                RedactionAction {
                    pattern_id: "rp-1".into(),
                    original_span: "x".into(),
                    replacement: "y".into(),
                },
            ],
            original_content: "x".into(),
            redacted_content: "y".into(),
            fully_redacted: false,
        };
        assert_eq!(report.action_count(), 1);
    }

    #[test]
    fn test_should_redact_by_sensitivity() {
        let engine = MemoryRedactionEngine::new();
        let entry = make_entry("e1", "data");
        assert!(engine.should_redact_by_sensitivity(&entry, &MemorySensitivity::Internal));
        assert!(engine.should_redact_by_sensitivity(&entry, &MemorySensitivity::Public));
        assert!(!engine.should_redact_by_sensitivity(&entry, &MemorySensitivity::Restricted));
    }

    #[test]
    fn test_redaction_engine_default() {
        let _engine = MemoryRedactionEngine;
    }

    #[test]
    fn test_redact_content_empty_policy() {
        let engine = MemoryRedactionEngine::new();
        let policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        let result = engine.redact_content("nothing to do", &policy).unwrap();
        assert_eq!(result.content, "nothing to do");
        assert!(result.actions.is_empty());
    }

    #[test]
    fn test_redaction_action_eq() {
        let a1 = RedactionAction {
            pattern_id: "rp-1".into(),
            original_span: "password".into(),
            replacement: "[REDACTED]".into(),
        };
        assert_eq!(a1, a1.clone());
    }

    #[test]
    fn test_redact_entry_fully_redacted() {
        let engine = MemoryRedactionEngine::new();
        let entry = make_entry("e1", "secret");
        let mut policy = MemoryRedactionPolicy::new("rdp-1", 1000);
        policy.add_pattern(RedactionPattern::new(
            "rp-sens",
            RedactionPatternType::SensitivityBased {
                min_level: MemorySensitivity::Public,
            },
            "[REDACTED]",
            "full redaction",
        ));
        let report = engine.redact_entry(&entry, &policy).unwrap();
        assert!(report.fully_redacted);
    }
}
