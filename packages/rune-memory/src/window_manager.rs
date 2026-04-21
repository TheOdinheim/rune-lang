// ═══════════════════════════════════════════════════════════════════════
// Layer 2 — Conversation window management. Trims conversation history
// according to ConversationWindowPolicy rules, with support for
// TruncateOldest, SlidingWindow, and SummarizeAndCompact strategies.
// Includes approximate token estimation via whitespace heuristic.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::memory::MemoryEntry;
use crate::retention::{ConversationWindowPolicy, SummarizationStrategy};

// ── WindowTrimResult ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WindowTrimResult {
    pub retained_entry_ids: Vec<String>,
    pub removed_entry_ids: Vec<String>,
    pub strategy_used: String,
    pub estimated_tokens_before: usize,
    pub estimated_tokens_after: usize,
}

impl WindowTrimResult {
    pub fn was_trimmed(&self) -> bool {
        !self.removed_entry_ids.is_empty()
    }

    pub fn removed_count(&self) -> usize {
        self.removed_entry_ids.len()
    }

    pub fn retained_count(&self) -> usize {
        self.retained_entry_ids.len()
    }
}

// ── PinnedEntryManager ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PinnedEntryManager {
    pinned_ids: HashSet<String>,
}

impl PinnedEntryManager {
    pub fn new() -> Self {
        Self {
            pinned_ids: HashSet::new(),
        }
    }

    pub fn pin(&mut self, entry_id: impl Into<String>) {
        self.pinned_ids.insert(entry_id.into());
    }

    pub fn unpin(&mut self, entry_id: &str) {
        self.pinned_ids.remove(entry_id);
    }

    pub fn is_pinned(&self, entry_id: &str) -> bool {
        self.pinned_ids.contains(entry_id)
    }

    pub fn pinned_count(&self) -> usize {
        self.pinned_ids.len()
    }
}

impl Default for PinnedEntryManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── ConversationWindowManager ─────────────────────────────────────

pub struct ConversationWindowManager {
    pinned: PinnedEntryManager,
}

impl ConversationWindowManager {
    pub fn new() -> Self {
        Self {
            pinned: PinnedEntryManager::new(),
        }
    }

    pub fn with_pinned(mut self, pinned: PinnedEntryManager) -> Self {
        self.pinned = pinned;
        self
    }

    pub fn pinned_manager(&self) -> &PinnedEntryManager {
        &self.pinned
    }

    pub fn pinned_manager_mut(&mut self) -> &mut PinnedEntryManager {
        &mut self.pinned
    }

    /// Approximate token count using whitespace heuristic:
    /// split on whitespace, count fragments. Real tokenization
    /// requires an adapter crate.
    pub fn estimate_tokens(content: &str) -> usize {
        content.split_whitespace().count()
    }

    /// Estimate total tokens for a slice of entries.
    pub fn estimate_total_tokens(entries: &[MemoryEntry]) -> usize {
        entries.iter().map(|e| Self::estimate_tokens(&e.content)).sum()
    }

    /// Determine whether a trim is needed given the policy.
    pub fn should_trim(
        &self,
        entries: &[MemoryEntry],
        policy: &ConversationWindowPolicy,
    ) -> bool {
        if let Some(max_turns) = policy.max_turns
            && entries.len() > max_turns
        {
            return true;
        }
        if let Some(max_tokens) = policy.max_tokens_estimate
            && Self::estimate_total_tokens(entries) > max_tokens
        {
            return true;
        }
        false
    }

    /// Trim the conversation window according to the policy.
    /// Entries should be ordered by created_at ascending.
    pub fn trim_window(
        &self,
        entries: &[MemoryEntry],
        policy: &ConversationWindowPolicy,
    ) -> WindowTrimResult {
        let tokens_before = Self::estimate_total_tokens(entries);
        let strategy_name = policy.summarization_strategy.to_string();

        if !self.should_trim(entries, policy) {
            return WindowTrimResult {
                retained_entry_ids: entries.iter().map(|e| e.entry_id.clone()).collect(),
                removed_entry_ids: Vec::new(),
                strategy_used: strategy_name,
                estimated_tokens_before: tokens_before,
                estimated_tokens_after: tokens_before,
            };
        }

        match policy.summarization_strategy {
            SummarizationStrategy::TruncateOldest => {
                self.trim_truncate_oldest(entries, policy, tokens_before)
            }
            SummarizationStrategy::SlidingWindow => {
                self.trim_sliding_window(entries, policy, tokens_before)
            }
            SummarizationStrategy::SummarizeAndCompact | SummarizationStrategy::Custom { .. } => {
                // Placeholder: falls back to TruncateOldest
                self.trim_truncate_oldest(entries, policy, tokens_before)
            }
        }
    }

    fn trim_truncate_oldest(
        &self,
        entries: &[MemoryEntry],
        policy: &ConversationWindowPolicy,
        tokens_before: usize,
    ) -> WindowTrimResult {
        let mut retained = Vec::new();
        let mut removed = Vec::new();

        // Determine how many to keep by turn limit
        let max_turns = policy.max_turns.unwrap_or(entries.len());

        // Separate pinned from unpinned
        let mut unpinned: Vec<&MemoryEntry> = Vec::new();
        let mut pinned_entries: Vec<&MemoryEntry> = Vec::new();

        for entry in entries {
            if policy.preserve_pinned_entries && self.pinned.is_pinned(&entry.entry_id) {
                pinned_entries.push(entry);
            } else {
                unpinned.push(entry);
            }
        }

        // All pinned are retained
        for e in &pinned_entries {
            retained.push(e.entry_id.clone());
        }

        // Keep the most recent unpinned, up to max_turns minus pinned count
        let available_slots = max_turns.saturating_sub(pinned_entries.len());
        if unpinned.len() > available_slots {
            let remove_count = unpinned.len() - available_slots;
            for e in unpinned.iter().take(remove_count) {
                removed.push(e.entry_id.clone());
            }
            for e in unpinned.iter().skip(remove_count) {
                retained.push(e.entry_id.clone());
            }
        } else {
            for e in &unpinned {
                retained.push(e.entry_id.clone());
            }
        }

        // Also check token limit
        if let Some(max_tokens) = policy.max_tokens_estimate {
            let mut token_budget = max_tokens;
            let mut final_retained = Vec::new();
            let mut extra_removed = Vec::new();

            // Process retained in reverse (newest first) to keep recent entries
            let retained_entries: Vec<&MemoryEntry> = entries
                .iter()
                .filter(|e| retained.contains(&e.entry_id))
                .collect();

            for e in retained_entries.iter().rev() {
                let tokens = Self::estimate_tokens(&e.content);
                if tokens <= token_budget {
                    token_budget -= tokens;
                    final_retained.push(e.entry_id.clone());
                } else if policy.preserve_pinned_entries
                    && self.pinned.is_pinned(&e.entry_id)
                {
                    // Always keep pinned even if over budget
                    final_retained.push(e.entry_id.clone());
                } else {
                    extra_removed.push(e.entry_id.clone());
                }
            }

            removed.extend(extra_removed);
            retained = final_retained;
        }

        let tokens_after: usize = entries
            .iter()
            .filter(|e| retained.contains(&e.entry_id))
            .map(|e| Self::estimate_tokens(&e.content))
            .sum();

        WindowTrimResult {
            retained_entry_ids: retained,
            removed_entry_ids: removed,
            strategy_used: "TruncateOldest".into(),
            estimated_tokens_before: tokens_before,
            estimated_tokens_after: tokens_after,
        }
    }

    fn trim_sliding_window(
        &self,
        entries: &[MemoryEntry],
        policy: &ConversationWindowPolicy,
        tokens_before: usize,
    ) -> WindowTrimResult {
        // Sliding window keeps the last N entries
        let max_turns = policy.max_turns.unwrap_or(entries.len());
        let mut retained = Vec::new();
        let mut removed = Vec::new();

        // Always retain pinned entries
        let mut pinned_ids: Vec<String> = Vec::new();
        if policy.preserve_pinned_entries {
            for e in entries {
                if self.pinned.is_pinned(&e.entry_id) {
                    pinned_ids.push(e.entry_id.clone());
                }
            }
        }

        let unpinned: Vec<&MemoryEntry> = entries
            .iter()
            .filter(|e| !pinned_ids.contains(&e.entry_id))
            .collect();

        let available = max_turns.saturating_sub(pinned_ids.len());
        let start = unpinned.len().saturating_sub(available);

        for (i, e) in unpinned.iter().enumerate() {
            if i < start {
                removed.push(e.entry_id.clone());
            } else {
                retained.push(e.entry_id.clone());
            }
        }
        retained.extend(pinned_ids);

        let tokens_after: usize = entries
            .iter()
            .filter(|e| retained.contains(&e.entry_id))
            .map(|e| Self::estimate_tokens(&e.content))
            .sum();

        WindowTrimResult {
            retained_entry_ids: retained,
            removed_entry_ids: removed,
            strategy_used: "SlidingWindow".into(),
            estimated_tokens_before: tokens_before,
            estimated_tokens_after: tokens_after,
        }
    }
}

impl Default for ConversationWindowManager {
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
    use crate::memory::{MemoryContentType, MemorySensitivity};

    fn make_entry(id: &str, created_at: i64, content: &str) -> MemoryEntry {
        MemoryEntry::new(
            id, "scope-1", content,
            MemoryContentType::ConversationTurn,
            MemorySensitivity::Public, "agent-1", created_at,
        )
    }

    fn make_policy(strategy: SummarizationStrategy) -> ConversationWindowPolicy {
        ConversationWindowPolicy::new("cwp-1", strategy, 1000)
    }

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(ConversationWindowManager::estimate_tokens("hello world"), 2);
        assert_eq!(ConversationWindowManager::estimate_tokens("one"), 1);
        assert_eq!(ConversationWindowManager::estimate_tokens(""), 0);
        assert_eq!(
            ConversationWindowManager::estimate_tokens("a b c d e"),
            5
        );
    }

    #[test]
    fn test_estimate_total_tokens() {
        let entries = vec![
            make_entry("e1", 100, "hello world"),
            make_entry("e2", 200, "one two three"),
        ];
        assert_eq!(ConversationWindowManager::estimate_total_tokens(&entries), 5);
    }

    #[test]
    fn test_should_trim_below_limit() {
        let manager = ConversationWindowManager::new();
        let entries = vec![make_entry("e1", 100, "hello")];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(5);
        assert!(!manager.should_trim(&entries, &policy));
    }

    #[test]
    fn test_should_trim_above_turn_limit() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "a"),
            make_entry("e2", 200, "b"),
            make_entry("e3", 300, "c"),
        ];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(2);
        assert!(manager.should_trim(&entries, &policy));
    }

    #[test]
    fn test_should_trim_above_token_limit() {
        let manager = ConversationWindowManager::new();
        let entries = vec![make_entry("e1", 100, "a b c d e f g h i j")];
        let policy =
            make_policy(SummarizationStrategy::TruncateOldest).with_max_tokens_estimate(5);
        assert!(manager.should_trim(&entries, &policy));
    }

    #[test]
    fn test_trim_window_no_trim_needed() {
        let manager = ConversationWindowManager::new();
        let entries = vec![make_entry("e1", 100, "hello")];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(5);
        let result = manager.trim_window(&entries, &policy);
        assert!(!result.was_trimmed());
        assert_eq!(result.retained_count(), 1);
    }

    #[test]
    fn test_trim_truncate_oldest() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "oldest"),
            make_entry("e2", 200, "middle"),
            make_entry("e3", 300, "newest"),
        ];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(2);
        let result = manager.trim_window(&entries, &policy);
        assert!(result.was_trimmed());
        assert_eq!(result.removed_count(), 1);
        assert!(result.removed_entry_ids.contains(&"e1".to_string()));
        assert!(result.retained_entry_ids.contains(&"e3".to_string()));
    }

    #[test]
    fn test_trim_sliding_window() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "a"),
            make_entry("e2", 200, "b"),
            make_entry("e3", 300, "c"),
            make_entry("e4", 400, "d"),
        ];
        let policy = make_policy(SummarizationStrategy::SlidingWindow).with_max_turns(2);
        let result = manager.trim_window(&entries, &policy);
        assert_eq!(result.removed_count(), 2);
        assert!(result.removed_entry_ids.contains(&"e1".to_string()));
        assert!(result.removed_entry_ids.contains(&"e2".to_string()));
        assert!(result.retained_entry_ids.contains(&"e3".to_string()));
        assert!(result.retained_entry_ids.contains(&"e4".to_string()));
        assert_eq!(result.strategy_used, "SlidingWindow");
    }

    #[test]
    fn test_trim_with_pinned_entries() {
        let mut pinned = PinnedEntryManager::new();
        pinned.pin("e1");
        let manager = ConversationWindowManager::new().with_pinned(pinned);
        let entries = vec![
            make_entry("e1", 100, "pinned oldest"),
            make_entry("e2", 200, "unpinned"),
            make_entry("e3", 300, "newest"),
        ];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(2);
        let result = manager.trim_window(&entries, &policy);
        // e1 is pinned so it stays; e2 gets removed
        assert!(result.retained_entry_ids.contains(&"e1".to_string()));
        assert!(result.removed_entry_ids.contains(&"e2".to_string()));
        assert!(result.retained_entry_ids.contains(&"e3".to_string()));
    }

    #[test]
    fn test_pinned_entry_manager() {
        let mut pm = PinnedEntryManager::new();
        assert_eq!(pm.pinned_count(), 0);
        pm.pin("e1");
        assert!(pm.is_pinned("e1"));
        assert!(!pm.is_pinned("e2"));
        assert_eq!(pm.pinned_count(), 1);
        pm.unpin("e1");
        assert!(!pm.is_pinned("e1"));
        assert_eq!(pm.pinned_count(), 0);
    }

    #[test]
    fn test_pinned_entry_manager_default() {
        let pm = PinnedEntryManager::default();
        assert_eq!(pm.pinned_count(), 0);
    }

    #[test]
    fn test_window_trim_result_methods() {
        let result = WindowTrimResult {
            retained_entry_ids: vec!["e1".into(), "e2".into()],
            removed_entry_ids: vec!["e3".into()],
            strategy_used: "TruncateOldest".into(),
            estimated_tokens_before: 100,
            estimated_tokens_after: 70,
        };
        assert!(result.was_trimmed());
        assert_eq!(result.removed_count(), 1);
        assert_eq!(result.retained_count(), 2);
    }

    #[test]
    fn test_window_manager_default() {
        let _wm = ConversationWindowManager::default();
    }

    #[test]
    fn test_trim_summarize_and_compact_falls_back() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "a"),
            make_entry("e2", 200, "b"),
            make_entry("e3", 300, "c"),
        ];
        let policy =
            make_policy(SummarizationStrategy::SummarizeAndCompact).with_max_turns(2);
        let result = manager.trim_window(&entries, &policy);
        assert!(result.was_trimmed());
    }

    #[test]
    fn test_trim_by_token_limit() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "one two three four five"),
            make_entry("e2", 200, "six seven"),
        ];
        // 7 total tokens, limit to 3
        let policy =
            make_policy(SummarizationStrategy::TruncateOldest).with_max_tokens_estimate(3);
        let result = manager.trim_window(&entries, &policy);
        assert!(result.was_trimmed());
        assert!(result.retained_entry_ids.contains(&"e2".to_string()));
    }

    #[test]
    fn test_sliding_window_with_pinned() {
        let mut pinned = PinnedEntryManager::new();
        pinned.pin("e1");
        let manager = ConversationWindowManager::new().with_pinned(pinned);
        let entries = vec![
            make_entry("e1", 100, "pinned"),
            make_entry("e2", 200, "b"),
            make_entry("e3", 300, "c"),
        ];
        let policy = make_policy(SummarizationStrategy::SlidingWindow).with_max_turns(2);
        let result = manager.trim_window(&entries, &policy);
        assert!(result.retained_entry_ids.contains(&"e1".to_string()));
        assert!(result.retained_entry_ids.contains(&"e3".to_string()));
    }

    #[test]
    fn test_pinned_manager_access() {
        let mut wm = ConversationWindowManager::new();
        wm.pinned_manager_mut().pin("e1");
        assert!(wm.pinned_manager().is_pinned("e1"));
    }

    #[test]
    fn test_trim_tokens_before_after() {
        let manager = ConversationWindowManager::new();
        let entries = vec![
            make_entry("e1", 100, "one two"),
            make_entry("e2", 200, "three"),
        ];
        let policy = make_policy(SummarizationStrategy::TruncateOldest).with_max_turns(1);
        let result = manager.trim_window(&entries, &policy);
        assert_eq!(result.estimated_tokens_before, 3);
        assert!(result.estimated_tokens_after <= result.estimated_tokens_before);
    }
}
