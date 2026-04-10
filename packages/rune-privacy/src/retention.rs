// ═══════════════════════════════════════════════════════════════════════
// Data Retention — Policy Enforcement and Automated Actions
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_permissions::ClassificationLevel;

use crate::pii::PiiCategory;

// ── RetentionScope ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RetentionScope {
    AllData,
    Category(PiiCategory),
    Purpose(String),
    Classification(ClassificationLevel),
    Custom(String),
}

impl fmt::Display for RetentionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllData => write!(f, "AllData"),
            Self::Category(c) => write!(f, "Category({c})"),
            Self::Purpose(p) => write!(f, "Purpose({p})"),
            Self::Classification(c) => write!(f, "Classification({c:?})"),
            Self::Custom(s) => write!(f, "Custom({s})"),
        }
    }
}

// ── RetentionAction ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RetentionAction {
    Delete,
    Anonymize,
    Archive,
    Review,
}

impl fmt::Display for RetentionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RetentionPolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub max_retention_days: u64,
    pub applies_to: RetentionScope,
    pub action_on_expiry: RetentionAction,
    pub active: bool,
}

// ── RetentionDataItem ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionDataItem {
    pub id: String,
    pub category: PiiCategory,
    pub age_days: u64,
    pub purpose: Option<String>,
}

// ── RetentionActionItem ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionActionItem {
    pub data_id: String,
    pub action: RetentionAction,
    pub policy_id: String,
    pub reason: String,
}

// ── RetentionCheck ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RetentionCheck {
    pub within_policy: bool,
    pub max_days: u64,
    pub current_days: u64,
    pub days_remaining: i64,
    pub action_required: Option<RetentionAction>,
}

// ── RetentionManager ──────────────────────────────────────────────────

#[derive(Default)]
pub struct RetentionManager {
    pub policies: Vec<RetentionPolicy>,
}

impl RetentionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_policy(&mut self, policy: RetentionPolicy) {
        self.policies.push(policy);
    }

    pub fn applicable_policies(&self, category: &PiiCategory) -> Vec<&RetentionPolicy> {
        self.policies
            .iter()
            .filter(|p| {
                p.active
                    && match &p.applies_to {
                        RetentionScope::AllData => true,
                        RetentionScope::Category(c) => c == category,
                        _ => false,
                    }
            })
            .collect()
    }

    pub fn check_retention(&self, data_category: &PiiCategory, age_days: u64) -> RetentionCheck {
        let applicable = self.applicable_policies(data_category);
        if applicable.is_empty() {
            return RetentionCheck {
                within_policy: true,
                max_days: u64::MAX,
                current_days: age_days,
                days_remaining: i64::MAX,
                action_required: None,
            };
        }
        // Most restrictive wins
        let strictest = applicable.iter().min_by_key(|p| p.max_retention_days).unwrap();
        let max = strictest.max_retention_days;
        let within = age_days <= max;
        RetentionCheck {
            within_policy: within,
            max_days: max,
            current_days: age_days,
            days_remaining: max as i64 - age_days as i64,
            action_required: if within { None } else { Some(strictest.action_on_expiry.clone()) },
        }
    }

    pub fn expired_data_actions(
        &self,
        data_items: &[RetentionDataItem],
    ) -> Vec<RetentionActionItem> {
        let mut actions = Vec::new();
        for item in data_items {
            let applicable = self.applicable_policies(&item.category);
            if let Some(strictest) = applicable.iter().min_by_key(|p| p.max_retention_days) {
                if item.age_days > strictest.max_retention_days {
                    actions.push(RetentionActionItem {
                        data_id: item.id.clone(),
                        action: strictest.action_on_expiry.clone(),
                        policy_id: strictest.id.clone(),
                        reason: format!(
                            "data is {} days old, exceeds policy max {} days",
                            item.age_days, strictest.max_retention_days
                        ),
                    });
                }
            }
        }
        actions
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(id: &str, max_days: u64, scope: RetentionScope, action: RetentionAction) -> RetentionPolicy {
        RetentionPolicy {
            id: id.into(),
            name: format!("Policy {id}"),
            max_retention_days: max_days,
            applies_to: scope,
            action_on_expiry: action,
            active: true,
        }
    }

    #[test]
    fn test_check_within_policy() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(make_policy(
            "p1",
            365,
            RetentionScope::Category(PiiCategory::Email),
            RetentionAction::Delete,
        ));
        let check = mgr.check_retention(&PiiCategory::Email, 100);
        assert!(check.within_policy);
        assert_eq!(check.days_remaining, 265);
    }

    #[test]
    fn test_check_expired() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(make_policy(
            "p1",
            30,
            RetentionScope::Category(PiiCategory::Email),
            RetentionAction::Delete,
        ));
        let check = mgr.check_retention(&PiiCategory::Email, 60);
        assert!(!check.within_policy);
        assert_eq!(check.action_required, Some(RetentionAction::Delete));
    }

    #[test]
    fn test_expired_data_actions() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(make_policy(
            "p1",
            30,
            RetentionScope::Category(PiiCategory::Email),
            RetentionAction::Anonymize,
        ));
        let items = vec![
            RetentionDataItem {
                id: "d1".into(),
                category: PiiCategory::Email,
                age_days: 60,
                purpose: None,
            },
            RetentionDataItem {
                id: "d2".into(),
                category: PiiCategory::Email,
                age_days: 10,
                purpose: None,
            },
        ];
        let actions = mgr.expired_data_actions(&items);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].data_id, "d1");
        assert_eq!(actions[0].action, RetentionAction::Anonymize);
    }

    #[test]
    fn test_applies_to_correct_category() {
        let mut mgr = RetentionManager::new();
        mgr.add_policy(make_policy(
            "p1",
            30,
            RetentionScope::Category(PiiCategory::Email),
            RetentionAction::Delete,
        ));
        assert_eq!(mgr.applicable_policies(&PiiCategory::Email).len(), 1);
        assert_eq!(mgr.applicable_policies(&PiiCategory::Phone).len(), 0);
    }

    #[test]
    fn test_retention_action_display() {
        assert_eq!(RetentionAction::Delete.to_string(), "Delete");
        assert_eq!(RetentionAction::Anonymize.to_string(), "Anonymize");
        assert_eq!(RetentionAction::Archive.to_string(), "Archive");
        assert_eq!(RetentionAction::Review.to_string(), "Review");
    }
}
