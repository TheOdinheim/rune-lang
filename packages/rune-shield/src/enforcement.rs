// ═══════════════════════════════════════════════════════════════════════
// Enforcement — Enforcement hook trait and routing.
//
// Layer 3 defines the contract for enforcement hooks that route
// governance decisions to external mitigation systems. The hook
// receives the decision and routes it — it does NOT execute the
// mitigation itself. RUNE provides the decision; the customer
// provides the enforcement.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::ShieldError;
use crate::response::ShieldVerdict;

// ── MitigationAction ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MitigationAction {
    Allow,
    Deny { reason: String, verdict_ref: String },
    Quarantine { reason: String, verdict_ref: String },
    Redact { reason: String, verdict_ref: String },
    Rewrite { reason: String, verdict_ref: String },
    Escalate { reason: String, verdict_ref: String },
}

impl MitigationAction {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Deny { .. } | Self::Quarantine { .. })
    }

    pub fn is_permit(&self) -> bool {
        matches!(self, Self::Allow | Self::Redact { .. } | Self::Rewrite { .. })
    }

    pub fn action_name(&self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Deny { .. } => "Deny",
            Self::Quarantine { .. } => "Quarantine",
            Self::Redact { .. } => "Redact",
            Self::Rewrite { .. } => "Rewrite",
            Self::Escalate { .. } => "Escalate",
        }
    }
}

impl fmt::Display for MitigationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("Allow"),
            Self::Deny { reason, .. } => write!(f, "Deny({reason})"),
            Self::Quarantine { reason, .. } => write!(f, "Quarantine({reason})"),
            Self::Redact { reason, .. } => write!(f, "Redact({reason})"),
            Self::Rewrite { reason, .. } => write!(f, "Rewrite({reason})"),
            Self::Escalate { reason, .. } => write!(f, "Escalate({reason})"),
        }
    }
}

// ── EnforcementHook trait ───────────────────────────────────────

pub trait EnforcementHook {
    fn on_action(&mut self, action: &MitigationAction) -> Result<(), ShieldError>;
    fn hook_id(&self) -> &str;
    fn supported_actions(&self) -> Vec<&'static str>;
    fn is_active(&self) -> bool;
}

// ── RecordingEnforcementHook ────────────────────────────────────

/// Reference implementation that records all routed actions.
pub struct RecordingEnforcementHook {
    id: String,
    actions: Vec<MitigationAction>,
    active: bool,
}

impl RecordingEnforcementHook {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            actions: Vec::new(),
            active: true,
        }
    }

    pub fn actions(&self) -> &[MitigationAction] {
        &self.actions
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl EnforcementHook for RecordingEnforcementHook {
    fn on_action(&mut self, action: &MitigationAction) -> Result<(), ShieldError> {
        self.actions.push(action.clone());
        Ok(())
    }

    fn hook_id(&self) -> &str {
        &self.id
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["Allow", "Deny", "Quarantine", "Redact", "Rewrite", "Escalate"]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── ChainedEnforcementHook ──────────────────────────────────────

/// Routes actions through multiple hooks in priority order.
/// Short-circuits on deny: if any hook returns an error, the chain
/// stops and the error propagates.
pub struct ChainedEnforcementHook {
    id: String,
    hooks: Vec<Box<dyn EnforcementHook>>,
    active: bool,
}

impl ChainedEnforcementHook {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            hooks: Vec::new(),
            active: true,
        }
    }

    pub fn add_hook(&mut self, hook: Box<dyn EnforcementHook>) {
        self.hooks.push(hook);
    }

    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl EnforcementHook for ChainedEnforcementHook {
    fn on_action(&mut self, action: &MitigationAction) -> Result<(), ShieldError> {
        for hook in &mut self.hooks {
            if hook.is_active() {
                hook.on_action(action)?;
            }
        }
        Ok(())
    }

    fn hook_id(&self) -> &str {
        &self.id
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["Allow", "Deny", "Quarantine", "Redact", "Rewrite", "Escalate"]
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ── Helper: verdict → mitigation action ─────────────────────────

/// Convert a ShieldVerdict to a MitigationAction.
pub fn verdict_to_mitigation(verdict: &ShieldVerdict, verdict_ref: &str) -> MitigationAction {
    let vref = verdict_ref.to_string();
    match &verdict.action {
        crate::response::ShieldAction::Allow => MitigationAction::Allow,
        crate::response::ShieldAction::Block { reason } => MitigationAction::Deny {
            reason: reason.clone(),
            verdict_ref: vref,
        },
        crate::response::ShieldAction::Quarantine { reason } => MitigationAction::Quarantine {
            reason: reason.clone(),
            verdict_ref: vref,
        },
        crate::response::ShieldAction::Escalate { reason } => MitigationAction::Escalate {
            reason: reason.clone(),
            verdict_ref: vref,
        },
        crate::response::ShieldAction::Modify { reason, .. } => MitigationAction::Rewrite {
            reason: reason.clone(),
            verdict_ref: vref,
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rune_security::SecuritySeverity;

    fn make_deny() -> MitigationAction {
        MitigationAction::Deny {
            reason: "injection".into(),
            verdict_ref: "v1".into(),
        }
    }

    #[test]
    fn test_mitigation_action_predicates() {
        assert!(MitigationAction::Allow.is_permit());
        assert!(!MitigationAction::Allow.is_blocking());
        assert!(make_deny().is_blocking());
        assert!(!make_deny().is_permit());
        let redact = MitigationAction::Redact {
            reason: "pii".into(),
            verdict_ref: "v2".into(),
        };
        assert!(redact.is_permit());
    }

    #[test]
    fn test_mitigation_action_names() {
        assert_eq!(MitigationAction::Allow.action_name(), "Allow");
        assert_eq!(make_deny().action_name(), "Deny");
        let q = MitigationAction::Quarantine {
            reason: "r".into(),
            verdict_ref: "v".into(),
        };
        assert_eq!(q.action_name(), "Quarantine");
    }

    #[test]
    fn test_mitigation_display() {
        assert_eq!(MitigationAction::Allow.to_string(), "Allow");
        assert!(make_deny().to_string().contains("injection"));
    }

    #[test]
    fn test_recording_hook() {
        let mut hook = RecordingEnforcementHook::new("h1");
        hook.on_action(&MitigationAction::Allow).unwrap();
        hook.on_action(&make_deny()).unwrap();
        assert_eq!(hook.action_count(), 2);
        assert_eq!(hook.hook_id(), "h1");
        assert!(hook.is_active());
    }

    #[test]
    fn test_recording_hook_deactivate() {
        let mut hook = RecordingEnforcementHook::new("h1");
        hook.deactivate();
        assert!(!hook.is_active());
    }

    #[test]
    fn test_chained_hook() {
        let mut chain = ChainedEnforcementHook::new("chain1");
        chain.add_hook(Box::new(RecordingEnforcementHook::new("h1")));
        chain.add_hook(Box::new(RecordingEnforcementHook::new("h2")));
        assert_eq!(chain.hook_count(), 2);
        chain.on_action(&make_deny()).unwrap();
        assert!(chain.is_active());
    }

    #[test]
    fn test_chained_hook_skips_inactive() {
        let mut chain = ChainedEnforcementHook::new("chain1");
        let mut inactive = RecordingEnforcementHook::new("h1");
        inactive.deactivate();
        chain.add_hook(Box::new(inactive));
        chain.add_hook(Box::new(RecordingEnforcementHook::new("h2")));
        chain.on_action(&MitigationAction::Allow).unwrap();
    }

    #[test]
    fn test_verdict_to_mitigation() {
        let v = ShieldVerdict::block("injection", SecuritySeverity::High, 0.9);
        let action = verdict_to_mitigation(&v, "v1");
        assert!(action.is_blocking());
        assert_eq!(action.action_name(), "Deny");

        let v2 = ShieldVerdict::allow();
        let action2 = verdict_to_mitigation(&v2, "v2");
        assert!(action2.is_permit());
    }

    #[test]
    fn test_supported_actions() {
        let hook = RecordingEnforcementHook::new("h1");
        let supported = hook.supported_actions();
        assert!(supported.contains(&"Deny"));
        assert!(supported.contains(&"Redact"));
    }

    #[test]
    fn test_all_mitigation_variants_display() {
        let actions = vec![
            MitigationAction::Allow,
            MitigationAction::Deny { reason: "r".into(), verdict_ref: "v".into() },
            MitigationAction::Quarantine { reason: "r".into(), verdict_ref: "v".into() },
            MitigationAction::Redact { reason: "r".into(), verdict_ref: "v".into() },
            MitigationAction::Rewrite { reason: "r".into(), verdict_ref: "v".into() },
            MitigationAction::Escalate { reason: "r".into(), verdict_ref: "v".into() },
        ];
        for a in &actions {
            assert!(!a.to_string().is_empty());
        }
    }
}
