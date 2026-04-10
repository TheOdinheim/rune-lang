// ═══════════════════════════════════════════════════════════════════════
// SecurityContext — propagation through call chains
//
// Carries security metadata (clearance, trust, active threats, risk) as
// code crosses module boundaries. Supports least-privilege delegation
// (restrict) and risk elevation (elevate_risk) but never the reverse.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_permissions::ClassificationLevel;

use crate::error::SecurityError;
use crate::severity::SecuritySeverity;
use crate::threat::ThreatCategory;

// ── SecurityContext ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub id: String,
    pub subject_id: Option<String>,
    pub clearance: ClassificationLevel,
    pub trust_score: f64,
    pub authenticated: bool,
    pub mfa_verified: bool,
    pub source_ip: Option<String>,
    pub session_id: Option<String>,
    pub active_threats: Vec<ThreatCategory>,
    pub risk_level: SecuritySeverity,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub parent_context_id: Option<String>,
    pub created_at: i64,
    pub depth: u32,
}

impl SecurityContext {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_id: None,
            clearance: ClassificationLevel::Public,
            trust_score: 0.0,
            authenticated: false,
            mfa_verified: false,
            source_ip: None,
            session_id: None,
            active_threats: Vec::new(),
            risk_level: SecuritySeverity::Info,
            capabilities: Vec::new(),
            metadata: HashMap::new(),
            parent_context_id: None,
            created_at: 0,
            depth: 0,
        }
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject_id = Some(subject.into());
        self
    }

    pub fn clearance(mut self, clearance: ClassificationLevel) -> Self {
        self.clearance = clearance;
        self
    }

    pub fn trust_score(mut self, score: f64) -> Self {
        self.trust_score = score;
        self
    }

    pub fn authenticated(mut self, auth: bool) -> Self {
        self.authenticated = auth;
        self
    }

    pub fn mfa(mut self, mfa: bool) -> Self {
        self.mfa_verified = mfa;
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn session(mut self, session: impl Into<String>) -> Self {
        self.session_id = Some(session.into());
        self
    }

    pub fn risk_level(mut self, risk: SecuritySeverity) -> Self {
        self.risk_level = risk;
        self
    }

    pub fn capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Self {
        self
    }

    /// Create a child context inheriting this context's properties, with
    /// incremented depth and parent_context_id linking back.
    pub fn derive_child(&self, child_id: &str) -> SecurityContext {
        let mut child = self.clone();
        child.id = child_id.into();
        child.parent_context_id = Some(self.id.clone());
        child.depth = self.depth + 1;
        child
    }

    /// Create a copy with reduced clearance. Never raises clearance.
    pub fn restrict(&self, new_clearance: ClassificationLevel) -> SecurityContext {
        let mut ctx = self.clone();
        if new_clearance < self.clearance {
            ctx.clearance = new_clearance;
        }
        ctx
    }

    /// Create a copy with increased risk level. Never lowers risk.
    pub fn elevate_risk(&self, new_risk: SecuritySeverity) -> SecurityContext {
        let mut ctx = self.clone();
        if new_risk > self.risk_level {
            ctx.risk_level = new_risk;
        }
        ctx
    }

    /// Create a copy with an added active threat.
    pub fn add_threat(&self, threat: ThreatCategory) -> SecurityContext {
        let mut ctx = self.clone();
        if !ctx.active_threats.contains(&threat) {
            ctx.active_threats.push(threat);
        }
        ctx
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    pub fn is_high_risk(&self) -> bool {
        self.risk_level >= SecuritySeverity::High
    }

    pub fn max_depth() -> u32 {
        64
    }
}

// ── ContextStack ──────────────────────────────────────────────────────

#[derive(Default)]
pub struct ContextStack {
    pub contexts: Vec<SecurityContext>,
}

impl ContextStack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, ctx: SecurityContext) -> Result<(), SecurityError> {
        if self.contexts.len() as u32 >= SecurityContext::max_depth() {
            return Err(SecurityError::ContextDepthExceeded {
                max: SecurityContext::max_depth(),
                attempted: self.contexts.len() as u32 + 1,
            });
        }
        self.contexts.push(ctx);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<SecurityContext> {
        self.contexts.pop()
    }

    pub fn current(&self) -> Option<&SecurityContext> {
        self.contexts.last()
    }

    pub fn depth(&self) -> usize {
        self.contexts.len()
    }

    /// Most restrictive clearance across the stack (minimum).
    pub fn effective_clearance(&self) -> ClassificationLevel {
        self.contexts
            .iter()
            .map(|c| c.clearance)
            .min()
            .unwrap_or(ClassificationLevel::Public)
    }

    /// Worst-case risk across the stack (maximum).
    pub fn effective_risk(&self) -> SecuritySeverity {
        self.contexts
            .iter()
            .map(|c| c.risk_level)
            .max()
            .unwrap_or(SecuritySeverity::Info)
    }

    pub fn all_threats(&self) -> Vec<&ThreatCategory> {
        let mut seen: Vec<&ThreatCategory> = Vec::new();
        for c in &self.contexts {
            for t in &c.active_threats {
                if !seen.contains(&t) {
                    seen.push(t);
                }
            }
        }
        seen
    }

    pub fn trace(&self) -> Vec<String> {
        self.contexts.iter().map(|c| c.id.clone()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_produces_fields() {
        let ctx = SecurityContext::new("ctx-001")
            .subject("user:alice")
            .clearance(ClassificationLevel::Confidential)
            .trust_score(0.8)
            .authenticated(true)
            .mfa(true)
            .source_ip("10.0.0.1")
            .risk_level(SecuritySeverity::Low)
            .capability("read:models")
            .build();
        assert_eq!(ctx.subject_id, Some("user:alice".into()));
        assert_eq!(ctx.clearance, ClassificationLevel::Confidential);
        assert!(ctx.authenticated);
        assert!(ctx.mfa_verified);
        assert!(ctx.has_capability("read:models"));
    }

    #[test]
    fn test_derive_child_increments_depth() {
        let parent = SecurityContext::new("parent");
        let child = parent.derive_child("child");
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_context_id, Some("parent".into()));
        assert_eq!(child.id, "child");
    }

    #[test]
    fn test_restrict_can_only_lower() {
        let ctx = SecurityContext::new("c").clearance(ClassificationLevel::Restricted);
        let lower = ctx.restrict(ClassificationLevel::Public);
        assert_eq!(lower.clearance, ClassificationLevel::Public);
        // Cannot raise
        let higher = ctx.restrict(ClassificationLevel::TopSecret);
        assert_eq!(higher.clearance, ClassificationLevel::Restricted);
    }

    #[test]
    fn test_elevate_risk_can_only_raise() {
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::Medium);
        let higher = ctx.elevate_risk(SecuritySeverity::Critical);
        assert_eq!(higher.risk_level, SecuritySeverity::Critical);
        let lower = ctx.elevate_risk(SecuritySeverity::Low);
        assert_eq!(lower.risk_level, SecuritySeverity::Medium);
    }

    #[test]
    fn test_add_threat_dedupes() {
        let ctx = SecurityContext::new("c");
        let ctx = ctx.add_threat(ThreatCategory::PromptInjection);
        let ctx = ctx.add_threat(ThreatCategory::PromptInjection);
        assert_eq!(ctx.active_threats.len(), 1);
    }

    #[test]
    fn test_has_capability() {
        let ctx = SecurityContext::new("c")
            .capability("read")
            .capability("write");
        assert!(ctx.has_capability("read"));
        assert!(!ctx.has_capability("admin"));
    }

    #[test]
    fn test_is_high_risk() {
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::Medium);
        assert!(!ctx.is_high_risk());
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::High);
        assert!(ctx.is_high_risk());
        let ctx = SecurityContext::new("c").risk_level(SecuritySeverity::Critical);
        assert!(ctx.is_high_risk());
    }

    #[test]
    fn test_stack_push_pop() {
        let mut stack = ContextStack::new();
        stack.push(SecurityContext::new("a")).unwrap();
        stack.push(SecurityContext::new("b")).unwrap();
        assert_eq!(stack.depth(), 2);
        assert_eq!(stack.current().unwrap().id, "b");
        stack.pop();
        assert_eq!(stack.depth(), 1);
    }

    #[test]
    fn test_stack_effective_clearance_most_restrictive() {
        let mut stack = ContextStack::new();
        stack
            .push(SecurityContext::new("a").clearance(ClassificationLevel::TopSecret))
            .unwrap();
        stack
            .push(SecurityContext::new("b").clearance(ClassificationLevel::Internal))
            .unwrap();
        stack
            .push(SecurityContext::new("c").clearance(ClassificationLevel::Confidential))
            .unwrap();
        assert_eq!(stack.effective_clearance(), ClassificationLevel::Internal);
    }

    #[test]
    fn test_stack_effective_risk_worst_case() {
        let mut stack = ContextStack::new();
        stack
            .push(SecurityContext::new("a").risk_level(SecuritySeverity::Low))
            .unwrap();
        stack
            .push(SecurityContext::new("b").risk_level(SecuritySeverity::Critical))
            .unwrap();
        stack
            .push(SecurityContext::new("c").risk_level(SecuritySeverity::Medium))
            .unwrap();
        assert_eq!(stack.effective_risk(), SecuritySeverity::Critical);
    }

    #[test]
    fn test_stack_all_threats_union() {
        let mut stack = ContextStack::new();
        stack
            .push(SecurityContext::new("a").clone().add_threat(ThreatCategory::Spoofing))
            .unwrap();
        stack
            .push(
                SecurityContext::new("b")
                    .clone()
                    .add_threat(ThreatCategory::DataPoisoning),
            )
            .unwrap();
        stack
            .push(
                SecurityContext::new("c")
                    .clone()
                    .add_threat(ThreatCategory::Spoofing),
            )
            .unwrap();
        assert_eq!(stack.all_threats().len(), 2);
    }

    #[test]
    fn test_stack_trace() {
        let mut stack = ContextStack::new();
        stack.push(SecurityContext::new("a")).unwrap();
        stack.push(SecurityContext::new("b")).unwrap();
        stack.push(SecurityContext::new("c")).unwrap();
        assert_eq!(stack.trace(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_stack_max_depth_enforced() {
        let mut stack = ContextStack::new();
        for i in 0..SecurityContext::max_depth() {
            stack.push(SecurityContext::new(format!("c{i}"))).unwrap();
        }
        let result = stack.push(SecurityContext::new("overflow"));
        assert!(matches!(
            result,
            Err(SecurityError::ContextDepthExceeded { .. })
        ));
    }
}
