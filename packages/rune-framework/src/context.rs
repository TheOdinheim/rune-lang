// ═══════════════════════════════════════════════════════════════════════
// Context — Mutable governance state flowing through pipeline stages.
//
// GovernanceContext accumulates flags, warnings, threat indicators,
// risk/trust scores, and explanation fragments as stages execute.
// Each stage reads and writes context; the pipeline reads the final
// state to produce a GovernanceDecisionResult.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

// ── GovernanceContext ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceContext {
    flags: HashMap<String, String>,
    pub risk_score: f64,
    pub trust_score: f64,
    pub policy_decision: Option<String>,
    pub shield_verdict: Option<String>,
    pub warnings: Vec<String>,
    pub threat_indicators: Vec<String>,
    pub explanation_fragments: Vec<String>,
    pub stage_log: Vec<String>,
}

impl GovernanceContext {
    pub fn new() -> Self {
        Self {
            flags: HashMap::new(),
            risk_score: 0.0,
            trust_score: 1.0,
            policy_decision: None,
            shield_verdict: None,
            warnings: Vec::new(),
            threat_indicators: Vec::new(),
            explanation_fragments: Vec::new(),
            stage_log: Vec::new(),
        }
    }

    // ── Flag operations ────────────────────────────────────────────

    pub fn set_flag(&mut self, key: String, value: String) {
        self.flags.insert(key, value);
    }

    pub fn get_flag(&self, key: &str) -> Option<String> {
        self.flags.get(key).cloned()
    }

    pub fn has_flag(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }

    pub fn flag_count(&self) -> usize {
        self.flags.len()
    }

    // ── Accumulation helpers ───────────────────────────────────────

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn add_threat(&mut self, indicator: String) {
        self.threat_indicators.push(indicator);
    }

    pub fn increase_risk(&mut self, delta: f64) {
        self.risk_score += delta;
        if self.risk_score > 1.0 {
            self.risk_score = 1.0;
        }
    }

    pub fn record_stage(&mut self, stage_name: &str, outcome: &str) {
        self.stage_log
            .push(format!("{stage_name}: {outcome}"));
    }

    // ── Query helpers ──────────────────────────────────────────────

    pub fn has_blocking_failure(&self) -> bool {
        self.stage_log.iter().any(|entry| entry.contains("Fail"))
    }

    pub fn first_failure(&self) -> Option<&str> {
        self.stage_log
            .iter()
            .find(|entry| entry.contains("Fail"))
            .map(|s| s.as_str())
    }

    pub fn build_explanation(&self) -> String {
        if self.explanation_fragments.is_empty() {
            if self.stage_log.is_empty() {
                return "No stages evaluated".into();
            }
            return self.stage_log.join("; ");
        }
        self.explanation_fragments.join("; ")
    }

    /// Flattens context into a string map for export/audit.
    pub fn to_flat_map(&self) -> HashMap<String, String> {
        let mut map = self.flags.clone();
        map.insert("risk_score".into(), self.risk_score.to_string());
        map.insert("trust_score".into(), self.trust_score.to_string());
        if let Some(ref pd) = self.policy_decision {
            map.insert("policy_decision".into(), pd.clone());
        }
        if let Some(ref sv) = self.shield_verdict {
            map.insert("shield_verdict".into(), sv.clone());
        }
        if !self.warnings.is_empty() {
            map.insert("warnings".into(), self.warnings.join(", "));
        }
        if !self.threat_indicators.is_empty() {
            map.insert("threat_indicators".into(), self.threat_indicators.join(", "));
        }
        map
    }
}

impl Default for GovernanceContext {
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

    #[test]
    fn test_context_new_defaults() {
        let ctx = GovernanceContext::new();
        assert_eq!(ctx.risk_score, 0.0);
        assert_eq!(ctx.trust_score, 1.0);
        assert!(ctx.policy_decision.is_none());
        assert!(ctx.shield_verdict.is_none());
        assert!(ctx.warnings.is_empty());
        assert!(ctx.threat_indicators.is_empty());
        assert_eq!(ctx.flag_count(), 0);
    }

    #[test]
    fn test_flag_operations() {
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("key".into(), "value".into());
        assert!(ctx.has_flag("key"));
        assert!(!ctx.has_flag("other"));
        assert_eq!(ctx.get_flag("key"), Some("value".into()));
        assert_eq!(ctx.get_flag("missing"), None);
        assert_eq!(ctx.flag_count(), 1);
    }

    #[test]
    fn test_add_warning_and_threat() {
        let mut ctx = GovernanceContext::new();
        ctx.add_warning("w1".into());
        ctx.add_warning("w2".into());
        ctx.add_threat("t1".into());
        assert_eq!(ctx.warnings.len(), 2);
        assert_eq!(ctx.threat_indicators.len(), 1);
    }

    #[test]
    fn test_increase_risk_capped() {
        let mut ctx = GovernanceContext::new();
        ctx.increase_risk(0.3);
        assert!((ctx.risk_score - 0.3).abs() < f64::EPSILON);
        ctx.increase_risk(0.5);
        assert!((ctx.risk_score - 0.8).abs() < f64::EPSILON);
        ctx.increase_risk(0.5); // would be 1.3, capped to 1.0
        assert!((ctx.risk_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_stage_and_failure_detection() {
        let mut ctx = GovernanceContext::new();
        ctx.record_stage("identity", "Pass");
        ctx.record_stage("policy", "Fail: denied");
        assert!(ctx.has_blocking_failure());
        assert_eq!(ctx.first_failure(), Some("policy: Fail: denied"));
    }

    #[test]
    fn test_no_blocking_failure() {
        let mut ctx = GovernanceContext::new();
        ctx.record_stage("identity", "Pass");
        ctx.record_stage("policy", "Pass");
        assert!(!ctx.has_blocking_failure());
        assert!(ctx.first_failure().is_none());
    }

    #[test]
    fn test_build_explanation_from_fragments() {
        let mut ctx = GovernanceContext::new();
        ctx.explanation_fragments.push("Identity verified".into());
        ctx.explanation_fragments.push("Policy permits".into());
        assert_eq!(ctx.build_explanation(), "Identity verified; Policy permits");
    }

    #[test]
    fn test_build_explanation_from_stage_log() {
        let mut ctx = GovernanceContext::new();
        ctx.record_stage("identity", "Pass");
        ctx.record_stage("policy", "Pass");
        assert_eq!(ctx.build_explanation(), "identity: Pass; policy: Pass");
    }

    #[test]
    fn test_build_explanation_empty() {
        let ctx = GovernanceContext::new();
        assert_eq!(ctx.build_explanation(), "No stages evaluated");
    }

    #[test]
    fn test_to_flat_map() {
        let mut ctx = GovernanceContext::new();
        ctx.set_flag("custom".into(), "val".into());
        ctx.risk_score = 0.5;
        ctx.trust_score = 0.8;
        ctx.policy_decision = Some("permit".into());
        ctx.shield_verdict = Some("clear".into());
        ctx.add_warning("w1".into());
        ctx.add_threat("t1".into());
        let map = ctx.to_flat_map();
        assert_eq!(map.get("custom").unwrap(), "val");
        assert_eq!(map.get("risk_score").unwrap(), "0.5");
        assert_eq!(map.get("trust_score").unwrap(), "0.8");
        assert_eq!(map.get("policy_decision").unwrap(), "permit");
        assert_eq!(map.get("shield_verdict").unwrap(), "clear");
        assert_eq!(map.get("warnings").unwrap(), "w1");
        assert_eq!(map.get("threat_indicators").unwrap(), "t1");
    }

    #[test]
    fn test_default() {
        let ctx = GovernanceContext::default();
        assert_eq!(ctx.risk_score, 0.0);
    }
}
