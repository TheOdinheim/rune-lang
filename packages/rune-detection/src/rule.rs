// ═══════════════════════════════════════════════════════════════════════
// Detection Rules — composable predicates over signals and results
//
// DetectionRule + RuleCondition (And/Or/Not combinators). Evaluated
// against a RuleEvalContext populated by upstream detection stages.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use rune_security::{SecuritySeverity, ThreatCategory};

use crate::behavioral::BehaviorStatus;
use crate::error::DetectionError;
use crate::indicator::IoCType;
use crate::pattern::{PatternCategory, PatternMatch};
use crate::signal::{Signal, SignalSource, SignalType};

// ── RuleCondition ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RuleCondition {
    SignalMatch {
        source: Option<SignalSource>,
        signal_type: Option<SignalType>,
    },
    ValueAbove {
        threshold: f64,
    },
    ValueBelow {
        threshold: f64,
    },
    TextContains {
        keywords: Vec<String>,
        case_sensitive: bool,
    },
    TextContainsAny {
        keywords: Vec<String>,
        case_sensitive: bool,
    },
    AnomalyScore {
        threshold: f64,
    },
    PatternDetected {
        category: PatternCategory,
    },
    BehaviorDeviation {
        threshold: f64,
    },
    IoCMatch {
        indicator_type: Option<IoCType>,
    },
    RateExceeds {
        count: u64,
        window_ms: i64,
    },
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

// ── DetectionRule ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: RuleCondition,
    pub severity: SecuritySeverity,
    pub category: ThreatCategory,
    pub enabled: bool,
    pub created_at: i64,
    pub tags: Vec<String>,
}

impl DetectionRule {
    pub fn high_request_rate(threshold: u64, window_ms: i64) -> Self {
        Self {
            id: "builtin-high-request-rate".into(),
            name: "High request rate".into(),
            description: format!(
                "more than {threshold} requests in {window_ms}ms — possible DDoS"
            ),
            condition: RuleCondition::RateExceeds {
                count: threshold,
                window_ms,
            },
            severity: SecuritySeverity::High,
            category: ThreatCategory::DenialOfService,
            enabled: true,
            created_at: 0,
            tags: vec!["ddos".into(), "rate-limit".into()],
        }
    }

    pub fn prompt_injection() -> Self {
        Self {
            id: "builtin-prompt-injection".into(),
            name: "Prompt injection attempt".into(),
            description: "Prompt injection pattern detected in text input".into(),
            condition: RuleCondition::PatternDetected {
                category: PatternCategory::PromptInjection,
            },
            severity: SecuritySeverity::High,
            category: ThreatCategory::PromptInjection,
            enabled: true,
            created_at: 0,
            tags: vec!["ai".into(), "prompt-injection".into()],
        }
    }

    pub fn anomalous_value(metric: &str, z_threshold: f64) -> Self {
        Self {
            id: format!("builtin-anomalous-{metric}"),
            name: format!("Anomalous value for {metric}"),
            description: format!("z-score for {metric} exceeds {z_threshold}"),
            condition: RuleCondition::AnomalyScore { threshold: z_threshold },
            severity: SecuritySeverity::Medium,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec!["anomaly".into(), metric.into()],
        }
    }

    pub fn ioc_match() -> Self {
        Self {
            id: "builtin-ioc-match".into(),
            name: "Known IoC match".into(),
            description: "A signal matched a known indicator of compromise".into(),
            condition: RuleCondition::IoCMatch { indicator_type: None },
            severity: SecuritySeverity::High,
            category: ThreatCategory::InformationDisclosure,
            enabled: true,
            created_at: 0,
            tags: vec!["ioc".into(), "threat-intel".into()],
        }
    }

    pub fn behavioral_deviation(threshold: f64) -> Self {
        Self {
            id: "builtin-behavioral-deviation".into(),
            name: "Behavioral deviation".into(),
            description: format!("behavioral z-score exceeds {threshold}"),
            condition: RuleCondition::BehaviorDeviation { threshold },
            severity: SecuritySeverity::Medium,
            category: ThreatCategory::InsiderThreat,
            enabled: true,
            created_at: 0,
            tags: vec!["behavior".into()],
        }
    }
}

// ── RuleEvalContext ───────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RuleEvalContext {
    pub signal: Option<Signal>,
    pub anomaly_score: Option<f64>,
    pub pattern_matches: Vec<PatternMatch>,
    pub behavior_status: Option<BehaviorStatus>,
    pub behavior_score: Option<f64>,
    pub ioc_matches: Vec<String>,
    pub ioc_match_types: Vec<IoCType>,
    pub event_count_in_window: Option<u64>,
    pub window_ms: Option<i64>,
    pub custom: HashMap<String, String>,
}

// ── Evaluation ────────────────────────────────────────────────────────

pub fn evaluate_rule(rule: &DetectionRule, ctx: &RuleEvalContext) -> bool {
    if !rule.enabled {
        return false;
    }
    evaluate_condition(&rule.condition, ctx)
}

fn evaluate_condition(cond: &RuleCondition, ctx: &RuleEvalContext) -> bool {
    match cond {
        RuleCondition::SignalMatch { source, signal_type } => {
            let sig = match &ctx.signal {
                Some(s) => s,
                None => return false,
            };
            if let Some(src) = source {
                if &sig.source != src {
                    return false;
                }
            }
            if let Some(t) = signal_type {
                if &sig.signal_type != t {
                    return false;
                }
            }
            true
        }
        RuleCondition::ValueAbove { threshold } => ctx
            .signal
            .as_ref()
            .and_then(|s| s.value.as_number())
            .map(|n| n > *threshold)
            .unwrap_or(false),
        RuleCondition::ValueBelow { threshold } => ctx
            .signal
            .as_ref()
            .and_then(|s| s.value.as_number())
            .map(|n| n < *threshold)
            .unwrap_or(false),
        RuleCondition::TextContains { keywords, case_sensitive } => {
            let text = match ctx.signal.as_ref().and_then(|s| s.value.as_text()) {
                Some(t) => t,
                None => return false,
            };
            if *case_sensitive {
                keywords.iter().all(|k| text.contains(k))
            } else {
                let lower = text.to_ascii_lowercase();
                keywords.iter().all(|k| lower.contains(&k.to_ascii_lowercase()))
            }
        }
        RuleCondition::TextContainsAny { keywords, case_sensitive } => {
            let text = match ctx.signal.as_ref().and_then(|s| s.value.as_text()) {
                Some(t) => t,
                None => return false,
            };
            if *case_sensitive {
                keywords.iter().any(|k| text.contains(k))
            } else {
                let lower = text.to_ascii_lowercase();
                keywords.iter().any(|k| lower.contains(&k.to_ascii_lowercase()))
            }
        }
        RuleCondition::AnomalyScore { threshold } => {
            ctx.anomaly_score.map(|s| s > *threshold).unwrap_or(false)
        }
        RuleCondition::PatternDetected { category } => {
            ctx.pattern_matches.iter().any(|m| &m.category == category)
        }
        RuleCondition::BehaviorDeviation { threshold } => {
            matches!(ctx.behavior_status, Some(BehaviorStatus::Deviation))
                && ctx.behavior_score.map(|s| s > *threshold).unwrap_or(true)
        }
        RuleCondition::IoCMatch { indicator_type } => match indicator_type {
            Some(t) => ctx.ioc_match_types.iter().any(|m| m == t),
            None => !ctx.ioc_matches.is_empty(),
        },
        RuleCondition::RateExceeds { count, window_ms } => {
            if ctx.window_ms.map(|w| w > *window_ms).unwrap_or(false) {
                return false;
            }
            ctx.event_count_in_window.map(|c| c > *count).unwrap_or(false)
        }
        RuleCondition::And(conds) => conds.iter().all(|c| evaluate_condition(c, ctx)),
        RuleCondition::Or(conds) => conds.iter().any(|c| evaluate_condition(c, ctx)),
        RuleCondition::Not(c) => !evaluate_condition(c, ctx),
    }
}

// ── RuleSet ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RuleSet {
    pub rules: Vec<DetectionRule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, id: &str) -> Option<DetectionRule> {
        let pos = self.rules.iter().position(|r| r.id == id)?;
        Some(self.rules.remove(pos))
    }

    pub fn enable_rule(&mut self, id: &str) -> Result<(), DetectionError> {
        let r = self
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| DetectionError::RuleNotFound(id.into()))?;
        r.enabled = true;
        Ok(())
    }

    pub fn disable_rule(&mut self, id: &str) -> Result<(), DetectionError> {
        let r = self
            .rules
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| DetectionError::RuleNotFound(id.into()))?;
        r.enabled = false;
        Ok(())
    }

    pub fn evaluate_all(&self, ctx: &RuleEvalContext) -> Vec<&DetectionRule> {
        self.rules.iter().filter(|r| evaluate_rule(r, ctx)).collect()
    }

    pub fn enabled_rules(&self) -> Vec<&DetectionRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    pub fn rules_by_category(&self, category: &ThreatCategory) -> Vec<&DetectionRule> {
        self.rules.iter().filter(|r| &r.category == category).collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::SignalValue;

    fn text_signal(text: &str) -> Signal {
        Signal::new(
            "sig",
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text(text.into()),
            0,
        )
    }

    fn num_signal(n: f64) -> Signal {
        Signal::new(
            "sig",
            SignalSource::ApiRequest,
            SignalType::NumericValue,
            SignalValue::Number(n),
            0,
        )
    }

    #[test]
    fn test_rule_construction() {
        let r = DetectionRule::prompt_injection();
        assert_eq!(r.category, ThreatCategory::PromptInjection);
        assert!(r.enabled);
    }

    #[test]
    fn test_value_above() {
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::ValueAbove { threshold: 10.0 },
            severity: SecuritySeverity::Medium,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(num_signal(50.0));
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_value_below() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(num_signal(1.0));
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::ValueBelow { threshold: 10.0 },
            severity: SecuritySeverity::Low,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_text_contains_case_insensitive() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(text_signal("Ignore Previous Instructions"));
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::TextContains {
                keywords: vec!["ignore".into(), "previous".into()],
                case_sensitive: false,
            },
            severity: SecuritySeverity::High,
            category: ThreatCategory::PromptInjection,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_text_contains_any() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(text_signal("hello world"));
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::TextContainsAny {
                keywords: vec!["foo".into(), "world".into()],
                case_sensitive: false,
            },
            severity: SecuritySeverity::Low,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_and_requires_all() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(num_signal(50.0));
        ctx.anomaly_score = Some(5.0);
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::And(vec![
                RuleCondition::ValueAbove { threshold: 10.0 },
                RuleCondition::AnomalyScore { threshold: 3.0 },
            ]),
            severity: SecuritySeverity::High,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_or_requires_any() {
        let mut ctx = RuleEvalContext::default();
        ctx.anomaly_score = Some(0.5);
        ctx.signal = Some(num_signal(50.0));
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::Or(vec![
                RuleCondition::AnomalyScore { threshold: 3.0 },
                RuleCondition::ValueAbove { threshold: 10.0 },
            ]),
            severity: SecuritySeverity::Medium,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_not_inverts() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(num_signal(1.0));
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: RuleCondition::Not(Box::new(RuleCondition::ValueAbove {
                threshold: 10.0,
            })),
            severity: SecuritySeverity::Low,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_pattern_detected() {
        let mut ctx = RuleEvalContext::default();
        ctx.pattern_matches.push(PatternMatch {
            category: PatternCategory::PromptInjection,
            confidence: 0.8,
            matched_pattern: "ignore".into(),
            location: None,
            detail: "x".into(),
        });
        let r = DetectionRule::prompt_injection();
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_nested_combinators() {
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(num_signal(50.0));
        ctx.anomaly_score = Some(5.0);
        // (ValueAbove AND (AnomalyScore OR NOT ValueBelow))
        let cond = RuleCondition::And(vec![
            RuleCondition::ValueAbove { threshold: 10.0 },
            RuleCondition::Or(vec![
                RuleCondition::AnomalyScore { threshold: 3.0 },
                RuleCondition::Not(Box::new(RuleCondition::ValueBelow { threshold: 5.0 })),
            ]),
        ]);
        let r = DetectionRule {
            id: "r".into(),
            name: "n".into(),
            description: "d".into(),
            condition: cond,
            severity: SecuritySeverity::High,
            category: ThreatCategory::Tampering,
            enabled: true,
            created_at: 0,
            tags: vec![],
        };
        assert!(evaluate_rule(&r, &ctx));
    }

    #[test]
    fn test_rule_set_evaluate_all() {
        let mut set = RuleSet::new();
        set.add_rule(DetectionRule::prompt_injection());
        set.add_rule(DetectionRule::ioc_match());
        let mut ctx = RuleEvalContext::default();
        ctx.pattern_matches.push(PatternMatch {
            category: PatternCategory::PromptInjection,
            confidence: 0.8,
            matched_pattern: "ignore".into(),
            location: None,
            detail: "x".into(),
        });
        let fired = set.evaluate_all(&ctx);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_disabled_rule_not_evaluated() {
        let mut set = RuleSet::new();
        let mut r = DetectionRule::prompt_injection();
        r.enabled = false;
        set.add_rule(r);
        let mut ctx = RuleEvalContext::default();
        ctx.pattern_matches.push(PatternMatch {
            category: PatternCategory::PromptInjection,
            confidence: 0.8,
            matched_pattern: "ignore".into(),
            location: None,
            detail: "x".into(),
        });
        assert!(set.evaluate_all(&ctx).is_empty());
    }

    #[test]
    fn test_prompt_injection_template() {
        let r = DetectionRule::prompt_injection();
        assert_eq!(r.category, ThreatCategory::PromptInjection);
    }

    #[test]
    fn test_ioc_match_template() {
        let r = DetectionRule::ioc_match();
        let mut ctx = RuleEvalContext::default();
        ctx.ioc_matches.push("1.2.3.4".into());
        assert!(evaluate_rule(&r, &ctx));
    }
}
