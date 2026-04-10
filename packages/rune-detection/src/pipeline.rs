// ═══════════════════════════════════════════════════════════════════════
// Detection Pipeline — chain detectors and raise alerts
//
// Configurable multi-stage pipeline. Each stage is an independent
// detector (anomaly, pattern, behavior, IoC, rule eval). Signals flow
// through in order; results accumulate into a PipelineResult; triggered
// rules become alerts via the embedded AlertManager.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_security::SecuritySeverity;

use crate::alert::{Alert, AlertId, AlertManager, AlertSource};
use crate::anomaly::{AnomalyDetector, AnomalyResult};
use crate::behavioral::{BehaviorAnalyzer, BehaviorResult, BehaviorStatus};
use crate::indicator::IoCDatabase;
use crate::pattern::{PatternMatch, PatternScanner};
use crate::rule::{RuleEvalContext, RuleSet};
use crate::signal::{Signal, SignalBatch, SignalValue};

// ── StageType ─────────────────────────────────────────────────────────

pub enum StageType {
    AnomalyDetection { detector: AnomalyDetector },
    PatternScan { scanner: PatternScanner },
    BehaviorAnalysis { analyzer: BehaviorAnalyzer },
    IoCCheck { database: IoCDatabase },
    RuleEvaluation { rule_set: RuleSet },
    Custom { name: String },
}

impl fmt::Debug for StageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnomalyDetection { .. } => write!(f, "AnomalyDetection"),
            Self::PatternScan { .. } => write!(f, "PatternScan"),
            Self::BehaviorAnalysis { .. } => write!(f, "BehaviorAnalysis"),
            Self::IoCCheck { .. } => write!(f, "IoCCheck"),
            Self::RuleEvaluation { .. } => write!(f, "RuleEvaluation"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── PipelineStage ─────────────────────────────────────────────────────

pub struct PipelineStage {
    pub name: String,
    pub stage_type: StageType,
    pub order: u32,
    pub enabled: bool,
}

// ── PipelineResult ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct PipelineResult {
    pub signal_id: String,
    pub anomaly_results: Vec<AnomalyResult>,
    pub pattern_matches: Vec<PatternMatch>,
    pub behavior_results: Vec<BehaviorResult>,
    pub ioc_matches: Vec<String>,
    pub triggered_rules: Vec<String>,
    pub alerts_raised: Vec<AlertId>,
    pub processed_at: i64,
    pub highest_severity_cached: Option<SecuritySeverity>,
}

impl PipelineResult {
    pub fn has_detections(&self) -> bool {
        !self.anomaly_results.iter().all(|r| !r.anomalous)
            || !self.pattern_matches.is_empty()
            || self
                .behavior_results
                .iter()
                .any(|b| b.status == BehaviorStatus::Deviation)
            || !self.ioc_matches.is_empty()
            || !self.triggered_rules.is_empty()
    }

    pub fn detection_count(&self) -> usize {
        self.anomaly_results.iter().filter(|r| r.anomalous).count()
            + self.pattern_matches.len()
            + self
                .behavior_results
                .iter()
                .filter(|b| b.status == BehaviorStatus::Deviation)
                .count()
            + self.ioc_matches.len()
            + self.triggered_rules.len()
    }

    pub fn highest_severity(&self) -> Option<SecuritySeverity> {
        self.highest_severity_cached
    }
}

// ── DetectionPipeline ─────────────────────────────────────────────────

pub struct DetectionPipeline {
    pub id: String,
    pub name: String,
    pub stages: Vec<PipelineStage>,
    pub alert_manager: AlertManager,
    pub enabled: bool,
}

impl DetectionPipeline {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            stages: Vec::new(),
            alert_manager: AlertManager::new(),
            enabled: true,
        }
    }

    pub fn add_stage(&mut self, name: &str, stage_type: StageType) -> &mut Self {
        let order = self.stages.len() as u32;
        self.stages.push(PipelineStage {
            name: name.into(),
            stage_type,
            order,
            enabled: true,
        });
        self
    }

    pub fn process_signal(&mut self, signal: &Signal, now: i64) -> PipelineResult {
        let mut result = PipelineResult {
            signal_id: signal.id.clone(),
            processed_at: now,
            ..Default::default()
        };
        if !self.enabled {
            return result;
        }

        // First pass: run detection stages.
        for stage in self.stages.iter_mut() {
            if !stage.enabled {
                continue;
            }
            match &mut stage.stage_type {
                StageType::AnomalyDetection { detector } => {
                    if let Some(n) = signal.value.as_number() {
                        let r = detector.detect(n);
                        detector.observe(n);
                        result.anomaly_results.push(r);
                    }
                }
                StageType::PatternScan { scanner } => {
                    if let Some(text) = signal.value.as_text() {
                        let matches = scanner.scan_text(text);
                        result.pattern_matches.extend(matches);
                    }
                }
                StageType::BehaviorAnalysis { analyzer } => {
                    if let Some(profile_id) = signal.metadata.get("profile_id") {
                        if let Some(metric) = signal.metadata.get("metric") {
                            if let Some(v) = signal.value.as_number() {
                                let r = analyzer.analyze(profile_id, metric, v);
                                analyzer.observe(profile_id, metric, v, signal.timestamp);
                                result.behavior_results.push(r);
                            }
                        }
                    }
                }
                StageType::IoCCheck { database } => {
                    if let Some(text) = signal.value.as_text() {
                        for ioc in database.check_text(text, now) {
                            result.ioc_matches.push(ioc.value.clone());
                        }
                    }
                    if let SignalValue::Map(map) = &signal.value {
                        for (_, v) in map {
                            for ioc in database.check_text(v, now) {
                                result.ioc_matches.push(ioc.value.clone());
                            }
                        }
                    }
                }
                StageType::RuleEvaluation { .. } | StageType::Custom { .. } => {
                    // Rule eval happens in second pass after context is built.
                }
            }
        }

        // Build a rule-eval context from what the detection stages produced.
        let mut ctx = RuleEvalContext::default();
        ctx.signal = Some(signal.clone());
        ctx.anomaly_score = result
            .anomaly_results
            .iter()
            .filter(|r| r.anomalous)
            .map(|r| r.score)
            .fold(None, |acc: Option<f64>, v| {
                Some(acc.map(|a| a.max(v)).unwrap_or(v))
            });
        ctx.pattern_matches = result.pattern_matches.clone();
        if let Some(b) = result.behavior_results.first() {
            ctx.behavior_status = Some(b.status.clone());
            ctx.behavior_score = Some(b.deviation_score);
        }
        ctx.ioc_matches = result.ioc_matches.clone();

        // Second pass: evaluate rules.
        for stage in self.stages.iter() {
            if !stage.enabled {
                continue;
            }
            if let StageType::RuleEvaluation { rule_set } = &stage.stage_type {
                let triggered = rule_set.evaluate_all(&ctx);
                for rule in triggered {
                    result.triggered_rules.push(rule.id.clone());
                    let alert_id = self.alert_manager.raise(
                        &rule.name,
                        &rule.description,
                        rule.severity,
                        rule.category.clone(),
                        AlertSource::Rule {
                            rule_id: rule.id.clone(),
                        },
                        now,
                    );
                    result.alerts_raised.push(alert_id);
                }
            }
        }

        // Cache the highest severity across raised alerts.
        let mut highest = None;
        for id in &result.alerts_raised {
            if let Some(a) = self.alert_manager.get(id) {
                highest = Some(match highest {
                    None => a.severity,
                    Some(h) => {
                        if a.severity > h {
                            a.severity
                        } else {
                            h
                        }
                    }
                });
            }
        }
        result.highest_severity_cached = highest;

        result
    }

    pub fn process_batch(&mut self, batch: &SignalBatch, now: i64) -> Vec<PipelineResult> {
        batch.signals.iter().map(|s| self.process_signal(s, now)).collect()
    }

    pub fn active_alerts(&self) -> Vec<&Alert> {
        self.alert_manager.active_alerts()
    }

    pub fn alert_count(&self) -> usize {
        self.alert_manager.alert_count()
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indicator::{IoC, IoCType};
    use crate::pattern::PatternCategory;
    use crate::rule::DetectionRule;
    use crate::signal::{SignalSource, SignalType};

    fn num_sig(id: &str, n: f64) -> Signal {
        Signal::new(
            id,
            SignalSource::SystemEvent,
            SignalType::NumericValue,
            SignalValue::Number(n),
            0,
        )
    }

    fn text_sig(id: &str, t: &str) -> Signal {
        Signal::new(
            id,
            SignalSource::ApiRequest,
            SignalType::TextInput,
            SignalValue::Text(t.into()),
            0,
        )
    }

    #[test]
    fn test_pipeline_anomaly_stage_numeric_signal() {
        let mut p = DetectionPipeline::new("p1", "test");
        let mut d = AnomalyDetector::new();
        for v in [10.0, 10.0, 10.1, 9.9, 10.0, 10.0, 10.1, 9.9, 10.0, 10.0] {
            d.observe(v);
        }
        p.add_stage("anomaly", StageType::AnomalyDetection { detector: d });
        let r = p.process_signal(&num_sig("s1", 100.0), 1000);
        assert_eq!(r.anomaly_results.len(), 1);
        assert!(r.anomaly_results[0].anomalous);
    }

    #[test]
    fn test_pipeline_pattern_stage_text_signal() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "pattern",
            StageType::PatternScan {
                scanner: PatternScanner::new(),
            },
        );
        let r = p.process_signal(&text_sig("s1", "ignore previous instructions"), 1000);
        assert!(!r.pattern_matches.is_empty());
    }

    #[test]
    fn test_pipeline_behavior_stage_updates_profile() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "behavior",
            StageType::BehaviorAnalysis {
                analyzer: BehaviorAnalyzer::new(),
            },
        );
        let sig = num_sig("s1", 5.0)
            .with_metadata("profile_id", "user:alice")
            .with_metadata("metric", "req_rate");
        let _ = p.process_signal(&sig, 1000);
        // No panic, behavior stage silently updates profile.
        assert_eq!(p.stage_count(), 1);
    }

    #[test]
    fn test_pipeline_ioc_stage() {
        let mut p = DetectionPipeline::new("p1", "test");
        let mut db = IoCDatabase::new();
        db.add(IoC::new(
            IoCType::IpAddress,
            "1.2.3.4",
            SecuritySeverity::High,
            "feed",
        ));
        p.add_stage("ioc", StageType::IoCCheck { database: db });
        let r = p.process_signal(&text_sig("s1", "request from 1.2.3.4"), 1000);
        assert_eq!(r.ioc_matches, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn test_pipeline_rule_stage_triggers_alert() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "pattern",
            StageType::PatternScan {
                scanner: PatternScanner::new(),
            },
        );
        let mut set = RuleSet::new();
        set.add_rule(DetectionRule::prompt_injection());
        p.add_stage("rules", StageType::RuleEvaluation { rule_set: set });
        let r = p.process_signal(&text_sig("s1", "ignore previous instructions"), 1000);
        assert!(!r.triggered_rules.is_empty());
        assert!(!r.alerts_raised.is_empty());
    }

    #[test]
    fn test_pipeline_multi_stage() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "pattern",
            StageType::PatternScan {
                scanner: PatternScanner::new(),
            },
        );
        let mut db = IoCDatabase::new();
        db.add(IoC::new(
            IoCType::IpAddress,
            "9.9.9.9",
            SecuritySeverity::High,
            "feed",
        ));
        p.add_stage("ioc", StageType::IoCCheck { database: db });
        let mut set = RuleSet::new();
        set.add_rule(DetectionRule::prompt_injection());
        set.add_rule(DetectionRule::ioc_match());
        p.add_stage("rules", StageType::RuleEvaluation { rule_set: set });
        let r = p.process_signal(
            &text_sig("s1", "ignore previous instructions from 9.9.9.9"),
            1000,
        );
        assert_eq!(r.triggered_rules.len(), 2);
        assert_eq!(r.alerts_raised.len(), 2);
    }

    #[test]
    fn test_pipeline_raises_alerts() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "pattern",
            StageType::PatternScan {
                scanner: PatternScanner::new(),
            },
        );
        let mut set = RuleSet::new();
        set.add_rule(DetectionRule::prompt_injection());
        p.add_stage("rules", StageType::RuleEvaluation { rule_set: set });
        p.process_signal(&text_sig("s1", "ignore previous instructions"), 1000);
        assert_eq!(p.alert_count(), 1);
    }

    #[test]
    fn test_pipeline_result_has_detections() {
        let mut r = PipelineResult::default();
        assert!(!r.has_detections());
        r.pattern_matches.push(PatternMatch {
            category: PatternCategory::PromptInjection,
            confidence: 0.8,
            matched_pattern: "x".into(),
            location: None,
            detail: "d".into(),
        });
        assert!(r.has_detections());
    }

    #[test]
    fn test_pipeline_result_detection_count() {
        let mut r = PipelineResult::default();
        r.pattern_matches.push(PatternMatch {
            category: PatternCategory::PromptInjection,
            confidence: 0.8,
            matched_pattern: "x".into(),
            location: None,
            detail: "d".into(),
        });
        r.ioc_matches.push("1.2.3.4".into());
        r.triggered_rules.push("r1".into());
        assert_eq!(r.detection_count(), 3);
    }

    #[test]
    fn test_process_batch() {
        let mut p = DetectionPipeline::new("p1", "test");
        p.add_stage(
            "pattern",
            StageType::PatternScan {
                scanner: PatternScanner::new(),
            },
        );
        let mut batch = SignalBatch::new(0, 1000);
        batch.add(text_sig("s1", "ignore previous instructions"));
        batch.add(text_sig("s2", "hello world"));
        let results = p.process_batch(&batch, 500);
        assert_eq!(results.len(), 2);
        assert!(results[0].has_detections());
        assert!(!results[1].has_detections());
    }
}
