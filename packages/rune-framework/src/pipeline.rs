// ═══════════════════════════════════════════════════════════════════════
// Pipeline — Governance pipeline with stage ordering, fail-closed
// semantics, and dry-run support.
//
// GovernancePipeline is the main entry point for evaluating governance
// requests. It executes stages in order, respecting FailAction
// semantics, and produces a GovernanceDecisionResult.
// ═══════════════════════════════════════════════════════════════════════

use rune_security::SecuritySeverity;

use crate::context::GovernanceContext;
use crate::error::FrameworkError;
use crate::request::*;
use crate::stage::{FailAction, StageDefinition};

// ── PipelineStageEntry ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PipelineStageEntry {
    pub definition: StageDefinition,
    pub timeout_ms: u64,
}

// ── GovernancePipeline ────────────────────────────────────────────────

#[derive(Clone)]
pub struct GovernancePipeline {
    stages: Vec<PipelineStageEntry>,
    pub risk_threshold: f64,
    pub default_timeout_ms: u64,
}

impl GovernancePipeline {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            risk_threshold: 0.8,
            default_timeout_ms: 5000,
        }
    }

    pub fn add_stage(&mut self, definition: StageDefinition) {
        let timeout = self.default_timeout_ms;
        self.stages.push(PipelineStageEntry {
            definition,
            timeout_ms: timeout,
        });
    }

    pub fn add_stage_with_timeout(&mut self, definition: StageDefinition, timeout_ms: u64) {
        self.stages.push(PipelineStageEntry {
            definition,
            timeout_ms,
        });
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    pub fn enabled_stages(&self) -> usize {
        self.stages.iter().filter(|s| s.definition.enabled).count()
    }

    pub fn stage_names(&self) -> Vec<&str> {
        self.stages.iter().map(|s| s.definition.name.as_str()).collect()
    }

    /// Main evaluation entry point. Executes stages in order, applies
    /// fail-closed semantics, and produces a GovernanceDecisionResult.
    pub fn evaluate(
        &self,
        request: &GovernanceRequest,
    ) -> Result<GovernanceDecisionResult, FrameworkError> {
        self.run_pipeline(request, false)
    }

    /// Dry-run evaluation. Executes all stages but marks the result
    /// as non-binding. Does NOT short-circuit on failures.
    pub fn dry_run(
        &self,
        request: &GovernanceRequest,
    ) -> Result<GovernanceDecisionResult, FrameworkError> {
        self.run_pipeline(request, true)
    }

    fn run_pipeline(
        &self,
        request: &GovernanceRequest,
        dry_run: bool,
    ) -> Result<GovernanceDecisionResult, FrameworkError> {
        if self.stages.is_empty() {
            return Err(FrameworkError::PipelineNotConfigured);
        }

        let mut ctx = GovernanceContext::new();
        let mut stage_results: Vec<StageResult> = Vec::new();
        let mut aborted = false;
        let mut escalate_to: Option<(String, String)> = None;
        let mut overall_severity = SecuritySeverity::Info;

        // Sort stages by order
        let mut sorted: Vec<&PipelineStageEntry> = self.stages.iter().collect();
        sorted.sort_by_key(|e| e.definition.order);

        for entry in &sorted {
            if !entry.definition.enabled {
                continue;
            }

            let result =
                (entry.definition.evaluator)(request, &mut ctx, &entry.definition.config);

            // Track the highest severity seen
            if result.severity > overall_severity {
                overall_severity = result.severity;
            }

            ctx.record_stage(&result.stage_name, &result.outcome.to_string());

            let is_blocking = result.outcome.is_blocking();
            stage_results.push(result);

            if is_blocking && !dry_run {
                match entry.definition.fail_action {
                    FailAction::Block => {
                        // Fail-closed: stop and deny
                        aborted = true;
                        break;
                    }
                    FailAction::Continue => {
                        // Fail-open: log and continue
                        ctx.add_warning(format!(
                            "Stage '{}' failed but pipeline continues (fail-open)",
                            entry.definition.name
                        ));
                    }
                    FailAction::Escalate => {
                        escalate_to = Some((
                            "security-reviewer".into(),
                            format!("Stage '{}' requires escalation", entry.definition.name),
                        ));
                        aborted = true;
                        break;
                    }
                    FailAction::Abort => {
                        aborted = true;
                        break;
                    }
                }
            }
        }

        // Determine outcome
        let outcome = if let Some((to, reason)) = escalate_to {
            GovernanceOutcome::Escalate { to, reason }
        } else if aborted {
            let reason = ctx
                .first_failure()
                .unwrap_or("Pipeline aborted")
                .to_string();
            GovernanceOutcome::Deny { reason }
        } else if ctx.risk_score > self.risk_threshold {
            GovernanceOutcome::ConditionalPermit {
                conditions: vec![format!(
                    "Risk score {:.2} exceeds threshold {:.2} — additional review required",
                    ctx.risk_score, self.risk_threshold
                )],
            }
        } else if ctx.has_blocking_failure() {
            // Failures existed but were all fail-open (Continue)
            GovernanceOutcome::ConditionalPermit {
                conditions: ctx
                    .warnings
                    .iter()
                    .filter(|w| w.contains("failed"))
                    .cloned()
                    .collect(),
            }
        } else {
            GovernanceOutcome::Permit
        };

        let explanation = ctx.build_explanation();

        Ok(GovernanceDecisionResult {
            request_id: request.id.clone(),
            outcome,
            stage_results,
            overall_severity,
            explanation,
            duration_ms: 0, // Layer 1 doesn't measure wall-clock time
            dry_run,
        })
    }
}

impl Default for GovernancePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GovernancePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernancePipeline")
            .field("stage_count", &self.stages.len())
            .field("risk_threshold", &self.risk_threshold)
            .field("default_timeout_ms", &self.default_timeout_ms)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::*;

    fn test_request() -> GovernanceRequest {
        GovernanceRequest::new(
            "req-001",
            SubjectInfo::new("user-1", "human"),
            ResourceInfo::new("res-1", "model", "public"),
            RequestContext::new("query", "prod", 1000),
        )
    }

    #[test]
    fn test_empty_pipeline_fails() {
        let pipeline = GovernancePipeline::new();
        let result = pipeline.evaluate(&test_request());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FrameworkError::PipelineNotConfigured);
    }

    #[test]
    fn test_single_stage_pass() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(StageDefinition::new("identity", StageType::Identity, identity_stage));
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert!(result.outcome.is_permitted());
        assert_eq!(result.stage_results.len(), 1);
    }

    #[test]
    fn test_multi_stage_all_pass() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("identity", StageType::Identity, identity_stage).with_order(1),
        );
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage).with_order(2),
        );
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage).with_order(3),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert_eq!(result.outcome, GovernanceOutcome::Permit);
        assert_eq!(result.stage_results.len(), 3);
        assert!(result.all_passed());
    }

    #[test]
    fn test_fail_closed_blocks() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("identity", StageType::Identity, identity_stage).with_order(1),
        );
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage)
                .with_order(2)
                .with_config("policy_action", "deny"),
        );
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage).with_order(3),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert!(result.outcome.is_denied());
        // Shield stage should NOT have executed (fail-closed)
        assert_eq!(result.stage_results.len(), 2);
    }

    #[test]
    fn test_fail_open_continues() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage)
                .with_order(1)
                .with_config("policy_action", "deny")
                .with_fail_action(FailAction::Continue),
        );
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage).with_order(2),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        // Both stages executed
        assert_eq!(result.stage_results.len(), 2);
        // Result is ConditionalPermit because failure was fail-open
        assert!(result.outcome.is_permitted());
    }

    #[test]
    fn test_escalate_action() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage)
                .with_order(1)
                .with_config("policy_action", "deny")
                .with_fail_action(FailAction::Escalate),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        match &result.outcome {
            GovernanceOutcome::Escalate { to, .. } => {
                assert_eq!(to, "security-reviewer");
            }
            other => panic!("Expected Escalate, got {other:?}"),
        }
    }

    #[test]
    fn test_disabled_stage_skipped() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage)
                .with_config("policy_action", "deny")
                .disabled(),
        );
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert!(result.outcome.is_permitted());
        assert_eq!(result.stage_results.len(), 1);
    }

    #[test]
    fn test_dry_run_no_short_circuit() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage)
                .with_order(1)
                .with_config("policy_action", "deny"),
        );
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage).with_order(2),
        );
        let result = pipeline.dry_run(&test_request()).unwrap();
        // Dry run executes ALL stages even after failure
        assert_eq!(result.stage_results.len(), 2);
        assert!(result.dry_run);
    }

    #[test]
    fn test_stage_ordering() {
        let mut pipeline = GovernancePipeline::new();
        // Add in reverse order
        pipeline.add_stage(
            StageDefinition::new("shield", StageType::Shield, shield_stage).with_order(3),
        );
        pipeline.add_stage(
            StageDefinition::new("identity", StageType::Identity, identity_stage).with_order(1),
        );
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage).with_order(2),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert_eq!(result.stage_results[0].stage_name, "identity");
        assert_eq!(result.stage_results[1].stage_name, "policy");
        assert_eq!(result.stage_results[2].stage_name, "shield");
    }

    #[test]
    fn test_risk_threshold_conditional_permit() {
        fn risky_stage(
            _req: &GovernanceRequest,
            ctx: &mut GovernanceContext,
            _config: &std::collections::HashMap<String, String>,
        ) -> StageResult {
            ctx.increase_risk(0.9);
            StageResult::pass("risky")
        }

        let mut pipeline = GovernancePipeline::new();
        pipeline.risk_threshold = 0.8;
        pipeline.add_stage(StageDefinition::new("risky", StageType::Detection, risky_stage));
        let result = pipeline.evaluate(&test_request()).unwrap();
        match &result.outcome {
            GovernanceOutcome::ConditionalPermit { conditions } => {
                assert!(!conditions.is_empty());
            }
            other => panic!("Expected ConditionalPermit, got {other:?}"),
        }
    }

    #[test]
    fn test_pipeline_metadata() {
        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("identity", StageType::Identity, identity_stage),
        );
        pipeline.add_stage(
            StageDefinition::new("policy", StageType::Policy, policy_stage).disabled(),
        );
        assert_eq!(pipeline.stage_count(), 2);
        assert_eq!(pipeline.enabled_stages(), 1);
        assert_eq!(pipeline.stage_names(), vec!["identity", "policy"]);
    }

    #[test]
    fn test_overall_severity_tracking() {
        fn high_sev_stage(
            _req: &GovernanceRequest,
            _ctx: &mut GovernanceContext,
            _config: &std::collections::HashMap<String, String>,
        ) -> StageResult {
            StageResult::pass("high-sev").with_severity(SecuritySeverity::High)
        }

        let mut pipeline = GovernancePipeline::new();
        pipeline.add_stage(
            StageDefinition::new("identity", StageType::Identity, identity_stage).with_order(1),
        );
        pipeline.add_stage(
            StageDefinition::new("high-sev", StageType::Detection, high_sev_stage).with_order(2),
        );
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert_eq!(result.overall_severity, SecuritySeverity::High);
    }
}
