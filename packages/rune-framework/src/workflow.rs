// ═══════════════════════════════════════════════════════════════════════
// Workflow — Workflow templates and pipeline construction from
// predefined stage configurations.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::FrameworkError;
use crate::pipeline::GovernancePipeline;
use crate::stage::*;

// ── WorkflowTemplate ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub name: String,
    pub description: String,
    pub stages: Vec<WorkflowStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub stage_type: StageType,
    pub name: String,
    pub fail_action: FailAction,
    pub order: u32,
    pub config: HashMap<String, String>,
}

impl WorkflowTemplate {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            stages: Vec::new(),
        }
    }

    pub fn add_stage(
        &mut self,
        stage_type: StageType,
        name: impl Into<String>,
        fail_action: FailAction,
        order: u32,
    ) {
        self.stages.push(WorkflowStage {
            stage_type,
            name: name.into(),
            fail_action,
            order,
            config: HashMap::new(),
        });
    }

    pub fn add_stage_with_config(
        &mut self,
        stage_type: StageType,
        name: impl Into<String>,
        fail_action: FailAction,
        order: u32,
        config: HashMap<String, String>,
    ) {
        self.stages.push(WorkflowStage {
            stage_type,
            name: name.into(),
            fail_action,
            order,
            config,
        });
    }

    // ── Built-in templates ─────────────────────────────────────────

    /// Full inference protection: identity → policy → shield → trust → compliance.
    pub fn inference_protection() -> Self {
        let mut t = Self::new(
            "inference_protection",
            "Full governance pipeline for AI model inference requests",
        );
        t.add_stage(StageType::Identity, "identity", FailAction::Block, 1);
        t.add_stage(StageType::Policy, "policy", FailAction::Block, 2);
        t.add_stage(StageType::Shield, "shield", FailAction::Block, 3);
        t.add_stage(StageType::Trust, "trust", FailAction::Escalate, 4);
        t.add_stage(StageType::Compliance, "compliance", FailAction::Block, 5);
        t
    }

    /// Data access: identity → permission → privacy → compliance.
    pub fn data_access() -> Self {
        let mut t = Self::new(
            "data_access",
            "Governance pipeline for data access requests",
        );
        t.add_stage(StageType::Identity, "identity", FailAction::Block, 1);
        t.add_stage(StageType::Permission, "permission", FailAction::Block, 2);
        t.add_stage(StageType::Privacy, "privacy", FailAction::Block, 3);
        t.add_stage(StageType::Compliance, "compliance", FailAction::Block, 4);
        t
    }

    /// Model deployment: identity → policy → trust → detection → compliance.
    pub fn model_deployment() -> Self {
        let mut t = Self::new(
            "model_deployment",
            "Governance pipeline for model deployment approvals",
        );
        t.add_stage(StageType::Identity, "identity", FailAction::Block, 1);
        t.add_stage(StageType::Policy, "policy", FailAction::Block, 2);
        t.add_stage(StageType::Trust, "trust", FailAction::Block, 3);
        t.add_stage(StageType::Detection, "detection", FailAction::Escalate, 4);
        t.add_stage(StageType::Compliance, "compliance", FailAction::Block, 5);
        t
    }

    /// Admin action: identity → policy → shield.
    pub fn admin_action() -> Self {
        let mut t = Self::new(
            "admin_action",
            "Governance pipeline for administrative actions",
        );
        t.add_stage(StageType::Identity, "identity", FailAction::Block, 1);
        t.add_stage(StageType::Policy, "policy", FailAction::Block, 2);
        t.add_stage(StageType::Shield, "shield", FailAction::Block, 3);
        t
    }

    /// Minimal: policy only (for testing/development).
    pub fn minimal() -> Self {
        let mut t = Self::new("minimal", "Minimal pipeline with policy check only");
        t.add_stage(StageType::Policy, "policy", FailAction::Block, 1);
        t
    }
}

impl fmt::Display for WorkflowTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} stages): {}",
            self.name,
            self.stages.len(),
            self.description
        )
    }
}

// ── Pipeline construction ─────────────────────────────────────────────

/// Stage evaluator registry: maps StageType to a StageFn.
pub type StageEvaluatorRegistry = HashMap<StageType, StageFn>;

/// Returns the default evaluator registry with all 5 built-in evaluators.
pub fn default_evaluator_registry() -> StageEvaluatorRegistry {
    let mut reg = HashMap::new();
    reg.insert(StageType::Identity, identity_stage as StageFn);
    reg.insert(StageType::Policy, policy_stage as StageFn);
    reg.insert(StageType::Shield, shield_stage as StageFn);
    reg.insert(StageType::Trust, trust_stage as StageFn);
    reg.insert(StageType::Compliance, compliance_stage as StageFn);
    reg
}

/// Builds a GovernancePipeline from a WorkflowTemplate using the
/// provided evaluator registry.
pub fn build_pipeline_from_template(
    template: &WorkflowTemplate,
    evaluators: &StageEvaluatorRegistry,
) -> Result<GovernancePipeline, FrameworkError> {
    let mut pipeline = GovernancePipeline::new();

    for ws in &template.stages {
        let evaluator = evaluators
            .get(&ws.stage_type)
            .ok_or_else(|| FrameworkError::StageNotFound {
                stage_name: format!("{} (type {:?})", ws.name, ws.stage_type),
            })?;

        let mut def = StageDefinition::new(ws.name.clone(), ws.stage_type, *evaluator)
            .with_fail_action(ws.fail_action)
            .with_order(ws.order);

        for (k, v) in &ws.config {
            def = def.with_config(k.clone(), v.clone());
        }

        pipeline.add_stage(def);
    }

    Ok(pipeline)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::*;

    fn test_request() -> GovernanceRequest {
        GovernanceRequest::new(
            "req-001",
            SubjectInfo::new("user-1", "human"),
            ResourceInfo::new("res-1", "model", "public"),
            RequestContext::new("query", "prod", 1000),
        )
    }

    #[test]
    fn test_inference_protection_template() {
        let t = WorkflowTemplate::inference_protection();
        assert_eq!(t.name, "inference_protection");
        assert_eq!(t.stages.len(), 5);
        assert_eq!(t.stages[0].stage_type, StageType::Identity);
        assert_eq!(t.stages[4].stage_type, StageType::Compliance);
    }

    #[test]
    fn test_data_access_template() {
        let t = WorkflowTemplate::data_access();
        assert_eq!(t.stages.len(), 4);
        assert_eq!(t.stages[2].stage_type, StageType::Privacy);
    }

    #[test]
    fn test_model_deployment_template() {
        let t = WorkflowTemplate::model_deployment();
        assert_eq!(t.stages.len(), 5);
        assert_eq!(t.stages[3].stage_type, StageType::Detection);
        assert_eq!(t.stages[3].fail_action, FailAction::Escalate);
    }

    #[test]
    fn test_admin_action_template() {
        let t = WorkflowTemplate::admin_action();
        assert_eq!(t.stages.len(), 3);
    }

    #[test]
    fn test_minimal_template() {
        let t = WorkflowTemplate::minimal();
        assert_eq!(t.stages.len(), 1);
        assert_eq!(t.stages[0].stage_type, StageType::Policy);
    }

    #[test]
    fn test_build_pipeline_from_template() {
        let t = WorkflowTemplate::minimal();
        let evaluators = default_evaluator_registry();
        let pipeline = build_pipeline_from_template(&t, &evaluators).unwrap();
        assert_eq!(pipeline.stage_count(), 1);
    }

    #[test]
    fn test_build_pipeline_missing_evaluator() {
        let mut t = WorkflowTemplate::new("custom", "test");
        t.add_stage(StageType::Permission, "permission", FailAction::Block, 1);
        let evaluators = default_evaluator_registry(); // no Permission evaluator
        let result = build_pipeline_from_template(&t, &evaluators);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_and_evaluate() {
        let t = WorkflowTemplate::inference_protection();
        let evaluators = default_evaluator_registry();
        let pipeline = build_pipeline_from_template(&t, &evaluators).unwrap();
        let result = pipeline.evaluate(&test_request()).unwrap();
        assert!(result.outcome.is_permitted());
    }

    #[test]
    fn test_template_display() {
        let t = WorkflowTemplate::inference_protection();
        let display = t.to_string();
        assert!(display.contains("inference_protection"));
        assert!(display.contains("5 stages"));
    }

    #[test]
    fn test_template_with_config() {
        let mut t = WorkflowTemplate::new("custom", "test");
        let mut config = HashMap::new();
        config.insert("max_risk".into(), "0.5".into());
        t.add_stage_with_config(StageType::Policy, "policy", FailAction::Block, 1, config);
        assert_eq!(
            t.stages[0].config.get("max_risk").unwrap(),
            "0.5"
        );
    }

    #[test]
    fn test_default_evaluator_registry() {
        let reg = default_evaluator_registry();
        assert_eq!(reg.len(), 5);
        assert!(reg.contains_key(&StageType::Identity));
        assert!(reg.contains_key(&StageType::Policy));
        assert!(reg.contains_key(&StageType::Shield));
        assert!(reg.contains_key(&StageType::Trust));
        assert!(reg.contains_key(&StageType::Compliance));
    }
}
