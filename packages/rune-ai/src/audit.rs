// ═══════════════════════════════════════════════════════════════════════
// Audit — AI governance audit events for model lifecycle, training
// data, evaluation gates, deployment, bias/fairness, drift detection,
// and model retirement.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use serde::{Deserialize, Serialize};

// ── AiEventType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AiEventType {
    ModelRegistered { model_id: String, model_name: String },
    ModelVersionCreated { model_id: String, version: String },
    ModelStatusChanged { model_id: String, from_status: String, to_status: String },
    DatasetRegistered { dataset_id: String, dataset_name: String },
    DatasetQualityAssessed { dataset_id: String, status: String },
    DataGovernancePolicyCreated { policy_id: String },
    EvaluationCriteriaCreated { criteria_id: String, metric_name: String },
    EvaluationResultRecorded { result_id: String, model_id: String, passed: bool },
    EvaluationGateCreated { gate_id: String, model_id: String },
    EvaluationGateStatusChanged { gate_id: String, status: String },
    DeploymentRequested { request_id: String, model_id: String, environment: String },
    DeploymentApproved { request_id: String, approved_by: String },
    DeploymentDenied { request_id: String, reason: String },
    DeploymentExecuted { deployment_id: String, model_id: String },
    DeploymentRolledBack { deployment_id: String, reason: String },
    FairnessPolicyCreated { policy_id: String, model_id: String },
    FairnessAssessmentCompleted { assessment_id: String, status: String },
    FairnessViolationDetected { policy_id: String, metric_id: String },
    DriftPolicyCreated { policy_id: String, model_id: String },
    DriftDetected { result_id: String, model_id: String, severity: String },
    DriftRemediationTriggered { model_id: String, action: String },
    DeprecationNoticeIssued { notice_id: String, model_id: String },
    ModelRetired { model_id: String, reason: String },
    LifecycleTransitionRecorded { model_id: String, from: String, to: String },
    // Layer 2
    ModelHashComputed { model_id: String, hash: String },
    ModelHashChainAppended { chain_length: String },
    ModelHashChainVerified { valid: bool },
    DatasetHashComputed { dataset_id: String, hash: String },
    CriterionEvaluated { criteria_id: String, passed: bool },
    GateEvaluated { gate_id: String, recommendation: String },
    DeploymentReadinessChecked { model_id: String, ready: bool },
    DeploymentBlockerDetected { model_id: String, blocker_type: String },
    FairnessEvaluated { policy_id: String, status: String },
    FairnessMetricChecked { metric_id: String, passed: bool },
    DriftEvaluated { policy_id: String, status: String },
    DriftMetricChecked { metric_id: String, severity: String },
    DriftRemediationRecommended { model_id: String, action: String },
    LifecycleTransitionExecuted { model_id: String, from: String, to: String },
    DeprecationStatusChecked { model_id: String, deprecated: bool },
    DeprecationNoticeGenerated { notice_id: String, model_id: String },
    DeploymentAgeChecked { deployment_id: String, within_limit: bool },
    AiMetricsComputed { metric_name: String, value: String },
}

impl fmt::Display for AiEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelRegistered { model_id, model_name } => {
                write!(f, "ModelRegistered({model_id}, name={model_name})")
            }
            Self::ModelVersionCreated { model_id, version } => {
                write!(f, "ModelVersionCreated({model_id}, version={version})")
            }
            Self::ModelStatusChanged { model_id, from_status, to_status } => {
                write!(f, "ModelStatusChanged({model_id}, {from_status}→{to_status})")
            }
            Self::DatasetRegistered { dataset_id, dataset_name } => {
                write!(f, "DatasetRegistered({dataset_id}, name={dataset_name})")
            }
            Self::DatasetQualityAssessed { dataset_id, status } => {
                write!(f, "DatasetQualityAssessed({dataset_id}, status={status})")
            }
            Self::DataGovernancePolicyCreated { policy_id } => {
                write!(f, "DataGovernancePolicyCreated({policy_id})")
            }
            Self::EvaluationCriteriaCreated { criteria_id, metric_name } => {
                write!(f, "EvaluationCriteriaCreated({criteria_id}, metric={metric_name})")
            }
            Self::EvaluationResultRecorded { result_id, model_id, passed } => {
                write!(f, "EvaluationResultRecorded({result_id}, model={model_id}, passed={passed})")
            }
            Self::EvaluationGateCreated { gate_id, model_id } => {
                write!(f, "EvaluationGateCreated({gate_id}, model={model_id})")
            }
            Self::EvaluationGateStatusChanged { gate_id, status } => {
                write!(f, "EvaluationGateStatusChanged({gate_id}, status={status})")
            }
            Self::DeploymentRequested { request_id, model_id, environment } => {
                write!(f, "DeploymentRequested({request_id}, model={model_id}, env={environment})")
            }
            Self::DeploymentApproved { request_id, approved_by } => {
                write!(f, "DeploymentApproved({request_id}, by={approved_by})")
            }
            Self::DeploymentDenied { request_id, reason } => {
                write!(f, "DeploymentDenied({request_id}): {reason}")
            }
            Self::DeploymentExecuted { deployment_id, model_id } => {
                write!(f, "DeploymentExecuted({deployment_id}, model={model_id})")
            }
            Self::DeploymentRolledBack { deployment_id, reason } => {
                write!(f, "DeploymentRolledBack({deployment_id}): {reason}")
            }
            Self::FairnessPolicyCreated { policy_id, model_id } => {
                write!(f, "FairnessPolicyCreated({policy_id}, model={model_id})")
            }
            Self::FairnessAssessmentCompleted { assessment_id, status } => {
                write!(f, "FairnessAssessmentCompleted({assessment_id}, status={status})")
            }
            Self::FairnessViolationDetected { policy_id, metric_id } => {
                write!(f, "FairnessViolationDetected(policy={policy_id}, metric={metric_id})")
            }
            Self::DriftPolicyCreated { policy_id, model_id } => {
                write!(f, "DriftPolicyCreated({policy_id}, model={model_id})")
            }
            Self::DriftDetected { result_id, model_id, severity } => {
                write!(f, "DriftDetected({result_id}, model={model_id}, severity={severity})")
            }
            Self::DriftRemediationTriggered { model_id, action } => {
                write!(f, "DriftRemediationTriggered(model={model_id}, action={action})")
            }
            Self::DeprecationNoticeIssued { notice_id, model_id } => {
                write!(f, "DeprecationNoticeIssued({notice_id}, model={model_id})")
            }
            Self::ModelRetired { model_id, reason } => {
                write!(f, "ModelRetired({model_id}): {reason}")
            }
            Self::LifecycleTransitionRecorded { model_id, from, to } => {
                write!(f, "LifecycleTransitionRecorded({model_id}, {from}→{to})")
            }
            // Layer 2
            Self::ModelHashComputed { model_id, hash } => {
                write!(f, "ModelHashComputed({model_id}, hash={hash})")
            }
            Self::ModelHashChainAppended { chain_length } => {
                write!(f, "ModelHashChainAppended(length={chain_length})")
            }
            Self::ModelHashChainVerified { valid } => {
                write!(f, "ModelHashChainVerified(valid={valid})")
            }
            Self::DatasetHashComputed { dataset_id, hash } => {
                write!(f, "DatasetHashComputed({dataset_id}, hash={hash})")
            }
            Self::CriterionEvaluated { criteria_id, passed } => {
                write!(f, "CriterionEvaluated({criteria_id}, passed={passed})")
            }
            Self::GateEvaluated { gate_id, recommendation } => {
                write!(f, "GateEvaluated({gate_id}, rec={recommendation})")
            }
            Self::DeploymentReadinessChecked { model_id, ready } => {
                write!(f, "DeploymentReadinessChecked({model_id}, ready={ready})")
            }
            Self::DeploymentBlockerDetected { model_id, blocker_type } => {
                write!(f, "DeploymentBlockerDetected({model_id}, type={blocker_type})")
            }
            Self::FairnessEvaluated { policy_id, status } => {
                write!(f, "FairnessEvaluated({policy_id}, status={status})")
            }
            Self::FairnessMetricChecked { metric_id, passed } => {
                write!(f, "FairnessMetricChecked({metric_id}, passed={passed})")
            }
            Self::DriftEvaluated { policy_id, status } => {
                write!(f, "DriftEvaluated({policy_id}, status={status})")
            }
            Self::DriftMetricChecked { metric_id, severity } => {
                write!(f, "DriftMetricChecked({metric_id}, severity={severity})")
            }
            Self::DriftRemediationRecommended { model_id, action } => {
                write!(f, "DriftRemediationRecommended({model_id}, action={action})")
            }
            Self::LifecycleTransitionExecuted { model_id, from, to } => {
                write!(f, "LifecycleTransitionExecuted({model_id}, {from}→{to})")
            }
            Self::DeprecationStatusChecked { model_id, deprecated } => {
                write!(f, "DeprecationStatusChecked({model_id}, deprecated={deprecated})")
            }
            Self::DeprecationNoticeGenerated { notice_id, model_id } => {
                write!(f, "DeprecationNoticeGenerated({notice_id}, model={model_id})")
            }
            Self::DeploymentAgeChecked { deployment_id, within_limit } => {
                write!(f, "DeploymentAgeChecked({deployment_id}, within_limit={within_limit})")
            }
            Self::AiMetricsComputed { metric_name, value } => {
                write!(f, "AiMetricsComputed({metric_name}={value})")
            }
        }
    }
}

impl AiEventType {
    pub fn type_name(&self) -> &str {
        match self {
            Self::ModelRegistered { .. } => "ModelRegistered",
            Self::ModelVersionCreated { .. } => "ModelVersionCreated",
            Self::ModelStatusChanged { .. } => "ModelStatusChanged",
            Self::DatasetRegistered { .. } => "DatasetRegistered",
            Self::DatasetQualityAssessed { .. } => "DatasetQualityAssessed",
            Self::DataGovernancePolicyCreated { .. } => "DataGovernancePolicyCreated",
            Self::EvaluationCriteriaCreated { .. } => "EvaluationCriteriaCreated",
            Self::EvaluationResultRecorded { .. } => "EvaluationResultRecorded",
            Self::EvaluationGateCreated { .. } => "EvaluationGateCreated",
            Self::EvaluationGateStatusChanged { .. } => "EvaluationGateStatusChanged",
            Self::DeploymentRequested { .. } => "DeploymentRequested",
            Self::DeploymentApproved { .. } => "DeploymentApproved",
            Self::DeploymentDenied { .. } => "DeploymentDenied",
            Self::DeploymentExecuted { .. } => "DeploymentExecuted",
            Self::DeploymentRolledBack { .. } => "DeploymentRolledBack",
            Self::FairnessPolicyCreated { .. } => "FairnessPolicyCreated",
            Self::FairnessAssessmentCompleted { .. } => "FairnessAssessmentCompleted",
            Self::FairnessViolationDetected { .. } => "FairnessViolationDetected",
            Self::DriftPolicyCreated { .. } => "DriftPolicyCreated",
            Self::DriftDetected { .. } => "DriftDetected",
            Self::DriftRemediationTriggered { .. } => "DriftRemediationTriggered",
            Self::DeprecationNoticeIssued { .. } => "DeprecationNoticeIssued",
            Self::ModelRetired { .. } => "ModelRetired",
            Self::LifecycleTransitionRecorded { .. } => "LifecycleTransitionRecorded",
            // Layer 2
            Self::ModelHashComputed { .. } => "ModelHashComputed",
            Self::ModelHashChainAppended { .. } => "ModelHashChainAppended",
            Self::ModelHashChainVerified { .. } => "ModelHashChainVerified",
            Self::DatasetHashComputed { .. } => "DatasetHashComputed",
            Self::CriterionEvaluated { .. } => "CriterionEvaluated",
            Self::GateEvaluated { .. } => "GateEvaluated",
            Self::DeploymentReadinessChecked { .. } => "DeploymentReadinessChecked",
            Self::DeploymentBlockerDetected { .. } => "DeploymentBlockerDetected",
            Self::FairnessEvaluated { .. } => "FairnessEvaluated",
            Self::FairnessMetricChecked { .. } => "FairnessMetricChecked",
            Self::DriftEvaluated { .. } => "DriftEvaluated",
            Self::DriftMetricChecked { .. } => "DriftMetricChecked",
            Self::DriftRemediationRecommended { .. } => "DriftRemediationRecommended",
            Self::LifecycleTransitionExecuted { .. } => "LifecycleTransitionExecuted",
            Self::DeprecationStatusChecked { .. } => "DeprecationStatusChecked",
            Self::DeprecationNoticeGenerated { .. } => "DeprecationNoticeGenerated",
            Self::DeploymentAgeChecked { .. } => "DeploymentAgeChecked",
            Self::AiMetricsComputed { .. } => "AiMetricsComputed",
        }
    }

    pub fn kind(&self) -> &str {
        match self {
            Self::ModelRegistered { .. }
            | Self::ModelVersionCreated { .. }
            | Self::ModelStatusChanged { .. } => "model_registry",
            Self::DatasetRegistered { .. }
            | Self::DatasetQualityAssessed { .. }
            | Self::DataGovernancePolicyCreated { .. } => "training_data",
            Self::EvaluationCriteriaCreated { .. }
            | Self::EvaluationResultRecorded { .. }
            | Self::EvaluationGateCreated { .. }
            | Self::EvaluationGateStatusChanged { .. } => "evaluation",
            Self::DeploymentRequested { .. }
            | Self::DeploymentApproved { .. }
            | Self::DeploymentDenied { .. }
            | Self::DeploymentExecuted { .. }
            | Self::DeploymentRolledBack { .. } => "deployment",
            Self::FairnessPolicyCreated { .. }
            | Self::FairnessAssessmentCompleted { .. }
            | Self::FairnessViolationDetected { .. } => "bias_fairness",
            Self::DriftPolicyCreated { .. }
            | Self::DriftDetected { .. }
            | Self::DriftRemediationTriggered { .. } => "drift",
            Self::DeprecationNoticeIssued { .. }
            | Self::ModelRetired { .. }
            | Self::LifecycleTransitionRecorded { .. } => "lifecycle",
            // Layer 2
            Self::ModelHashComputed { .. }
            | Self::ModelHashChainAppended { .. }
            | Self::ModelHashChainVerified { .. }
            | Self::DatasetHashComputed { .. } => "model_hash",
            Self::CriterionEvaluated { .. }
            | Self::GateEvaluated { .. } => "evaluation_engine",
            Self::DeploymentReadinessChecked { .. }
            | Self::DeploymentBlockerDetected { .. }
            | Self::DeploymentAgeChecked { .. } => "deployment_readiness",
            Self::FairnessEvaluated { .. }
            | Self::FairnessMetricChecked { .. } => "fairness_evaluator",
            Self::DriftEvaluated { .. }
            | Self::DriftMetricChecked { .. }
            | Self::DriftRemediationRecommended { .. } => "drift_evaluator",
            Self::LifecycleTransitionExecuted { .. }
            | Self::DeprecationStatusChecked { .. }
            | Self::DeprecationNoticeGenerated { .. } => "lifecycle_engine",
            Self::AiMetricsComputed { .. } => "ai_metrics",
        }
    }
}

// ── AiAuditEvent ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AiAuditEvent {
    pub event: AiEventType,
    pub actor: String,
    pub timestamp: i64,
    pub description: String,
}

impl AiAuditEvent {
    pub fn new(
        event: AiEventType,
        actor: impl Into<String>,
        timestamp: i64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event,
            actor: actor.into(),
            timestamp,
            description: description.into(),
        }
    }
}

// ── AiAuditLog ───────────────────────────────────────────────────────

pub struct AiAuditLog {
    events: Vec<AiAuditEvent>,
}

impl AiAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, event: AiAuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[AiAuditEvent] {
        &self.events
    }

    pub fn events_by_kind(&self, kind: &str) -> Vec<&AiAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.event.kind() == kind)
            .collect()
    }

    pub fn since(&self, timestamp: i64) -> Vec<&AiAuditEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for AiAuditLog {
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

    fn make_event(event_type: AiEventType) -> AiAuditEvent {
        AiAuditEvent::new(event_type, "agent-1", 1000, "test")
    }

    #[test]
    fn test_event_type_display_all_variants() {
        let types: Vec<AiEventType> = vec![
            AiEventType::ModelRegistered { model_id: "m1".into(), model_name: "GPT".into() },
            AiEventType::ModelVersionCreated { model_id: "m1".into(), version: "1.0".into() },
            AiEventType::ModelStatusChanged { model_id: "m1".into(), from_status: "Draft".into(), to_status: "Registered".into() },
            AiEventType::DatasetRegistered { dataset_id: "ds1".into(), dataset_name: "train".into() },
            AiEventType::DatasetQualityAssessed { dataset_id: "ds1".into(), status: "Validated".into() },
            AiEventType::DataGovernancePolicyCreated { policy_id: "dgp1".into() },
            AiEventType::EvaluationCriteriaCreated { criteria_id: "ec1".into(), metric_name: "accuracy".into() },
            AiEventType::EvaluationResultRecorded { result_id: "er1".into(), model_id: "m1".into(), passed: true },
            AiEventType::EvaluationGateCreated { gate_id: "g1".into(), model_id: "m1".into() },
            AiEventType::EvaluationGateStatusChanged { gate_id: "g1".into(), status: "Passed".into() },
            AiEventType::DeploymentRequested { request_id: "r1".into(), model_id: "m1".into(), environment: "Production".into() },
            AiEventType::DeploymentApproved { request_id: "r1".into(), approved_by: "admin".into() },
            AiEventType::DeploymentDenied { request_id: "r2".into(), reason: "risk".into() },
            AiEventType::DeploymentExecuted { deployment_id: "d1".into(), model_id: "m1".into() },
            AiEventType::DeploymentRolledBack { deployment_id: "d1".into(), reason: "regression".into() },
            AiEventType::FairnessPolicyCreated { policy_id: "fp1".into(), model_id: "m1".into() },
            AiEventType::FairnessAssessmentCompleted { assessment_id: "fa1".into(), status: "Fair".into() },
            AiEventType::FairnessViolationDetected { policy_id: "fp1".into(), metric_id: "fm1".into() },
            AiEventType::DriftPolicyCreated { policy_id: "dp1".into(), model_id: "m1".into() },
            AiEventType::DriftDetected { result_id: "dd1".into(), model_id: "m1".into(), severity: "High".into() },
            AiEventType::DriftRemediationTriggered { model_id: "m1".into(), action: "Retrain".into() },
            AiEventType::DeprecationNoticeIssued { notice_id: "dn1".into(), model_id: "m1".into() },
            AiEventType::ModelRetired { model_id: "m1".into(), reason: "sunset".into() },
            AiEventType::LifecycleTransitionRecorded { model_id: "m1".into(), from: "Deployed".into(), to: "Deprecated".into() },
            // Layer 2
            AiEventType::ModelHashComputed { model_id: "m1".into(), hash: "abc".into() },
            AiEventType::ModelHashChainAppended { chain_length: "5".into() },
            AiEventType::ModelHashChainVerified { valid: true },
            AiEventType::DatasetHashComputed { dataset_id: "ds1".into(), hash: "def".into() },
            AiEventType::CriterionEvaluated { criteria_id: "ec1".into(), passed: true },
            AiEventType::GateEvaluated { gate_id: "g1".into(), recommendation: "Pass".into() },
            AiEventType::DeploymentReadinessChecked { model_id: "m1".into(), ready: true },
            AiEventType::DeploymentBlockerDetected { model_id: "m1".into(), blocker_type: "ModelNotApproved".into() },
            AiEventType::FairnessEvaluated { policy_id: "fp1".into(), status: "Fair".into() },
            AiEventType::FairnessMetricChecked { metric_id: "fm1".into(), passed: true },
            AiEventType::DriftEvaluated { policy_id: "dp1".into(), status: "NoDrift".into() },
            AiEventType::DriftMetricChecked { metric_id: "dm1".into(), severity: "Low".into() },
            AiEventType::DriftRemediationRecommended { model_id: "m1".into(), action: "Retrain".into() },
            AiEventType::LifecycleTransitionExecuted { model_id: "m1".into(), from: "Draft".into(), to: "Registered".into() },
            AiEventType::DeprecationStatusChecked { model_id: "m1".into(), deprecated: false },
            AiEventType::DeprecationNoticeGenerated { notice_id: "dn1".into(), model_id: "m1".into() },
            AiEventType::DeploymentAgeChecked { deployment_id: "d1".into(), within_limit: true },
            AiEventType::AiMetricsComputed { metric_name: "pass_rate".into(), value: "0.95".into() },
        ];
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
        assert_eq!(types.len(), 42);
    }

    #[test]
    fn test_type_name_all_variants() {
        let events: Vec<AiEventType> = vec![
            AiEventType::ModelRegistered { model_id: "m".into(), model_name: "n".into() },
            AiEventType::ModelVersionCreated { model_id: "m".into(), version: "v".into() },
            AiEventType::ModelStatusChanged { model_id: "m".into(), from_status: "a".into(), to_status: "b".into() },
            AiEventType::DatasetRegistered { dataset_id: "d".into(), dataset_name: "n".into() },
            AiEventType::DatasetQualityAssessed { dataset_id: "d".into(), status: "s".into() },
            AiEventType::DataGovernancePolicyCreated { policy_id: "p".into() },
            AiEventType::EvaluationCriteriaCreated { criteria_id: "c".into(), metric_name: "m".into() },
            AiEventType::EvaluationResultRecorded { result_id: "r".into(), model_id: "m".into(), passed: true },
            AiEventType::EvaluationGateCreated { gate_id: "g".into(), model_id: "m".into() },
            AiEventType::EvaluationGateStatusChanged { gate_id: "g".into(), status: "s".into() },
            AiEventType::DeploymentRequested { request_id: "r".into(), model_id: "m".into(), environment: "e".into() },
            AiEventType::DeploymentApproved { request_id: "r".into(), approved_by: "a".into() },
            AiEventType::DeploymentDenied { request_id: "r".into(), reason: "n".into() },
            AiEventType::DeploymentExecuted { deployment_id: "d".into(), model_id: "m".into() },
            AiEventType::DeploymentRolledBack { deployment_id: "d".into(), reason: "r".into() },
            AiEventType::FairnessPolicyCreated { policy_id: "p".into(), model_id: "m".into() },
            AiEventType::FairnessAssessmentCompleted { assessment_id: "a".into(), status: "s".into() },
            AiEventType::FairnessViolationDetected { policy_id: "p".into(), metric_id: "m".into() },
            AiEventType::DriftPolicyCreated { policy_id: "p".into(), model_id: "m".into() },
            AiEventType::DriftDetected { result_id: "r".into(), model_id: "m".into(), severity: "s".into() },
            AiEventType::DriftRemediationTriggered { model_id: "m".into(), action: "a".into() },
            AiEventType::DeprecationNoticeIssued { notice_id: "n".into(), model_id: "m".into() },
            AiEventType::ModelRetired { model_id: "m".into(), reason: "r".into() },
            AiEventType::LifecycleTransitionRecorded { model_id: "m".into(), from: "a".into(), to: "b".into() },
            // Layer 2
            AiEventType::ModelHashComputed { model_id: "m".into(), hash: "h".into() },
            AiEventType::ModelHashChainAppended { chain_length: "1".into() },
            AiEventType::ModelHashChainVerified { valid: true },
            AiEventType::DatasetHashComputed { dataset_id: "d".into(), hash: "h".into() },
            AiEventType::CriterionEvaluated { criteria_id: "c".into(), passed: true },
            AiEventType::GateEvaluated { gate_id: "g".into(), recommendation: "Pass".into() },
            AiEventType::DeploymentReadinessChecked { model_id: "m".into(), ready: true },
            AiEventType::DeploymentBlockerDetected { model_id: "m".into(), blocker_type: "t".into() },
            AiEventType::FairnessEvaluated { policy_id: "p".into(), status: "s".into() },
            AiEventType::FairnessMetricChecked { metric_id: "m".into(), passed: true },
            AiEventType::DriftEvaluated { policy_id: "p".into(), status: "s".into() },
            AiEventType::DriftMetricChecked { metric_id: "m".into(), severity: "s".into() },
            AiEventType::DriftRemediationRecommended { model_id: "m".into(), action: "a".into() },
            AiEventType::LifecycleTransitionExecuted { model_id: "m".into(), from: "a".into(), to: "b".into() },
            AiEventType::DeprecationStatusChecked { model_id: "m".into(), deprecated: false },
            AiEventType::DeprecationNoticeGenerated { notice_id: "n".into(), model_id: "m".into() },
            AiEventType::DeploymentAgeChecked { deployment_id: "d".into(), within_limit: true },
            AiEventType::AiMetricsComputed { metric_name: "m".into(), value: "v".into() },
        ];
        for e in &events {
            assert!(!e.type_name().is_empty());
        }
        assert_eq!(events.len(), 42);
    }

    #[test]
    fn test_kind_model_registry() {
        assert_eq!(
            AiEventType::ModelRegistered { model_id: "m".into(), model_name: "n".into() }.kind(),
            "model_registry"
        );
        assert_eq!(
            AiEventType::ModelVersionCreated { model_id: "m".into(), version: "v".into() }.kind(),
            "model_registry"
        );
        assert_eq!(
            AiEventType::ModelStatusChanged { model_id: "m".into(), from_status: "a".into(), to_status: "b".into() }.kind(),
            "model_registry"
        );
    }

    #[test]
    fn test_kind_training_data() {
        assert_eq!(
            AiEventType::DatasetRegistered { dataset_id: "d".into(), dataset_name: "n".into() }.kind(),
            "training_data"
        );
        assert_eq!(
            AiEventType::DataGovernancePolicyCreated { policy_id: "p".into() }.kind(),
            "training_data"
        );
    }

    #[test]
    fn test_kind_evaluation() {
        assert_eq!(
            AiEventType::EvaluationCriteriaCreated { criteria_id: "c".into(), metric_name: "m".into() }.kind(),
            "evaluation"
        );
        assert_eq!(
            AiEventType::EvaluationGateStatusChanged { gate_id: "g".into(), status: "s".into() }.kind(),
            "evaluation"
        );
    }

    #[test]
    fn test_kind_deployment() {
        assert_eq!(
            AiEventType::DeploymentRequested { request_id: "r".into(), model_id: "m".into(), environment: "e".into() }.kind(),
            "deployment"
        );
        assert_eq!(
            AiEventType::DeploymentRolledBack { deployment_id: "d".into(), reason: "r".into() }.kind(),
            "deployment"
        );
    }

    #[test]
    fn test_kind_bias_fairness() {
        assert_eq!(
            AiEventType::FairnessPolicyCreated { policy_id: "p".into(), model_id: "m".into() }.kind(),
            "bias_fairness"
        );
        assert_eq!(
            AiEventType::FairnessViolationDetected { policy_id: "p".into(), metric_id: "m".into() }.kind(),
            "bias_fairness"
        );
    }

    #[test]
    fn test_kind_drift() {
        assert_eq!(
            AiEventType::DriftDetected { result_id: "r".into(), model_id: "m".into(), severity: "s".into() }.kind(),
            "drift"
        );
        assert_eq!(
            AiEventType::DriftRemediationTriggered { model_id: "m".into(), action: "a".into() }.kind(),
            "drift"
        );
    }

    #[test]
    fn test_kind_lifecycle() {
        assert_eq!(
            AiEventType::DeprecationNoticeIssued { notice_id: "n".into(), model_id: "m".into() }.kind(),
            "lifecycle"
        );
        assert_eq!(
            AiEventType::ModelRetired { model_id: "m".into(), reason: "r".into() }.kind(),
            "lifecycle"
        );
        assert_eq!(
            AiEventType::LifecycleTransitionRecorded { model_id: "m".into(), from: "a".into(), to: "b".into() }.kind(),
            "lifecycle"
        );
    }

    #[test]
    fn test_kind_model_hash() {
        assert_eq!(
            AiEventType::ModelHashComputed { model_id: "m".into(), hash: "h".into() }.kind(),
            "model_hash"
        );
        assert_eq!(
            AiEventType::DatasetHashComputed { dataset_id: "d".into(), hash: "h".into() }.kind(),
            "model_hash"
        );
    }

    #[test]
    fn test_kind_evaluation_engine() {
        assert_eq!(
            AiEventType::CriterionEvaluated { criteria_id: "c".into(), passed: true }.kind(),
            "evaluation_engine"
        );
        assert_eq!(
            AiEventType::GateEvaluated { gate_id: "g".into(), recommendation: "Pass".into() }.kind(),
            "evaluation_engine"
        );
    }

    #[test]
    fn test_kind_deployment_readiness() {
        assert_eq!(
            AiEventType::DeploymentReadinessChecked { model_id: "m".into(), ready: true }.kind(),
            "deployment_readiness"
        );
        assert_eq!(
            AiEventType::DeploymentAgeChecked { deployment_id: "d".into(), within_limit: true }.kind(),
            "deployment_readiness"
        );
    }

    #[test]
    fn test_kind_fairness_evaluator() {
        assert_eq!(
            AiEventType::FairnessEvaluated { policy_id: "p".into(), status: "s".into() }.kind(),
            "fairness_evaluator"
        );
        assert_eq!(
            AiEventType::FairnessMetricChecked { metric_id: "m".into(), passed: true }.kind(),
            "fairness_evaluator"
        );
    }

    #[test]
    fn test_kind_drift_evaluator() {
        assert_eq!(
            AiEventType::DriftEvaluated { policy_id: "p".into(), status: "s".into() }.kind(),
            "drift_evaluator"
        );
        assert_eq!(
            AiEventType::DriftRemediationRecommended { model_id: "m".into(), action: "a".into() }.kind(),
            "drift_evaluator"
        );
    }

    #[test]
    fn test_kind_lifecycle_engine() {
        assert_eq!(
            AiEventType::LifecycleTransitionExecuted { model_id: "m".into(), from: "a".into(), to: "b".into() }.kind(),
            "lifecycle_engine"
        );
        assert_eq!(
            AiEventType::DeprecationNoticeGenerated { notice_id: "n".into(), model_id: "m".into() }.kind(),
            "lifecycle_engine"
        );
    }

    #[test]
    fn test_kind_ai_metrics() {
        assert_eq!(
            AiEventType::AiMetricsComputed { metric_name: "m".into(), value: "v".into() }.kind(),
            "ai_metrics"
        );
    }

    #[test]
    fn test_audit_event_construction() {
        let event = AiAuditEvent::new(
            AiEventType::ModelRegistered { model_id: "m1".into(), model_name: "GPT".into() },
            "alice", 1000, "Registered model GPT",
        );
        assert_eq!(event.actor, "alice");
        assert_eq!(event.timestamp, 1000);
    }

    #[test]
    fn test_audit_log_record_and_count() {
        let mut log = AiAuditLog::new();
        log.record(make_event(AiEventType::ModelRegistered { model_id: "m1".into(), model_name: "GPT".into() }));
        log.record(make_event(AiEventType::DatasetRegistered { dataset_id: "ds1".into(), dataset_name: "train".into() }));
        assert_eq!(log.event_count(), 2);
        assert_eq!(log.events().len(), 2);
    }

    #[test]
    fn test_audit_log_events_by_kind() {
        let mut log = AiAuditLog::new();
        log.record(make_event(AiEventType::ModelRegistered { model_id: "m1".into(), model_name: "GPT".into() }));
        log.record(make_event(AiEventType::DriftDetected { result_id: "r1".into(), model_id: "m1".into(), severity: "High".into() }));
        log.record(make_event(AiEventType::DriftRemediationTriggered { model_id: "m1".into(), action: "Retrain".into() }));
        assert_eq!(log.events_by_kind("model_registry").len(), 1);
        assert_eq!(log.events_by_kind("drift").len(), 2);
        assert_eq!(log.events_by_kind("deployment").len(), 0);
    }

    #[test]
    fn test_audit_log_since() {
        let mut log = AiAuditLog::new();
        log.record(AiAuditEvent::new(
            AiEventType::ModelRegistered { model_id: "m1".into(), model_name: "n".into() },
            "a", 500, "early",
        ));
        log.record(AiAuditEvent::new(
            AiEventType::ModelRetired { model_id: "m1".into(), reason: "eol".into() },
            "a", 1500, "late",
        ));
        assert_eq!(log.since(1000).len(), 1);
        assert_eq!(log.since(500).len(), 2);
        assert_eq!(log.since(2000).len(), 0);
    }

    #[test]
    fn test_audit_log_default() {
        let log = AiAuditLog::default();
        assert_eq!(log.event_count(), 0);
    }
}
