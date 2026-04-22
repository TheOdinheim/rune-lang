// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AI governance exporter trait. Defines the export contract
// for model inventory, evaluation reports, deployment reports, fairness
// reports, and drift reports. Five implementations: JsonAiExporter,
// ModelCardExporter, EuAiActComplianceExporter, NistAiRmfExporter,
// DeploymentAuditExporter.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{
    StoredDatasetRecord, StoredDeploymentRecord, StoredDriftResult,
    StoredFairnessAssessment, StoredModelRecord,
};
use crate::error::AiError;

// ── AiGovernanceExporter trait ─────────────────────────────────────

pub trait AiGovernanceExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError>;
    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError>;
    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError>;
    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError>;
    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError>;
    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonAiExporter ─────────────────────────────────────────────────

pub struct JsonAiExporter;

impl AiGovernanceExporter for JsonAiExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let entries: Vec<serde_json::Value> = models
            .iter()
            .map(|m| {
                serde_json::json!({
                    "model_id": m.model_id,
                    "model_name": m.model_name,
                    "model_version": m.model_version,
                    "status": format!("{:?}", m.status),
                    "model_hash": m.model_hash,
                    "evaluation_count": m.evaluation_count,
                    "deployment_count": m.deployment_count,
                    "stored_at": m.stored_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "model_inventory",
            "model_count": models.len(),
            "models": entries,
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let entries: Vec<serde_json::Value> = models
            .iter()
            .map(|m| {
                serde_json::json!({
                    "model_id": m.model_id,
                    "evaluation_count": m.evaluation_count,
                    "last_evaluated_at": m.last_evaluated_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "evaluation_report",
            "models": entries,
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError> {
        let entries: Vec<serde_json::Value> = deployments
            .iter()
            .map(|d| {
                serde_json::json!({
                    "deployment_id": d.deployment_id,
                    "model_id": d.model_id,
                    "environment": format!("{}", d.environment),
                    "status": format!("{:?}", d.status),
                    "deployed_at": d.deployed_at,
                    "deployed_by": d.deployed_by,
                    "health_check_count": d.health_check_count,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "deployment_report",
            "deployment_count": deployments.len(),
            "deployments": entries,
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError> {
        let entries: Vec<serde_json::Value> = assessments
            .iter()
            .map(|a| {
                serde_json::json!({
                    "assessment_id": a.assessment_id,
                    "model_id": a.model_id,
                    "overall_status": format!("{:?}", a.overall_status),
                    "assessed_at": a.assessed_at,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "fairness_report",
            "assessments": entries,
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError> {
        let entries: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "result_id": r.result_id,
                    "model_id": r.model_id,
                    "overall_status": format!("{:?}", r.overall_status),
                    "remediation_applied": r.remediation_applied,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "drift_report",
            "results": entries,
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError> {
        serde_json::to_string_pretty(&serde_json::json!({
            "report_type": "batch_export",
            "model_count": models.len(),
            "dataset_count": datasets.len(),
            "deployment_count": deployments.len(),
        }))
        .map_err(|e| AiError::InvalidOperation(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "json"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── ModelCardExporter ──────────────────────────────────────────────

/// Emits a structured model card following the Model Cards for Model
/// Reporting pattern: model details, intended use, performance metrics,
/// fairness considerations, training data summary, deployment history.
pub struct ModelCardExporter;

impl AiGovernanceExporter for ModelCardExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Model Cards\n\n");
        for m in models {
            output.push_str(&format!("## {}\n\n", m.model_name));
            output.push_str(&format!("- **Model ID**: {}\n", m.model_id));
            output.push_str(&format!("- **Version**: {}\n", m.model_version));
            output.push_str(&format!("- **Architecture**: {:?}\n", m.architecture));
            output.push_str(&format!("- **Task Type**: {:?}\n", m.task_type));
            output.push_str(&format!("- **Framework**: {}\n", m.framework));
            output.push_str(&format!("- **Status**: {:?}\n", m.status));
            output.push_str(&format!("- **Integrity Hash**: {}\n", m.model_hash));
            output.push_str(&format!("- **Created By**: {}\n", m.created_by));
            output.push('\n');
        }
        Ok(output)
    }

    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Evaluation Summary\n\n");
        for m in models {
            output.push_str(&format!(
                "- **{}**: {} evaluations\n", m.model_id, m.evaluation_count,
            ));
        }
        Ok(output)
    }

    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment History\n\n");
        for d in deployments {
            output.push_str(&format!(
                "- {} → {} (env={}, by={})\n",
                d.deployment_id, d.model_id, d.environment, d.deployed_by,
            ));
        }
        Ok(output)
    }

    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError> {
        let mut output = String::from("# Fairness Considerations\n\n");
        for a in assessments {
            output.push_str(&format!(
                "- {}: {:?} (assessed by {})\n",
                a.model_id, a.overall_status, a.assessed_by,
            ));
        }
        Ok(output)
    }

    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError> {
        let mut output = String::from("# Drift Analysis\n\n");
        for r in results {
            output.push_str(&format!(
                "- {}: {:?}\n", r.model_id, r.overall_status,
            ));
        }
        Ok(output)
    }

    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError> {
        let mut output = String::from("# Model Card Batch Report\n\n");
        output.push_str(&format!("- Models: {}\n", models.len()));
        output.push_str(&format!("- Datasets: {}\n", datasets.len()));
        output.push_str(&format!("- Deployments: {}\n", deployments.len()));
        Ok(output)
    }

    fn format_name(&self) -> &str {
        "model_card"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── EuAiActComplianceExporter ──────────────────────────────────────

/// Emits EU AI Act compliance evidence: risk classification evidence,
/// bias monitoring documentation, transparency obligations, human
/// oversight documentation. References framework requirements by
/// opaque string.
pub struct EuAiActComplianceExporter;

impl AiGovernanceExporter for EuAiActComplianceExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Model Risk Classification\n\n");
        for m in models {
            output.push_str(&format!("## Model: {}\n\n", m.model_id));
            output.push_str(&format!("- **Status**: {:?}\n", m.status));
            output.push_str("- **Article 6**: Risk classification evidence required\n");
            output.push_str("- **Article 9**: Risk management system documentation\n");
            output.push_str(&format!("- **Article 13**: Transparency — architecture: {:?}\n", m.architecture));
            output.push_str("- **Article 14**: Human oversight documentation required\n\n");
        }
        Ok(output)
    }

    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Article 15 Accuracy & Robustness\n\n");
        for m in models {
            output.push_str(&format!(
                "- {}: {} evaluations conducted\n", m.model_id, m.evaluation_count,
            ));
        }
        Ok(output)
    }

    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Deployment Transparency Record\n\n");
        for d in deployments {
            output.push_str(&format!(
                "- Deployment {} of model {} to {} by {}\n",
                d.deployment_id, d.model_id, d.environment, d.deployed_by,
            ));
        }
        Ok(output)
    }

    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Article 10 Bias Monitoring\n\n");
        for a in assessments {
            output.push_str(&format!(
                "- Model {}: {:?}\n", a.model_id, a.overall_status,
            ));
        }
        output.push_str("\n## Compliance Notes\n\n");
        output.push_str("- Protected attribute monitoring per Article 10(2)(f)\n");
        output.push_str("- Bias detection and mitigation measures documented\n");
        Ok(output)
    }

    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Post-Market Monitoring\n\n");
        for r in results {
            output.push_str(&format!(
                "- Model {}: {:?}\n", r.model_id, r.overall_status,
            ));
        }
        Ok(output)
    }

    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        _datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError> {
        let mut output = String::from("# EU AI Act — Compliance Evidence Summary\n\n");
        output.push_str(&format!("- Models registered: {}\n", models.len()));
        output.push_str(&format!("- Deployments tracked: {}\n", deployments.len()));
        output.push_str("- Framework reference: EU AI Act (Regulation 2024/1689)\n");
        Ok(output)
    }

    fn format_name(&self) -> &str {
        "eu_ai_act_compliance"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── NistAiRmfExporter ─────────────────────────────────────────────

/// Emits NIST AI RMF evidence: Govern/Map/Measure/Manage function
/// documentation with model governance evidence mapped to AI RMF
/// categories.
pub struct NistAiRmfExporter;

impl AiGovernanceExporter for NistAiRmfExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — GOVERN Function\n\n");
        output.push_str("## Model Governance Inventory\n\n");
        for m in models {
            output.push_str(&format!(
                "- **{}** ({}): status={:?}, hash={}\n",
                m.model_name, m.model_id, m.status, m.model_hash,
            ));
        }
        Ok(output)
    }

    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — MEASURE Function\n\n");
        output.push_str("## Evaluation Evidence\n\n");
        for m in models {
            output.push_str(&format!(
                "- {}: {} evaluation cycles\n", m.model_id, m.evaluation_count,
            ));
        }
        Ok(output)
    }

    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — MANAGE Function\n\n");
        output.push_str("## Deployment Management\n\n");
        for d in deployments {
            output.push_str(&format!(
                "- {}: model={}, env={}\n",
                d.deployment_id, d.model_id, d.environment,
            ));
        }
        Ok(output)
    }

    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — MAP Function\n\n");
        output.push_str("## Fairness & Bias Mapping\n\n");
        for a in assessments {
            output.push_str(&format!(
                "- {}: {:?}\n", a.model_id, a.overall_status,
            ));
        }
        Ok(output)
    }

    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — MEASURE Function\n\n");
        output.push_str("## Drift Measurement\n\n");
        for r in results {
            output.push_str(&format!(
                "- {}: {:?}\n", r.model_id, r.overall_status,
            ));
        }
        Ok(output)
    }

    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError> {
        let mut output = String::from("# NIST AI RMF — Cross-Function Evidence Summary\n\n");
        output.push_str(&format!("- GOVERN: {} models registered\n", models.len()));
        output.push_str(&format!("- MAP: {} datasets catalogued\n", datasets.len()));
        output.push_str(&format!("- MANAGE: {} deployments tracked\n", deployments.len()));
        output.push_str("- Framework reference: NIST AI RMF 1.0\n");
        Ok(output)
    }

    fn format_name(&self) -> &str {
        "nist_ai_rmf"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── DeploymentAuditExporter ────────────────────────────────────────

/// Deployment governance audit trail — which models were deployed where,
/// by whom, with what approval chain, rollback history.
pub struct DeploymentAuditExporter;

impl AiGovernanceExporter for DeploymentAuditExporter {
    fn export_model_inventory(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment Audit — Model Summary\n\n");
        for m in models {
            output.push_str(&format!(
                "- {}: {} deployments, active_ref={:?}\n",
                m.model_id, m.deployment_count, m.active_deployment_ref,
            ));
        }
        Ok(output)
    }

    fn export_evaluation_report(&self, models: &[StoredModelRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment Audit — Pre-Deployment Evaluation\n\n");
        for m in models {
            output.push_str(&format!(
                "- {}: {} evaluations, last={:?}\n",
                m.model_id, m.evaluation_count, m.last_evaluated_at,
            ));
        }
        Ok(output)
    }

    fn export_deployment_report(&self, deployments: &[StoredDeploymentRecord]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment Audit Trail\n\n");
        for d in deployments {
            output.push_str(&format!("## Deployment: {}\n\n", d.deployment_id));
            output.push_str(&format!("- **Model**: {} v{}\n", d.model_id, d.model_version));
            output.push_str(&format!("- **Environment**: {}\n", d.environment));
            output.push_str(&format!("- **Deployed By**: {}\n", d.deployed_by));
            output.push_str(&format!("- **Deployed At**: {}\n", d.deployed_at));
            output.push_str(&format!("- **Status**: {:?}\n", d.status));
            output.push_str(&format!("- **Health Checks**: {}\n", d.health_check_count));
            if let Some(pred) = &d.predecessor_deployment_id {
                output.push_str(&format!("- **Predecessor**: {pred}\n"));
            }
            output.push('\n');
        }
        Ok(output)
    }

    fn export_fairness_report(&self, assessments: &[StoredFairnessAssessment]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment Audit — Fairness Gate Results\n\n");
        for a in assessments {
            output.push_str(&format!(
                "- Model {} (v{}): {:?}\n",
                a.model_id, a.model_version, a.overall_status,
            ));
        }
        Ok(output)
    }

    fn export_drift_report(&self, results: &[StoredDriftResult]) -> Result<String, AiError> {
        let mut output = String::from("# Deployment Audit — Post-Deployment Drift\n\n");
        for r in results {
            output.push_str(&format!(
                "- Model {} (v{}): {:?}, remediation={:?}\n",
                r.model_id, r.model_version, r.overall_status, r.remediation_applied,
            ));
        }
        Ok(output)
    }

    fn export_batch(
        &self,
        models: &[StoredModelRecord],
        _datasets: &[StoredDatasetRecord],
        deployments: &[StoredDeploymentRecord],
    ) -> Result<String, AiError> {
        let active = deployments.iter().filter(|d| matches!(d.status, crate::deployment::DeploymentStatus::Active)).count();
        let mut output = String::from("# Deployment Audit — Batch Summary\n\n");
        output.push_str(&format!("- Models: {}\n", models.len()));
        output.push_str(&format!("- Total Deployments: {}\n", deployments.len()));
        output.push_str(&format!("- Active Deployments: {active}\n"));
        Ok(output)
    }

    fn format_name(&self) -> &str {
        "deployment_audit"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{StoredDatasetRecord, StoredDeploymentRecord, StoredModelRecord};
    use crate::bias_fairness::FairnessStatus;
    use crate::deployment::DeploymentEnvironment;
    use crate::drift::DriftStatus;
    use crate::model_registry::{ModelArchitecture, ModelRecord, ModelTaskType};
    use crate::training_data::DatasetRecord;

    fn make_stored_model() -> StoredModelRecord {
        let record = ModelRecord::new(
            "m-1", "TestModel", "1.0.0",
            ModelArchitecture::Transformer, ModelTaskType::Classification,
            "pytorch", "alice", 1000,
        );
        StoredModelRecord::from_record(&record, 5000)
    }

    fn make_stored_dataset() -> StoredDatasetRecord {
        let record = DatasetRecord::new(
            "ds-1", "TestDataset", "1.0",
            crate::training_data::DatasetSource::Internal { team: "ml".into() },
            crate::training_data::DatasetFormat::Csv, 1000, "alice",
        );
        StoredDatasetRecord::from_record(&record, 5000)
    }

    fn make_stored_deployment() -> StoredDeploymentRecord {
        let record = crate::deployment::DeploymentRecord::new(
            "d-1", "req-1", "m-1", "1.0.0",
            DeploymentEnvironment::Production, 3000, "alice",
        );
        StoredDeploymentRecord::from_record(&record, 5000)
    }

    fn make_stored_assessment() -> StoredFairnessAssessment {
        StoredFairnessAssessment {
            assessment_id: "fa-1".into(),
            policy_id: "fp-1".into(),
            model_id: "m-1".into(),
            model_version: "1.0.0".into(),
            overall_status: FairnessStatus::Fair,
            assessed_at: 4000,
            assessed_by: "alice".into(),
            metadata: Default::default(),
            stored_at: 5000,
        }
    }

    fn make_stored_drift() -> StoredDriftResult {
        StoredDriftResult {
            result_id: "dr-1".into(),
            policy_id: "dp-1".into(),
            model_id: "m-1".into(),
            model_version: "1.0.0".into(),
            overall_status: DriftStatus::NoDrift,
            detected_at: 4000,
            detection_window_start: 3000,
            detection_window_end: 4000,
            metadata: Default::default(),
            stored_at: 5000,
            remediation_applied: None,
        }
    }

    #[test]
    fn test_json_model_inventory() {
        let exporter = JsonAiExporter;
        let result = exporter.export_model_inventory(&[make_stored_model()]).unwrap();
        assert!(result.contains("model_inventory"));
        assert!(result.contains("m-1"));
    }

    #[test]
    fn test_json_deployment_report() {
        let exporter = JsonAiExporter;
        let result = exporter.export_deployment_report(&[make_stored_deployment()]).unwrap();
        assert!(result.contains("deployment_report"));
        assert!(result.contains("d-1"));
    }

    #[test]
    fn test_json_fairness_report() {
        let exporter = JsonAiExporter;
        let result = exporter.export_fairness_report(&[make_stored_assessment()]).unwrap();
        assert!(result.contains("fairness_report"));
    }

    #[test]
    fn test_json_drift_report() {
        let exporter = JsonAiExporter;
        let result = exporter.export_drift_report(&[make_stored_drift()]).unwrap();
        assert!(result.contains("drift_report"));
    }

    #[test]
    fn test_json_batch() {
        let exporter = JsonAiExporter;
        let result = exporter.export_batch(
            &[make_stored_model()], &[make_stored_dataset()], &[make_stored_deployment()],
        ).unwrap();
        assert!(result.contains("batch_export"));
    }

    #[test]
    fn test_json_format_info() {
        let exporter = JsonAiExporter;
        assert_eq!(exporter.format_name(), "json");
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_model_card_inventory() {
        let exporter = ModelCardExporter;
        let result = exporter.export_model_inventory(&[make_stored_model()]).unwrap();
        assert!(result.contains("Model Cards"));
        assert!(result.contains("Integrity Hash"));
    }

    #[test]
    fn test_model_card_format_info() {
        let exporter = ModelCardExporter;
        assert_eq!(exporter.format_name(), "model_card");
        assert_eq!(exporter.content_type(), "text/markdown");
    }

    #[test]
    fn test_eu_ai_act_inventory() {
        let exporter = EuAiActComplianceExporter;
        let result = exporter.export_model_inventory(&[make_stored_model()]).unwrap();
        assert!(result.contains("EU AI Act"));
        assert!(result.contains("Article 6"));
        assert!(result.contains("Article 13"));
    }

    #[test]
    fn test_eu_ai_act_fairness() {
        let exporter = EuAiActComplianceExporter;
        let result = exporter.export_fairness_report(&[make_stored_assessment()]).unwrap();
        assert!(result.contains("Article 10"));
        assert!(result.contains("Protected attribute"));
    }

    #[test]
    fn test_nist_rmf_inventory() {
        let exporter = NistAiRmfExporter;
        let result = exporter.export_model_inventory(&[make_stored_model()]).unwrap();
        assert!(result.contains("GOVERN"));
    }

    #[test]
    fn test_nist_rmf_batch() {
        let exporter = NistAiRmfExporter;
        let result = exporter.export_batch(
            &[make_stored_model()], &[make_stored_dataset()], &[make_stored_deployment()],
        ).unwrap();
        assert!(result.contains("GOVERN"));
        assert!(result.contains("MAP"));
        assert!(result.contains("MANAGE"));
        assert!(result.contains("NIST AI RMF 1.0"));
    }

    #[test]
    fn test_deployment_audit_report() {
        let exporter = DeploymentAuditExporter;
        let result = exporter.export_deployment_report(&[make_stored_deployment()]).unwrap();
        assert!(result.contains("Deployment Audit Trail"));
        assert!(result.contains("Deployed By"));
        assert!(result.contains("Health Checks"));
    }

    #[test]
    fn test_deployment_audit_format_info() {
        let exporter = DeploymentAuditExporter;
        assert_eq!(exporter.format_name(), "deployment_audit");
        assert_eq!(exporter.content_type(), "text/markdown");
    }
}
