// ═══════════════════════════════════════════════════════════════════════
// Layer 3 — AgentGovernanceExporter trait for exporting agent governance
// data: JSON, agent card (directory format), human oversight report
// (EU AI Act), autonomy assessment (NIST AI RMF), delegation chain
// report.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{
    StoredAgentGovernanceProfile, StoredAutonomyConfiguration,
    StoredDelegationChainRecord, StoredToolPolicy,
};
use crate::error::AgentError;

// ── AgentGovernanceExporter trait ────────────────────────────────────

pub trait AgentGovernanceExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError>;

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError>;

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError>;

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError>;

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError>;

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonAgentGovernanceExporter ─────────────────────────────────────

pub struct JsonAgentGovernanceExporter;

impl AgentGovernanceExporter for JsonAgentGovernanceExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError> {
        serde_json::to_string_pretty(profile)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError> {
        serde_json::to_string_pretty(config)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "tool_policies": policies,
            "policy_count": policies.len(),
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "delegation_chains": chains,
            "chain_count": chains.len(),
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "agent_governance_profiles": profiles,
            "autonomy_configurations": configs,
            "profile_count": profiles.len(),
            "config_count": configs.len(),
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "JSON"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── AgentCardExporter ───────────────────────────────────────────────
// Exports agent profiles as agent card documents for agent directories.

pub struct AgentCardExporter;

impl AgentGovernanceExporter for AgentCardExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "agent_card": {
                "id": profile.agent_id,
                "name": profile.agent_name,
                "type": profile.agent_type,
                "owner": profile.owner,
                "autonomy_level": profile.autonomy_level,
                "capabilities": profile.capabilities,
                "domains": profile.allowed_domains,
                "governance_status": profile.governance_status.to_string(),
                "metadata": profile.metadata,
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "agent_card_autonomy": {
                "agent_id": config.agent_id,
                "level": config.autonomy_level,
                "escalation_target": config.escalation_target,
                "human_oversight": config.requires_human_oversight,
                "oversight_frequency": config.oversight_frequency,
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError> {
        let tools: Vec<serde_json::Value> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "tool": p.tool_ref,
                    "decision": p.decision.to_string(),
                    "requires_approval": p.requires_approval,
                })
            })
            .collect();
        let doc = serde_json::json!({ "agent_card_tools": tools });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError> {
        let entries: Vec<serde_json::Value> = chains
            .iter()
            .map(|c| {
                serde_json::json!({
                    "delegator": c.delegator_id,
                    "delegatee": c.delegatee_id,
                    "task": c.task_description,
                    "depth": c.depth,
                    "status": c.chain_status.to_string(),
                })
            })
            .collect();
        let doc = serde_json::json!({ "agent_card_delegations": entries });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        _configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError> {
        let cards: Vec<serde_json::Value> = profiles
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.agent_id,
                    "name": p.agent_name,
                    "type": p.agent_type,
                    "autonomy_level": p.autonomy_level,
                    "status": p.governance_status.to_string(),
                })
            })
            .collect();
        let doc = serde_json::json!({ "agent_directory": cards });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "AgentCard"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── HumanOversightReportExporter ────────────────────────────────────
// EU AI Act Article 14 compliance: human oversight capability report.

pub struct HumanOversightReportExporter;

impl AgentGovernanceExporter for HumanOversightReportExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Human Oversight Report\n\n");
        report.push_str(&format!("## Agent: {} ({})\n\n", profile.agent_name, profile.agent_id));
        report.push_str(&format!("- **Type**: {}\n", profile.agent_type));
        report.push_str(&format!("- **Owner**: {}\n", profile.owner));
        report.push_str(&format!("- **Autonomy Level**: {}\n", profile.autonomy_level));
        report.push_str(&format!("- **Governance Status**: {}\n", profile.governance_status));
        report.push_str(&format!("- **Capabilities**: {}\n", profile.capabilities.join(", ")));
        report.push_str(&format!("- **Domains**: {}\n\n", profile.allowed_domains.join(", ")));
        report.push_str("### EU AI Act Article 14 Compliance\n\n");
        report.push_str("- Human oversight mechanisms: documented\n");
        report.push_str("- Override capability: available via governance controls\n");
        report.push_str("- Monitoring: continuous via agent governance backend\n");
        Ok(report)
    }

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Autonomy Configuration — Human Oversight\n\n");
        report.push_str(&format!("- **Agent**: {}\n", config.agent_id));
        report.push_str(&format!("- **Autonomy Level**: {}\n", config.autonomy_level));
        report.push_str(&format!("- **Escalation Target**: {}\n", config.escalation_target));
        report.push_str(&format!(
            "- **Requires Human Oversight**: {}\n",
            if config.requires_human_oversight { "Yes" } else { "No" }
        ));
        report.push_str(&format!("- **Oversight Frequency**: {}\n", config.oversight_frequency));
        Ok(report)
    }

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Tool Policy — Human Oversight Report\n\n");
        report.push_str(&format!("Total policies: {}\n\n", policies.len()));
        for p in policies {
            report.push_str(&format!(
                "- Tool `{}` → {} (approval: {})\n",
                p.tool_ref,
                p.decision,
                if p.requires_approval { "required" } else { "not required" }
            ));
        }
        Ok(report)
    }

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegation Chain — Human Oversight Report\n\n");
        for c in chains {
            report.push_str(&format!(
                "- {} → {} (depth {}/{}, status: {})\n",
                c.delegator_id, c.delegatee_id, c.depth, c.max_depth_allowed,
                c.chain_status
            ));
        }
        Ok(report)
    }

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Agent Governance — Human Oversight Summary\n\n");
        report.push_str(&format!("- Governed agents: {}\n", profiles.len()));
        report.push_str(&format!("- Autonomy configurations: {}\n\n", configs.len()));
        let oversight_count = configs.iter().filter(|c| c.requires_human_oversight).count();
        report.push_str(&format!(
            "- Agents requiring human oversight: {}/{}\n",
            oversight_count,
            configs.len()
        ));
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "HumanOversightReport"
    }

    fn content_type(&self) -> &str {
        "text/markdown"
    }
}

// ── AutonomyAssessmentExporter ──────────────────────────────────────
// NIST AI RMF aligned autonomy assessment export.

pub struct AutonomyAssessmentExporter;

impl AgentGovernanceExporter for AutonomyAssessmentExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "nist_ai_rmf_assessment": {
                "agent_id": profile.agent_id,
                "agent_type": profile.agent_type,
                "autonomy_level": profile.autonomy_level,
                "governance_status": profile.governance_status.to_string(),
                "govern": {
                    "accountability": profile.owner,
                    "capabilities_declared": profile.capabilities,
                    "domain_restrictions": profile.allowed_domains,
                },
                "map": {
                    "intended_use": profile.allowed_domains.join(", "),
                },
                "manage": {
                    "governance_status": profile.governance_status.to_string(),
                },
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "nist_ai_rmf_autonomy": {
                "agent_id": config.agent_id,
                "autonomy_level": config.autonomy_level,
                "manage": {
                    "escalation_policy": config.escalation_target,
                    "human_oversight": config.requires_human_oversight,
                    "oversight_frequency": config.oversight_frequency,
                    "max_actions": config.max_actions_per_session,
                    "risk_levels_permitted": config.allowed_risk_levels,
                },
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError> {
        let entries: Vec<serde_json::Value> = policies
            .iter()
            .map(|p| {
                serde_json::json!({
                    "tool_ref": p.tool_ref,
                    "decision": p.decision.to_string(),
                    "justification": p.justification,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "nist_ai_rmf_tool_governance": entries,
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError> {
        let entries: Vec<serde_json::Value> = chains
            .iter()
            .map(|c| {
                serde_json::json!({
                    "delegator": c.delegator_id,
                    "delegatee": c.delegatee_id,
                    "depth": c.depth,
                    "max_depth": c.max_depth_allowed,
                    "status": c.chain_status.to_string(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "nist_ai_rmf_delegation_chains": entries,
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError> {
        let doc = serde_json::json!({
            "nist_ai_rmf_batch_assessment": {
                "governed_agents": profiles.len(),
                "autonomy_configs": configs.len(),
            }
        });
        serde_json::to_string_pretty(&doc)
            .map_err(|e| AgentError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str {
        "AutonomyAssessment"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── DelegationChainExporter ─────────────────────────────────────────

pub struct DelegationChainExporter;

impl AgentGovernanceExporter for DelegationChainExporter {
    fn export_agent_profile(
        &self,
        profile: &StoredAgentGovernanceProfile,
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegation Chain Profile\n\n");
        report.push_str(&format!("Agent: {} ({})\n", profile.agent_name, profile.agent_id));
        report.push_str(&format!("Autonomy: {}\n", profile.autonomy_level));
        Ok(report)
    }

    fn export_autonomy_config(
        &self,
        config: &StoredAutonomyConfiguration,
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegation Autonomy Constraints\n\n");
        report.push_str(&format!("Agent: {}\n", config.agent_id));
        report.push_str(&format!("Level: {}\n", config.autonomy_level));
        report.push_str(&format!("Escalation: {}\n", config.escalation_target));
        Ok(report)
    }

    fn export_tool_policy_report(
        &self,
        policies: &[StoredToolPolicy],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegated Tool Policies\n\n");
        for p in policies {
            report.push_str(&format!("- {} → {}\n", p.tool_ref, p.decision));
        }
        Ok(report)
    }

    fn export_delegation_chain_report(
        &self,
        chains: &[StoredDelegationChainRecord],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegation Chain Report\n\n");
        report.push_str(&format!("Total chains: {}\n\n", chains.len()));
        for c in chains {
            report.push_str(&format!(
                "## Chain: {}\n\n- Delegator: {}\n- Delegatee: {}\n- Task: {}\n- Depth: {}/{}\n- Status: {}\n\n",
                c.chain_id, c.delegator_id, c.delegatee_id, c.task_description,
                c.depth, c.max_depth_allowed, c.chain_status
            ));
        }
        Ok(report)
    }

    fn export_batch(
        &self,
        profiles: &[StoredAgentGovernanceProfile],
        _configs: &[StoredAutonomyConfiguration],
    ) -> Result<String, AgentError> {
        let mut report = String::new();
        report.push_str("# Delegation Chain Summary\n\n");
        for p in profiles {
            report.push_str(&format!("- {} ({})\n", p.agent_name, p.autonomy_level));
        }
        Ok(report)
    }

    fn format_name(&self) -> &str {
        "DelegationChainReport"
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
    use crate::backend::{
        StoredAgentGovernanceStatus, StoredDelegationChainStatus,
        StoredToolPolicyDecision,
    };
    use std::collections::HashMap;

    fn sample_profile() -> StoredAgentGovernanceProfile {
        StoredAgentGovernanceProfile {
            profile_id: "p1".into(),
            agent_id: "agent-1".into(),
            agent_name: "SearchBot".into(),
            agent_type: "Autonomous".into(),
            owner: "ops-team".into(),
            autonomy_level: "ActMediumRisk".into(),
            capabilities: vec!["search".into()],
            allowed_domains: vec!["data".into()],
            governance_status: StoredAgentGovernanceStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_config() -> StoredAutonomyConfiguration {
        StoredAutonomyConfiguration {
            config_id: "c1".into(),
            agent_id: "agent-1".into(),
            autonomy_level: "ActLowRisk".into(),
            escalation_target: "human-operator".into(),
            max_actions_per_session: "100".into(),
            allowed_risk_levels: vec!["low".into()],
            requires_human_oversight: true,
            oversight_frequency: "every_action".into(),
            created_at: 1000,
            metadata: HashMap::new(),
        }
    }

    fn sample_policies() -> Vec<StoredToolPolicy> {
        vec![StoredToolPolicy {
            policy_id: "tp1".into(),
            agent_id: "agent-1".into(),
            tool_ref: "web-search".into(),
            decision: StoredToolPolicyDecision::Allow,
            justification: "approved".into(),
            max_invocations: "50".into(),
            cooldown_ms: "1000".into(),
            requires_approval: false,
            created_at: 1000,
            metadata: HashMap::new(),
        }]
    }

    fn sample_chains() -> Vec<StoredDelegationChainRecord> {
        vec![StoredDelegationChainRecord {
            chain_id: "ch1".into(),
            delegator_id: "agent-1".into(),
            delegatee_id: "agent-2".into(),
            task_description: "analyze data".into(),
            depth: 1,
            max_depth_allowed: 3,
            autonomy_constraint: "ActLowRisk".into(),
            chain_status: StoredDelegationChainStatus::Active,
            created_at: 1000,
            completed_at: None,
            metadata: HashMap::new(),
        }]
    }

    #[test]
    fn test_json_exporter_profile() {
        let exp = JsonAgentGovernanceExporter;
        let out = exp.export_agent_profile(&sample_profile()).unwrap();
        assert!(out.contains("agent-1"));
        assert!(out.contains("SearchBot"));
    }

    #[test]
    fn test_json_exporter_config() {
        let exp = JsonAgentGovernanceExporter;
        let out = exp.export_autonomy_config(&sample_config()).unwrap();
        assert!(out.contains("human-operator"));
    }

    #[test]
    fn test_json_exporter_tool_policies() {
        let exp = JsonAgentGovernanceExporter;
        let out = exp.export_tool_policy_report(&sample_policies()).unwrap();
        assert!(out.contains("web-search"));
    }

    #[test]
    fn test_json_exporter_delegation_chains() {
        let exp = JsonAgentGovernanceExporter;
        let out = exp
            .export_delegation_chain_report(&sample_chains())
            .unwrap();
        assert!(out.contains("agent-2"));
    }

    #[test]
    fn test_json_exporter_batch() {
        let exp = JsonAgentGovernanceExporter;
        let out = exp
            .export_batch(&[sample_profile()], &[sample_config()])
            .unwrap();
        assert!(out.contains("agent_governance_profiles"));
    }

    #[test]
    fn test_agent_card_exporter() {
        let exp = AgentCardExporter;
        let out = exp.export_agent_profile(&sample_profile()).unwrap();
        assert!(out.contains("agent_card"));
        assert_eq!(exp.format_name(), "AgentCard");
    }

    #[test]
    fn test_human_oversight_report() {
        let exp = HumanOversightReportExporter;
        let out = exp.export_agent_profile(&sample_profile()).unwrap();
        assert!(out.contains("Human Oversight Report"));
        assert!(out.contains("EU AI Act Article 14"));
        assert_eq!(exp.content_type(), "text/markdown");
    }

    #[test]
    fn test_autonomy_assessment_exporter() {
        let exp = AutonomyAssessmentExporter;
        let out = exp.export_agent_profile(&sample_profile()).unwrap();
        assert!(out.contains("nist_ai_rmf_assessment"));
        assert_eq!(exp.format_name(), "AutonomyAssessment");
    }

    #[test]
    fn test_delegation_chain_exporter() {
        let exp = DelegationChainExporter;
        let out = exp
            .export_delegation_chain_report(&sample_chains())
            .unwrap();
        assert!(out.contains("Delegation Chain Report"));
        assert!(out.contains("agent-2"));
        assert_eq!(exp.format_name(), "DelegationChainReport");
    }

    #[test]
    fn test_all_exporters_format_and_content_type() {
        let exporters: Vec<Box<dyn AgentGovernanceExporter>> = vec![
            Box::new(JsonAgentGovernanceExporter),
            Box::new(AgentCardExporter),
            Box::new(HumanOversightReportExporter),
            Box::new(AutonomyAssessmentExporter),
            Box::new(DelegationChainExporter),
        ];
        for e in &exporters {
            assert!(!e.format_name().is_empty());
            assert!(!e.content_type().is_empty());
        }
        assert_eq!(exporters.len(), 5);
    }
}
