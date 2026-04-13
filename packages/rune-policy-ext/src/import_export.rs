// ═══════════════════════════════════════════════════════════════════════
// Import/Export — Policy import and export in standard formats.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::error::PolicyExtError;
use crate::policy::*;

// ── PolicyFormat ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyFormat {
    Json,
    Yaml,
    Rego,
    Summary,
}

impl fmt::Display for PolicyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Rego => "rego",
            Self::Summary => "summary",
        };
        f.write_str(s)
    }
}

// ── PolicyExporter ──────────────────────────────────────────────────

pub struct PolicyExporter;

impl PolicyExporter {
    pub fn new() -> Self {
        Self
    }

    pub fn export(&self, policy: &ManagedPolicy, format: PolicyFormat) -> String {
        match format {
            PolicyFormat::Json => self.export_json(policy),
            PolicyFormat::Yaml => self.export_yaml_like(policy),
            PolicyFormat::Rego => self.export_rego(policy),
            PolicyFormat::Summary => self.export_summary(policy),
        }
    }

    pub fn export_json(&self, policy: &ManagedPolicy) -> String {
        serde_json::to_string_pretty(policy).unwrap_or_default()
    }

    pub fn export_yaml_like(&self, policy: &ManagedPolicy) -> String {
        let mut lines = Vec::new();
        lines.push(format!("name: \"{}\"", policy.name));
        lines.push(format!("id: \"{}\"", policy.id));
        lines.push(format!("domain: {}", policy.category));
        lines.push(format!("version: {}", policy.version));
        lines.push(format!("status: {}", policy.status));
        lines.push(format!("owner: \"{}\"", policy.owner));
        if !policy.rules.is_empty() {
            lines.push("rules:".into());
            for rule in &policy.rules {
                lines.push(format!("  - id: \"{}\"", rule.id));
                lines.push(format!("    name: \"{}\"", rule.name));
                lines.push(format!("    action: {}", rule.action));
                lines.push(format!("    priority: {}", rule.priority));
                lines.push(format!("    enabled: {}", rule.enabled));
            }
        }
        lines.join("\n")
    }

    fn export_rego(&self, policy: &ManagedPolicy) -> String {
        let mut lines = Vec::new();
        lines.push(format!("# Policy: {}", policy.name));
        lines.push(format!("package rune.policy.{}", policy.id.0.replace('-', "_")));
        lines.push(String::new());
        for rule in &policy.rules {
            lines.push(format!("# Rule: {}", rule.name));
            lines.push(format!("# Action: {}", rule.action));
        }
        lines.join("\n")
    }

    pub fn export_summary(&self, policy: &ManagedPolicy) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Policy: {} ({})", policy.name, policy.id));
        lines.push(format!("Domain: {}", policy.category));
        lines.push(format!("Version: {} — Status: {}", policy.version, policy.status));
        lines.push(format!("Owner: {}", policy.owner));
        lines.push(format!("Rules: {} total", policy.rules.len()));
        let enabled = policy.rules.iter().filter(|r| r.enabled).count();
        lines.push(format!("  Enabled: {}, Disabled: {}", enabled, policy.rules.len() - enabled));
        if !policy.framework_bindings.is_empty() {
            lines.push(format!(
                "Framework bindings: {}",
                policy.framework_bindings.len()
            ));
        }
        lines.join("\n")
    }
}

impl Default for PolicyExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ── PolicyImporter ──────────────────────────────────────────────────

pub struct PolicyImporter;

impl PolicyImporter {
    pub fn new() -> Self {
        Self
    }

    pub fn import_json(&self, json: &str) -> Result<ManagedPolicy, PolicyExtError> {
        serde_json::from_str(json).map_err(|e| PolicyExtError::ImportFailed {
            format: "json".into(),
            reason: e.to_string(),
        })
    }

    pub fn import_batch_json(&self, json: &str) -> Result<Vec<ManagedPolicy>, PolicyExtError> {
        serde_json::from_str(json).map_err(|e| PolicyExtError::ImportFailed {
            format: "json".into(),
            reason: e.to_string(),
        })
    }
}

impl Default for PolicyImporter {
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

    fn sample_policy() -> ManagedPolicy {
        ManagedPolicy::new("p1", "Access Control", PolicyDomain::AccessControl, "security-team", 1000)
            .with_description("Main access control policy")
            .with_rule(PolicyRule::new("r1", "Deny untrusted", RuleExpression::Always, PolicyAction::Deny).with_priority(10))
            .with_rule(PolicyRule::new("r2", "Audit admin", RuleExpression::Equals { field: "role".into(), value: "admin".into() }, PolicyAction::Audit))
    }

    #[test]
    fn test_export_json_valid() {
        let exporter = PolicyExporter::new();
        let json = exporter.export_json(&sample_policy());
        assert!(json.contains("Access Control"));
        assert!(json.contains("r1"));
    }

    #[test]
    fn test_json_roundtrip() {
        let exporter = PolicyExporter::new();
        let importer = PolicyImporter::new();
        let json = exporter.export_json(&sample_policy());
        let imported = importer.import_json(&json).unwrap();
        assert_eq!(imported.name, "Access Control");
        assert_eq!(imported.rules.len(), 2);
    }

    #[test]
    fn test_export_yaml_like() {
        let exporter = PolicyExporter::new();
        let yaml = exporter.export_yaml_like(&sample_policy());
        assert!(yaml.contains("name: \"Access Control\""));
        assert!(yaml.contains("domain: access-control"));
        assert!(yaml.contains("rules:"));
    }

    #[test]
    fn test_export_summary() {
        let exporter = PolicyExporter::new();
        let summary = exporter.export_summary(&sample_policy());
        assert!(summary.contains("2 total"));
        assert!(summary.contains("access-control"));
    }

    #[test]
    fn test_import_json_valid() {
        let exporter = PolicyExporter::new();
        let importer = PolicyImporter::new();
        let json = exporter.export_json(&sample_policy());
        let result = importer.import_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_json_invalid() {
        let importer = PolicyImporter::new();
        let result = importer.import_json("not valid json");
        assert!(matches!(result, Err(PolicyExtError::ImportFailed { .. })));
    }

    #[test]
    fn test_import_batch_json() {
        let exporter = PolicyExporter::new();
        let importer = PolicyImporter::new();
        let p1 = sample_policy();
        let mut p2 = ManagedPolicy::new("p2", "Network", PolicyDomain::NetworkSecurity, "team", 2000);
        p2.rules = Vec::new();
        let json = format!(
            "[{},{}]",
            exporter.export_json(&p1),
            exporter.export_json(&p2)
        );
        let imported = importer.import_batch_json(&json).unwrap();
        assert_eq!(imported.len(), 2);
    }

    #[test]
    fn test_policy_format_display() {
        assert_eq!(PolicyFormat::Json.to_string(), "json");
        assert_eq!(PolicyFormat::Yaml.to_string(), "yaml");
        assert_eq!(PolicyFormat::Rego.to_string(), "rego");
        assert_eq!(PolicyFormat::Summary.to_string(), "summary");
    }
}
