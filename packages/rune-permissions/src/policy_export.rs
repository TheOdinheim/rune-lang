// ═══════════════════════════════════════════════════════════════════════
// Policy Export — Pluggable policy serialization trait.
//
// Layer 3 defines one-way policy export into standard formats.
// Round-trip parsing requires dedicated parser crates and is out of
// scope for trait boundary definition.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::StoredPolicyDefinition;
use crate::error::PermissionError;

// ── PolicyExporter trait ─────────────────────────────────────

pub trait PolicyExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError>;
    fn export_batch(&self, policies: &[StoredPolicyDefinition]) -> Result<Vec<Vec<u8>>, PermissionError> {
        policies.iter().map(|p| self.export_policy(p)).collect()
    }
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── RegoExporter ─────────────────────────────────────────────

pub struct RegoExporter {
    package_prefix: String,
}

impl RegoExporter {
    pub fn new(package_prefix: &str) -> Self {
        Self {
            package_prefix: package_prefix.to_string(),
        }
    }
}

impl PolicyExporter for RegoExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError> {
        let safe_id = policy.policy_id.replace('-', "_");
        let mut rego = String::new();
        rego.push_str(&format!("package {}.{}\n\n", self.package_prefix, safe_id));
        rego.push_str(&format!("# Policy: {}\n", policy.name));
        rego.push_str(&format!("# Type: {}\n", policy.policy_type));
        if !policy.description.is_empty() {
            rego.push_str(&format!("# Description: {}\n", policy.description));
        }
        rego.push('\n');
        rego.push_str("default allow := false\n\n");
        rego.push_str("allow if {\n");
        rego.push_str("    # Policy rules evaluated here\n");
        rego.push_str(&format!("    input.policy_type == \"{}\"\n", policy.policy_type));
        rego.push_str("}\n");
        Ok(rego.into_bytes())
    }

    fn format_name(&self) -> &str {
        "rego"
    }

    fn content_type(&self) -> &str {
        "text/plain"
    }
}

// ── CedarExporter ────────────────────────────────────────────

pub struct CedarExporter;

impl CedarExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CedarExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyExporter for CedarExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError> {
        let mut cedar = String::new();
        cedar.push_str(&format!("// Policy: {} ({})\n", policy.name, policy.policy_id));
        if !policy.description.is_empty() {
            cedar.push_str(&format!("// {}\n", policy.description));
        }
        cedar.push_str("permit (\n");
        cedar.push_str("    principal,\n");
        cedar.push_str("    action,\n");
        cedar.push_str("    resource\n");
        cedar.push_str(") when {\n");
        cedar.push_str(&format!("    // policy_type: {}\n", policy.policy_type));
        cedar.push_str("    true\n");
        cedar.push_str("};\n");
        Ok(cedar.into_bytes())
    }

    fn format_name(&self) -> &str {
        "cedar"
    }

    fn content_type(&self) -> &str {
        "text/plain"
    }
}

// ── XacmlExporter ────────────────────────────────────────────

pub struct XacmlExporter;

impl XacmlExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for XacmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyExporter for XacmlExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<PolicySet xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"\n");
        xml.push_str(&format!("  PolicySetId=\"{}\"\n", policy.policy_id));
        xml.push_str("  PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides\">\n");
        xml.push_str(&format!("  <Description>{}</Description>\n",
            if policy.description.is_empty() { &policy.name } else { &policy.description }));
        xml.push_str("  <Policy\n");
        xml.push_str(&format!("    PolicyId=\"{}-rule\"\n", policy.policy_id));
        xml.push_str("    RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">\n");
        xml.push_str("    <Target/>\n");
        xml.push_str("    <Rule RuleId=\"rule-1\" Effect=\"Permit\">\n");
        xml.push_str("      <Condition>\n");
        xml.push_str(&format!("        <!-- policy_type: {} -->\n", policy.policy_type));
        xml.push_str("      </Condition>\n");
        xml.push_str("    </Rule>\n");
        xml.push_str("  </Policy>\n");
        xml.push_str("</PolicySet>\n");
        Ok(xml.into_bytes())
    }

    fn format_name(&self) -> &str {
        "xacml"
    }

    fn content_type(&self) -> &str {
        "application/xml"
    }
}

// ── OpaBundleExporter ────────────────────────────────────────

pub struct OpaBundleExporter {
    package_prefix: String,
}

impl OpaBundleExporter {
    pub fn new(package_prefix: &str) -> Self {
        Self {
            package_prefix: package_prefix.to_string(),
        }
    }
}

impl PolicyExporter for OpaBundleExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError> {
        let safe_id = policy.policy_id.replace('-', "_");
        let rego_path = format!("{}/{}.rego", self.package_prefix.replace('.', "/"), safe_id);
        let bundle = serde_json::json!({
            "manifest": {
                "revision": "",
                "roots": [&self.package_prefix]
            },
            "files": [{
                "path": rego_path,
                "package": format!("{}.{}", self.package_prefix, safe_id),
                "policy_id": &policy.policy_id,
                "policy_type": &policy.policy_type,
            }]
        });
        let bytes = serde_json::to_vec_pretty(&bundle)
            .map_err(|e| PermissionError::InvalidOperation(format!("OPA bundle serialization failed: {e}")))?;
        Ok(bytes)
    }

    fn format_name(&self) -> &str {
        "opa-bundle"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ── JsonPolicyExporter ───────────────────────────────────────

pub struct JsonPolicyExporter;

impl JsonPolicyExporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonPolicyExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyExporter for JsonPolicyExporter {
    fn export_policy(&self, policy: &StoredPolicyDefinition) -> Result<Vec<u8>, PermissionError> {
        let obj = serde_json::json!({
            "policy_id": &policy.policy_id,
            "name": &policy.name,
            "description": &policy.description,
            "policy_type": &policy.policy_type,
            "active": policy.active,
            "created_at": policy.created_at,
            "updated_at": policy.updated_at,
            "rules": &policy.rules_json,
            "metadata": &policy.metadata,
        });
        let bytes = serde_json::to_vec_pretty(&obj)
            .map_err(|e| PermissionError::InvalidOperation(format!("JSON serialization failed: {e}")))?;
        Ok(bytes)
    }

    fn format_name(&self) -> &str {
        "json"
    }

    fn content_type(&self) -> &str {
        "application/json"
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> StoredPolicyDefinition {
        let mut p = StoredPolicyDefinition::new("pol-1", "Read Access Policy", "rbac");
        p.description = "Allow read access to documents".to_string();
        p
    }

    #[test]
    fn test_rego_export() {
        let exporter = RegoExporter::new("rune.policies");
        let result = exporter.export_policy(&test_policy()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("package rune.policies.pol_1"));
        assert!(text.contains("default allow := false"));
        assert!(text.contains("rbac"));
        assert_eq!(exporter.format_name(), "rego");
    }

    #[test]
    fn test_cedar_export() {
        let exporter = CedarExporter::new();
        let result = exporter.export_policy(&test_policy()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("permit"));
        assert!(text.contains("principal"));
        assert!(text.contains("pol-1"));
        assert_eq!(exporter.content_type(), "text/plain");
    }

    #[test]
    fn test_xacml_export() {
        let exporter = XacmlExporter::new();
        let result = exporter.export_policy(&test_policy()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("PolicySet"));
        assert!(text.contains("xacml:3.0"));
        assert!(text.contains("pol-1"));
        assert!(text.contains("Permit"));
        assert_eq!(exporter.content_type(), "application/xml");
    }

    #[test]
    fn test_opa_bundle_export() {
        let exporter = OpaBundleExporter::new("rune.policies");
        let result = exporter.export_policy(&test_policy()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("manifest"));
        assert!(text.contains("rune.policies"));
        assert!(text.contains("pol_1.rego"));
        assert_eq!(exporter.format_name(), "opa-bundle");
    }

    #[test]
    fn test_json_export() {
        let exporter = JsonPolicyExporter::new();
        let result = exporter.export_policy(&test_policy()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("pol-1"));
        assert!(text.contains("Read Access Policy"));
        assert!(text.contains("rbac"));
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_export_batch() {
        let exporter = JsonPolicyExporter::new();
        let policies = vec![
            StoredPolicyDefinition::new("p1", "A", "rbac"),
            StoredPolicyDefinition::new("p2", "B", "abac"),
        ];
        let results = exporter.export_batch(&policies).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_all_five_format_names() {
        let formats: Vec<Box<dyn PolicyExporter>> = vec![
            Box::new(RegoExporter::new("x")),
            Box::new(CedarExporter::new()),
            Box::new(XacmlExporter::new()),
            Box::new(OpaBundleExporter::new("x")),
            Box::new(JsonPolicyExporter::new()),
        ];
        let names: Vec<&str> = formats.iter().map(|f| f.format_name()).collect();
        assert_eq!(names, vec!["rego", "cedar", "xacml", "opa-bundle", "json"]);
    }
}
