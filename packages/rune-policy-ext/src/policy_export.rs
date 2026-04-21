// ═══════════════════════════════════════════════════════════════════════
// Policy Package Exporter — Layer 3 trait boundary for serializing
// policy packages to standard interchange formats.
//
// Five implementations: JSON (native), OPA bundle (Rego), Cedar
// (AWS Cedar), signed bundle manifest (OPA signed bundles), and
// XACML PolicySet (OASIS 3.0). Actual tarball packaging and signing
// belong in adapter crates.
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::StoredPolicyPackage;
use crate::error::PolicyExtError;

// ── PolicyPackageExporter trait ───────────────────────────────────

pub trait PolicyPackageExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError>;

    fn export_package_with_dependencies(
        &self,
        package: &StoredPolicyPackage,
        dependencies: &[StoredPolicyPackage],
    ) -> Result<Vec<u8>, PolicyExtError> {
        // Default: export only the primary package
        let _ = dependencies;
        self.export_package(package)
    }

    fn export_batch(&self, packages: &[StoredPolicyPackage]) -> Result<Vec<u8>, PolicyExtError> {
        let mut combined = Vec::new();
        for pkg in packages {
            let exported = self.export_package(pkg)?;
            combined.extend(exported);
        }
        Ok(combined)
    }

    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonPolicyPackageExporter ─────────────────────────────────────

#[derive(Default)]
pub struct JsonPolicyPackageExporter;

impl JsonPolicyPackageExporter {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyPackageExporter for JsonPolicyPackageExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError> {
        let mut json = String::from("{\n");
        json.push_str(&format!("  \"package_id\": \"{}\",\n", package.package_id));
        json.push_str(&format!("  \"name\": \"{}\",\n", package.name));
        json.push_str(&format!("  \"namespace\": \"{}\",\n", package.namespace));
        json.push_str(&format!("  \"version\": \"{}\",\n", package.version));
        json.push_str(&format!(
            "  \"description\": \"{}\",\n",
            package.description
        ));

        let tags_json: Vec<String> = package.tags.iter().map(|t| format!("\"{t}\"")).collect();
        json.push_str(&format!("  \"tags\": [{}],\n", tags_json.join(", ")));

        let refs_json: Vec<String> = package
            .rule_set_refs
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect();
        json.push_str(&format!(
            "  \"rule_set_refs\": [{}],\n",
            refs_json.join(", ")
        ));

        if let Some(ref sig) = package.signature_ref {
            json.push_str(&format!("  \"signature_ref\": \"{sig}\",\n"));
        }

        json.push_str(&format!("  \"created_at\": \"{}\"\n", package.created_at));
        json.push('}');
        Ok(json.into_bytes())
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── OpaBundleExporter ─────────────────────────────────────────────

#[derive(Default)]
pub struct OpaBundleExporter;

impl OpaBundleExporter {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyPackageExporter for OpaBundleExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError> {
        // Emit OPA bundle structure as bytes (manifest + rego file paths)
        // Actual tarball packaging belongs in adapter crates
        let mut bundle = String::new();

        // .manifest
        bundle.push_str("# OPA Bundle Manifest\n");
        bundle.push_str(&format!("# Package: {}\n", package.name));
        bundle.push_str(&format!("# Namespace: {}\n", package.namespace));
        bundle.push_str("{\n");
        bundle.push_str(&format!(
            "  \"roots\": [\"{}\"],\n",
            package.namespace.replace('.', "/")
        ));
        bundle.push_str(&format!("  \"revision\": \"{}\",\n", package.version));

        if let Some(ref sig) = package.signature_ref {
            bundle.push_str(&format!("  \"signature_ref\": \"{sig}\",\n"));
        }

        bundle.push_str("  \"metadata\": {\n");
        bundle.push_str(&format!("    \"package_id\": \"{}\"\n", package.package_id));
        bundle.push_str("  }\n");
        bundle.push_str("}\n\n");

        // Rego file path stubs
        for rule_ref in &package.rule_set_refs {
            let rego_path = format!(
                "{}/{}.rego",
                package.namespace.replace('.', "/"),
                rule_ref
            );
            bundle.push_str(&format!("# File: {rego_path}\n"));
            bundle.push_str(&format!("package {}\n\n", package.namespace));
        }

        // data.json stub
        bundle.push_str("# data.json\n");
        bundle.push_str("{\n");
        bundle.push_str(&format!(
            "  \"{}\": {{}}\n",
            package.namespace.replace('.', "/")
        ));
        bundle.push_str("}\n");

        Ok(bundle.into_bytes())
    }

    fn format_name(&self) -> &str { "opa-bundle" }
    fn content_type(&self) -> &str { "application/vnd.openpolicyagent.bundle" }
}

// ── CedarPolicyExporter ──────────────────────────────────────────

#[derive(Default)]
pub struct CedarPolicyExporter;

impl CedarPolicyExporter {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyPackageExporter for CedarPolicyExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError> {
        let mut cedar = String::new();

        // Namespace declaration
        cedar.push_str(&format!(
            "// Cedar Policy Set: {} v{}\n",
            package.name, package.version
        ));
        cedar.push_str(&format!("// Namespace: {}\n", package.namespace));
        cedar.push_str(&format!("// Package ID: {}\n\n", package.package_id));

        if let Some(ref sig) = package.signature_ref {
            cedar.push_str(&format!("// Signature ref: {sig}\n\n"));
        }

        // Policy stubs per rule set ref
        for (i, rule_ref) in package.rule_set_refs.iter().enumerate() {
            cedar.push_str(&format!(
                "@id(\"{}::{}\")\n",
                package.namespace, rule_ref
            ));
            cedar.push_str(&format!(
                "// Rule set: {} (precedence: {})\n",
                rule_ref, i
            ));
            cedar.push_str("permit (\n");
            cedar.push_str("  principal,\n");
            cedar.push_str("  action,\n");
            cedar.push_str("  resource\n");
            cedar.push_str(");\n\n");
        }

        Ok(cedar.into_bytes())
    }

    fn format_name(&self) -> &str { "cedar" }
    fn content_type(&self) -> &str { "text/x-cedar" }
}

// ── SignedBundleManifestExporter ──────────────────────────────────

#[derive(Default)]
pub struct SignedBundleManifestExporter;

impl SignedBundleManifestExporter {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyPackageExporter for SignedBundleManifestExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError> {
        // OPA signed bundle manifest with SHA256 file hashes
        let mut manifest = String::new();

        manifest.push_str("{\n");
        manifest.push_str(&format!("  \"revision\": \"{}\",\n", package.version));
        manifest.push_str(&format!(
            "  \"roots\": [\"{}\"],\n",
            package.namespace.replace('.', "/")
        ));

        // File hashes
        manifest.push_str("  \"files\": [\n");
        let mut files = Vec::new();
        for rule_ref in &package.rule_set_refs {
            let path = format!(
                "{}/{}.rego",
                package.namespace.replace('.', "/"),
                rule_ref
            );
            files.push(format!(
                "    {{\"name\": \"{path}\", \"hash\": \"sha256:<placeholder>\", \"algorithm\": \"SHA-256\"}}"
            ));
        }
        files.push(
            "    {\"name\": \"data.json\", \"hash\": \"sha256:<placeholder>\", \"algorithm\": \"SHA-256\"}"
                .to_string(),
        );
        manifest.push_str(&files.join(",\n"));
        manifest.push_str("\n  ],\n");

        // Signing metadata
        manifest.push_str("  \"signing\": {\n");
        manifest.push_str("    \"key_id\": \"<signing-key-id>\",\n");
        manifest.push_str("    \"algorithm\": \"RS256\",\n");

        if let Some(ref sig) = package.signature_ref {
            manifest.push_str(&format!("    \"signature_ref\": \"{sig}\",\n"));
        }

        manifest.push_str("    \"signatures\": []\n");
        manifest.push_str("  }\n");
        manifest.push_str("}\n");

        Ok(manifest.into_bytes())
    }

    fn format_name(&self) -> &str { "signed-bundle-manifest" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── XacmlPolicySetExporter ───────────────────────────────────────

#[derive(Default)]
pub struct XacmlPolicySetExporter;

impl XacmlPolicySetExporter {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyPackageExporter for XacmlPolicySetExporter {
    fn export_package(&self, package: &StoredPolicyPackage) -> Result<Vec<u8>, PolicyExtError> {
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<PolicySet\n");
        xml.push_str("  xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"\n");
        xml.push_str(&format!(
            "  PolicySetId=\"{}\"\n",
            package.package_id
        ));
        xml.push_str("  Version=\"1.0\"\n");
        xml.push_str("  PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides\">\n");

        // Description
        xml.push_str(&format!(
            "  <Description>{} v{}</Description>\n",
            package.name, package.version
        ));

        // Target (namespace-scoped)
        xml.push_str("  <Target>\n");
        xml.push_str("    <AnyOf>\n");
        xml.push_str("      <AllOf>\n");
        xml.push_str("        <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">\n");
        xml.push_str(&format!(
            "          <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">{}</AttributeValue>\n",
            package.namespace
        ));
        xml.push_str("          <AttributeDesignator Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\" AttributeId=\"namespace\" DataType=\"http://www.w3.org/2001/XMLSchema#string\"/>\n");
        xml.push_str("        </Match>\n");
        xml.push_str("      </AllOf>\n");
        xml.push_str("    </AnyOf>\n");
        xml.push_str("  </Target>\n");

        // Policy stubs per rule set ref
        for rule_ref in &package.rule_set_refs {
            xml.push_str(&format!(
                "  <Policy PolicyId=\"{}::{}\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">\n",
                package.namespace, rule_ref
            ));
            xml.push_str("    <Target/>\n");
            xml.push_str(&format!(
                "    <Rule RuleId=\"{rule_ref}-default\" Effect=\"Permit\">\n"
            ));
            xml.push_str("      <Condition/>\n");
            xml.push_str("    </Rule>\n");
            xml.push_str("  </Policy>\n");
        }

        if let Some(ref sig) = package.signature_ref {
            xml.push_str(&format!(
                "  <!-- Signature ref: {sig} -->\n"
            ));
        }

        xml.push_str("</PolicySet>\n");

        Ok(xml.into_bytes())
    }

    fn format_name(&self) -> &str { "xacml-policy-set" }
    fn content_type(&self) -> &str { "application/xml" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_package() -> StoredPolicyPackage {
        StoredPolicyPackage {
            package_id: "pkg-1".to_string(),
            name: "access-control".to_string(),
            namespace: "org.rune.policy".to_string(),
            version: "1.0.0".to_string(),
            description: "Access control policy package".to_string(),
            tags: vec!["access".to_string(), "security".to_string()],
            rule_set_refs: vec!["admin-rules".to_string(), "user-rules".to_string()],
            dependencies: vec![],
            signature_ref: Some("sig-abc123".to_string()),
            created_at: "2026-04-20T00:00:00Z".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonPolicyPackageExporter::new();
        let result = exporter.export_package(&sample_package()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("\"package_id\": \"pkg-1\""));
        assert!(text.contains("\"namespace\": \"org.rune.policy\""));
        assert!(text.contains("\"signature_ref\": \"sig-abc123\""));
        assert_eq!(exporter.format_name(), "json");
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_opa_bundle_exporter() {
        let exporter = OpaBundleExporter::new();
        let result = exporter.export_package(&sample_package()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("\"roots\": [\"org/rune/policy\"]"));
        assert!(text.contains("\"revision\": \"1.0.0\""));
        assert!(text.contains("admin-rules.rego"));
        assert!(text.contains("data.json"));
        assert!(text.contains("signature_ref"));
        assert_eq!(exporter.format_name(), "opa-bundle");
    }

    #[test]
    fn test_cedar_exporter() {
        let exporter = CedarPolicyExporter::new();
        let result = exporter.export_package(&sample_package()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("@id(\"org.rune.policy::admin-rules\")"));
        assert!(text.contains("permit ("));
        assert!(text.contains("Signature ref: sig-abc123"));
        assert_eq!(exporter.format_name(), "cedar");
    }

    #[test]
    fn test_signed_manifest_exporter() {
        let exporter = SignedBundleManifestExporter::new();
        let result = exporter.export_package(&sample_package()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("\"revision\": \"1.0.0\""));
        assert!(text.contains("sha256:"));
        assert!(text.contains("\"algorithm\": \"RS256\""));
        assert!(text.contains("signature_ref"));
        assert_eq!(exporter.format_name(), "signed-bundle-manifest");
    }

    #[test]
    fn test_xacml_exporter() {
        let exporter = XacmlPolicySetExporter::new();
        let result = exporter.export_package(&sample_package()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("<PolicySet"));
        assert!(text.contains("PolicySetId=\"pkg-1\""));
        assert!(text.contains("deny-overrides"));
        assert!(text.contains("org.rune.policy::admin-rules"));
        assert!(text.contains("Signature ref: sig-abc123"));
        assert_eq!(exporter.format_name(), "xacml-policy-set");
        assert_eq!(exporter.content_type(), "application/xml");
    }

    #[test]
    fn test_export_batch() {
        let exporter = JsonPolicyPackageExporter::new();
        let pkgs = vec![sample_package(), sample_package()];
        let result = exporter.export_batch(&pkgs).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_export_with_dependencies() {
        let exporter = JsonPolicyPackageExporter::new();
        let deps = vec![sample_package()];
        let result = exporter
            .export_package_with_dependencies(&sample_package(), &deps)
            .unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_no_signature_ref() {
        let mut pkg = sample_package();
        pkg.signature_ref = None;
        let exporter = JsonPolicyPackageExporter::new();
        let result = exporter.export_package(&pkg).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(!text.contains("signature_ref"));
    }

    #[test]
    fn test_new_constructors() {
        let _ = JsonPolicyPackageExporter::new();
        let _ = OpaBundleExporter::new();
        let _ = CedarPolicyExporter::new();
        let _ = SignedBundleManifestExporter::new();
        let _ = XacmlPolicySetExporter::new();
    }
}
