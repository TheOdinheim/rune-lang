// ═══════════════════════════════════════════════════════════════════════
// Identity Export — Pluggable identity export trait boundary.
//
// Layer 3 defines the contract for exporting identity data in
// standard formats. All exporters MUST exclude credential material
// (defense in depth). Supported formats:
//   - SCIM (System for Cross-domain Identity Management)
//   - OCSF IAM (Open Cybersecurity Schema Framework)
//   - ECS (Elastic Common Schema)
//   - LDIF (LDAP Data Interchange Format)
//   - JSON (generic identity JSON)
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use serde_json;

use crate::error::IdentityError;
use crate::identity::{Identity, IdentityStatus};

// ── ExportFormat ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFormat {
    Scim,
    OcsfIam,
    Ecs,
    Ldif,
    Json,
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scim => write!(f, "SCIM"),
            Self::OcsfIam => write!(f, "OCSF-IAM"),
            Self::Ecs => write!(f, "ECS"),
            Self::Ldif => write!(f, "LDIF"),
            Self::Json => write!(f, "JSON"),
        }
    }
}

// ── ExportedIdentity ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExportedIdentity {
    pub format: ExportFormat,
    pub identity_id: String,
    pub payload: String,
}

// ── IdentityExporter trait ───────────────────────────────────

pub trait IdentityExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError>;
    fn export_format(&self) -> ExportFormat;
    fn exporter_id(&self) -> &str;
}

// ── Helper: identity status string ───────────────────────────

fn status_string(status: &IdentityStatus) -> &'static str {
    match status {
        IdentityStatus::Active => "active",
        IdentityStatus::Suspended => "suspended",
        IdentityStatus::Locked => "locked",
        IdentityStatus::PendingVerification => "pending_verification",
        IdentityStatus::Revoked => "revoked",
        IdentityStatus::Expired => "expired",
    }
}

// ── ScimIdentityExporter ─────────────────────────────────────

pub struct ScimIdentityExporter {
    id: String,
}

impl ScimIdentityExporter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl IdentityExporter for ScimIdentityExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError> {
        let mut obj = serde_json::Map::new();
        obj.insert("schemas".into(), serde_json::json!(["urn:ietf:params:scim:schemas:core:2.0:User"]));
        obj.insert("id".into(), serde_json::Value::String(identity.id.as_str().to_string()));
        obj.insert("userName".into(), serde_json::Value::String(
            identity.display_name.clone(),
        ));
        obj.insert("active".into(), serde_json::Value::Bool(
            identity.status == IdentityStatus::Active,
        ));
        if let Some(ref email) = identity.email {
            obj.insert("emails".into(), serde_json::json!([{"value": email, "primary": true}]));
        }
        if let Some(ref org) = identity.organization {
            obj.insert("organization".into(), serde_json::Value::String(org.clone()));
        }
        let payload = serde_json::to_string_pretty(&obj)
            .map_err(|e| IdentityError::InvalidOperation(format!("SCIM serialization failed: {e}")))?;
        Ok(ExportedIdentity {
            format: ExportFormat::Scim,
            identity_id: identity.id.as_str().to_string(),
            payload,
        })
    }

    fn export_format(&self) -> ExportFormat {
        ExportFormat::Scim
    }

    fn exporter_id(&self) -> &str {
        &self.id
    }
}

// ── OcsfIamExporter ──────────────────────────────────────────

pub struct OcsfIamExporter {
    id: String,
}

impl OcsfIamExporter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl IdentityExporter for OcsfIamExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError> {
        let mut obj = serde_json::Map::new();
        obj.insert("class_uid".into(), serde_json::json!(3001)); // Identity Activity
        obj.insert("category_uid".into(), serde_json::json!(3)); // Identity & Access Management
        obj.insert("activity_id".into(), serde_json::json!(1)); // Read
        let mut user = serde_json::Map::new();
        user.insert("uid".into(), serde_json::Value::String(identity.id.as_str().to_string()));
        user.insert("type".into(), serde_json::Value::String(
            identity.identity_type.type_name().to_string(),
        ));
        if !identity.display_name.is_empty() {
            user.insert("name".into(), serde_json::Value::String(identity.display_name.clone()));
        }
        if let Some(ref email) = identity.email {
            user.insert("email_addr".into(), serde_json::Value::String(email.clone()));
        }
        obj.insert("user".into(), serde_json::Value::Object(user));
        obj.insert("status".into(), serde_json::Value::String(status_string(&identity.status).to_string()));
        obj.insert("time".into(), serde_json::json!(identity.created_at));
        let payload = serde_json::to_string_pretty(&obj)
            .map_err(|e| IdentityError::InvalidOperation(format!("OCSF serialization failed: {e}")))?;
        Ok(ExportedIdentity {
            format: ExportFormat::OcsfIam,
            identity_id: identity.id.as_str().to_string(),
            payload,
        })
    }

    fn export_format(&self) -> ExportFormat {
        ExportFormat::OcsfIam
    }

    fn exporter_id(&self) -> &str {
        &self.id
    }
}

// ── EcsUserExporter ──────────────────────────────────────────

pub struct EcsUserExporter {
    id: String,
}

impl EcsUserExporter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl IdentityExporter for EcsUserExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError> {
        let mut obj = serde_json::Map::new();
        let mut user = serde_json::Map::new();
        user.insert("id".into(), serde_json::Value::String(identity.id.as_str().to_string()));
        if !identity.display_name.is_empty() {
            user.insert("name".into(), serde_json::Value::String(identity.display_name.clone()));
        }
        if let Some(ref email) = identity.email {
            user.insert("email".into(), serde_json::Value::String(email.clone()));
        }
        let mut group = serde_json::Map::new();
        if let Some(ref org) = identity.organization {
            group.insert("name".into(), serde_json::Value::String(org.clone()));
        }
        user.insert("group".into(), serde_json::Value::Object(group));
        obj.insert("user".into(), serde_json::Value::Object(user));
        obj.insert("event.category".into(), serde_json::json!(["iam"]));
        obj.insert("event.kind".into(), serde_json::Value::String("state".to_string()));
        let payload = serde_json::to_string_pretty(&obj)
            .map_err(|e| IdentityError::InvalidOperation(format!("ECS serialization failed: {e}")))?;
        Ok(ExportedIdentity {
            format: ExportFormat::Ecs,
            identity_id: identity.id.as_str().to_string(),
            payload,
        })
    }

    fn export_format(&self) -> ExportFormat {
        ExportFormat::Ecs
    }

    fn exporter_id(&self) -> &str {
        &self.id
    }
}

// ── LdifExporter ─────────────────────────────────────────────

pub struct LdifExporter {
    id: String,
    base_dn: String,
}

impl LdifExporter {
    pub fn new(id: &str, base_dn: &str) -> Self {
        Self {
            id: id.to_string(),
            base_dn: base_dn.to_string(),
        }
    }
}

impl IdentityExporter for LdifExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError> {
        let uid = identity.id.local_part();
        let cn = if identity.display_name.is_empty() { uid } else { &identity.display_name };
        let mut lines = Vec::new();
        lines.push(format!("dn: uid={uid},ou=people,{}", self.base_dn));
        lines.push("objectClass: inetOrgPerson".to_string());
        lines.push(format!("uid: {uid}"));
        lines.push(format!("cn: {cn}"));
        if let Some(ref email) = identity.email {
            lines.push(format!("mail: {email}"));
        }
        if let Some(ref org) = identity.organization {
            lines.push(format!("o: {org}"));
        }
        lines.push(format!("description: status={}", status_string(&identity.status)));
        lines.push(String::new()); // LDIF record separator
        Ok(ExportedIdentity {
            format: ExportFormat::Ldif,
            identity_id: identity.id.as_str().to_string(),
            payload: lines.join("\n"),
        })
    }

    fn export_format(&self) -> ExportFormat {
        ExportFormat::Ldif
    }

    fn exporter_id(&self) -> &str {
        &self.id
    }
}

// ── JsonIdentityExporter ─────────────────────────────────────

pub struct JsonIdentityExporter {
    id: String,
}

impl JsonIdentityExporter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl IdentityExporter for JsonIdentityExporter {
    fn export_identity(&self, identity: &Identity) -> Result<ExportedIdentity, IdentityError> {
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), serde_json::Value::String(identity.id.as_str().to_string()));
        obj.insert("type".into(), serde_json::Value::String(
            identity.identity_type.type_name().to_string(),
        ));
        if !identity.display_name.is_empty() {
            obj.insert("display_name".into(), serde_json::Value::String(identity.display_name.clone()));
        }
        if let Some(ref email) = identity.email {
            obj.insert("email".into(), serde_json::Value::String(email.clone()));
        }
        if let Some(ref org) = identity.organization {
            obj.insert("organization".into(), serde_json::Value::String(org.clone()));
        }
        obj.insert("status".into(), serde_json::Value::String(status_string(&identity.status).to_string()));
        obj.insert("created_at".into(), serde_json::json!(identity.created_at));
        let payload = serde_json::to_string_pretty(&obj)
            .map_err(|e| IdentityError::InvalidOperation(format!("JSON serialization failed: {e}")))?;
        Ok(ExportedIdentity {
            format: ExportFormat::Json,
            identity_id: identity.id.as_str().to_string(),
            payload,
        })
    }

    fn export_format(&self) -> ExportFormat {
        ExportFormat::Json
    }

    fn exporter_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityId;
    use crate::identity_type::IdentityType;

    fn make_test_identity() -> Identity {
        Identity::new(IdentityId::new("user:alice"), IdentityType::default_user())
            .display_name("Alice Smith")
            .email("alice@example.com")
            .organization("ACME Corp")
            .created_at(1000)
            .build()
    }

    fn make_minimal_identity() -> Identity {
        Identity::new(IdentityId::new("svc:bot"), IdentityType::default_service())
            .created_at(2000)
            .build()
    }

    // ── SCIM ──

    #[test]
    fn test_scim_export() {
        let exporter = ScimIdentityExporter::new("scim-1");
        let result = exporter.export_identity(&make_test_identity()).unwrap();
        assert_eq!(result.format, ExportFormat::Scim);
        assert!(result.payload.contains("urn:ietf:params:scim:schemas:core:2.0:User"));
        assert!(result.payload.contains("user:alice"));
        assert!(result.payload.contains("alice@example.com"));
        assert!(!result.payload.contains("password"));
        assert!(!result.payload.contains("hash"));
        assert!(!result.payload.contains("secret"));
    }

    #[test]
    fn test_scim_export_minimal() {
        let exporter = ScimIdentityExporter::new("scim-1");
        let result = exporter.export_identity(&make_minimal_identity()).unwrap();
        assert!(result.payload.contains("svc:bot"));
    }

    // ── OCSF IAM ──

    #[test]
    fn test_ocsf_iam_export() {
        let exporter = OcsfIamExporter::new("ocsf-1");
        let result = exporter.export_identity(&make_test_identity()).unwrap();
        assert_eq!(result.format, ExportFormat::OcsfIam);
        assert!(result.payload.contains("3001"));
        assert!(result.payload.contains("user:alice"));
        assert!(!result.payload.contains("password"));
        assert!(!result.payload.contains("hash"));
    }

    // ── ECS ──

    #[test]
    fn test_ecs_export() {
        let exporter = EcsUserExporter::new("ecs-1");
        let result = exporter.export_identity(&make_test_identity()).unwrap();
        assert_eq!(result.format, ExportFormat::Ecs);
        assert!(result.payload.contains("iam"));
        assert!(result.payload.contains("user:alice"));
        assert!(result.payload.contains("Alice Smith"));
        assert!(!result.payload.contains("password"));
    }

    // ── LDIF ──

    #[test]
    fn test_ldif_export() {
        let exporter = LdifExporter::new("ldif-1", "dc=example,dc=com");
        let result = exporter.export_identity(&make_test_identity()).unwrap();
        assert_eq!(result.format, ExportFormat::Ldif);
        assert!(result.payload.contains("dn: uid=alice,ou=people,dc=example,dc=com"));
        assert!(result.payload.contains("objectClass: inetOrgPerson"));
        assert!(result.payload.contains("cn: Alice Smith"));
        assert!(result.payload.contains("mail: alice@example.com"));
        assert!(result.payload.contains("o: ACME Corp"));
        assert!(!result.payload.contains("password"));
        assert!(!result.payload.contains("hash"));
    }

    #[test]
    fn test_ldif_export_minimal() {
        let exporter = LdifExporter::new("ldif-1", "dc=x");
        let result = exporter.export_identity(&make_minimal_identity()).unwrap();
        assert!(result.payload.contains("uid=bot"));
    }

    // ── JSON ──

    #[test]
    fn test_json_export() {
        let exporter = JsonIdentityExporter::new("json-1");
        let result = exporter.export_identity(&make_test_identity()).unwrap();
        assert_eq!(result.format, ExportFormat::Json);
        assert!(result.payload.contains("user:alice"));
        assert!(result.payload.contains("Alice Smith"));
        assert!(result.payload.contains("active"));
        assert!(!result.payload.contains("password"));
        assert!(!result.payload.contains("hash"));
        assert!(!result.payload.contains("secret"));
    }

    // ── Format metadata ──

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Scim.to_string(), "SCIM");
        assert_eq!(ExportFormat::OcsfIam.to_string(), "OCSF-IAM");
        assert_eq!(ExportFormat::Ecs.to_string(), "ECS");
        assert_eq!(ExportFormat::Ldif.to_string(), "LDIF");
        assert_eq!(ExportFormat::Json.to_string(), "JSON");
    }

    #[test]
    fn test_exporter_ids() {
        assert_eq!(ScimIdentityExporter::new("s1").exporter_id(), "s1");
        assert_eq!(OcsfIamExporter::new("o1").exporter_id(), "o1");
        assert_eq!(EcsUserExporter::new("e1").exporter_id(), "e1");
        assert_eq!(LdifExporter::new("l1", "dc=x").exporter_id(), "l1");
        assert_eq!(JsonIdentityExporter::new("j1").exporter_id(), "j1");
    }

    #[test]
    fn test_all_five_formats_exclude_credentials() {
        let identity = make_test_identity();
        let exporters: Vec<Box<dyn IdentityExporter>> = vec![
            Box::new(ScimIdentityExporter::new("s")),
            Box::new(OcsfIamExporter::new("o")),
            Box::new(EcsUserExporter::new("e")),
            Box::new(LdifExporter::new("l", "dc=x")),
            Box::new(JsonIdentityExporter::new("j")),
        ];
        for exporter in &exporters {
            let result = exporter.export_identity(&identity).unwrap();
            let lower = result.payload.to_lowercase();
            assert!(!lower.contains("password"), "{} leaks password", exporter.export_format());
            assert!(!lower.contains("hash"), "{} leaks hash", exporter.export_format());
            assert!(!lower.contains("secret"), "{} leaks secret", exporter.export_format());
            assert!(!lower.contains("totp"), "{} leaks totp", exporter.export_format());
            assert!(!lower.contains("recovery"), "{} leaks recovery", exporter.export_format());
        }
    }
}
