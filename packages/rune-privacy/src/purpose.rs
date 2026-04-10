// ═══════════════════════════════════════════════════════════════════════
// Purpose Limitation and Data Minimization
//
// Data tagged with its collection purpose cannot be used for undeclared
// purposes. Data minimization checks for excess collection.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use rune_identity::IdentityId;

use crate::error::PrivacyError;
use crate::pii::PiiCategory;

// ── LegalBasis ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegalBasis {
    Consent,
    ContractPerformance,
    LegalObligation,
    VitalInterests,
    PublicInterest,
    LegitimateInterest,
}

impl fmt::Display for LegalBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consent => write!(f, "Consent (Art. 6(1)(a))"),
            Self::ContractPerformance => write!(f, "ContractPerformance (Art. 6(1)(b))"),
            Self::LegalObligation => write!(f, "LegalObligation (Art. 6(1)(c))"),
            Self::VitalInterests => write!(f, "VitalInterests (Art. 6(1)(d))"),
            Self::PublicInterest => write!(f, "PublicInterest (Art. 6(1)(e))"),
            Self::LegitimateInterest => write!(f, "LegitimateInterest (Art. 6(1)(f))"),
        }
    }
}

// ── Purpose ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Purpose {
    pub id: String,
    pub name: String,
    pub description: String,
    pub legal_basis: LegalBasis,
    pub data_categories: Vec<PiiCategory>,
    pub retention_days: Option<u64>,
    pub active: bool,
    pub created_at: i64,
}

impl Purpose {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        legal_basis: LegalBasis,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            legal_basis,
            data_categories: Vec::new(),
            retention_days: None,
            active: true,
            created_at: 0,
        }
    }
}

impl PartialEq for Purpose {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Purpose {}

// ── DataTag ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataTag {
    pub data_id: String,
    pub field_name: String,
    pub purpose_id: String,
    pub collected_at: i64,
    pub expires_at: Option<i64>,
    pub subject_id: IdentityId,
}

// ── PurposeCheck ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PurposeCheck {
    pub allowed: bool,
    pub data_id: String,
    pub requested_purpose: String,
    pub original_purposes: Vec<String>,
    pub reason: String,
}

// ── PurposeRegistry ───────────────────────────────────────────────────

#[derive(Default)]
pub struct PurposeRegistry {
    pub purposes: HashMap<String, Purpose>,
    pub data_tags: Vec<DataTag>,
}

impl PurposeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_purpose(&mut self, purpose: Purpose) -> Result<(), PrivacyError> {
        if self.purposes.contains_key(&purpose.id) {
            return Err(PrivacyError::InvalidOperation(format!(
                "purpose {} already registered",
                purpose.id
            )));
        }
        self.purposes.insert(purpose.id.clone(), purpose);
        Ok(())
    }

    pub fn get_purpose(&self, id: &str) -> Option<&Purpose> {
        self.purposes.get(id)
    }

    pub fn tag_data(&mut self, tag: DataTag) -> Result<(), PrivacyError> {
        if !self.purposes.contains_key(&tag.purpose_id) {
            return Err(PrivacyError::PurposeNotFound(tag.purpose_id.clone()));
        }
        self.data_tags.push(tag);
        Ok(())
    }

    pub fn check_purpose(&self, data_id: &str, intended_purpose: &str) -> PurposeCheck {
        let original: Vec<String> = self
            .data_tags
            .iter()
            .filter(|t| t.data_id == data_id)
            .map(|t| t.purpose_id.clone())
            .collect();
        let allowed = original.iter().any(|p| p == intended_purpose);
        let reason = if allowed {
            "intended purpose matches original collection purpose".into()
        } else if original.is_empty() {
            "no original purpose recorded for data".into()
        } else {
            format!("data was collected for {original:?}, not for '{intended_purpose}'")
        };
        PurposeCheck {
            allowed,
            data_id: data_id.to_string(),
            requested_purpose: intended_purpose.to_string(),
            original_purposes: original,
            reason,
        }
    }

    pub fn purposes_for_data(&self, data_id: &str) -> Vec<&Purpose> {
        self.data_tags
            .iter()
            .filter(|t| t.data_id == data_id)
            .filter_map(|t| self.purposes.get(&t.purpose_id))
            .collect()
    }

    pub fn data_for_purpose(&self, purpose_id: &str) -> Vec<&DataTag> {
        self.data_tags.iter().filter(|t| t.purpose_id == purpose_id).collect()
    }

    pub fn expired_data(&self, now: i64) -> Vec<&DataTag> {
        self.data_tags
            .iter()
            .filter(|t| t.expires_at.is_some_and(|e| now >= e))
            .collect()
    }
}

// ── DataMinimization ──────────────────────────────────────────────────

#[derive(Default)]
pub struct DataMinimization {
    pub required_fields: HashMap<String, Vec<String>>,
}

impl DataMinimization {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn define_required(&mut self, purpose: &str, fields: Vec<String>) {
        self.required_fields.insert(purpose.to_string(), fields);
    }

    pub fn check_minimization(
        &self,
        purpose: &str,
        collected_fields: &[String],
    ) -> MinimizationResult {
        let required = self.required_fields.get(purpose).cloned().unwrap_or_default();
        let collected: Vec<String> = collected_fields.to_vec();

        let excess: Vec<String> = collected
            .iter()
            .filter(|f| !required.contains(f))
            .cloned()
            .collect();
        let missing: Vec<String> = required
            .iter()
            .filter(|f| !collected.contains(f))
            .cloned()
            .collect();

        MinimizationResult {
            is_minimized: excess.is_empty(),
            purpose: purpose.to_string(),
            required_fields: required,
            collected_fields: collected,
            excess_fields: excess,
            missing_fields: missing,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MinimizationResult {
    pub purpose: String,
    pub required_fields: Vec<String>,
    pub collected_fields: Vec<String>,
    pub excess_fields: Vec<String>,
    pub missing_fields: Vec<String>,
    pub is_minimized: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_purpose(id: &str) -> Purpose {
        Purpose::new(id, format!("Purpose {id}"), LegalBasis::Consent)
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = PurposeRegistry::new();
        reg.register_purpose(test_purpose("p1")).unwrap();
        assert!(reg.get_purpose("p1").is_some());
    }

    #[test]
    fn test_tag_data_links_to_purpose() {
        let mut reg = PurposeRegistry::new();
        reg.register_purpose(test_purpose("p1")).unwrap();
        reg.tag_data(DataTag {
            data_id: "d1".into(),
            field_name: "email".into(),
            purpose_id: "p1".into(),
            collected_at: 1000,
            expires_at: None,
            subject_id: IdentityId::new("user:alice"),
        })
        .unwrap();
        let tags = reg.data_for_purpose("p1");
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn test_tag_data_missing_purpose_fails() {
        let mut reg = PurposeRegistry::new();
        let result = reg.tag_data(DataTag {
            data_id: "d1".into(),
            field_name: "email".into(),
            purpose_id: "nonexistent".into(),
            collected_at: 1000,
            expires_at: None,
            subject_id: IdentityId::new("user:alice"),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_check_purpose_allowed() {
        let mut reg = PurposeRegistry::new();
        reg.register_purpose(test_purpose("p1")).unwrap();
        reg.tag_data(DataTag {
            data_id: "d1".into(),
            field_name: "email".into(),
            purpose_id: "p1".into(),
            collected_at: 0,
            expires_at: None,
            subject_id: IdentityId::new("user:alice"),
        })
        .unwrap();
        let check = reg.check_purpose("d1", "p1");
        assert!(check.allowed);
    }

    #[test]
    fn test_check_purpose_denied() {
        let mut reg = PurposeRegistry::new();
        reg.register_purpose(test_purpose("p1")).unwrap();
        reg.register_purpose(test_purpose("p2")).unwrap();
        reg.tag_data(DataTag {
            data_id: "d1".into(),
            field_name: "email".into(),
            purpose_id: "p1".into(),
            collected_at: 0,
            expires_at: None,
            subject_id: IdentityId::new("user:alice"),
        })
        .unwrap();
        let check = reg.check_purpose("d1", "p2");
        assert!(!check.allowed);
    }

    #[test]
    fn test_minimization_detects_excess() {
        let mut min = DataMinimization::new();
        min.define_required("signup", vec!["email".into(), "name".into()]);
        let result = min.check_minimization(
            "signup",
            &["email".into(), "name".into(), "phone".into(), "ssn".into()],
        );
        assert_eq!(result.excess_fields.len(), 2);
        assert!(!result.is_minimized);
    }

    #[test]
    fn test_minimization_detects_missing() {
        let mut min = DataMinimization::new();
        min.define_required("signup", vec!["email".into(), "name".into()]);
        let result = min.check_minimization("signup", &["email".into()]);
        assert_eq!(result.missing_fields.len(), 1);
    }

    #[test]
    fn test_minimization_exact_match() {
        let mut min = DataMinimization::new();
        min.define_required("signup", vec!["email".into(), "name".into()]);
        let result = min.check_minimization("signup", &["email".into(), "name".into()]);
        assert!(result.is_minimized);
        assert!(result.excess_fields.is_empty());
    }

    #[test]
    fn test_expired_data() {
        let mut reg = PurposeRegistry::new();
        reg.register_purpose(test_purpose("p1")).unwrap();
        reg.tag_data(DataTag {
            data_id: "d1".into(),
            field_name: "email".into(),
            purpose_id: "p1".into(),
            collected_at: 0,
            expires_at: Some(1000),
            subject_id: IdentityId::new("user:alice"),
        })
        .unwrap();
        let expired = reg.expired_data(2000);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_legal_basis_display() {
        assert!(LegalBasis::Consent.to_string().contains("Art. 6(1)(a)"));
        assert!(LegalBasis::LegitimateInterest.to_string().contains("Art. 6(1)(f)"));
    }
}
