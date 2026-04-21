// ═══════════════════════════════════════════════════════════════════════
// Truth Export — Serialization of claims into standard external formats.
//
// Each exporter produces a Vec<u8> in a well-known format.  The trait
// intentionally takes &StoredClaim (the persistence type from
// backend.rs) so that export always works from the canonical stored
// form, not from transient in-memory representations.
//
// Five formats ship with this module:
//   1. JSON — direct serde_json serialization
//   2. W3C Verifiable Credential envelope (JSON-LD skeleton)
//   3. Schema.org ClaimReview (JSON-LD skeleton)
//   4. STIX 2.1 Observation (JSON)
//   5. Plain text — human-readable summary
//
// All "skeleton" formats produce structurally valid JSON that a
// downstream system can enrich with signatures, contexts, etc.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::backend::StoredClaim;
use crate::error::TruthError;

// ── ClaimExporter trait ───────────────────────────────────────────

pub trait ClaimExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError>;

    fn export_batch(&self, claims: &[StoredClaim]) -> Result<Vec<u8>, TruthError> {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(claims.len());
        for c in claims {
            parts.push(self.export_claim(c)?);
        }
        // Default: newline-separated individual exports
        let joined: Vec<u8> = parts.join(&b'\n');
        Ok(joined)
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError>;

    fn format_name(&self) -> &str;
    fn media_type(&self) -> &str;
}

// ── JsonClaimExporter ─────────────────────────────────────────────

pub struct JsonClaimExporter;

impl ClaimExporter for JsonClaimExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError> {
        serde_json::to_vec_pretty(&claim_to_json(claim))
            .map_err(|e| TruthError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError> {
        let mut obj = claim_to_json(claim);
        if let Some(map) = obj.as_object_mut() {
            map.insert(
                "evidence_refs".to_string(),
                serde_json::Value::Array(
                    evidence_refs.iter().map(|r| serde_json::Value::String(r.clone())).collect(),
                ),
            );
        }
        serde_json::to_vec_pretty(&obj)
            .map_err(|e| TruthError::InvalidOperation(format!("JSON serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "json" }
    fn media_type(&self) -> &str { "application/json" }
}

// ── W3cVerifiableCredentialExporter ───────────────────────────────

pub struct W3cVerifiableCredentialExporter;

impl ClaimExporter for W3cVerifiableCredentialExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError> {
        self.export_claim_with_evidence(claim, &[])
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError> {
        let body_str = String::from_utf8_lossy(&claim.claim_body_bytes);
        let vc = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "TruthClaim"],
            "issuer": claim.claimant,
            "issuanceDate": claim.asserted_at,
            "credentialSubject": {
                "id": claim.subject_of_claim_ref.as_str(),
                "claimType": claim.claim_type,
                "claimBody": body_str,
                "confidence": claim.confidence_score,
            },
            "evidence": evidence_refs,
        });
        serde_json::to_vec_pretty(&vc)
            .map_err(|e| TruthError::InvalidOperation(format!("VC serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "w3c-vc" }
    fn media_type(&self) -> &str { "application/ld+json" }
}

// ── SchemaOrgClaimReviewExporter ──────────────────────────────────

pub struct SchemaOrgClaimReviewExporter;

impl ClaimExporter for SchemaOrgClaimReviewExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError> {
        self.export_claim_with_evidence(claim, &[])
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError> {
        let body_str = String::from_utf8_lossy(&claim.claim_body_bytes);
        let review = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "ClaimReview",
            "claimReviewed": body_str,
            "author": { "@type": "Organization", "name": claim.claimant },
            "reviewRating": {
                "@type": "Rating",
                "ratingValue": claim.confidence_score,
            },
            "itemReviewed": {
                "@type": "Claim",
                "name": claim.claim_type,
                "about": claim.subject_of_claim_ref.as_str(),
            },
            "evidenceRefs": evidence_refs,
        });
        serde_json::to_vec_pretty(&review)
            .map_err(|e| TruthError::InvalidOperation(format!("ClaimReview serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "schema-org-claim-review" }
    fn media_type(&self) -> &str { "application/ld+json" }
}

// ── Stix21ObservationExporter ─────────────────────────────────────

pub struct Stix21ObservationExporter;

impl ClaimExporter for Stix21ObservationExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError> {
        self.export_claim_with_evidence(claim, &[])
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError> {
        let body_str = String::from_utf8_lossy(&claim.claim_body_bytes);
        let obs = serde_json::json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": format!("observed-data--{}", claim.claim_id),
            "created": claim.asserted_at,
            "modified": claim.asserted_at,
            "first_observed": claim.asserted_at,
            "last_observed": claim.asserted_at,
            "number_observed": 1,
            "object_refs": [claim.subject_of_claim_ref.as_str()],
            "x_claim_type": claim.claim_type,
            "x_claim_body": body_str,
            "x_confidence": claim.confidence_score,
            "x_evidence_refs": evidence_refs,
        });
        serde_json::to_vec_pretty(&obs)
            .map_err(|e| TruthError::InvalidOperation(format!("STIX serialization failed: {e}")))
    }

    fn format_name(&self) -> &str { "stix-2.1-observation" }
    fn media_type(&self) -> &str { "application/json" }
}

// ── PlainTextClaimExporter ────────────────────────────────────────

pub struct PlainTextClaimExporter;

impl ClaimExporter for PlainTextClaimExporter {
    fn export_claim(&self, claim: &StoredClaim) -> Result<Vec<u8>, TruthError> {
        self.export_claim_with_evidence(claim, &[])
    }

    fn export_claim_with_evidence(
        &self,
        claim: &StoredClaim,
        evidence_refs: &[String],
    ) -> Result<Vec<u8>, TruthError> {
        let body_str = String::from_utf8_lossy(&claim.claim_body_bytes);
        let mut text = format!(
            "Claim: {}\nSubject: {}\nType: {}\nBody: {}\nClaimant: {}\nAsserted At: {}\nConfidence: {}",
            claim.claim_id,
            claim.subject_of_claim_ref.as_str(),
            claim.claim_type,
            body_str,
            claim.claimant,
            claim.asserted_at,
            claim.confidence_score,
        );
        if !evidence_refs.is_empty() {
            text.push_str(&format!("\nEvidence: {}", evidence_refs.join(", ")));
        }
        if let Some(retracted) = claim.retracted_at {
            text.push_str(&format!("\nRetracted At: {retracted}"));
        }
        Ok(text.into_bytes())
    }

    fn format_name(&self) -> &str { "plain-text" }
    fn media_type(&self) -> &str { "text/plain" }
}

// ── ExportFormat enum ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    W3cVerifiableCredential,
    SchemaOrgClaimReview,
    Stix21Observation,
    PlainText,
}

impl ExportFormat {
    pub fn exporter(&self) -> Box<dyn ClaimExporter> {
        match self {
            Self::Json => Box::new(JsonClaimExporter),
            Self::W3cVerifiableCredential => Box::new(W3cVerifiableCredentialExporter),
            Self::SchemaOrgClaimReview => Box::new(SchemaOrgClaimReviewExporter),
            Self::Stix21Observation => Box::new(Stix21ObservationExporter),
            Self::PlainText => Box::new(PlainTextClaimExporter),
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::W3cVerifiableCredential => f.write_str("w3c-vc"),
            Self::SchemaOrgClaimReview => f.write_str("schema-org-claim-review"),
            Self::Stix21Observation => f.write_str("stix-2.1-observation"),
            Self::PlainText => f.write_str("plain-text"),
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────

fn claim_to_json(claim: &StoredClaim) -> serde_json::Value {
    let body_str = String::from_utf8_lossy(&claim.claim_body_bytes);
    serde_json::json!({
        "claim_id": claim.claim_id,
        "subject": claim.subject_of_claim_ref.as_str(),
        "claim_type": claim.claim_type,
        "claim_body": body_str,
        "claimant": claim.claimant,
        "asserted_at": claim.asserted_at,
        "confidence_score": claim.confidence_score,
        "evidence_attestation_refs": claim.evidence_attestation_refs,
        "retracted_at": claim.retracted_at,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SubjectOfClaimRef;

    fn make_claim() -> StoredClaim {
        StoredClaim {
            claim_id: "claim-1".to_string(),
            subject_of_claim_ref: SubjectOfClaimRef::new("subject-1"),
            claim_type: "factual-accuracy".to_string(),
            claim_body_bytes: b"{\"statement\": \"the sky is blue\"}".to_vec(),
            claimant: "alice".to_string(),
            asserted_at: 1000,
            confidence_score: "0.95".to_string(),
            evidence_attestation_refs: vec!["att-1".to_string()],
            retracted_at: None,
        }
    }

    #[test]
    fn test_json_export() {
        let exporter = JsonClaimExporter;
        let bytes = exporter.export_claim(&make_claim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("claim-1"));
        assert!(text.contains("alice"));
    }

    #[test]
    fn test_json_export_with_evidence() {
        let exporter = JsonClaimExporter;
        let refs = vec!["att-2".to_string(), "att-3".to_string()];
        let bytes = exporter.export_claim_with_evidence(&make_claim(), &refs).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("att-2"));
        assert!(text.contains("evidence_refs"));
    }

    #[test]
    fn test_w3c_vc_export() {
        let exporter = W3cVerifiableCredentialExporter;
        let bytes = exporter.export_claim(&make_claim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("VerifiableCredential"));
        assert!(text.contains("credentialSubject"));
    }

    #[test]
    fn test_schema_org_export() {
        let exporter = SchemaOrgClaimReviewExporter;
        let bytes = exporter.export_claim(&make_claim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("ClaimReview"));
        assert!(text.contains("schema.org"));
    }

    #[test]
    fn test_stix_export() {
        let exporter = Stix21ObservationExporter;
        let bytes = exporter.export_claim(&make_claim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("observed-data"));
        assert!(text.contains("2.1"));
    }

    #[test]
    fn test_plain_text_export() {
        let exporter = PlainTextClaimExporter;
        let bytes = exporter.export_claim(&make_claim()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Claim: claim-1"));
        assert!(text.contains("Claimant: alice"));
    }

    #[test]
    fn test_plain_text_with_retraction() {
        let exporter = PlainTextClaimExporter;
        let mut claim = make_claim();
        claim.retracted_at = Some(2000);
        let bytes = exporter.export_claim(&claim).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Retracted At: 2000"));
    }

    #[test]
    fn test_plain_text_with_evidence() {
        let exporter = PlainTextClaimExporter;
        let refs = vec!["att-1".to_string(), "att-2".to_string()];
        let bytes = exporter.export_claim_with_evidence(&make_claim(), &refs).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Evidence: att-1, att-2"));
    }

    #[test]
    fn test_batch_export() {
        let exporter = JsonClaimExporter;
        let claims = vec![make_claim(), make_claim()];
        let bytes = exporter.export_batch(&claims).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_export_format_enum() {
        let formats = [
            ExportFormat::Json,
            ExportFormat::W3cVerifiableCredential,
            ExportFormat::SchemaOrgClaimReview,
            ExportFormat::Stix21Observation,
            ExportFormat::PlainText,
        ];
        for fmt in &formats {
            let exporter = fmt.exporter();
            assert!(!exporter.format_name().is_empty());
            assert!(!exporter.media_type().is_empty());
        }
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::PlainText.to_string(), "plain-text");
    }

    #[test]
    fn test_exporter_media_types() {
        assert_eq!(JsonClaimExporter.media_type(), "application/json");
        assert_eq!(W3cVerifiableCredentialExporter.media_type(), "application/ld+json");
        assert_eq!(PlainTextClaimExporter.media_type(), "text/plain");
    }
}
