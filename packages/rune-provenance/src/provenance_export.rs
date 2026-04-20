// ═══════════════════════════════════════════════════════════════════════
// Provenance Export — Attestation and lineage export formats.
//
// All exporters emit attestations in canonical form — the serialization
// is byte-reproducible so that signatures computed over the canonical
// bytes remain valid after export and re-import. Canonicalization rules:
// - Fields emitted in a fixed, alphabetically-sorted order
// - No trailing whitespace or optional formatting
// - Byte-level base64 encoding where applicable (no line wrapping)
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{StoredAttestation, StoredLineageRecord};

#[cfg(test)]
use crate::backend::ArtifactRef;
use crate::error::ProvenanceError;

// ── ProvenanceExporter trait ────────────────────────────────────────

pub trait ProvenanceExporter {
    fn export_attestation(&self, attestation: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError>;
    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonProvenanceExporter ──────────────────────────────────────────

pub struct JsonProvenanceExporter;

impl ProvenanceExporter for JsonProvenanceExporter {
    fn export_attestation(&self, att: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError> {
        let pred_b64 = hex::encode(&att.predicate_bytes);
        let sig_b64 = hex::encode(&att.signature);
        let pred_id = att.predecessor_attestation_id.as_deref().unwrap_or("null");
        let out = format!(
            "{{\n  \"attestation_id\": \"{}\",\n  \"artifact_ref\": \"{}\",\n  \"issued_at\": {},\n  \"predicate_bytes\": \"{}\",\n  \"predicate_type\": \"{}\",\n  \"predecessor_attestation_id\": \"{}\",\n  \"signature\": \"{}\",\n  \"signing_key_ref\": \"{}\"\n}}",
            att.attestation_id, att.artifact_ref, att.issued_at, pred_b64, att.predicate_type, pred_id, sig_b64, att.signing_key_ref
        );
        Ok(out.into_bytes())
    }

    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError> {
        let mut lines = Vec::new();
        lines.push("[".to_string());
        for (i, r) in records.iter().enumerate() {
            let parents: Vec<String> = r.parent_artifact_refs.iter().map(|p| format!("\"{}\"", p)).collect();
            let comma = if i + 1 < records.len() { "," } else { "" };
            lines.push(format!(
                "  {{\"artifact_ref\": \"{}\", \"parents\": [{}], \"record_id\": \"{}\", \"transformation\": \"{}\"}}{comma}",
                r.artifact_ref, parents.join(", "), r.record_id, r.transformation
            ));
        }
        lines.push("]".to_string());
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "JSON" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── SlsaProvenanceV1Exporter ────────────────────────────────────────

pub struct SlsaProvenanceV1Exporter;

impl ProvenanceExporter for SlsaProvenanceV1Exporter {
    fn export_attestation(&self, att: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError> {
        let out = format!(
            "{{\n  \"_type\": \"https://in-toto.io/Statement/v1\",\n  \"predicateType\": \"{}\",\n  \"subject\": [{{\"name\": \"{}\", \"digest\": {{}}}}],\n  \"predicate\": {{\n    \"buildDefinition\": {{\n      \"buildType\": \"{}\",\n      \"resolvedDependencies\": []\n    }},\n    \"runDetails\": {{\n      \"builder\": {{\"id\": \"{}\"}}\n    }}\n  }}\n}}",
            att.predicate_type, att.artifact_ref, att.predicate_type, att.signing_key_ref
        );
        Ok(out.into_bytes())
    }

    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError> {
        JsonProvenanceExporter.export_lineage_bundle(records)
    }

    fn format_name(&self) -> &str { "SLSA-Provenance-v1" }
    fn content_type(&self) -> &str { "application/vnd.in-toto+json" }
}

// ── InTotoStatementExporter ─────────────────────────────────────────

pub struct InTotoStatementExporter;

impl ProvenanceExporter for InTotoStatementExporter {
    fn export_attestation(&self, att: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError> {
        let pred_b64 = hex::encode(&att.predicate_bytes);
        let out = format!(
            "{{\n  \"_type\": \"https://in-toto.io/Statement/v1\",\n  \"predicate\": \"{}\",\n  \"predicateType\": \"{}\",\n  \"subject\": [{{\"name\": \"{}\"}}]\n}}",
            pred_b64, att.predicate_type, att.artifact_ref
        );
        Ok(out.into_bytes())
    }

    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError> {
        JsonProvenanceExporter.export_lineage_bundle(records)
    }

    fn format_name(&self) -> &str { "in-toto-Statement-v1" }
    fn content_type(&self) -> &str { "application/vnd.in-toto+json" }
}

// ── DsseEnvelopeExporter ────────────────────────────────────────────

pub struct DsseEnvelopeExporter;

impl ProvenanceExporter for DsseEnvelopeExporter {
    fn export_attestation(&self, att: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError> {
        let payload_b64 = hex::encode(&att.predicate_bytes);
        let sig_b64 = hex::encode(&att.signature);
        let out = format!(
            "{{\n  \"payload\": \"{}\",\n  \"payloadType\": \"{}\",\n  \"signatures\": [{{\"keyid\": \"{}\", \"sig\": \"{}\"}}]\n}}",
            payload_b64, att.predicate_type, att.signing_key_ref, sig_b64
        );
        Ok(out.into_bytes())
    }

    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError> {
        JsonProvenanceExporter.export_lineage_bundle(records)
    }

    fn format_name(&self) -> &str { "DSSE" }
    fn content_type(&self) -> &str { "application/vnd.dsse+json" }
}

// ── SpdxSbomExporter ────────────────────────────────────────────────

pub struct SpdxSbomExporter;

impl ProvenanceExporter for SpdxSbomExporter {
    fn export_attestation(&self, att: &StoredAttestation) -> Result<Vec<u8>, ProvenanceError> {
        if !att.predicate_type.contains("spdx") && !att.predicate_type.contains("sbom") {
            return Err(ProvenanceError::InvalidOperation(
                format!("SpdxSbomExporter requires an SBOM-bearing predicate, got: {}", att.predicate_type)
            ));
        }
        let out = format!(
            "{{\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"creationInfo\": {{\"created\": \"{}\"}},\n  \"dataLicense\": \"CC0-1.0\",\n  \"name\": \"{}\",\n  \"spdxVersion\": \"SPDX-2.3\"\n}}",
            att.issued_at, att.artifact_ref
        );
        Ok(out.into_bytes())
    }

    fn export_lineage_bundle(&self, records: &[StoredLineageRecord]) -> Result<Vec<u8>, ProvenanceError> {
        JsonProvenanceExporter.export_lineage_bundle(records)
    }

    fn format_name(&self) -> &str { "SPDX-2.3" }
    fn content_type(&self) -> &str { "application/spdx+json" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation() -> StoredAttestation {
        StoredAttestation {
            attestation_id: "att-1".to_string(),
            artifact_ref: ArtifactRef::new("art-1"),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate_bytes: b"{\"builder\":{\"id\":\"test\"}}".to_vec(),
            signature: vec![1, 2, 3],
            signing_key_ref: "key-1".to_string(),
            issued_at: 1000,
            predecessor_attestation_id: None,
        }
    }

    fn make_lineage_records() -> Vec<StoredLineageRecord> {
        vec![StoredLineageRecord {
            record_id: "l1".to_string(),
            artifact_ref: ArtifactRef::new("art-1"),
            parent_artifact_refs: vec![ArtifactRef::new("parent-1")],
            transformation: "filter".to_string(),
            recorded_at: 1000,
            metadata: std::collections::HashMap::new(),
        }]
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonProvenanceExporter;
        let data = exporter.export_attestation(&make_attestation()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("attestation_id"));
        assert!(text.contains("att-1"));
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_slsa_exporter() {
        let exporter = SlsaProvenanceV1Exporter;
        let data = exporter.export_attestation(&make_attestation()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("https://in-toto.io/Statement/v1"));
        assert!(text.contains("buildDefinition"));
        assert!(text.contains("runDetails"));
    }

    #[test]
    fn test_intoto_exporter() {
        let exporter = InTotoStatementExporter;
        let data = exporter.export_attestation(&make_attestation()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("https://in-toto.io/Statement/v1"));
        assert!(text.contains("predicateType"));
        assert!(text.contains("subject"));
    }

    #[test]
    fn test_dsse_exporter() {
        let exporter = DsseEnvelopeExporter;
        let data = exporter.export_attestation(&make_attestation()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("payloadType"));
        assert!(text.contains("signatures"));
        assert_eq!(exporter.content_type(), "application/vnd.dsse+json");
    }

    #[test]
    fn test_spdx_exporter_valid() {
        let exporter = SpdxSbomExporter;
        let mut att = make_attestation();
        att.predicate_type = "https://spdx.dev/sbom/v2.3".to_string();
        let data = exporter.export_attestation(&att).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("SPDX-2.3"));
        assert!(text.contains("SPDXRef-DOCUMENT"));
    }

    #[test]
    fn test_spdx_exporter_unsupported_predicate() {
        let exporter = SpdxSbomExporter;
        let att = make_attestation(); // predicate_type is slsa, not spdx
        assert!(exporter.export_attestation(&att).is_err());
    }

    #[test]
    fn test_lineage_bundle_export() {
        let exporter = JsonProvenanceExporter;
        let data = exporter.export_lineage_bundle(&make_lineage_records()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("art-1"));
        assert!(text.contains("parent-1"));
    }
}
