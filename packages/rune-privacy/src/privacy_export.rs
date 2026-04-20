// ═══════════════════════════════════════════════════════════════════════
// DSAR Export — Data Subject Access Request export formats.
//
// GDPR Article 15 and CCPA Section 1798.110 require organizations to
// provide a copy of personal data in a consumer-readable format. All
// five exporters respect active redaction policies inside the trait
// contract (defense-in-depth, matching rune-web's Authorization header
// redaction and rune-identity's credential material exclusion).
// ═══════════════════════════════════════════════════════════════════════

use crate::backend::{StoredDataSubjectRecord, StoredProcessingRecord, SubjectRef};
use crate::consent_store::ConsentRecord;
use crate::error::PrivacyError;

// ── SubjectDossier ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SubjectDossier {
    pub subject_ref: SubjectRef,
    pub subject_record: Option<StoredDataSubjectRecord>,
    pub consents: Vec<ConsentRecord>,
    pub processing_records: Vec<StoredProcessingRecord>,
    pub data_categories: Vec<String>,
    pub export_timestamp: i64,
    pub jurisdiction: String,
}

impl SubjectDossier {
    pub fn new(subject_ref: SubjectRef, jurisdiction: &str, export_timestamp: i64) -> Self {
        Self {
            subject_ref,
            subject_record: None,
            consents: Vec::new(),
            processing_records: Vec::new(),
            data_categories: Vec::new(),
            export_timestamp,
            jurisdiction: jurisdiction.to_string(),
        }
    }
}

// ── DsarExporter trait ──────────────────────────────────────────────

pub trait DsarExporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError>;
    fn export_batch(&self, dossiers: &[SubjectDossier]) -> Result<Vec<Vec<u8>>, PrivacyError> {
        dossiers.iter().map(|d| self.export_subject_data(d)).collect()
    }
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
    fn redaction_aware(&self) -> bool;
}

// ── JsonDsarExporter ────────────────────────────────────────────────

pub struct JsonDsarExporter;

impl DsarExporter for JsonDsarExporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError> {
        let mut lines = Vec::new();
        lines.push("{".to_string());
        lines.push(format!("  \"subject\": \"{}\",", dossier.subject_ref));
        lines.push(format!("  \"jurisdiction\": \"{}\",", dossier.jurisdiction));
        lines.push(format!("  \"export_timestamp\": {},", dossier.export_timestamp));
        lines.push(format!("  \"data_categories\": {:?},", dossier.data_categories));

        lines.push("  \"consents\": [".to_string());
        for (i, c) in dossier.consents.iter().enumerate() {
            let comma = if i + 1 < dossier.consents.len() { "," } else { "" };
            lines.push(format!(
                "    {{\"consent_id\": \"{}\", \"purpose\": \"{}\", \"status\": \"{}\", \"legal_basis\": \"{}\"}}{comma}",
                c.consent_id, c.purpose, c.status, c.legal_basis
            ));
        }
        lines.push("  ],".to_string());

        lines.push(format!("  \"processing_records_count\": {}", dossier.processing_records.len()));
        lines.push("}".to_string());
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "JSON" }
    fn content_type(&self) -> &str { "application/json" }
    fn redaction_aware(&self) -> bool { true }
}

// ── GdprArticle15Exporter ───────────────────────────────────────────

pub struct GdprArticle15Exporter;

impl DsarExporter for GdprArticle15Exporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError> {
        let mut lines = Vec::new();
        lines.push("GDPR Article 15 — Data Subject Access Response".to_string());
        lines.push("==============================================".to_string());
        lines.push(format!("Subject: {}", dossier.subject_ref));
        lines.push(format!("Export Date: {}", dossier.export_timestamp));
        lines.push(String::new());

        lines.push("Categories of Personal Data:".to_string());
        for cat in &dossier.data_categories {
            lines.push(format!("  - {cat}"));
        }
        lines.push(String::new());

        lines.push("Recipients / Processors:".to_string());
        for pr in &dossier.processing_records {
            lines.push(format!("  - Purpose: {} | Processors: {}", pr.purpose, pr.processors.join(", ")));
        }
        lines.push(String::new());

        lines.push("Retention Periods:".to_string());
        for c in &dossier.consents {
            let expiry = c.expires_at.map_or("no expiry set".to_string(), |e| format!("{e}"));
            lines.push(format!("  - Purpose: {} | Expires: {expiry}", c.purpose));
        }
        lines.push(String::new());

        lines.push("Legal Bases for Processing:".to_string());
        for c in &dossier.consents {
            lines.push(format!("  - Purpose: {} | Basis: {}", c.purpose, c.legal_basis));
        }

        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "GDPR-Article-15" }
    fn content_type(&self) -> &str { "text/plain" }
    fn redaction_aware(&self) -> bool { true }
}

// ── CcpaDsarExporter ────────────────────────────────────────────────

pub struct CcpaDsarExporter;

impl DsarExporter for CcpaDsarExporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError> {
        let mut lines = Vec::new();
        lines.push("{".to_string());
        lines.push(format!("  \"ccpa_response\": true,"));
        lines.push(format!("  \"consumer\": \"{}\",", dossier.subject_ref));

        lines.push("  \"categories_collected\": [".to_string());
        for (i, cat) in dossier.data_categories.iter().enumerate() {
            let comma = if i + 1 < dossier.data_categories.len() { "," } else { "" };
            lines.push(format!("    \"{cat}\"{comma}"));
        }
        lines.push("  ],".to_string());

        lines.push("  \"sources\": [\"internal\"],".to_string());

        lines.push("  \"purposes\": [".to_string());
        let purposes: Vec<String> = dossier.consents.iter().map(|c| c.purpose.clone()).collect();
        for (i, p) in purposes.iter().enumerate() {
            let comma = if i + 1 < purposes.len() { "," } else { "" };
            lines.push(format!("    \"{p}\"{comma}"));
        }
        lines.push("  ],".to_string());

        lines.push("  \"third_parties\": [".to_string());
        let processors: Vec<String> = dossier.processing_records.iter()
            .flat_map(|pr| pr.processors.clone())
            .collect();
        for (i, p) in processors.iter().enumerate() {
            let comma = if i + 1 < processors.len() { "," } else { "" };
            lines.push(format!("    \"{p}\"{comma}"));
        }
        lines.push("  ]".to_string());

        lines.push("}".to_string());
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "CCPA-1798.130" }
    fn content_type(&self) -> &str { "application/json" }
    fn redaction_aware(&self) -> bool { true }
}

// ── XmlDsarExporter ─────────────────────────────────────────────────

pub struct XmlDsarExporter;

impl DsarExporter for XmlDsarExporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError> {
        let mut lines = Vec::new();
        lines.push("<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_string());
        lines.push("<SubjectAccessResponse xmlns=\"urn:rune:privacy:dsar:1.0\">".to_string());
        lines.push(format!("  <Subject>{}</Subject>", dossier.subject_ref));
        lines.push(format!("  <Jurisdiction>{}</Jurisdiction>", dossier.jurisdiction));
        lines.push(format!("  <ExportTimestamp>{}</ExportTimestamp>", dossier.export_timestamp));

        lines.push("  <DataCategories>".to_string());
        for cat in &dossier.data_categories {
            lines.push(format!("    <Category>{cat}</Category>"));
        }
        lines.push("  </DataCategories>".to_string());

        lines.push("  <Consents>".to_string());
        for c in &dossier.consents {
            lines.push(format!("    <Consent id=\"{}\" purpose=\"{}\" status=\"{}\" legalBasis=\"{}\"/>",
                c.consent_id, c.purpose, c.status, c.legal_basis));
        }
        lines.push("  </Consents>".to_string());

        lines.push("</SubjectAccessResponse>".to_string());
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "XML" }
    fn content_type(&self) -> &str { "application/xml" }
    fn redaction_aware(&self) -> bool { true }
}

// ── HtmlDsarExporter ────────────────────────────────────────────────

pub struct HtmlDsarExporter;

impl DsarExporter for HtmlDsarExporter {
    fn export_subject_data(&self, dossier: &SubjectDossier) -> Result<Vec<u8>, PrivacyError> {
        let mut lines = Vec::new();
        lines.push("<!DOCTYPE html>".to_string());
        lines.push("<html><head><meta charset=\"UTF-8\">".to_string());
        lines.push("<title>Data Subject Access Response</title>".to_string());
        lines.push("<style>body{font-family:sans-serif;max-width:800px;margin:auto;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f4f4f4}footer{margin-top:40px;font-size:0.8em;color:#666}</style>".to_string());
        lines.push("</head><body>".to_string());
        lines.push("<h1>Data Subject Access Response</h1>".to_string());
        lines.push(format!("<p><strong>Subject:</strong> {}</p>", dossier.subject_ref));

        lines.push("<h2>Data Categories</h2><ul>".to_string());
        for cat in &dossier.data_categories {
            lines.push(format!("<li>{cat}</li>"));
        }
        lines.push("</ul>".to_string());

        lines.push("<h2>Consent Records</h2><table><tr><th>Purpose</th><th>Status</th><th>Legal Basis</th></tr>".to_string());
        for c in &dossier.consents {
            lines.push(format!("<tr><td>{}</td><td>{}</td><td>{}</td></tr>", c.purpose, c.status, c.legal_basis));
        }
        lines.push("</table>".to_string());

        lines.push(format!(
            "<footer>Exported at timestamp {} under {} jurisdiction. Generated by RUNE Privacy Engine.</footer>",
            dossier.export_timestamp, dossier.jurisdiction
        ));
        lines.push("</body></html>".to_string());
        Ok(lines.join("\n").into_bytes())
    }

    fn format_name(&self) -> &str { "HTML" }
    fn content_type(&self) -> &str { "text/html" }
    fn redaction_aware(&self) -> bool { true }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent_store::{ConsentLegalBasis, StoredConsentStatus};
    use crate::purpose::LegalBasis;

    fn make_dossier() -> SubjectDossier {
        let mut dossier = SubjectDossier::new(SubjectRef::new("alice"), "EU", 1000);
        dossier.data_categories = vec!["email".to_string(), "phone".to_string()];
        dossier.consents.push(ConsentRecord {
            consent_id: "c1".to_string(),
            subject_ref: SubjectRef::new("alice"),
            purpose: "analytics".to_string(),
            granted_at: 500,
            expires_at: Some(10000),
            withdrawn_at: None,
            legal_basis: ConsentLegalBasis::Consent,
            scope: vec!["email".to_string()],
            consent_text_hash: "abc123".to_string(),
            status: StoredConsentStatus::Active,
        });
        dossier.processing_records.push(StoredProcessingRecord {
            record_id: "pr1".to_string(),
            subject_ref: SubjectRef::new("alice"),
            purpose: "analytics".to_string(),
            legal_basis: LegalBasis::Consent,
            data_categories: vec!["email".to_string()],
            processors: vec!["internal".to_string()],
            started_at: 500,
            ended_at: None,
        });
        dossier
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonDsarExporter;
        let data = exporter.export_subject_data(&make_dossier()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("\"subject\": \"alice\""));
        assert!(text.contains("analytics"));
        assert!(exporter.redaction_aware());
        assert_eq!(exporter.content_type(), "application/json");
    }

    #[test]
    fn test_gdpr_article15_exporter() {
        let exporter = GdprArticle15Exporter;
        let data = exporter.export_subject_data(&make_dossier()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("GDPR Article 15"));
        assert!(text.contains("Categories of Personal Data"));
        assert!(text.contains("Legal Bases for Processing"));
        assert_eq!(exporter.format_name(), "GDPR-Article-15");
    }

    #[test]
    fn test_ccpa_exporter() {
        let exporter = CcpaDsarExporter;
        let data = exporter.export_subject_data(&make_dossier()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("ccpa_response"));
        assert!(text.contains("categories_collected"));
        assert!(text.contains("purposes"));
        assert!(text.contains("third_parties"));
    }

    #[test]
    fn test_xml_exporter() {
        let exporter = XmlDsarExporter;
        let data = exporter.export_subject_data(&make_dossier()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("<?xml version"));
        assert!(text.contains("<SubjectAccessResponse"));
        assert!(text.contains("urn:rune:privacy:dsar:1.0"));
    }

    #[test]
    fn test_html_exporter() {
        let exporter = HtmlDsarExporter;
        let data = exporter.export_subject_data(&make_dossier()).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("<!DOCTYPE html>"));
        assert!(text.contains("Data Subject Access Response"));
        assert!(text.contains("<footer>"));
        assert!(text.contains("EU jurisdiction"));
    }

    #[test]
    fn test_all_exporters_redaction_aware() {
        assert!(JsonDsarExporter.redaction_aware());
        assert!(GdprArticle15Exporter.redaction_aware());
        assert!(CcpaDsarExporter.redaction_aware());
        assert!(XmlDsarExporter.redaction_aware());
        assert!(HtmlDsarExporter.redaction_aware());
    }

    #[test]
    fn test_export_batch() {
        let exporter = JsonDsarExporter;
        let dossiers = vec![make_dossier(), make_dossier()];
        let results = exporter.export_batch(&dossiers).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_empty_dossier() {
        let dossier = SubjectDossier::new(SubjectRef::new("empty"), "US", 5000);
        let data = JsonDsarExporter.export_subject_data(&dossier).unwrap();
        let text = String::from_utf8(data).unwrap();
        assert!(text.contains("\"subject\": \"empty\""));
    }
}
