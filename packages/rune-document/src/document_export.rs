// ═══════════════════════════════════════════════════════════════════════
// Document Exporter — Trait for serializing documents into structured
// interchange formats.
//
// Five implementations cover the distinct document consumption modes:
//   - JSON (programmatic consumption)
//   - PDF/A-3 (archival — structure only, byte-stream in adapter crates)
//   - DITA 1.3 (OASIS technical documentation)
//   - DocBook 5.1 (structured content)
//   - Atom 1.0 (RFC 4287 feed syndication)
//
// All five preserve attestation_refs and retention_policy_ref for
// downstream provenance and retention linkage.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use crate::error::DocumentError;

// ── ExportableDocument ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportableDocument {
    pub document_id: String,
    pub title: String,
    pub description: String,
    pub author: String,
    pub category: String,
    pub classification_level: String,
    pub content: String,
    pub version: String,
    pub created_at: i64,
    pub last_modified_at: i64,
    pub content_sha3_hash: String,
    pub metadata: HashMap<String, String>,
    pub attestation_refs: Vec<String>,
    pub retention_policy_ref: Option<String>,
}

// ── DocumentExporter trait ─────────────────────────────────────

pub trait DocumentExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError>;
    fn export_document_with_metadata(
        &self,
        doc: &ExportableDocument,
    ) -> Result<Vec<u8>, DocumentError>;
    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError>;
    fn format_name(&self) -> &str;
    fn content_type(&self) -> &str;
}

// ── JsonDocumentExporter ───────────────────────────────────────

pub struct JsonDocumentExporter;

impl Default for JsonDocumentExporter {
    fn default() -> Self { Self }
}

impl JsonDocumentExporter {
    pub fn new() -> Self { Self }

    fn doc_to_json(doc: &ExportableDocument) -> serde_json::Value {
        serde_json::json!({
            "document_id": doc.document_id,
            "title": doc.title,
            "description": doc.description,
            "author": doc.author,
            "category": doc.category,
            "classification_level": doc.classification_level,
            "content": doc.content,
            "version": doc.version,
            "created_at": doc.created_at,
            "last_modified_at": doc.last_modified_at,
            "content_sha3_hash": doc.content_sha3_hash,
            "metadata": doc.metadata,
            "attestation_refs": doc.attestation_refs,
            "retention_policy_ref": doc.retention_policy_ref,
        })
    }
}

impl DocumentExporter for JsonDocumentExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        serde_json::to_vec_pretty(&Self::doc_to_json(doc))
            .map_err(|e| DocumentError::SerializationFailed(e.to_string()))
    }

    fn export_document_with_metadata(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        let mut json = Self::doc_to_json(doc);
        let obj = json.as_object_mut().unwrap();
        obj.insert("_export_format".into(), serde_json::Value::String("json".into()));
        obj.insert("_export_version".into(), serde_json::Value::String("1.0".into()));
        serde_json::to_vec_pretty(&json)
            .map_err(|e| DocumentError::SerializationFailed(e.to_string()))
    }

    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError> {
        let arr: Vec<serde_json::Value> = docs.iter().map(Self::doc_to_json).collect();
        serde_json::to_vec_pretty(&arr)
            .map_err(|e| DocumentError::SerializationFailed(e.to_string()))
    }

    fn format_name(&self) -> &str { "json" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── PdfAExporter ───────────────────────────────────────────────

pub struct PdfAExporter;

impl Default for PdfAExporter {
    fn default() -> Self { Self }
}

impl PdfAExporter {
    pub fn new() -> Self { Self }
}

impl DocumentExporter for PdfAExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        let structure = serde_json::json!({
            "pdfa_conformance": "PDF/A-3",
            "iso_standard": "ISO 19005-3",
            "document_id_hash": doc.content_sha3_hash,
            "xmp_metadata": {
                "dc:title": doc.title,
                "dc:creator": doc.author,
                "dc:description": doc.description,
                "dc:date": doc.created_at,
                "pdfaid:part": 3,
                "pdfaid:conformance": "B",
            },
            "font_embedding": "required",
            "content_stream": {
                "text": doc.content,
                "version": doc.version,
            },
            "attestation_refs": doc.attestation_refs,
            "retention_policy_ref": doc.retention_policy_ref,
        });
        serde_json::to_vec_pretty(&structure)
            .map_err(|e| DocumentError::SerializationFailed(e.to_string()))
    }

    fn export_document_with_metadata(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        let mut structure = serde_json::json!({
            "pdfa_conformance": "PDF/A-3",
            "iso_standard": "ISO 19005-3",
            "document_id_hash": doc.content_sha3_hash,
            "xmp_metadata": {
                "dc:title": doc.title,
                "dc:creator": doc.author,
                "dc:description": doc.description,
                "dc:date": doc.created_at,
                "pdfaid:part": 3,
                "pdfaid:conformance": "B",
            },
            "font_embedding": "required",
            "content_stream": {
                "text": doc.content,
                "version": doc.version,
            },
            "attestation_refs": doc.attestation_refs,
            "retention_policy_ref": doc.retention_policy_ref,
        });
        let obj = structure.as_object_mut().unwrap();
        obj.insert("document_metadata".into(), serde_json::json!(doc.metadata));
        obj.insert("classification_level".into(), serde_json::Value::String(doc.classification_level.clone()));
        serde_json::to_vec_pretty(&structure)
            .map_err(|e| DocumentError::SerializationFailed(e.to_string()))
    }

    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError> {
        let mut results = Vec::new();
        for doc in docs {
            let exported = self.export_document(doc)?;
            results.extend_from_slice(&exported);
            results.push(b'\n');
        }
        Ok(results)
    }

    fn format_name(&self) -> &str { "pdf-a-3" }
    fn content_type(&self) -> &str { "application/json" }
}

// ── DitaTopicExporter ──────────────────────────────────────────

pub struct DitaTopicExporter;

impl Default for DitaTopicExporter {
    fn default() -> Self { Self }
}

impl DitaTopicExporter {
    pub fn new() -> Self { Self }

    fn render_topic(doc: &ExportableDocument, include_metadata: bool) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<!DOCTYPE topic PUBLIC \"-//OASIS//DTD DITA Topic//EN\" \"topic.dtd\">\n");
        xml.push_str(&format!("<topic id=\"{}\">\n", doc.document_id));
        xml.push_str(&format!("  <title>{}</title>\n", doc.title));
        xml.push_str("  <prolog>\n");
        xml.push_str(&format!("    <author>{}</author>\n", doc.author));
        xml.push_str(&format!("    <critdates><created date=\"{}\"/></critdates>\n", doc.created_at));
        if include_metadata {
            for (key, value) in &doc.metadata {
                xml.push_str(&format!("    <metadata><othermeta name=\"{}\" content=\"{}\"/></metadata>\n", key, value));
            }
        }
        for att_ref in &doc.attestation_refs {
            xml.push_str(&format!("    <metadata><othermeta name=\"attestation_ref\" content=\"{}\"/></metadata>\n", att_ref));
        }
        if let Some(ref ret_ref) = doc.retention_policy_ref {
            xml.push_str(&format!("    <metadata><othermeta name=\"retention_policy_ref\" content=\"{}\"/></metadata>\n", ret_ref));
        }
        xml.push_str("  </prolog>\n");
        xml.push_str("  <body>\n");
        xml.push_str(&format!("    <p>{}</p>\n", doc.content));
        xml.push_str("  </body>\n");
        xml.push_str("</topic>\n");
        xml
    }
}

impl DocumentExporter for DitaTopicExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        Ok(Self::render_topic(doc, false).into_bytes())
    }

    fn export_document_with_metadata(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        Ok(Self::render_topic(doc, true).into_bytes())
    }

    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError> {
        let mut result = Vec::new();
        for doc in docs {
            result.extend_from_slice(&Self::render_topic(doc, false).into_bytes());
        }
        Ok(result)
    }

    fn format_name(&self) -> &str { "dita-1.3" }
    fn content_type(&self) -> &str { "application/xml" }
}

// ── DocbookExporter ────────────────────────────────────────────

pub struct DocbookExporter;

impl Default for DocbookExporter {
    fn default() -> Self { Self }
}

impl DocbookExporter {
    pub fn new() -> Self { Self }

    fn render(doc: &ExportableDocument, include_metadata: bool) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<article xmlns=\"http://docbook.org/ns/docbook\" version=\"5.1\">\n");
        xml.push_str("  <info>\n");
        xml.push_str(&format!("    <title>{}</title>\n", doc.title));
        xml.push_str(&format!("    <author><personname>{}</personname></author>\n", doc.author));
        xml.push_str(&format!("    <date>{}</date>\n", doc.created_at));
        if include_metadata {
            for (key, value) in &doc.metadata {
                xml.push_str(&format!("    <bibliomisc role=\"{}\">{}</bibliomisc>\n", key, value));
            }
        }
        for att_ref in &doc.attestation_refs {
            xml.push_str(&format!("    <bibliomisc role=\"attestation_ref\">{}</bibliomisc>\n", att_ref));
        }
        if let Some(ref ret_ref) = doc.retention_policy_ref {
            xml.push_str(&format!("    <bibliomisc role=\"retention_policy_ref\">{}</bibliomisc>\n", ret_ref));
        }
        xml.push_str("  </info>\n");
        xml.push_str("  <simpara>\n");
        xml.push_str(&format!("    {}\n", doc.content));
        xml.push_str("  </simpara>\n");
        xml.push_str("</article>\n");
        xml
    }
}

impl DocumentExporter for DocbookExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        Ok(Self::render(doc, false).into_bytes())
    }

    fn export_document_with_metadata(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        Ok(Self::render(doc, true).into_bytes())
    }

    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError> {
        let mut result = Vec::new();
        for doc in docs {
            result.extend_from_slice(&Self::render(doc, false).into_bytes());
        }
        Ok(result)
    }

    fn format_name(&self) -> &str { "docbook-5.1" }
    fn content_type(&self) -> &str { "application/xml" }
}

// ── AtomFeedExporter ───────────────────────────────────────────

pub struct AtomFeedExporter {
    feed_id: String,
    feed_title: String,
}

impl AtomFeedExporter {
    pub fn new(feed_id: &str, feed_title: &str) -> Self {
        Self {
            feed_id: feed_id.to_string(),
            feed_title: feed_title.to_string(),
        }
    }

    fn render_entry(doc: &ExportableDocument) -> String {
        let mut xml = String::new();
        xml.push_str("  <entry>\n");
        xml.push_str(&format!("    <id>{}</id>\n", doc.document_id));
        xml.push_str(&format!("    <title>{}</title>\n", doc.title));
        xml.push_str(&format!("    <updated>{}</updated>\n", doc.last_modified_at));
        xml.push_str(&format!("    <author><name>{}</name></author>\n", doc.author));
        xml.push_str(&format!("    <summary>{}</summary>\n", doc.description));
        xml.push_str(&format!("    <content type=\"text\">{}</content>\n", doc.content));
        for att_ref in &doc.attestation_refs {
            xml.push_str(&format!("    <link rel=\"attestation\" href=\"{}\"/>\n", att_ref));
        }
        if let Some(ref ret_ref) = doc.retention_policy_ref {
            xml.push_str(&format!("    <link rel=\"retention-policy\" href=\"{}\"/>\n", ret_ref));
        }
        xml.push_str("  </entry>\n");
        xml
    }
}

impl DocumentExporter for AtomFeedExporter {
    fn export_document(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
        xml.push_str(&format!("  <id>{}</id>\n", self.feed_id));
        xml.push_str(&format!("  <title>{}</title>\n", self.feed_title));
        xml.push_str(&format!("  <updated>{}</updated>\n", doc.last_modified_at));
        xml.push_str(&Self::render_entry(doc));
        xml.push_str("</feed>\n");
        Ok(xml.into_bytes())
    }

    fn export_document_with_metadata(&self, doc: &ExportableDocument) -> Result<Vec<u8>, DocumentError> {
        self.export_document(doc)
    }

    fn export_batch(&self, docs: &[ExportableDocument]) -> Result<Vec<u8>, DocumentError> {
        let latest_updated = docs.iter().map(|d| d.last_modified_at).max().unwrap_or(0);
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<feed xmlns=\"http://www.w3.org/2005/Atom\">\n");
        xml.push_str(&format!("  <id>{}</id>\n", self.feed_id));
        xml.push_str(&format!("  <title>{}</title>\n", self.feed_title));
        xml.push_str(&format!("  <updated>{}</updated>\n", latest_updated));
        for doc in docs {
            xml.push_str(&Self::render_entry(doc));
        }
        xml.push_str("</feed>\n");
        Ok(xml.into_bytes())
    }

    fn format_name(&self) -> &str { "atom-1.0" }
    fn content_type(&self) -> &str { "application/atom+xml" }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> ExportableDocument {
        ExportableDocument {
            document_id: "doc-1".into(),
            title: "Security Policy".into(),
            description: "Corporate security policy".into(),
            author: "alice".into(),
            category: "policy".into(),
            classification_level: "internal".into(),
            content: "All employees must use MFA.".into(),
            version: "1.0".into(),
            created_at: 1000,
            last_modified_at: 2000,
            content_sha3_hash: "abc123".into(),
            metadata: HashMap::from([("dept".into(), "security".into())]),
            attestation_refs: vec!["att-1".into()],
            retention_policy_ref: Some("rp-1".into()),
        }
    }

    #[test]
    fn test_json_exporter() {
        let exporter = JsonDocumentExporter::new();
        let doc = sample_doc();
        let result = exporter.export_document(&doc).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("doc-1"));
        assert!(text.contains("att-1"));
        assert!(text.contains("rp-1"));
        assert_eq!(exporter.format_name(), "json");
    }

    #[test]
    fn test_json_with_metadata() {
        let exporter = JsonDocumentExporter::new();
        let result = exporter.export_document_with_metadata(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("_export_format"));
    }

    #[test]
    fn test_json_batch() {
        let exporter = JsonDocumentExporter::new();
        let doc = sample_doc();
        let result = exporter.export_batch(&[doc.clone(), doc]).unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_slice(&result).unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_pdfa_exporter() {
        let exporter = PdfAExporter::new();
        let result = exporter.export_document(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("PDF/A-3"));
        assert!(text.contains("ISO 19005-3"));
        assert!(text.contains("att-1"));
        assert_eq!(exporter.format_name(), "pdf-a-3");
    }

    #[test]
    fn test_pdfa_with_metadata() {
        let exporter = PdfAExporter::new();
        let result = exporter.export_document_with_metadata(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("classification_level"));
    }

    #[test]
    fn test_dita_exporter() {
        let exporter = DitaTopicExporter::new();
        let result = exporter.export_document(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("<topic"));
        assert!(text.contains("<title>Security Policy</title>"));
        assert!(text.contains("attestation_ref"));
        assert!(text.contains("retention_policy_ref"));
        assert_eq!(exporter.format_name(), "dita-1.3");
        assert_eq!(exporter.content_type(), "application/xml");
    }

    #[test]
    fn test_dita_with_metadata() {
        let exporter = DitaTopicExporter::new();
        let result = exporter.export_document_with_metadata(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("dept"));
    }

    #[test]
    fn test_docbook_exporter() {
        let exporter = DocbookExporter::new();
        let result = exporter.export_document(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("<article"));
        assert!(text.contains("docbook.org"));
        assert!(text.contains("version=\"5.1\""));
        assert!(text.contains("attestation_ref"));
        assert_eq!(exporter.format_name(), "docbook-5.1");
    }

    #[test]
    fn test_atom_exporter() {
        let exporter = AtomFeedExporter::new("urn:rune:docs", "RUNE Documents");
        let result = exporter.export_document(&sample_doc()).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("<feed"));
        assert!(text.contains("Atom"));
        assert!(text.contains("<entry>"));
        assert!(text.contains("attestation"));
        assert!(text.contains("retention-policy"));
        assert_eq!(exporter.format_name(), "atom-1.0");
        assert_eq!(exporter.content_type(), "application/atom+xml");
    }

    #[test]
    fn test_atom_batch() {
        let exporter = AtomFeedExporter::new("urn:rune:docs", "RUNE Documents");
        let doc = sample_doc();
        let result = exporter.export_batch(&[doc.clone(), doc]).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert_eq!(text.matches("<entry>").count(), 2);
    }
}
