// ═══════════════════════════════════════════════════════════════════════
// Content Ingestor — Trait for normalizing content from multiple
// source formats into canonical UTF-8 text before storage.
//
// Only Markdown, plain text, and HTML (tag-stripping) ingestors are
// shipped.  PDF text extraction, DOCX parsing, and email MIME parsing
// require full format libraries that belong in adapter crates.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::fmt;

use crate::error::DocumentError;

// ── ContentSourceFormat ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContentSourceFormat {
    MarkdownText,
    PlainText,
    HtmlDocument,
    DocxXml,
    OdtXml,
    RtfDocument,
    PdfText,
    EmailMime,
    CsvTabular,
    Custom { format_name: String },
}

impl fmt::Display for ContentSourceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MarkdownText => write!(f, "markdown"),
            Self::PlainText => write!(f, "plain-text"),
            Self::HtmlDocument => write!(f, "html"),
            Self::DocxXml => write!(f, "docx-xml"),
            Self::OdtXml => write!(f, "odt-xml"),
            Self::RtfDocument => write!(f, "rtf"),
            Self::PdfText => write!(f, "pdf-text"),
            Self::EmailMime => write!(f, "email-mime"),
            Self::CsvTabular => write!(f, "csv"),
            Self::Custom { format_name } => write!(f, "custom({format_name})"),
        }
    }
}

// ── NormalizedContent ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedContent {
    pub content_id: String,
    pub source_format: ContentSourceFormat,
    pub canonical_text: String,
    pub extracted_metadata: HashMap<String, String>,
    pub extraction_confidence: String,
    pub warnings: Vec<String>,
}

// ── ContentIngestor trait ──────────────────────────────────────

pub trait ContentIngestor {
    fn ingest_content(
        &self,
        raw_bytes: &[u8],
        source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError>;

    fn ingest_stream(
        &self,
        chunks: &[&[u8]],
        source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError> {
        let mut combined = Vec::new();
        for chunk in chunks {
            combined.extend_from_slice(chunk);
        }
        self.ingest_content(&combined, source_format, content_id)
    }

    fn supported_formats(&self) -> Vec<ContentSourceFormat>;
    fn ingestor_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── MarkdownContentIngestor ────────────────────────────────────

pub struct MarkdownContentIngestor {
    id: String,
}

impl MarkdownContentIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ContentIngestor for MarkdownContentIngestor {
    fn ingest_content(
        &self,
        raw_bytes: &[u8],
        _source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError> {
        let text = String::from_utf8_lossy(raw_bytes);
        let mut metadata = HashMap::new();
        metadata.insert("line_count".into(), text.lines().count().to_string());

        Ok(NormalizedContent {
            content_id: content_id.to_string(),
            source_format: ContentSourceFormat::MarkdownText,
            canonical_text: text.into_owned(),
            extracted_metadata: metadata,
            extraction_confidence: "1.0".to_string(),
            warnings: Vec::new(),
        })
    }

    fn supported_formats(&self) -> Vec<ContentSourceFormat> {
        vec![ContentSourceFormat::MarkdownText]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── PlainTextContentIngestor ───────────────────────────────────

pub struct PlainTextContentIngestor {
    id: String,
}

impl PlainTextContentIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ContentIngestor for PlainTextContentIngestor {
    fn ingest_content(
        &self,
        raw_bytes: &[u8],
        _source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError> {
        let text = String::from_utf8_lossy(raw_bytes);
        let mut metadata = HashMap::new();
        metadata.insert("byte_length".into(), raw_bytes.len().to_string());

        Ok(NormalizedContent {
            content_id: content_id.to_string(),
            source_format: ContentSourceFormat::PlainText,
            canonical_text: text.into_owned(),
            extracted_metadata: metadata,
            extraction_confidence: "1.0".to_string(),
            warnings: Vec::new(),
        })
    }

    fn supported_formats(&self) -> Vec<ContentSourceFormat> {
        vec![ContentSourceFormat::PlainText]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── HtmlContentIngestor ────────────────────────────────────────

pub struct HtmlContentIngestor {
    id: String,
}

impl HtmlContentIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }

    fn strip_tags(html: &str) -> String {
        let mut result = String::with_capacity(html.len());
        let mut in_tag = false;
        let mut in_entity = false;
        let mut entity_buf = String::new();

        for ch in html.chars() {
            if in_entity {
                entity_buf.push(ch);
                if ch == ';' {
                    let decoded = match entity_buf.as_str() {
                        "&amp;" => "&",
                        "&lt;" => "<",
                        "&gt;" => ">",
                        "&quot;" => "\"",
                        "&apos;" => "'",
                        "&#39;" => "'",
                        "&nbsp;" => " ",
                        _ => "",
                    };
                    result.push_str(decoded);
                    in_entity = false;
                    entity_buf.clear();
                }
                continue;
            }
            match ch {
                '<' => in_tag = true,
                '>' => {
                    in_tag = false;
                    result.push(' ');
                }
                '&' if !in_tag => {
                    in_entity = true;
                    entity_buf.clear();
                    entity_buf.push('&');
                }
                _ if !in_tag => result.push(ch),
                _ => {}
            }
        }

        // Collapse whitespace
        let mut collapsed = String::with_capacity(result.len());
        let mut last_was_space = true;
        for ch in result.chars() {
            if ch.is_whitespace() {
                if !last_was_space {
                    collapsed.push(' ');
                    last_was_space = true;
                }
            } else {
                collapsed.push(ch);
                last_was_space = false;
            }
        }
        collapsed.trim().to_string()
    }
}

impl ContentIngestor for HtmlContentIngestor {
    fn ingest_content(
        &self,
        raw_bytes: &[u8],
        _source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError> {
        let html = String::from_utf8_lossy(raw_bytes);
        let canonical = Self::strip_tags(&html);

        let mut metadata = HashMap::new();
        metadata.insert("original_byte_length".into(), raw_bytes.len().to_string());
        metadata.insert("stripped_char_length".into(), canonical.len().to_string());

        let mut warnings = Vec::new();
        if html.contains("<script") {
            warnings.push("Script tags detected and stripped".to_string());
        }

        Ok(NormalizedContent {
            content_id: content_id.to_string(),
            source_format: ContentSourceFormat::HtmlDocument,
            canonical_text: canonical,
            extracted_metadata: metadata,
            extraction_confidence: "0.9".to_string(),
            warnings,
        })
    }

    fn supported_formats(&self) -> Vec<ContentSourceFormat> {
        vec![ContentSourceFormat::HtmlDocument]
    }

    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullContentIngestor ────────────────────────────────────────

pub struct NullContentIngestor {
    id: String,
}

impl NullContentIngestor {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ContentIngestor for NullContentIngestor {
    fn ingest_content(
        &self,
        _raw_bytes: &[u8],
        source_format: &ContentSourceFormat,
        content_id: &str,
    ) -> Result<NormalizedContent, DocumentError> {
        Ok(NormalizedContent {
            content_id: content_id.to_string(),
            source_format: source_format.clone(),
            canonical_text: String::new(),
            extracted_metadata: HashMap::new(),
            extraction_confidence: "0".to_string(),
            warnings: vec!["Null ingestor — no extraction performed".to_string()],
        })
    }

    fn supported_formats(&self) -> Vec<ContentSourceFormat> { vec![] }
    fn ingestor_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_source_format_display() {
        assert_eq!(ContentSourceFormat::MarkdownText.to_string(), "markdown");
        assert_eq!(ContentSourceFormat::PlainText.to_string(), "plain-text");
        assert_eq!(ContentSourceFormat::HtmlDocument.to_string(), "html");
        assert_eq!(ContentSourceFormat::DocxXml.to_string(), "docx-xml");
        assert_eq!(ContentSourceFormat::PdfText.to_string(), "pdf-text");
        assert_eq!(ContentSourceFormat::Custom { format_name: "x".into() }.to_string(), "custom(x)");
    }

    #[test]
    fn test_markdown_ingestor() {
        let ingestor = MarkdownContentIngestor::new("md-1");
        let content = b"# Hello\n\nWorld";
        let result = ingestor.ingest_content(content, &ContentSourceFormat::MarkdownText, "c1").unwrap();
        assert_eq!(result.canonical_text, "# Hello\n\nWorld");
        assert_eq!(result.extraction_confidence, "1.0");
        assert!(result.warnings.is_empty());
        assert_eq!(ingestor.ingestor_id(), "md-1");
        assert!(ingestor.is_active());
    }

    #[test]
    fn test_plain_text_ingestor() {
        let ingestor = PlainTextContentIngestor::new("pt-1");
        let content = b"Hello world";
        let result = ingestor.ingest_content(content, &ContentSourceFormat::PlainText, "c1").unwrap();
        assert_eq!(result.canonical_text, "Hello world");
        assert_eq!(result.extracted_metadata.get("byte_length").unwrap(), "11");
    }

    #[test]
    fn test_html_ingestor_strips_tags() {
        let ingestor = HtmlContentIngestor::new("html-1");
        let content = b"<html><body><h1>Title</h1><p>Hello &amp; world</p></body></html>";
        let result = ingestor.ingest_content(content, &ContentSourceFormat::HtmlDocument, "c1").unwrap();
        assert!(result.canonical_text.contains("Title"));
        assert!(result.canonical_text.contains("Hello & world"));
        assert!(!result.canonical_text.contains("<"));
    }

    #[test]
    fn test_html_ingestor_decodes_entities() {
        let ingestor = HtmlContentIngestor::new("html-1");
        let content = b"&lt;script&gt; &amp; &quot;test&quot;";
        let result = ingestor.ingest_content(content, &ContentSourceFormat::HtmlDocument, "c1").unwrap();
        assert!(result.canonical_text.contains("<script>"));
        assert!(result.canonical_text.contains("& \"test\""));
    }

    #[test]
    fn test_html_ingestor_warns_on_script() {
        let ingestor = HtmlContentIngestor::new("html-1");
        let content = b"<p>text</p><script>alert(1)</script>";
        let result = ingestor.ingest_content(content, &ContentSourceFormat::HtmlDocument, "c1").unwrap();
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_ingest_stream() {
        let ingestor = PlainTextContentIngestor::new("pt-1");
        let chunks: Vec<&[u8]> = vec![b"hello ", b"world"];
        let result = ingestor.ingest_stream(&chunks, &ContentSourceFormat::PlainText, "c1").unwrap();
        assert_eq!(result.canonical_text, "hello world");
    }

    #[test]
    fn test_null_ingestor() {
        let ingestor = NullContentIngestor::new("null-1");
        let result = ingestor.ingest_content(b"data", &ContentSourceFormat::PlainText, "c1").unwrap();
        assert!(result.canonical_text.is_empty());
        assert!(!ingestor.is_active());
        assert!(ingestor.supported_formats().is_empty());
    }

    #[test]
    fn test_supported_formats() {
        let md = MarkdownContentIngestor::new("md");
        assert_eq!(md.supported_formats(), vec![ContentSourceFormat::MarkdownText]);
        let html = HtmlContentIngestor::new("html");
        assert_eq!(html.supported_formats(), vec![ContentSourceFormat::HtmlDocument]);
    }
}
