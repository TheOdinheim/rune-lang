// ═══════════════════════════════════════════════════════════════════════
// Content Format Converter — Layer 3 trait boundary for converting
// document content between formats.
//
// Ships Markdown→HTML and HTML→PlainText converters.  Richer
// conversions (Markdown→PDF, DOCX→HTML) belong in adapter crates with
// full format library dependencies.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::content_ingestion::ContentSourceFormat;
use crate::error::DocumentError;

// ── ConversionPair ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConversionPair {
    pub from: ContentSourceFormat,
    pub to: ContentSourceFormat,
}

impl fmt::Display for ConversionPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.from, self.to)
    }
}

// ── ContentFormatConverter trait ──────────────────────────────────

pub trait ContentFormatConverter {
    fn convert_content(
        &self,
        content: &str,
        from: &ContentSourceFormat,
        to: &ContentSourceFormat,
    ) -> Result<String, DocumentError>;

    fn supported_conversions(&self) -> Vec<ConversionPair>;
    fn converter_id(&self) -> &str;
    fn is_active(&self) -> bool;
}

// ── MarkdownToHtmlConverter ───────────────────────────────────────

#[derive(Default)]
pub struct MarkdownToHtmlConverter {
    id: String,
}

impl MarkdownToHtmlConverter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }

    fn convert_markdown(md: &str) -> String {
        let mut html = String::with_capacity(md.len() * 2);
        let mut in_code_block = false;
        let mut in_list = false;

        for line in md.lines() {
            // Fenced code blocks
            if line.starts_with("```") {
                if in_code_block {
                    html.push_str("</code></pre>\n");
                    in_code_block = false;
                } else {
                    html.push_str("<pre><code>");
                    in_code_block = true;
                }
                continue;
            }

            if in_code_block {
                html.push_str(&escape_html(line));
                html.push('\n');
                continue;
            }

            // Close list if line is not a list item
            if in_list && !line.starts_with("- ") && !line.starts_with("* ") {
                html.push_str("</ul>\n");
                in_list = false;
            }

            let trimmed = line.trim();

            // Blank lines
            if trimmed.is_empty() {
                continue;
            }

            // Headings
            if let Some(rest) = trimmed.strip_prefix("### ") {
                html.push_str(&format!("<h3>{}</h3>\n", Self::inline_markup(rest)));
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("## ") {
                html.push_str(&format!("<h2>{}</h2>\n", Self::inline_markup(rest)));
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("# ") {
                html.push_str(&format!("<h1>{}</h1>\n", Self::inline_markup(rest)));
                continue;
            }

            // Unordered list items
            if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")) {
                if !in_list {
                    html.push_str("<ul>\n");
                    in_list = true;
                }
                html.push_str(&format!("<li>{}</li>\n", Self::inline_markup(rest)));
                continue;
            }

            // Paragraph
            html.push_str(&format!("<p>{}</p>\n", Self::inline_markup(trimmed)));
        }

        if in_code_block {
            html.push_str("</code></pre>\n");
        }
        if in_list {
            html.push_str("</ul>\n");
        }

        html.trim_end().to_string()
    }

    fn inline_markup(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            // Bold (**text**)
            if i + 1 < len
                && chars[i] == '*'
                && chars[i + 1] == '*'
                && let Some(end) = find_closing(&chars, i + 2, &['*', '*'])
            {
                let inner: String = chars[i + 2..end].iter().collect();
                result.push_str(&format!("<strong>{inner}</strong>"));
                i = end + 2;
                continue;
            }

            // Emphasis (*text*)
            if chars[i] == '*'
                && let Some(end) = find_closing_single(&chars, i + 1, '*')
            {
                let inner: String = chars[i + 1..end].iter().collect();
                result.push_str(&format!("<em>{inner}</em>"));
                i = end + 1;
                continue;
            }

            // Inline code (`text`)
            if chars[i] == '`'
                && let Some(end) = find_closing_single(&chars, i + 1, '`')
            {
                let inner: String = chars[i + 1..end].iter().collect();
                result.push_str(&format!("<code>{inner}</code>"));
                i = end + 1;
                continue;
            }

            // Links [text](url)
            if chars[i] == '['
                && let Some(close_bracket) = find_closing_single(&chars, i + 1, ']')
                && close_bracket + 1 < len
                && chars[close_bracket + 1] == '('
                && let Some(close_paren) = find_closing_single(&chars, close_bracket + 2, ')')
            {
                let link_text: String = chars[i + 1..close_bracket].iter().collect();
                let url: String = chars[close_bracket + 2..close_paren].iter().collect();
                result.push_str(&format!("<a href=\"{url}\">{link_text}</a>"));
                i = close_paren + 1;
                continue;
            }

            // Images ![alt](src)
            if chars[i] == '!'
                && i + 1 < len
                && chars[i + 1] == '['
                && let Some(close_bracket) = find_closing_single(&chars, i + 2, ']')
                && close_bracket + 1 < len
                && chars[close_bracket + 1] == '('
                && let Some(close_paren) = find_closing_single(&chars, close_bracket + 2, ')')
            {
                let alt: String = chars[i + 2..close_bracket].iter().collect();
                let src: String = chars[close_bracket + 2..close_paren].iter().collect();
                result.push_str(&format!("<img src=\"{src}\" alt=\"{alt}\">"));
                i = close_paren + 1;
                continue;
            }

            result.push(chars[i]);
            i += 1;
        }

        result
    }
}

fn find_closing(chars: &[char], start: usize, pattern: &[char; 2]) -> Option<usize> {
    let len = chars.len();
    (start..len.saturating_sub(1)).find(|&j| chars[j] == pattern[0] && chars[j + 1] == pattern[1])
}

fn find_closing_single(chars: &[char], start: usize, ch: char) -> Option<usize> {
    (start..chars.len()).find(|&j| chars[j] == ch)
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl ContentFormatConverter for MarkdownToHtmlConverter {
    fn convert_content(
        &self,
        content: &str,
        from: &ContentSourceFormat,
        to: &ContentSourceFormat,
    ) -> Result<String, DocumentError> {
        if *from != ContentSourceFormat::MarkdownText || *to != ContentSourceFormat::HtmlDocument {
            return Err(DocumentError::InvalidOperation(format!(
                "MarkdownToHtmlConverter only supports markdown -> html, got {from} -> {to}"
            )));
        }
        Ok(Self::convert_markdown(content))
    }

    fn supported_conversions(&self) -> Vec<ConversionPair> {
        vec![ConversionPair {
            from: ContentSourceFormat::MarkdownText,
            to: ContentSourceFormat::HtmlDocument,
        }]
    }

    fn converter_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── HtmlToPlainTextConverter ──────────────────────────────────────

#[derive(Default)]
pub struct HtmlToPlainTextConverter {
    id: String,
}

impl HtmlToPlainTextConverter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }

    fn strip_to_text(html: &str) -> String {
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
                        "&apos;" | "&#39;" => "'",
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

impl ContentFormatConverter for HtmlToPlainTextConverter {
    fn convert_content(
        &self,
        content: &str,
        from: &ContentSourceFormat,
        to: &ContentSourceFormat,
    ) -> Result<String, DocumentError> {
        if *from != ContentSourceFormat::HtmlDocument || *to != ContentSourceFormat::PlainText {
            return Err(DocumentError::InvalidOperation(format!(
                "HtmlToPlainTextConverter only supports html -> plain-text, got {from} -> {to}"
            )));
        }
        Ok(Self::strip_to_text(content))
    }

    fn supported_conversions(&self) -> Vec<ConversionPair> {
        vec![ConversionPair {
            from: ContentSourceFormat::HtmlDocument,
            to: ContentSourceFormat::PlainText,
        }]
    }

    fn converter_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { true }
}

// ── NullContentFormatConverter ────────────────────────────────────

pub struct NullContentFormatConverter {
    id: String,
}

impl NullContentFormatConverter {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl ContentFormatConverter for NullContentFormatConverter {
    fn convert_content(
        &self,
        _content: &str,
        _from: &ContentSourceFormat,
        _to: &ContentSourceFormat,
    ) -> Result<String, DocumentError> {
        Err(DocumentError::InvalidOperation(
            "null converter performs no conversion".to_string(),
        ))
    }

    fn supported_conversions(&self) -> Vec<ConversionPair> { vec![] }
    fn converter_id(&self) -> &str { &self.id }
    fn is_active(&self) -> bool { false }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_pair_display() {
        let pair = ConversionPair {
            from: ContentSourceFormat::MarkdownText,
            to: ContentSourceFormat::HtmlDocument,
        };
        assert_eq!(pair.to_string(), "markdown -> html");
    }

    #[test]
    fn test_markdown_headings() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "# H1\n## H2\n### H3",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<h1>H1</h1>"));
        assert!(result.contains("<h2>H2</h2>"));
        assert!(result.contains("<h3>H3</h3>"));
    }

    #[test]
    fn test_markdown_paragraphs() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "Hello world",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<p>Hello world</p>"));
    }

    #[test]
    fn test_markdown_emphasis() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "This is *italic* and **bold**",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<em>italic</em>"));
        assert!(result.contains("<strong>bold</strong>"));
    }

    #[test]
    fn test_markdown_code_blocks() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "```\nfn main() {}\n```",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<pre><code>"));
        assert!(result.contains("fn main()"));
    }

    #[test]
    fn test_markdown_lists() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "- item one\n- item two",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<ul>"));
        assert!(result.contains("<li>item one</li>"));
        assert!(result.contains("<li>item two</li>"));
        assert!(result.contains("</ul>"));
    }

    #[test]
    fn test_markdown_links() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "[click](https://example.com)",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<a href=\"https://example.com\">click</a>"));
    }

    #[test]
    fn test_markdown_images() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "![logo](img.png)",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<img src=\"img.png\" alt=\"logo\">"));
    }

    #[test]
    fn test_html_to_plaintext() {
        let converter = HtmlToPlainTextConverter::new("html2txt");
        let result = converter
            .convert_content(
                "<h1>Title</h1><p>Hello &amp; world</p>",
                &ContentSourceFormat::HtmlDocument,
                &ContentSourceFormat::PlainText,
            )
            .unwrap();
        assert!(result.contains("Title"));
        assert!(result.contains("Hello & world"));
        assert!(!result.contains('<'));
    }

    #[test]
    fn test_html_to_plaintext_entities() {
        let converter = HtmlToPlainTextConverter::new("html2txt");
        let result = converter
            .convert_content(
                "&lt;tag&gt; &amp; &quot;quoted&quot;",
                &ContentSourceFormat::HtmlDocument,
                &ContentSourceFormat::PlainText,
            )
            .unwrap();
        assert!(result.contains("<tag>"));
        assert!(result.contains("& \"quoted\""));
    }

    #[test]
    fn test_wrong_format_rejected() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        assert!(converter
            .convert_content(
                "text",
                &ContentSourceFormat::PlainText,
                &ContentSourceFormat::HtmlDocument,
            )
            .is_err());

        let converter2 = HtmlToPlainTextConverter::new("html2txt");
        assert!(converter2
            .convert_content(
                "text",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::PlainText,
            )
            .is_err());
    }

    #[test]
    fn test_null_converter() {
        let converter = NullContentFormatConverter::new("null-1");
        assert!(!converter.is_active());
        assert!(converter.supported_conversions().is_empty());
        assert!(converter
            .convert_content(
                "x",
                &ContentSourceFormat::PlainText,
                &ContentSourceFormat::HtmlDocument,
            )
            .is_err());
    }

    #[test]
    fn test_supported_conversions() {
        let md = MarkdownToHtmlConverter::new("md");
        assert_eq!(md.supported_conversions().len(), 1);
        assert_eq!(
            md.supported_conversions()[0],
            ConversionPair {
                from: ContentSourceFormat::MarkdownText,
                to: ContentSourceFormat::HtmlDocument,
            }
        );

        let html = HtmlToPlainTextConverter::new("html");
        assert_eq!(html.supported_conversions().len(), 1);
    }

    #[test]
    fn test_converter_ids() {
        let md = MarkdownToHtmlConverter::new("my-md");
        assert_eq!(md.converter_id(), "my-md");
        assert!(md.is_active());

        let html = HtmlToPlainTextConverter::new("my-html");
        assert_eq!(html.converter_id(), "my-html");
        assert!(html.is_active());
    }

    #[test]
    fn test_markdown_inline_code() {
        let converter = MarkdownToHtmlConverter::new("md2html");
        let result = converter
            .convert_content(
                "Use `cargo test` to run",
                &ContentSourceFormat::MarkdownText,
                &ContentSourceFormat::HtmlDocument,
            )
            .unwrap();
        assert!(result.contains("<code>cargo test</code>"));
    }

    #[test]
    fn test_markdown_default() {
        let converter = MarkdownToHtmlConverter::default();
        assert!(converter.is_active());
    }

    #[test]
    fn test_html_to_plaintext_default() {
        let converter = HtmlToPlainTextConverter::default();
        assert!(converter.is_active());
    }
}
