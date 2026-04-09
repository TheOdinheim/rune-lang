// ═══════════════════════════════════════════════════════════════════════
// RUNE Documentation Generator — rune doc
//
// Extracts doc comments from .rune source files and generates Markdown
// documentation. Comments on lines immediately preceding a declaration
// are treated as doc comments.
// ═══════════════════════════════════════════════════════════════════════

use crate::ast::nodes::*;
use crate::lexer::scanner::Lexer;
use crate::parser::parser::Parser;

#[cfg(test)]
mod tests;

// ── Types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DocItemKind {
    Policy,
    Rule,
    Function,
    Type,
    Struct,
    Enum,
    Module,
}

impl std::fmt::Display for DocItemKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocItemKind::Policy => write!(f, "Policy"),
            DocItemKind::Rule => write!(f, "Rule"),
            DocItemKind::Function => write!(f, "Function"),
            DocItemKind::Type => write!(f, "Type"),
            DocItemKind::Struct => write!(f, "Struct"),
            DocItemKind::Enum => write!(f, "Enum"),
            DocItemKind::Module => write!(f, "Module"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DocItem {
    pub name: String,
    pub kind: DocItemKind,
    pub doc_comment: Option<String>,
    pub signature: String,
    pub children: Vec<DocItem>,
    pub line_number: u32,
}

// ── Doc extraction ──────────────────────────────────────────────────

pub fn extract_docs(source: &str) -> Vec<DocItem> {
    let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
    if !lex_errors.is_empty() {
        return Vec::new();
    }

    let (file, parse_errors) = Parser::new(tokens).parse();
    if !parse_errors.is_empty() {
        return Vec::new();
    }

    let source_lines: Vec<&str> = source.lines().collect();
    let mut items = Vec::new();

    for item in &file.items {
        if let Some(doc_item) = extract_item_doc(item, &source_lines) {
            items.push(doc_item);
        }
    }

    items
}

fn extract_item_doc(item: &Item, source_lines: &[&str]) -> Option<DocItem> {
    match &item.kind {
        ItemKind::Policy(policy) => {
            let line = policy.span.line;
            let comment = extract_comment_above(source_lines, line);
            let sig = format!("policy {}", policy.name.name);

            let children: Vec<DocItem> = policy
                .rules
                .iter()
                .map(|rule| {
                    let rule_line = rule.span.line;
                    let rule_comment = extract_comment_above(source_lines, rule_line);
                    let rule_sig = format_rule_signature(rule);
                    DocItem {
                        name: rule.name.name.clone(),
                        kind: DocItemKind::Rule,
                        doc_comment: rule_comment,
                        signature: rule_sig,
                        children: Vec::new(),
                        line_number: rule_line,
                    }
                })
                .collect();

            Some(DocItem {
                name: policy.name.name.clone(),
                kind: DocItemKind::Policy,
                doc_comment: comment,
                signature: sig,
                children,
                line_number: line,
            })
        }
        ItemKind::Function(fn_decl) => {
            let line = fn_decl.span.line;
            let comment = extract_comment_above(source_lines, line);
            let sig = format_fn_signature(&fn_decl.signature);
            Some(DocItem {
                name: fn_decl.signature.name.name.clone(),
                kind: DocItemKind::Function,
                doc_comment: comment,
                signature: sig,
                children: Vec::new(),
                line_number: line,
            })
        }
        ItemKind::StructDef(s) => {
            let line = s.span.line;
            let comment = extract_comment_above(source_lines, line);
            let sig = format!("struct {}", s.name.name);

            let children: Vec<DocItem> = s
                .fields
                .iter()
                .map(|field| DocItem {
                    name: field.name.name.clone(),
                    kind: DocItemKind::Type,
                    doc_comment: extract_comment_above(source_lines, field.span.line),
                    signature: format!("{}: <type>", field.name.name),
                    children: Vec::new(),
                    line_number: field.span.line,
                })
                .collect();

            Some(DocItem {
                name: s.name.name.clone(),
                kind: DocItemKind::Struct,
                doc_comment: comment,
                signature: sig,
                children,
                line_number: line,
            })
        }
        ItemKind::EnumDef(e) => {
            let line = e.span.line;
            let comment = extract_comment_above(source_lines, line);
            let sig = format!("enum {}", e.name.name);

            let children: Vec<DocItem> = e
                .variants
                .iter()
                .map(|variant| DocItem {
                    name: variant.name.name.clone(),
                    kind: DocItemKind::Type,
                    doc_comment: extract_comment_above(source_lines, variant.span.line),
                    signature: variant.name.name.clone(),
                    children: Vec::new(),
                    line_number: variant.span.line,
                })
                .collect();

            Some(DocItem {
                name: e.name.name.clone(),
                kind: DocItemKind::Enum,
                doc_comment: comment,
                signature: sig,
                children,
                line_number: line,
            })
        }
        ItemKind::TypeAlias(t) => {
            let line = t.span.line;
            let comment = extract_comment_above(source_lines, line);
            Some(DocItem {
                name: t.name.name.clone(),
                kind: DocItemKind::Type,
                doc_comment: comment,
                signature: format!("type {}", t.name.name),
                children: Vec::new(),
                line_number: line,
            })
        }
        ItemKind::TypeConstraint(tc) => {
            let line = tc.span.line;
            let comment = extract_comment_above(source_lines, line);
            Some(DocItem {
                name: tc.name.name.clone(),
                kind: DocItemKind::Type,
                doc_comment: comment,
                signature: format!("type {} = ... where {{ ... }}", tc.name.name),
                children: Vec::new(),
                line_number: line,
            })
        }
        ItemKind::Module(m) => {
            let line = m.span.line;
            let comment = extract_comment_above(source_lines, line);
            let vis = if m.visibility == Visibility::Public { "pub " } else { "" };
            let sig = format!("{}mod {}", vis, m.name.name);

            let children: Vec<DocItem> = if let Some(ref items) = m.items {
                items
                    .iter()
                    .filter(|item| {
                        match &item.kind {
                            ItemKind::Function(f) => f.signature.is_pub,
                            ItemKind::Policy(p) => p.visibility == Visibility::Public,
                            ItemKind::StructDef(s) => s.visibility == Visibility::Public,
                            ItemKind::EnumDef(e) => e.visibility == Visibility::Public,
                            ItemKind::TypeAlias(t) => t.visibility == Visibility::Public,
                            ItemKind::Module(m) => m.visibility == Visibility::Public,
                            _ => false,
                        }
                    })
                    .filter_map(|item| extract_item_doc(item, source_lines))
                    .collect()
            } else {
                Vec::new()
            };

            Some(DocItem {
                name: m.name.name.clone(),
                kind: DocItemKind::Module,
                doc_comment: comment,
                signature: sig,
                children,
                line_number: line,
            })
        }
        _ => None,
    }
}

fn extract_comment_above(source_lines: &[&str], decl_line: u32) -> Option<String> {
    if decl_line <= 1 {
        return None;
    }

    let mut comment_lines = Vec::new();
    let mut line_idx = (decl_line as usize).saturating_sub(2); // 1-based to 0-based, then one line above

    loop {
        if line_idx >= source_lines.len() {
            break;
        }
        let trimmed = source_lines[line_idx].trim();
        if trimmed.starts_with("//") {
            let text = trimmed.trim_start_matches("//").trim();
            comment_lines.push(text.to_string());
        } else {
            break;
        }
        if line_idx == 0 {
            break;
        }
        line_idx -= 1;
    }

    if comment_lines.is_empty() {
        None
    } else {
        comment_lines.reverse();
        Some(comment_lines.join("\n"))
    }
}

fn format_fn_signature(sig: &FnSignature) -> String {
    let params: Vec<String> = sig
        .params
        .iter()
        .map(|p| format!("{}: <type>", p.name.name))
        .collect();

    let ret = if sig.return_type.is_some() {
        " -> <type>"
    } else {
        ""
    };

    format!("fn {}({}){}", sig.name.name, params.join(", "), ret)
}

fn format_rule_signature(rule: &RuleDef) -> String {
    let params: Vec<String> = rule
        .params
        .iter()
        .map(|p| format!("{}: <type>", p.name.name))
        .collect();

    format!("rule {}({})", rule.name.name, params.join(", "))
}

// ── Markdown rendering ──────────────────────────────────────────────

pub fn render_markdown(items: &[DocItem], module_name: &str) -> String {
    let mut out = String::new();

    // Title.
    out.push_str(&format!("# {module_name}\n\n"));

    if items.is_empty() {
        out.push_str("No documented items.\n");
        return out;
    }

    // Table of contents.
    out.push_str("## Table of Contents\n\n");
    for item in items {
        let anchor = item.name.to_lowercase().replace(' ', "-");
        out.push_str(&format!(
            "- [{}](#{})\n",
            item.name, anchor
        ));
    }
    out.push('\n');

    // Items.
    for item in items {
        out.push_str(&format!("## {}\n\n", item.name));
        out.push_str(&format!("**{}** (line {})\n\n", item.kind, item.line_number));
        out.push_str(&format!("```rune\n{}\n```\n\n", item.signature));

        if let Some(ref doc) = item.doc_comment {
            out.push_str(doc);
            out.push_str("\n\n");
        }

        if !item.children.is_empty() {
            out.push_str("### Members\n\n");
            for child in &item.children {
                out.push_str(&format!("#### {}\n\n", child.name));
                out.push_str(&format!("```rune\n{}\n```\n\n", child.signature));
                if let Some(ref doc) = child.doc_comment {
                    out.push_str(doc);
                    out.push_str("\n\n");
                }
            }
        }
    }

    out
}
