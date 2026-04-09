// ═══════════════════════════════════════════════════════════════════════
// RUNE Language Server Protocol (LSP) Server
//
// Real-time diagnostics, go-to-definition, hover, and completions for
// RUNE source files. Works with VS Code, Neovim, Helix, Zed, and any
// LSP-compatible editor.
//
// Design constraint: must handle invalid and incomplete source gracefully.
// Developers type mid-expression constantly. The LSP never panics, never
// hangs, and reports whatever diagnostics it can from partial input.
//
// Pillar: Security Baked In — real-time diagnostics catch governance
// errors as developers type, before code is ever committed.
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::Mutex;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use crate::compiler::{check_source, CompileError};

#[cfg(test)]
mod tests;

// ── Server struct ────────────────────────────────────────────────────

pub struct RuneLanguageServer {
    client: Client,
    document_map: Mutex<HashMap<Url, String>>,
}

impl RuneLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            document_map: Mutex::new(HashMap::new()),
        }
    }
}

// ── LanguageServer trait implementation ───────────────────────────────

#[tower_lsp::async_trait]
impl LanguageServer for RuneLanguageServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![".".to_string(), ":".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "rune-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "rune-lsp initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let text = params.text_document.text.clone();
        {
            let mut map = self.document_map.lock().unwrap();
            map.insert(uri.clone(), text.clone());
        }
        self.publish_diagnostics(uri, &text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        if let Some(change) = params.content_changes.into_iter().last() {
            let text = change.text;
            {
                let mut map = self.document_map.lock().unwrap();
                map.insert(uri.clone(), text.clone());
            }
            self.publish_diagnostics(uri, &text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        {
            let mut map = self.document_map.lock().unwrap();
            map.remove(&uri);
        }
        // Clear diagnostics for closed file.
        self.client
            .publish_diagnostics(uri, vec![], None)
            .await;
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let source = {
            let map = self.document_map.lock().unwrap();
            map.get(uri).cloned()
        };

        let source = match source {
            Some(s) => s,
            None => return Ok(None),
        };

        let word = match find_word_at_position(&source, pos.line, pos.character) {
            Some(w) => w,
            None => return Ok(None),
        };

        // Check for keyword documentation.
        if let Some(doc) = keyword_hover(&word) {
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: doc.to_string(),
                }),
                range: None,
            }));
        }

        // Try to find type information from parsed declarations.
        if let Some(info) = find_declaration_info(&source, &word) {
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: info,
                }),
                range: None,
            }));
        }

        Ok(None)
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri.clone();
        let pos = params.text_document_position_params.position;

        let source = {
            let map = self.document_map.lock().unwrap();
            map.get(&uri).cloned()
        };

        let source = match source {
            Some(s) => s,
            None => return Ok(None),
        };

        let word = match find_word_at_position(&source, pos.line, pos.character) {
            Some(w) => w,
            None => return Ok(None),
        };

        if let Some((line, col)) = find_definition_location(&source, &word) {
            let location = Location {
                uri,
                range: Range {
                    start: Position::new(line, col),
                    end: Position::new(line, col + word.len() as u32),
                },
            };
            return Ok(Some(GotoDefinitionResponse::Scalar(location)));
        }

        Ok(None)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;

        let source = {
            let map = self.document_map.lock().unwrap();
            map.get(uri).cloned()
        };

        let mut items = keyword_completions();

        // Add identifier completions from the current file.
        if let Some(source) = source {
            items.extend(identifier_completions(&source));
        }

        Ok(Some(CompletionResponse::Array(items)))
    }
}

// ── Diagnostics ──────────────────────────────────────────────────────

impl RuneLanguageServer {
    async fn publish_diagnostics(&self, uri: Url, source: &str) {
        let diagnostics = compile_diagnostics(source);
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }
}

/// Run check_source and convert errors to LSP diagnostics.
/// Catches panics from malformed input.
pub fn compile_diagnostics(source: &str) -> Vec<Diagnostic> {
    let source_owned = source.to_string();
    let result = std::panic::catch_unwind(|| check_source(&source_owned, 0));

    match result {
        Ok(Ok(())) => vec![],
        Ok(Err(errors)) => errors.iter().map(compile_error_to_diagnostic).collect(),
        Err(_) => {
            vec![Diagnostic {
                range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                severity: Some(DiagnosticSeverity::ERROR),
                source: Some("rune".to_string()),
                message: "internal compiler error — please report this bug".to_string(),
                ..Default::default()
            }]
        }
    }
}

/// Convert a CompileError to an LSP Diagnostic.
/// RUNE uses 1-based lines/columns; LSP uses 0-based.
pub fn compile_error_to_diagnostic(error: &CompileError) -> Diagnostic {
    let line = error.span.line.saturating_sub(1);
    let col = error.span.column.saturating_sub(1);
    Diagnostic {
        range: Range::new(
            Position::new(line, col),
            Position::new(line, col + 1),
        ),
        severity: Some(DiagnosticSeverity::ERROR),
        source: Some("rune".to_string()),
        message: format!("[{}] {}", error.phase_tag(), error.message),
        ..Default::default()
    }
}

// ── Word finding ─────────────────────────────────────────────────────

/// Find the word (identifier or keyword) at the given 0-based line and column.
pub fn find_word_at_position(source: &str, line: u32, col: u32) -> Option<String> {
    let target_line = source.lines().nth(line as usize)?;
    let col = col as usize;

    if col >= target_line.len() {
        return None;
    }

    let bytes = target_line.as_bytes();
    if !is_ident_char(bytes[col]) {
        return None;
    }

    // Walk backwards to find start.
    let mut start = col;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }

    // Walk forwards to find end.
    let mut end = col;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }

    Some(target_line[start..end].to_string())
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── Keyword hover documentation ──────────────────────────────────────

/// Return documentation for RUNE keywords.
pub fn keyword_hover(word: &str) -> Option<&'static str> {
    Some(match word {
        "policy" => "**policy** — Declares a governance policy containing rules.\n\n```rune\npolicy name {\n    rule ...\n}\n```",
        "rule" => "**rule** — A governance rule within a policy. Must return a governance decision: `permit`, `deny`, `escalate`, or `quarantine`.",
        "fn" => "**fn** — Declares a function.\n\n```rune\nfn name(params) -> ReturnType { body }\n```",
        "permit" => "**permit** — Governance decision: allow the action. Encoded as `0` in WASM.",
        "deny" => "**deny** — Governance decision: reject the action. Encoded as `1` in WASM.",
        "escalate" => "**escalate** — Governance decision: escalate to human review. Encoded as `2` in WASM.",
        "quarantine" => "**quarantine** — Governance decision: isolate for investigation. Encoded as `3` in WASM.",
        "let" => "**let** — Variable binding.\n\n```rune\nlet x: Int = 42;\nlet mut y: Int = 0;\n```",
        "if" => "**if** — Conditional expression.\n\n```rune\nif condition { then_branch } else { else_branch }\n```",
        "match" => "**match** — Pattern matching expression.\n\n```rune\nmatch value {\n    pattern => result,\n}\n```",
        "struct" => "**struct** — Declares a named product type with fields.",
        "enum" => "**enum** — Declares a named sum type with variants.",
        "type" => "**type** — Declares a type alias or type constraint.\n\n```rune\ntype Name = BaseType where { predicates };\n```",
        "capability" => "**capability** — Declares a capability type.\n\nPillar: Zero Trust Throughout — no ambient authority.",
        "effect" => "**effect** — Declares an effect type.\n\nPillar: Security Baked In — all side effects tracked.",
        "audit" => "**audit** — Audited block. Compiler auto-instruments for the audit trail.\n\nPillar: Security Baked In.",
        "secure_zone" => "**secure_zone** — Isolation boundary providing capabilities.\n\nPillar: Assumed Breach.",
        "unsafe_ffi" => "**unsafe_ffi** — Escape hatch for foreign function calls.\n\nPillar: Security Baked In — auditable escape hatch.",
        "attest" => "**attest** — Verify model/artifact trust chain.\n\nPillar: Zero Trust Throughout.",
        "require" => "**require** — Runtime assertion that a value meets refinement predicates.",
        "mod" => "**mod** — Declares a module.\n\n```rune\nmod name { ... }\nmod name; // file-based\n```\n\nModules organize code into namespaces with visibility control.",
        "use" => "**use** — Imports names from a module.\n\n```rune\nuse crypto::verify;\nuse crypto::*;\nuse crypto::verify as v;\n```",
        "as" => "**as** — Renames an import.\n\n```rune\nuse crypto::verify as v;\n```",
        "self" => "**self** — Refers to the current module.\n\n```rune\nuse self::helper;\nself::helper()\n```",
        "super" => "**super** — Refers to the parent module.\n\n```rune\nuse super::utils::hash;\nsuper::helper()\n```",
        "pub" => "**pub** — Makes a declaration visible outside its module.\n\n```rune\npub fn verify() -> Bool { true }\npub mod crypto { ... }\n```",
        "where" => "**where** — Refinement type predicates.\n\n```rune\ntype T = Int where { value >= 0, value <= 100 };\n```",
        "while" => "**while** — Loop while condition is true.\n\n```rune\nwhile condition { body }\n```",
        "for" => "**for** — Iterate over a range or collection.\n\n```rune\nfor x in collection { body }\n```",
        "return" => "**return** — Return a value from the current function.",
        "true" | "false" => "**Bool** literal.",
        "Int" => "**Int** — 64-bit signed integer type.",
        "Float" => "**Float** — 64-bit floating-point type.",
        "Bool" => "**Bool** — Boolean type (`true` or `false`).",
        "String" => "**String** — UTF-8 string type.",
        _ => return None,
    })
}

// ── Declaration info (hover for user-defined names) ──────────────────

/// Try to find type/signature information for a user-defined name.
fn find_declaration_info(source: &str, name: &str) -> Option<String> {
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
    if !lex_errors.is_empty() {
        return None;
    }
    let (file, _) = Parser::new(tokens).parse();

    for item in &file.items {
        match &item.kind {
            crate::ast::nodes::ItemKind::Function(f) => {
                if f.signature.name.name == name {
                    let params: Vec<String> = f.signature.params.iter().map(|p| {
                        format!("{}: {}", p.name.name, type_expr_to_string(&p.ty))
                    }).collect();
                    let ret = f.signature.return_type.as_ref()
                        .map(|t| format!(" -> {}", type_expr_to_string(t)))
                        .unwrap_or_default();
                    return Some(format!("```rune\nfn {}({}){}\n```", name, params.join(", "), ret));
                }
            }
            crate::ast::nodes::ItemKind::Policy(p) => {
                if p.name.name == name {
                    let rule_names: Vec<&str> = p.rules.iter().map(|r| r.name.name.as_str()).collect();
                    return Some(format!("**policy** `{}`\n\nRules: {}", name, rule_names.join(", ")));
                }
                for rule in &p.rules {
                    if rule.name.name == name {
                        let params: Vec<String> = rule.params.iter().map(|p| {
                            format!("{}: {}", p.name.name, type_expr_to_string(&p.ty))
                        }).collect();
                        return Some(format!("```rune\nrule {}({})\n```\n\nIn policy `{}`", name, params.join(", "), p.name.name));
                    }
                }
            }
            crate::ast::nodes::ItemKind::StructDef(s) => {
                if s.name.name == name {
                    return Some(format!("**struct** `{}`", name));
                }
            }
            crate::ast::nodes::ItemKind::EnumDef(e) => {
                if e.name.name == name {
                    return Some(format!("**enum** `{}`", name));
                }
            }
            crate::ast::nodes::ItemKind::TypeAlias(t) => {
                if t.name.name == name {
                    return Some(format!("**type** `{}` = `{}`", name, type_expr_to_string(&t.ty)));
                }
            }
            crate::ast::nodes::ItemKind::TypeConstraint(t) => {
                if t.name.name == name {
                    return Some(format!("**type** `{}` = `{}` where {{...}}", name, type_expr_to_string(&t.base_type)));
                }
            }
            crate::ast::nodes::ItemKind::Module(m) => {
                if m.name.name == name {
                    let vis = if m.visibility == crate::ast::nodes::Visibility::Public { "pub " } else { "" };
                    let kind = if m.items.is_some() { "inline" } else { "file-based" };
                    return Some(format!("```rune\n{}mod {}\n```\n\n{} module", vis, name, kind));
                }
            }
            _ => {}
        }
    }
    None
}

fn type_expr_to_string(ty: &crate::ast::nodes::TypeExpr) -> String {
    match &ty.kind {
        crate::ast::nodes::TypeExprKind::Named { path, type_args } => {
            let base: String = path.segments.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join("::");
            if type_args.is_empty() {
                base
            } else {
                let args: Vec<String> = type_args.iter().map(type_expr_to_string).collect();
                format!("{}<{}>", base, args.join(", "))
            }
        }
        crate::ast::nodes::TypeExprKind::Unit => "()".to_string(),
        crate::ast::nodes::TypeExprKind::Tuple(types) => {
            let parts: Vec<String> = types.iter().map(type_expr_to_string).collect();
            format!("({})", parts.join(", "))
        }
        _ => "...".to_string(),
    }
}

// ── Go-to-definition ─────────────────────────────────────────────────

/// Find the 0-based (line, column) of a declaration for the given name.
fn find_definition_location(source: &str, name: &str) -> Option<(u32, u32)> {
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
    if !lex_errors.is_empty() {
        return None;
    }
    let (file, _) = Parser::new(tokens).parse();

    for item in &file.items {
        match &item.kind {
            crate::ast::nodes::ItemKind::Function(f) => {
                if f.signature.name.name == name {
                    let span = &f.signature.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            crate::ast::nodes::ItemKind::Policy(p) => {
                if p.name.name == name {
                    let span = &p.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
                for rule in &p.rules {
                    if rule.name.name == name {
                        let span = &rule.name.span;
                        return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                    }
                }
            }
            crate::ast::nodes::ItemKind::StructDef(s) => {
                if s.name.name == name {
                    let span = &s.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            crate::ast::nodes::ItemKind::EnumDef(e) => {
                if e.name.name == name {
                    let span = &e.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            crate::ast::nodes::ItemKind::TypeAlias(t) => {
                if t.name.name == name {
                    let span = &t.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            crate::ast::nodes::ItemKind::TypeConstraint(t) => {
                if t.name.name == name {
                    let span = &t.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            crate::ast::nodes::ItemKind::Module(m) => {
                if m.name.name == name {
                    let span = &m.name.span;
                    return Some((span.line.saturating_sub(1), span.column.saturating_sub(1)));
                }
            }
            _ => {}
        }
    }
    None
}

// ── Completions ──────────────────────────────────────────────────────

/// Return keyword completions for RUNE.
pub fn keyword_completions() -> Vec<CompletionItem> {
    let keywords = [
        "policy", "rule", "fn", "type", "struct", "enum", "if", "else",
        "while", "for", "match", "let", "mut", "return", "break", "continue",
        "true", "false", "permit", "deny", "escalate", "quarantine",
        "with", "effects", "capabilities", "require", "satisfies",
        "audit", "unsafe_ffi", "secure_zone", "attest", "where",
        "in", "not", "impl", "trait", "pub", "mod", "use", "const",
    ];

    let types = ["Int", "Float", "Bool", "String"];

    let mut items: Vec<CompletionItem> = keywords
        .iter()
        .map(|kw| CompletionItem {
            label: kw.to_string(),
            kind: Some(CompletionItemKind::KEYWORD),
            detail: Some("keyword".to_string()),
            ..Default::default()
        })
        .collect();

    items.extend(types.iter().map(|ty| CompletionItem {
        label: ty.to_string(),
        kind: Some(CompletionItemKind::STRUCT),
        detail: Some("built-in type".to_string()),
        ..Default::default()
    }));

    items
}

/// Extract identifier completions from the current file's declarations.
pub fn identifier_completions(source: &str) -> Vec<CompletionItem> {
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
    if !lex_errors.is_empty() {
        return vec![];
    }
    let (file, _) = Parser::new(tokens).parse();

    let mut items = Vec::new();

    for item in &file.items {
        match &item.kind {
            crate::ast::nodes::ItemKind::Function(f) => {
                items.push(CompletionItem {
                    label: f.signature.name.name.clone(),
                    kind: Some(CompletionItemKind::FUNCTION),
                    detail: Some("function".to_string()),
                    ..Default::default()
                });
            }
            crate::ast::nodes::ItemKind::Policy(p) => {
                items.push(CompletionItem {
                    label: p.name.name.clone(),
                    kind: Some(CompletionItemKind::MODULE),
                    detail: Some("policy".to_string()),
                    ..Default::default()
                });
                for rule in &p.rules {
                    items.push(CompletionItem {
                        label: rule.name.name.clone(),
                        kind: Some(CompletionItemKind::FUNCTION),
                        detail: Some(format!("rule in {}", p.name.name)),
                        ..Default::default()
                    });
                }
            }
            crate::ast::nodes::ItemKind::StructDef(s) => {
                items.push(CompletionItem {
                    label: s.name.name.clone(),
                    kind: Some(CompletionItemKind::STRUCT),
                    detail: Some("struct".to_string()),
                    ..Default::default()
                });
            }
            crate::ast::nodes::ItemKind::EnumDef(e) => {
                items.push(CompletionItem {
                    label: e.name.name.clone(),
                    kind: Some(CompletionItemKind::ENUM),
                    detail: Some("enum".to_string()),
                    ..Default::default()
                });
            }
            crate::ast::nodes::ItemKind::TypeAlias(t) => {
                items.push(CompletionItem {
                    label: t.name.name.clone(),
                    kind: Some(CompletionItemKind::STRUCT),
                    detail: Some("type alias".to_string()),
                    ..Default::default()
                });
            }
            crate::ast::nodes::ItemKind::Module(m) => {
                items.push(CompletionItem {
                    label: m.name.name.clone(),
                    kind: Some(CompletionItemKind::MODULE),
                    detail: Some("module".to_string()),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }

    items
}
