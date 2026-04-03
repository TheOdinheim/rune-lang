use crate::ast::nodes::*;
use crate::lexer::token::{Span, Token, TokenKind};

// ═══════════════════════════════════════════════════════════════════════
// Parse errors
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "error at line {}, column {}: {}",
            self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for ParseError {}

// ═══════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════

/// Hand-written recursive descent parser for RUNE source files.
///
/// Consumes a token stream produced by the lexer and builds an AST.
/// Uses Pratt parsing (precedence climbing) for expressions.
///
/// On error, records the diagnostic and skips to the next
/// synchronization point (`;` or `}`) to continue reporting errors.
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    errors: Vec<ParseError>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0, errors: Vec::new() }
    }

    /// Parse the entire token stream as a source file.
    pub fn parse(mut self) -> (SourceFile, Vec<ParseError>) {
        let start_span = self.current_span();
        let mut items = Vec::new();

        while !self.at_eof() {
            match self.parse_item() {
                Ok(item) => items.push(item),
                Err(e) => {
                    self.errors.push(e);
                    self.synchronize();
                }
            }
        }

        let end_span = self.current_span();
        let file = SourceFile {
            items,
            span: self.merge_spans(start_span, end_span),
        };
        (file, self.errors)
    }

    // ── Token utilities ──────────────────────────────────────────────

    pub(crate) fn current_kind(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    pub(crate) fn current_span(&self) -> Span {
        self.tokens[self.pos].span
    }

    pub(crate) fn previous_span(&self) -> Span {
        if self.pos > 0 {
            self.tokens[self.pos - 1].span
        } else {
            self.tokens[0].span
        }
    }

    pub(crate) fn at_eof(&self) -> bool {
        matches!(self.current_kind(), TokenKind::Eof)
    }

    pub(crate) fn check(&self, kind: &TokenKind) -> bool {
        std::mem::discriminant(self.current_kind()) == std::mem::discriminant(kind)
    }

    pub(crate) fn advance(&mut self) -> &Token {
        if !self.at_eof() {
            self.pos += 1;
        }
        &self.tokens[self.pos - 1]
    }

    pub(crate) fn expect(&mut self, kind: &TokenKind) -> Result<Span, ParseError> {
        if self.check(kind) {
            Ok(self.advance().span)
        } else {
            Err(self.error_expected(&format!("{kind:?}")))
        }
    }

    pub(crate) fn expect_identifier(&mut self) -> Result<Ident, ParseError> {
        match self.current_kind().clone() {
            TokenKind::Identifier(name) => {
                let span = self.advance().span;
                Ok(Ident::new(name, span))
            }
            // `self` is a keyword but valid as a parameter name.
            TokenKind::SelfValue => {
                let span = self.advance().span;
                Ok(Ident::new("self".to_string(), span))
            }
            _ => Err(self.error_expected("identifier")),
        }
    }

    pub(crate) fn expect_semicolon(&mut self) -> Result<Span, ParseError> {
        self.expect(&TokenKind::Semicolon)
    }

    pub(crate) fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(crate) fn merge_spans(&self, start: Span, end: Span) -> Span {
        Span::new(start.file_id, start.start, end.end, start.line, start.column)
    }

    // ── Error helpers ────────────────────────────────────────────────

    pub(crate) fn error_expected(&self, expected: &str) -> ParseError {
        let got = format!("{:?}", self.current_kind());
        ParseError {
            message: format!("expected {expected}, found {got}"),
            span: self.current_span(),
        }
    }

    pub(crate) fn error_at_current(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            span: self.current_span(),
        }
    }

    /// Skip tokens until we reach a synchronization point.
    fn synchronize(&mut self) {
        while !self.at_eof() {
            // Stop after a semicolon.
            if matches!(self.current_kind(), TokenKind::Semicolon) {
                self.advance();
                return;
            }
            // Stop before a keyword that starts a new declaration.
            if matches!(
                self.current_kind(),
                TokenKind::Policy
                    | TokenKind::Rule
                    | TokenKind::Fn
                    | TokenKind::Let
                    | TokenKind::Struct
                    | TokenKind::Enum
                    | TokenKind::Type
                    | TokenKind::Impl
                    | TokenKind::Trait
                    | TokenKind::Mod
                    | TokenKind::Use
                    | TokenKind::Const
                    | TokenKind::Capability
                    | TokenKind::Effect
                    | TokenKind::Pub
            ) {
                return;
            }
            // Stop after a closing brace.
            if matches!(self.current_kind(), TokenKind::RightBrace) {
                self.advance();
                return;
            }
            self.advance();
        }
    }

    // ── Top-level item parsing ───────────────────────────────────────

    pub(crate) fn parse_item(&mut self) -> Result<Item, ParseError> {
        let is_pub = self.eat(&TokenKind::Pub);
        let start_span = if is_pub { self.previous_span() } else { self.current_span() };

        let kind = match self.current_kind().clone() {
            TokenKind::Policy => {
                self.advance();
                ItemKind::Policy(self.parse_policy_decl(start_span)?)
            }
            TokenKind::Fn => {
                self.advance();
                ItemKind::Function(self.parse_fn_decl(is_pub, start_span)?)
            }
            TokenKind::Struct => {
                self.advance();
                ItemKind::StructDef(self.parse_struct_def(start_span)?)
            }
            TokenKind::Enum => {
                self.advance();
                ItemKind::EnumDef(self.parse_enum_def(start_span)?)
            }
            TokenKind::Type => {
                self.advance();
                ItemKind::TypeAlias(self.parse_type_alias(start_span)?)
            }
            TokenKind::Impl => {
                self.advance();
                ItemKind::ImplBlock(self.parse_impl_block(start_span)?)
            }
            TokenKind::Trait => {
                self.advance();
                ItemKind::TraitDef(self.parse_trait_def(start_span)?)
            }
            TokenKind::Capability => {
                self.advance();
                ItemKind::Capability(self.parse_capability_decl(start_span)?)
            }
            TokenKind::Effect => {
                self.advance();
                ItemKind::Effect(self.parse_effect_decl(start_span)?)
            }
            TokenKind::Mod => {
                self.advance();
                ItemKind::Module(self.parse_module_decl(start_span)?)
            }
            TokenKind::Use => {
                self.advance();
                ItemKind::Use(self.parse_use_decl(start_span)?)
            }
            TokenKind::Const => {
                self.advance();
                ItemKind::Const(self.parse_const_decl(start_span)?)
            }
            _ => return Err(self.error_at_current("expected a declaration (fn, policy, struct, enum, ...)")),
        };

        let end_span = self.previous_span();
        Ok(Item { kind, span: self.merge_spans(start_span, end_span) })
    }

    // ── Policy declarations ──────────────────────────────────────────

    fn parse_policy_decl(&mut self, start_span: Span) -> Result<PolicyDecl, ParseError> {
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::LeftBrace)?;

        let mut rules = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            rules.push(self.parse_rule_def()?);
        }

        let end = self.expect(&TokenKind::RightBrace)?;
        Ok(PolicyDecl {
            name,
            rules,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_rule_def(&mut self) -> Result<RuleDef, ParseError> {
        let start_span = self.expect(&TokenKind::Rule)?;
        let name = self.expect_identifier()?;

        // Optional parameter list
        let params = if self.check(&TokenKind::LeftParen) {
            self.parse_param_list()?
        } else {
            Vec::new()
        };

        // Optional when clause
        let when_clause = if self.eat(&TokenKind::When) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };

        // Body block
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();

        Ok(RuleDef {
            name,
            params,
            when_clause,
            body,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Function declarations ────────────────────────────────────────

    pub(crate) fn parse_fn_decl(
        &mut self,
        is_pub: bool,
        start_span: Span,
    ) -> Result<FnDecl, ParseError> {
        let sig = self.parse_fn_signature(is_pub, start_span)?;

        // Body is optional (for trait method signatures ending with `;`).
        let body = if self.check(&TokenKind::LeftBrace) {
            Some(Box::new(self.parse_block_expr()?))
        } else {
            self.expect_semicolon()?;
            None
        };

        let end = self.previous_span();
        Ok(FnDecl {
            signature: sig,
            body,
            span: self.merge_spans(start_span, end),
        })
    }

    pub(crate) fn parse_fn_signature(
        &mut self,
        is_pub: bool,
        start_span: Span,
    ) -> Result<FnSignature, ParseError> {
        let name = self.expect_identifier()?;
        let generic_params = self.parse_optional_generic_params()?;
        let params = self.parse_param_list()?;

        let return_type = if self.eat(&TokenKind::Arrow) {
            Some(self.parse_type_expr()?)
        } else {
            None
        };

        // Optional effect annotation: `with effects { io, network }`
        let effects = if self.check(&TokenKind::Identifier("with".into())) {
            // peek at "with" — it's not a keyword, so it's an identifier
            if let TokenKind::Identifier(ref s) = self.current_kind().clone() {
                if s == "with" {
                    self.advance(); // consume "with"
                    // Expect either `effects` identifier or directly the brace
                    if let TokenKind::Identifier(ref s2) = self.current_kind().clone() {
                        if s2 == "effects" {
                            self.advance(); // consume "effects"
                        }
                    }
                    self.parse_effect_list()?
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let end = self.previous_span();
        Ok(FnSignature {
            is_pub,
            name,
            generic_params,
            params,
            return_type,
            effects,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_effect_list(&mut self) -> Result<Vec<Path>, ParseError> {
        self.expect(&TokenKind::LeftBrace)?;
        let mut effects = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            effects.push(self.parse_path()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RightBrace)?;
        Ok(effects)
    }

    pub(crate) fn parse_param_list(&mut self) -> Result<Vec<Param>, ParseError> {
        self.expect(&TokenKind::LeftParen)?;
        let mut params = Vec::new();

        while !self.check(&TokenKind::RightParen) && !self.at_eof() {
            params.push(self.parse_param()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }

        self.expect(&TokenKind::RightParen)?;
        Ok(params)
    }

    fn parse_param(&mut self) -> Result<Param, ParseError> {
        let start_span = self.current_span();
        let is_mut = self.eat(&TokenKind::Mut);
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.parse_type_expr()?;
        let end = self.previous_span();
        Ok(Param {
            is_mut,
            name,
            ty,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Struct definitions ───────────────────────────────────────────

    fn parse_struct_def(&mut self, start_span: Span) -> Result<StructDef, ParseError> {
        let name = self.expect_identifier()?;
        let generic_params = self.parse_optional_generic_params()?;

        self.expect(&TokenKind::LeftBrace)?;
        let mut fields = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            fields.push(self.parse_field_def()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(StructDef {
            name,
            generic_params,
            fields,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_field_def(&mut self) -> Result<FieldDef, ParseError> {
        let start_span = self.current_span();
        let is_pub = self.eat(&TokenKind::Pub);
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.parse_type_expr()?;
        let end = self.previous_span();
        Ok(FieldDef {
            is_pub,
            name,
            ty,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Enum definitions ─────────────────────────────────────────────

    fn parse_enum_def(&mut self, start_span: Span) -> Result<EnumDef, ParseError> {
        let name = self.expect_identifier()?;
        let generic_params = self.parse_optional_generic_params()?;

        self.expect(&TokenKind::LeftBrace)?;
        let mut variants = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            variants.push(self.parse_variant_def()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(EnumDef {
            name,
            generic_params,
            variants,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_variant_def(&mut self) -> Result<VariantDef, ParseError> {
        let start_span = self.current_span();
        let name = self.expect_identifier()?;

        let fields = if self.check(&TokenKind::LeftParen) {
            self.advance();
            let mut types = Vec::new();
            while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                types.push(self.parse_type_expr()?);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(&TokenKind::RightParen)?;
            VariantFields::Tuple(types)
        } else if self.check(&TokenKind::LeftBrace) {
            self.advance();
            let mut fields = Vec::new();
            while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
                fields.push(self.parse_field_def()?);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect(&TokenKind::RightBrace)?;
            VariantFields::Struct(fields)
        } else {
            VariantFields::Unit
        };

        let end = self.previous_span();
        Ok(VariantDef {
            name,
            fields,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Type alias ───────────────────────────────────────────────────

    fn parse_type_alias(&mut self, start_span: Span) -> Result<TypeAliasDecl, ParseError> {
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::Equal)?;
        let ty = self.parse_type_expr()?;
        self.expect_semicolon()?;
        let end = self.previous_span();
        Ok(TypeAliasDecl {
            name,
            ty,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Impl blocks ──────────────────────────────────────────────────

    fn parse_impl_block(&mut self, start_span: Span) -> Result<ImplBlock, ParseError> {
        let generic_params = self.parse_optional_generic_params()?;

        // Parse the type (or trait name). We need lookahead to determine
        // if this is `impl Type { ... }` or `impl Trait for Type { ... }`.
        let first_type = self.parse_type_expr()?;

        let (trait_path, target_ty) = if self.eat(&TokenKind::For) {
            // `impl Trait for Type`
            let trait_path = match &first_type.kind {
                TypeExprKind::Named { path, type_args: _ } => path.clone(),
                _ => return Err(ParseError {
                    message: "expected trait name before `for`".into(),
                    span: first_type.span,
                }),
            };
            let target = self.parse_type_expr()?;
            (Some(trait_path), target)
        } else {
            (None, first_type)
        };

        self.expect(&TokenKind::LeftBrace)?;
        let mut items = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            items.push(self.parse_item()?);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(ImplBlock {
            trait_path,
            target_ty,
            generic_params,
            items,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Trait definitions ────────────────────────────────────────────

    fn parse_trait_def(&mut self, start_span: Span) -> Result<TraitDef, ParseError> {
        let name = self.expect_identifier()?;
        let generic_params = self.parse_optional_generic_params()?;

        self.expect(&TokenKind::LeftBrace)?;
        let mut items = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            let item = self.parse_trait_item()?;
            items.push(item);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(TraitDef {
            name,
            generic_params,
            items,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_trait_item(&mut self) -> Result<TraitItem, ParseError> {
        let start_span = self.current_span();
        let is_pub = self.eat(&TokenKind::Pub);

        match self.current_kind().clone() {
            TokenKind::Fn => {
                self.advance();
                let fn_start = if is_pub { start_span } else { self.previous_span() };
                let decl = self.parse_fn_decl(is_pub, fn_start)?;
                let end = self.previous_span();
                Ok(TraitItem {
                    kind: TraitItemKind::Function(decl),
                    span: self.merge_spans(start_span, end),
                })
            }
            TokenKind::Type => {
                self.advance();
                let alias = self.parse_type_alias(start_span)?;
                let end = self.previous_span();
                Ok(TraitItem {
                    kind: TraitItemKind::TypeAlias(alias),
                    span: self.merge_spans(start_span, end),
                })
            }
            _ => Err(self.error_at_current("expected `fn` or `type` in trait body")),
        }
    }

    // ── Capability declarations ──────────────────────────────────────

    fn parse_capability_decl(&mut self, start_span: Span) -> Result<CapabilityDecl, ParseError> {
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::LeftBrace)?;

        let mut items = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            items.push(self.parse_capability_item()?);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(CapabilityDecl {
            name,
            items,
            span: self.merge_spans(start_span, end),
        })
    }

    fn parse_capability_item(&mut self) -> Result<CapabilityItem, ParseError> {
        let start_span = self.current_span();
        let kind = match self.current_kind().clone() {
            TokenKind::Fn => {
                self.advance();
                let sig = self.parse_fn_signature(false, start_span)?;
                self.expect_semicolon()?;
                CapabilityItemKind::Function(sig)
            }
            TokenKind::Require => {
                self.advance();
                let path = self.parse_path()?;
                self.expect_semicolon()?;
                CapabilityItemKind::Require(path)
            }
            TokenKind::Grant => {
                self.advance();
                let path = self.parse_path()?;
                self.expect_semicolon()?;
                CapabilityItemKind::Grant(path)
            }
            TokenKind::Revoke => {
                self.advance();
                let path = self.parse_path()?;
                self.expect_semicolon()?;
                CapabilityItemKind::Revoke(path)
            }
            _ => return Err(self.error_at_current(
                "expected `fn`, `require`, `grant`, or `revoke` in capability body",
            )),
        };
        let end = self.previous_span();
        Ok(CapabilityItem { kind, span: self.merge_spans(start_span, end) })
    }

    // ── Effect declarations ──────────────────────────────────────────

    fn parse_effect_decl(&mut self, start_span: Span) -> Result<EffectDecl, ParseError> {
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::LeftBrace)?;

        let mut operations = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            let op_start = self.current_span();
            self.expect(&TokenKind::Fn)?;
            let sig = self.parse_fn_signature(false, op_start)?;
            self.expect_semicolon()?;
            operations.push(sig);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(EffectDecl {
            name,
            operations,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Module declarations ──────────────────────────────────────────

    fn parse_module_decl(&mut self, start_span: Span) -> Result<ModuleDecl, ParseError> {
        let name = self.expect_identifier()?;

        let items = if self.check(&TokenKind::LeftBrace) {
            self.advance();
            let mut items = Vec::new();
            while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
                items.push(self.parse_item()?);
            }
            self.expect(&TokenKind::RightBrace)?;
            Some(items)
        } else {
            self.expect_semicolon()?;
            None
        };

        let end = self.previous_span();
        Ok(ModuleDecl {
            name,
            items,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Use declarations ─────────────────────────────────────────────

    fn parse_use_decl(&mut self, start_span: Span) -> Result<UseDecl, ParseError> {
        let path = self.parse_path()?;
        let alias = if self.eat(&TokenKind::As) {
            Some(self.expect_identifier()?)
        } else {
            None
        };
        self.expect_semicolon()?;
        let end = self.previous_span();
        Ok(UseDecl {
            path,
            alias,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Const declarations ───────────────────────────────────────────

    fn parse_const_decl(&mut self, start_span: Span) -> Result<ConstDecl, ParseError> {
        let name = self.expect_identifier()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.parse_type_expr()?;
        self.expect(&TokenKind::Equal)?;
        let value = Box::new(self.parse_expr()?);
        self.expect_semicolon()?;
        let end = self.previous_span();
        Ok(ConstDecl {
            name,
            ty,
            value,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Generic parameters ───────────────────────────────────────────

    pub(crate) fn parse_optional_generic_params(&mut self) -> Result<Vec<GenericParam>, ParseError> {
        if !self.check(&TokenKind::LeftAngle) {
            return Ok(Vec::new());
        }
        self.advance(); // consume <

        let mut params = Vec::new();
        while !self.check(&TokenKind::RightAngle) && !self.at_eof() {
            let start_span = self.current_span();
            let name = self.expect_identifier()?;
            let mut bounds = Vec::new();
            if self.eat(&TokenKind::Colon) {
                bounds.push(self.parse_type_expr()?);
                while self.eat(&TokenKind::Plus) {
                    bounds.push(self.parse_type_expr()?);
                }
            }
            let end = self.previous_span();
            params.push(GenericParam {
                name,
                bounds,
                span: self.merge_spans(start_span, end),
            });
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }

        self.expect(&TokenKind::RightAngle)?;
        Ok(params)
    }

    // ── Path parsing ─────────────────────────────────────────────────

    pub(crate) fn parse_path(&mut self) -> Result<Path, ParseError> {
        let start_span = self.current_span();
        let first = self.expect_identifier()?;
        let mut segments = vec![first];

        while self.check(&TokenKind::ColonColon) {
            self.advance();
            segments.push(self.expect_identifier()?);
        }

        let end = self.previous_span();
        Ok(Path {
            segments,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Block parsing ────────────────────────────────────────────────

    pub(crate) fn parse_block_expr(&mut self) -> Result<Expr, ParseError> {
        let start_span = self.expect(&TokenKind::LeftBrace)?;
        let block = self.parse_block_inner(start_span)?;
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::Block(block),
            span: self.merge_spans(start_span, end),
        })
    }

    pub(crate) fn parse_block_inner(&mut self, start_span: Span) -> Result<Block, ParseError> {
        let mut stmts = Vec::new();

        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            // Try to parse an item first (fn, struct, etc.).
            if self.is_item_start() {
                let item = self.parse_item()?;
                let span = item.span;
                stmts.push(Stmt {
                    kind: StmtKind::Item(item),
                    span,
                });
                continue;
            }

            // Otherwise parse an expression/statement.
            let expr = self.parse_expr()?;
            let span = expr.span;

            if self.eat(&TokenKind::Semicolon) {
                stmts.push(Stmt { kind: StmtKind::Expr(expr), span });
            } else if self.check(&TokenKind::RightBrace) {
                // Tail expression — no semicolon before closing brace.
                stmts.push(Stmt { kind: StmtKind::TailExpr(expr), span });
            } else {
                // Expression-like statements that don't need semicolons
                // (blocks, if, match, etc.)
                if self.is_block_like_expr(&expr) {
                    stmts.push(Stmt { kind: StmtKind::Expr(expr), span });
                } else {
                    stmts.push(Stmt { kind: StmtKind::TailExpr(expr), span });
                }
            }
        }

        let end = self.expect(&TokenKind::RightBrace)?;
        Ok(Block {
            stmts,
            span: self.merge_spans(start_span, end),
        })
    }

    fn is_block_like_expr(&self, expr: &Expr) -> bool {
        matches!(
            expr.kind,
            ExprKind::Block(_)
                | ExprKind::If { .. }
                | ExprKind::Match { .. }
                | ExprKind::For { .. }
                | ExprKind::While { .. }
                | ExprKind::Audit(_)
                | ExprKind::UnsafeFfi(_)
                | ExprKind::SecureZone { .. }
        )
    }

    pub(crate) fn is_item_start(&self) -> bool {
        match self.current_kind() {
            TokenKind::Fn
            | TokenKind::Struct
            | TokenKind::Enum
            | TokenKind::Type
            | TokenKind::Impl
            | TokenKind::Trait
            | TokenKind::Policy
            | TokenKind::Capability
            | TokenKind::Effect
            | TokenKind::Mod
            | TokenKind::Use
            | TokenKind::Const => true,
            TokenKind::Pub => {
                // Look ahead: pub followed by fn, struct, etc.
                if self.pos + 1 < self.tokens.len() {
                    matches!(
                        self.tokens[self.pos + 1].kind,
                        TokenKind::Fn
                            | TokenKind::Struct
                            | TokenKind::Enum
                            | TokenKind::Type
                            | TokenKind::Impl
                            | TokenKind::Trait
                            | TokenKind::Const
                    )
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}
