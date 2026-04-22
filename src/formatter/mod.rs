// ═══════════════════════════════════════════════════════════════════════
// AST-Based Formatter — Canonical Style for RUNE
//
// Parses .rune source, walks the AST, and pretty-prints with consistent
// style. Like rustfmt and gofmt, the formatter is opinionated — there
// is one correct style.
//
// Rules:
//   - 4-space indentation (no tabs)
//   - Opening brace on same line as declaration
//   - One blank line between top-level declarations
//   - Single space around binary operators, after commas, after colons
//   - Where clause predicates on separate lines
//   - Comments preserved via line-position extraction from source
//   - Trailing newline, no trailing whitespace
//
// Pillar: Security Baked In — consistent formatting enables automated
// review and reduces hiding spots for policy manipulation.
// ═══════════════════════════════════════════════════════════════════════

use crate::ast::nodes::*;
use crate::compiler::{CompileError, CompilePhase};
use crate::lexer::scanner::Lexer;
use crate::parser::parser::Parser;

#[cfg(test)]
mod tests;

// ── Public API ───────────────────────────────────────────────────────

/// Format RUNE source code, returning the canonically formatted result.
///
/// Parses the source, walks the AST, and pretty-prints with consistent
/// style. Comments from the original source are preserved.
pub fn format_source(source: &str) -> Result<String, Vec<CompileError>> {
    let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
    if !lex_errors.is_empty() {
        return Err(lex_errors
            .into_iter()
            .map(|e| CompileError {
                phase: CompilePhase::Lex,
                message: e.message,
                span: e.span,
            })
            .collect());
    }

    let (file, parse_errors) = Parser::new(tokens).parse();
    if !parse_errors.is_empty() {
        return Err(parse_errors
            .into_iter()
            .map(|e| CompileError {
                phase: CompilePhase::Parse,
                message: e.message,
                span: e.span,
            })
            .collect());
    }

    let comments = extract_comments(source);
    let mut fmt = Formatter::new(comments);
    fmt.format_file(&file);
    Ok(fmt.finish())
}

// ── Comment extraction ───────────────────────────────────────────────

/// A comment extracted from source with its line number.
#[derive(Debug, Clone)]
struct Comment {
    /// 1-based line number where the comment starts.
    line: u32,
    /// The full comment text including `//` or `/* */`.
    text: String,
    /// Whether this is a standalone comment (on its own line).
    standalone: bool,
}

/// Extract all comments from source text with their line positions.
fn extract_comments(source: &str) -> Vec<Comment> {
    let mut comments = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            comments.push(Comment {
                line: (i + 1) as u32,
                text: trimmed.to_string(),
                standalone: true,
            });
        }
    }
    comments
}

// ── Formatter ────────────────────────────────────────────────────────

struct Formatter {
    output: String,
    indent_level: usize,
    comments: Vec<Comment>,
    /// Next comment index to emit.
    comment_idx: usize,
}

impl Formatter {
    fn new(comments: Vec<Comment>) -> Self {
        Self {
            output: String::new(),
            indent_level: 0,
            comments,
            comment_idx: 0,
        }
    }

    fn finish(mut self) -> String {
        // Emit any trailing comments.
        while self.comment_idx < self.comments.len() {
            self.indent();
            self.push(&self.comments[self.comment_idx].text.clone());
            self.newline();
            self.comment_idx += 1;
        }

        // Ensure exactly one trailing newline.
        let trimmed = self.output.trim_end().to_string();
        self.output = trimmed;
        self.output.push('\n');
        self.output
    }

    // ── Helpers ──────────────────────────────────────────────────

    fn indent(&mut self) {
        for _ in 0..self.indent_level {
            self.output.push_str("    ");
        }
    }

    fn newline(&mut self) {
        // Remove trailing whitespace before newline.
        let trimmed_len = self.output.trim_end_matches(' ').len();
        self.output.truncate(trimmed_len);
        self.output.push('\n');
    }

    fn push(&mut self, s: &str) {
        self.output.push_str(s);
    }

    fn push_line(&mut self, s: &str) {
        self.indent();
        self.push(s);
        self.newline();
    }

    /// Emit any standalone comments that appear before the given line.
    fn emit_comments_before(&mut self, line: u32) {
        while self.comment_idx < self.comments.len() {
            if self.comments[self.comment_idx].line < line
                && self.comments[self.comment_idx].standalone
            {
                let text = self.comments[self.comment_idx].text.clone();
                self.indent();
                self.push(&text);
                self.newline();
                self.comment_idx += 1;
            } else {
                break;
            }
        }
    }

    // ── Top-level ────────────────────────────────────────────────

    fn format_file(&mut self, file: &SourceFile) {
        for (i, item) in file.items.iter().enumerate() {
            if i > 0 {
                self.newline();
            }
            self.emit_comments_before(item.span.line);
            self.format_item(item);
        }
    }

    fn format_item(&mut self, item: &Item) {
        match &item.kind {
            ItemKind::Policy(p) => self.format_policy(p),
            ItemKind::Function(f) => self.format_function(f),
            ItemKind::TypeAlias(t) => self.format_type_alias(t),
            ItemKind::TypeConstraint(t) => self.format_type_constraint(t),
            ItemKind::StructDef(s) => self.format_struct(s),
            ItemKind::EnumDef(e) => self.format_enum(e),
            ItemKind::Capability(c) => self.format_capability(c),
            ItemKind::Effect(e) => self.format_effect(e),
            ItemKind::TraitDef(t) => self.format_trait(t),
            ItemKind::ImplBlock(i) => self.format_impl(i),
            ItemKind::Const(c) => self.format_const(c),
            ItemKind::Module(m) => self.format_module(m),
            ItemKind::Use(u) => self.format_use(u),
            ItemKind::Extern(e) => self.format_extern_block(e),
        }
    }

    // ── Policy ───────────────────────────────────────────────────

    fn format_policy(&mut self, policy: &PolicyDecl) {
        self.indent();
        if policy.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push(&format!("policy {} {{", policy.name.name));
        self.newline();
        self.indent_level += 1;

        for (i, rule) in policy.rules.iter().enumerate() {
            if i > 0 {
                self.newline();
            }
            self.emit_comments_before(rule.span.line);
            self.format_rule(rule);
        }

        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_rule(&mut self, rule: &RuleDef) {
        self.indent();
        self.push(&format!("rule {}", rule.name.name));
        self.format_params(&rule.params);

        if let Some(guard) = &rule.when_clause {
            self.push(" when ");
            self.format_expr(guard);
        }

        self.push(" ");
        self.format_expr_as_block(&rule.body);
        self.newline();
    }

    // ── Functions ────────────────────────────────────────────────

    fn format_function(&mut self, func: &FnDecl) {
        self.indent();
        if func.signature.is_pub {
            self.push("pub ");
        }
        self.push(&format!("fn {}", func.signature.name.name));
        self.format_params(&func.signature.params);

        if let Some(ret) = &func.signature.return_type {
            self.push(" -> ");
            self.format_type_expr(ret);
        }

        if !func.signature.effects.is_empty() {
            self.push(" with effects { ");
            for (i, effect) in func.signature.effects.iter().enumerate() {
                if i > 0 {
                    self.push(", ");
                }
                self.format_path(effect);
            }
            self.push(" }");
        }

        if let Some(body) = &func.body {
            self.push(" ");
            self.format_expr_as_block(body);
            self.newline();
        } else {
            self.push(";");
            self.newline();
        }
    }

    fn format_params(&mut self, params: &[Param]) {
        self.push("(");
        for (i, param) in params.iter().enumerate() {
            if i > 0 {
                self.push(", ");
            }
            if param.is_mut {
                self.push("mut ");
            }
            self.push(&param.name.name);
            self.push(": ");
            self.format_type_expr(&param.ty);
        }
        self.push(")");
    }

    // ── Type declarations ────────────────────────────────────────

    fn format_type_alias(&mut self, alias: &TypeAliasDecl) {
        self.indent();
        if alias.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push(&format!("type {} = ", alias.name.name));
        self.format_type_expr(&alias.ty);
        self.push(";");
        self.newline();
    }

    fn format_type_constraint(&mut self, tc: &TypeConstraintDecl) {
        self.indent();
        if tc.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push(&format!("type {} = ", tc.name.name));
        self.format_type_expr(&tc.base_type);
        self.push(" where {");
        self.newline();
        self.indent_level += 1;
        for (i, pred) in tc.where_clause.predicates.iter().enumerate() {
            self.indent();
            self.format_refinement_predicate(pred);
            if i < tc.where_clause.predicates.len() - 1 {
                self.push(",");
            }
            self.newline();
        }
        self.indent_level -= 1;
        self.push_line("};");
    }

    fn format_struct(&mut self, s: &StructDef) {
        self.indent();
        if s.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push(&format!("struct {}", s.name.name));
        self.format_generic_params(&s.generic_params);
        self.push(" {");
        self.newline();
        self.indent_level += 1;
        for (i, field) in s.fields.iter().enumerate() {
            self.indent();
            if field.is_pub {
                self.push("pub ");
            }
            self.push(&field.name.name);
            self.push(": ");
            self.format_type_expr(&field.ty);
            if i < s.fields.len() - 1 {
                self.push(",");
            }
            self.newline();
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_enum(&mut self, e: &EnumDef) {
        self.indent();
        if e.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push(&format!("enum {}", e.name.name));
        self.format_generic_params(&e.generic_params);
        self.push(" {");
        self.newline();
        self.indent_level += 1;
        for (i, variant) in e.variants.iter().enumerate() {
            self.indent();
            self.push(&variant.name.name);
            match &variant.fields {
                VariantFields::Unit => {}
                VariantFields::Tuple(types) => {
                    self.push("(");
                    for (j, ty) in types.iter().enumerate() {
                        if j > 0 {
                            self.push(", ");
                        }
                        self.format_type_expr(ty);
                    }
                    self.push(")");
                }
                VariantFields::Struct(fields) => {
                    self.push(" { ");
                    for (j, f) in fields.iter().enumerate() {
                        if j > 0 {
                            self.push(", ");
                        }
                        self.push(&f.name.name);
                        self.push(": ");
                        self.format_type_expr(&f.ty);
                    }
                    self.push(" }");
                }
            }
            if i < e.variants.len() - 1 {
                self.push(",");
            }
            self.newline();
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_capability(&mut self, cap: &CapabilityDecl) {
        self.indent();
        self.push(&format!("capability {} {{", cap.name.name));
        self.newline();
        self.indent_level += 1;
        for item in &cap.items {
            match &item.kind {
                CapabilityItemKind::Function(sig) => {
                    self.indent();
                    self.push(&format!("fn {}", sig.name.name));
                    self.format_params(&sig.params);
                    if let Some(ret) = &sig.return_type {
                        self.push(" -> ");
                        self.format_type_expr(ret);
                    }
                    self.push(";");
                    self.newline();
                }
                CapabilityItemKind::Require(path) => {
                    self.indent();
                    self.push("require ");
                    self.format_path(path);
                    self.push(";");
                    self.newline();
                }
                CapabilityItemKind::Grant(path) => {
                    self.indent();
                    self.push("grant ");
                    self.format_path(path);
                    self.push(";");
                    self.newline();
                }
                CapabilityItemKind::Revoke(path) => {
                    self.indent();
                    self.push("revoke ");
                    self.format_path(path);
                    self.push(";");
                    self.newline();
                }
            }
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_effect(&mut self, effect: &EffectDecl) {
        self.indent();
        self.push(&format!("effect {} {{", effect.name.name));
        self.newline();
        self.indent_level += 1;
        for op in &effect.operations {
            self.indent();
            self.push(&format!("fn {}", op.name.name));
            self.format_params(&op.params);
            if let Some(ret) = &op.return_type {
                self.push(" -> ");
                self.format_type_expr(ret);
            }
            self.push(";");
            self.newline();
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_trait(&mut self, t: &TraitDef) {
        self.indent();
        self.push(&format!("trait {}", t.name.name));
        self.format_generic_params(&t.generic_params);
        self.push(" {");
        self.newline();
        self.indent_level += 1;
        for item in &t.items {
            match &item.kind {
                TraitItemKind::Function(f) => self.format_function(f),
                TraitItemKind::TypeAlias(ta) => self.format_type_alias(ta),
            }
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_impl(&mut self, imp: &ImplBlock) {
        self.indent();
        self.push("impl ");
        if let Some(trait_path) = &imp.trait_path {
            self.format_path(trait_path);
            self.push(" for ");
        }
        self.format_type_expr(&imp.target_ty);
        self.push(" {");
        self.newline();
        self.indent_level += 1;
        for item in &imp.items {
            self.format_item(item);
        }
        self.indent_level -= 1;
        self.push_line("}");
    }

    fn format_const(&mut self, c: &ConstDecl) {
        self.indent();
        self.push(&format!("const {}: ", c.name.name));
        self.format_type_expr(&c.ty);
        self.push(" = ");
        self.format_expr(&c.value);
        self.push(";");
        self.newline();
    }

    fn format_module(&mut self, m: &ModuleDecl) {
        self.indent();
        if m.visibility == Visibility::Public {
            self.push("pub ");
        }
        if let Some(items) = &m.items {
            self.push(&format!("mod {} {{", m.name.name));
            self.newline();
            self.indent_level += 1;
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    self.newline();
                }
                self.emit_comments_before(item.span.line);
                self.format_item(item);
            }
            self.indent_level -= 1;
            self.push_line("}");
        } else {
            self.push(&format!("mod {};", m.name.name));
            self.newline();
        }
    }

    fn format_use(&mut self, u: &UseDecl) {
        self.indent();
        if u.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push("use ");
        self.format_path(&u.path);
        match u.kind {
            UseKind::Glob => self.push("::*"),
            UseKind::Single | UseKind::Module => {}
        }
        if let Some(alias) = &u.alias {
            self.push(&format!(" as {}", alias.name));
        }
        self.push(";");
        self.newline();
    }

    fn format_extern_block(&mut self, block: &ExternBlock) {
        self.indent();
        if block.visibility == Visibility::Public {
            self.push("pub ");
        }
        self.push("extern ");
        if let Some(ref abi) = block.abi {
            self.push(&format!("\"{}\" ", abi));
        }
        if block.functions.len() == 1 && block.abi.is_none() {
            // Standalone extern fn sugar.
            let f = &block.functions[0];
            self.push(&format!("fn {}(", f.name.name));
            for (i, param) in f.params.iter().enumerate() {
                if i > 0 {
                    self.push(", ");
                }
                self.push(&format!("{}: ", param.name.name));
                self.format_type_expr(&param.ty);
            }
            self.push(")");
            if let Some(ref ret) = f.return_type {
                self.push(" -> ");
                self.format_type_expr(ret);
            }
            self.push(";");
            self.newline();
        } else {
            self.push("{");
            self.newline();
            self.indent_level += 1;
            for f in &block.functions {
                self.indent();
                self.push(&format!("fn {}(", f.name.name));
                for (i, param) in f.params.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.push(&format!("{}: ", param.name.name));
                    self.format_type_expr(&param.ty);
                }
                self.push(")");
                if let Some(ref ret) = f.return_type {
                    self.push(" -> ");
                    self.format_type_expr(ret);
                }
                self.push(";");
                self.newline();
            }
            self.indent_level -= 1;
            self.push_line("}");
        }
    }

    // ── Type expressions ─────────────────────────────────────────

    fn format_type_expr(&mut self, ty: &TypeExpr) {
        match &ty.kind {
            TypeExprKind::Named { path, type_args } => {
                self.format_path(path);
                if !type_args.is_empty() {
                    self.push("<");
                    for (i, arg) in type_args.iter().enumerate() {
                        if i > 0 {
                            self.push(", ");
                        }
                        self.format_type_expr(arg);
                    }
                    self.push(">");
                }
            }
            TypeExprKind::Tuple(types) => {
                self.push("(");
                for (i, t) in types.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_type_expr(t);
                }
                self.push(")");
            }
            TypeExprKind::Function { params, return_type } => {
                self.push("fn(");
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_type_expr(p);
                }
                self.push(") -> ");
                self.format_type_expr(return_type);
            }
            TypeExprKind::Unit => {
                self.push("()");
            }
            TypeExprKind::Reference { is_mut, inner } => {
                if *is_mut {
                    self.push("&mut ");
                } else {
                    self.push("&");
                }
                self.format_type_expr(inner);
            }
            TypeExprKind::Refined { base, where_clause } => {
                self.format_type_expr(base);
                self.push(" where { ");
                for (i, pred) in where_clause.predicates.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_refinement_predicate(pred);
                }
                self.push(" }");
            }
            TypeExprKind::Qualified { linearity, inner } => {
                self.push(&format!("{} ", linearity));
                self.format_type_expr(inner);
            }
        }
    }

    fn format_generic_params(&mut self, params: &[GenericParam]) {
        if params.is_empty() {
            return;
        }
        self.push("<");
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                self.push(", ");
            }
            self.push(&p.name.name);
            if !p.bounds.is_empty() {
                self.push(": ");
                for (j, b) in p.bounds.iter().enumerate() {
                    if j > 0 {
                        self.push(" + ");
                    }
                    self.format_type_expr(b);
                }
            }
        }
        self.push(">");
    }

    fn format_path(&mut self, path: &Path) {
        for (i, seg) in path.segments.iter().enumerate() {
            if i > 0 {
                self.push("::");
            }
            self.push(&seg.name);
        }
    }

    fn format_refinement_predicate(&mut self, pred: &RefinementPredicate) {
        self.push(&pred.field.name);
        self.push(" ");
        self.push(match pred.op {
            RefinementOp::Eq => "==",
            RefinementOp::Ne => "!=",
            RefinementOp::Lt => "<",
            RefinementOp::Gt => ">",
            RefinementOp::Le => "<=",
            RefinementOp::Ge => ">=",
            RefinementOp::In => "in",
            RefinementOp::NotIn => "not_in",
        });
        self.push(" ");
        self.format_refinement_value(&pred.value);
    }

    fn format_refinement_value(&mut self, val: &RefinementValue) {
        match val {
            RefinementValue::Bool(b) => self.push(if *b { "true" } else { "false" }),
            RefinementValue::Int(n) => self.push(&n.to_string()),
            RefinementValue::Float(f) => self.push(&format!("{f}")),
            RefinementValue::String(s) => self.push(&format!("\"{s}\"")),
            RefinementValue::List(items) => {
                self.push("[");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_refinement_value(item);
                }
                self.push("]");
            }
        }
    }

    // ── Expressions ──────────────────────────────────────────────

    /// Format an expression that should be rendered as a block.
    /// If the expression is already a Block, format it directly.
    /// Otherwise, wrap it in braces.
    fn format_expr_as_block(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Block(block) => self.format_block(block),
            _ => {
                self.push("{");
                self.newline();
                self.indent_level += 1;
                self.indent();
                self.format_expr(expr);
                self.newline();
                self.indent_level -= 1;
                self.indent();
                self.push("}");
            }
        }
    }

    fn format_block(&mut self, block: &Block) {
        self.push("{");
        self.newline();
        self.indent_level += 1;

        for stmt in &block.stmts {
            self.emit_comments_before(stmt.span.line);
            self.format_stmt(stmt);
        }

        self.indent_level -= 1;
        self.indent();
        self.push("}");
    }

    fn format_stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Item(item) => self.format_item(item),
            StmtKind::Expr(expr) => {
                self.indent();
                self.format_expr(expr);
                self.push(";");
                self.newline();
            }
            StmtKind::TailExpr(expr) => {
                self.indent();
                self.format_expr(expr);
                self.newline();
            }
        }
    }

    fn format_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            // Literals
            ExprKind::IntLiteral(s) => self.push(s),
            ExprKind::FloatLiteral(s) => self.push(s),
            ExprKind::StringLiteral(s) => {
                self.push("\"");
                self.push(s);
                self.push("\"");
            }
            ExprKind::BoolLiteral(b) => self.push(if *b { "true" } else { "false" }),

            // Names
            ExprKind::Identifier(name) => self.push(name),
            ExprKind::Path(path) => self.format_path(path),

            // Operators
            ExprKind::Binary { op, left, right } => {
                self.format_expr(left);
                self.push(&format!(" {} ", binop_str(*op)));
                self.format_expr(right);
            }
            ExprKind::Unary { op, operand } => {
                self.push(unaryop_str(*op));
                self.format_expr(operand);
            }

            // Calls
            ExprKind::Call { callee, args } => {
                self.format_expr(callee);
                self.push("(");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_expr(arg);
                }
                self.push(")");
            }
            ExprKind::FieldAccess { object, field } => {
                self.format_expr(object);
                self.push(".");
                self.push(&field.name);
            }
            ExprKind::MethodCall { object, method, args } => {
                self.format_expr(object);
                self.push(".");
                self.push(&method.name);
                self.push("(");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_expr(arg);
                }
                self.push(")");
            }
            ExprKind::Index { object, index } => {
                self.format_expr(object);
                self.push("[");
                self.format_expr(index);
                self.push("]");
            }

            // Control flow
            ExprKind::If { condition, then_branch, else_branch } => {
                self.push("if ");
                self.format_expr(condition);
                self.push(" ");
                self.format_expr_as_block(then_branch);
                if let Some(else_expr) = else_branch {
                    self.push(" else ");
                    match &else_expr.kind {
                        ExprKind::If { .. } => self.format_expr(else_expr),
                        _ => self.format_expr_as_block(else_expr),
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.push("match ");
                self.format_expr(subject);
                self.push(" {");
                self.newline();
                self.indent_level += 1;
                for arm in arms {
                    self.indent();
                    self.format_pattern(&arm.pattern);
                    if let Some(guard) = &arm.guard {
                        self.push(" if ");
                        self.format_expr(guard);
                    }
                    self.push(" => ");
                    self.format_expr(&arm.body);
                    self.push(",");
                    self.newline();
                }
                self.indent_level -= 1;
                self.indent();
                self.push("}");
            }
            ExprKind::Block(block) => self.format_block(block),
            ExprKind::For { binding, iterator, body } => {
                self.push("for ");
                self.push(&binding.name);
                self.push(" in ");
                self.format_expr(iterator);
                self.push(" ");
                self.format_expr_as_block(body);
            }
            ExprKind::While { condition, body } => {
                self.push("while ");
                self.format_expr(condition);
                self.push(" ");
                self.format_expr_as_block(body);
            }
            ExprKind::Return(val) => {
                self.push("return");
                if let Some(v) = val {
                    self.push(" ");
                    self.format_expr(v);
                }
            }
            ExprKind::Break(val) => {
                self.push("break");
                if let Some(v) = val {
                    self.push(" ");
                    self.format_expr(v);
                }
            }
            ExprKind::Continue => self.push("continue"),

            // Let binding
            ExprKind::Let { is_mut, name, ty, value } => {
                self.push("let ");
                if *is_mut {
                    self.push("mut ");
                }
                self.push(&name.name);
                if let Some(t) = ty {
                    self.push(": ");
                    self.format_type_expr(t);
                }
                self.push(" = ");
                self.format_expr(value);
            }

            // Assignment
            ExprKind::Assign { target, value } => {
                self.format_expr(target);
                self.push(" = ");
                self.format_expr(value);
            }
            ExprKind::CompoundAssign { op, target, value } => {
                self.format_expr(target);
                self.push(&format!(" {}= ", binop_str(*op)));
                self.format_expr(value);
            }

            // Governance decisions
            ExprKind::Permit => self.push("permit"),
            ExprKind::Deny => self.push("deny"),
            ExprKind::Escalate => self.push("escalate"),
            ExprKind::Quarantine => self.push("quarantine"),

            // Governance modifiers
            ExprKind::Attest(inner) => {
                self.push("attest ");
                self.format_expr(inner);
            }
            ExprKind::Audit(body) => {
                self.push("audit ");
                self.format_expr_as_block(body);
            }
            ExprKind::SecureZone { capabilities, body } => {
                self.push("secure_zone");
                if !capabilities.is_empty() {
                    self.push("[");
                    for (i, cap) in capabilities.iter().enumerate() {
                        if i > 0 {
                            self.push(", ");
                        }
                        self.format_path(cap);
                    }
                    self.push("]");
                }
                self.push(" ");
                self.format_expr_as_block(body);
            }
            ExprKind::UnsafeFfi(body) => {
                self.push("unsafe_ffi ");
                self.format_expr_as_block(body);
            }

            // Effects
            ExprKind::Perform { effect, args } => {
                self.push("perform ");
                self.format_path(effect);
                self.push("(");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_expr(arg);
                }
                self.push(")");
            }
            ExprKind::Handle { expr, handlers } => {
                self.push("handle ");
                self.format_expr(expr);
                self.push(" {");
                self.newline();
                self.indent_level += 1;
                for handler in handlers {
                    self.indent();
                    self.format_path(&handler.effect);
                    self.format_params(&handler.params);
                    self.push(" => ");
                    self.format_expr(&handler.body);
                    self.push(",");
                    self.newline();
                }
                self.indent_level -= 1;
                self.indent();
                self.push("}");
            }

            ExprKind::Require { target, predicates } => {
                self.push("require ");
                self.format_expr(target);
                self.push(" satisfies { ");
                for (i, pred) in predicates.predicates.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_refinement_predicate(pred);
                }
                self.push(" }");
            }

            // Struct / enum construction
            ExprKind::StructLiteral { path, fields, .. } => {
                self.format_path(path);
                self.push(" { ");
                for (i, field) in fields.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.push(&field.name.name);
                    if let Some(val) = &field.value {
                        self.push(": ");
                        self.format_expr(val);
                    }
                }
                self.push(" }");
            }

            ExprKind::Tuple(elems) => {
                self.push("(");
                for (i, elem) in elems.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_expr(elem);
                }
                self.push(")");
            }

            ExprKind::Range { start, end, inclusive } => {
                if let Some(s) = start {
                    self.format_expr(s);
                }
                self.push(if *inclusive { "..." } else { ".." });
                if let Some(e) = end {
                    self.format_expr(e);
                }
            }
        }
    }

    fn format_pattern(&mut self, pattern: &Pattern) {
        match &pattern.kind {
            PatternKind::Wildcard => self.push("_"),
            PatternKind::Binding { is_mut, name } => {
                if *is_mut {
                    self.push("mut ");
                }
                self.push(&name.name);
            }
            PatternKind::Literal(expr) => self.format_expr(expr),
            PatternKind::Constructor { path, fields } => {
                self.format_path(path);
                self.push("(");
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_pattern(f);
                }
                self.push(")");
            }
            PatternKind::Struct { path, fields } => {
                self.format_path(path);
                self.push(" { ");
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.push(&f.name.name);
                    if let Some(p) = &f.pattern {
                        self.push(": ");
                        self.format_pattern(p);
                    }
                }
                self.push(" }");
            }
            PatternKind::Tuple(pats) => {
                self.push("(");
                for (i, p) in pats.iter().enumerate() {
                    if i > 0 {
                        self.push(", ");
                    }
                    self.format_pattern(p);
                }
                self.push(")");
            }
            PatternKind::Path(path) => self.format_path(path),
        }
    }
}

// ── Operator formatting ──────────────────────────────────────────────

fn binop_str(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Mod => "%",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::And => "&&",
        BinOp::Or => "||",
        BinOp::BitAnd => "&",
        BinOp::BitOr => "|",
        BinOp::BitXor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
    }
}

fn unaryop_str(op: UnaryOp) -> &'static str {
    match op {
        UnaryOp::Neg => "-",
        UnaryOp::Not => "!",
        UnaryOp::BitNot => "~",
    }
}
