// ═══════════════════════════════════════════════════════════════════════
// Top-level Compilation Pipeline
//
// Unifies the full RUNE compilation pipeline:
//   source → lex → parse → type check → lower to IR → compile to WASM
//
// Returns WASM bytes on success, or a list of CompileErrors on failure.
// ═══════════════════════════════════════════════════════════════════════

use crate::codegen::wasm_gen::compile_to_wasm;
use crate::ir::lower::Lowerer;
use crate::lexer::scanner::Lexer;
use crate::lexer::token::Span;
use crate::parser::parser::Parser;
use crate::types::checker::TypeChecker;
use crate::types::context::TypeContext;

// ── Unified compile error ──────────────────────────────────────────────

/// A compilation error from any phase of the pipeline.
#[derive(Debug, Clone)]
pub struct CompileError {
    pub phase: CompilePhase,
    pub message: String,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilePhase {
    Lex,
    Parse,
    Type,
}

impl CompileError {
    /// Short tag for the compilation phase (used in error output).
    pub fn phase_tag(&self) -> &'static str {
        match self.phase {
            CompilePhase::Lex => "lex",
            CompilePhase::Parse => "parse",
            CompilePhase::Type => "type",
        }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} error at line {}, column {}: {}",
            self.phase_tag(), self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for CompileError {}

// ── Pipeline ───────────────────────────────────────────────────────────

/// Compile RUNE source code to WASM bytecode.
///
/// Returns the WASM bytes on success, or all collected errors on failure.
/// Errors from all phases are collected — lex errors don't prevent
/// reporting parse errors that can still be detected.
pub fn compile_source(source: &str, file_id: u32) -> Result<Vec<u8>, Vec<CompileError>> {
    let mut errors = Vec::new();

    // Phase 1: Lex.
    let (tokens, lex_errors) = Lexer::new(source, file_id).tokenize();
    for e in &lex_errors {
        errors.push(CompileError {
            phase: CompilePhase::Lex,
            message: e.message.clone(),
            span: e.span.clone(),
        });
    }
    if !lex_errors.is_empty() {
        return Err(errors);
    }

    // Phase 2: Parse.
    let (file, parse_errors) = Parser::new(tokens).parse();
    for e in &parse_errors {
        errors.push(CompileError {
            phase: CompilePhase::Parse,
            message: e.message.clone(),
            span: e.span.clone(),
        });
    }
    if !parse_errors.is_empty() {
        return Err(errors);
    }

    // Phase 3: Type check (collect errors, don't abort on first).
    let mut ctx = TypeContext::new();
    let mut checker = TypeChecker::new(&mut ctx);
    checker.check_source_file(&file);
    if !ctx.errors.is_empty() {
        for e in &ctx.errors {
            errors.push(CompileError {
                phase: CompilePhase::Type,
                message: e.message.clone(),
                span: e.span.clone(),
            });
        }
        return Err(errors);
    }

    // Phase 4: Lower to IR.
    let mut lowerer = Lowerer::new();
    let ir_module = lowerer.lower_source_file(&file);

    // Phase 5: Compile to WASM.
    let wasm_bytes = compile_to_wasm(&ir_module);

    Ok(wasm_bytes)
}

/// Check RUNE source code without generating WASM (lex + parse + type check).
///
/// Returns Ok(()) on success, or all collected errors on failure.
pub fn check_source(source: &str, file_id: u32) -> Result<(), Vec<CompileError>> {
    let mut errors = Vec::new();

    // Phase 1: Lex.
    let (tokens, lex_errors) = Lexer::new(source, file_id).tokenize();
    for e in &lex_errors {
        errors.push(CompileError {
            phase: CompilePhase::Lex,
            message: e.message.clone(),
            span: e.span.clone(),
        });
    }
    if !lex_errors.is_empty() {
        return Err(errors);
    }

    // Phase 2: Parse.
    let (_file, parse_errors) = Parser::new(tokens).parse();
    for e in &parse_errors {
        errors.push(CompileError {
            phase: CompilePhase::Parse,
            message: e.message.clone(),
            span: e.span.clone(),
        });
    }
    if !parse_errors.is_empty() {
        return Err(errors);
    }

    // Phase 3: Type check.
    let mut ctx = TypeContext::new();
    let mut checker = TypeChecker::new(&mut ctx);
    checker.check_source_file(&_file);
    if !ctx.errors.is_empty() {
        for e in &ctx.errors {
            errors.push(CompileError {
                phase: CompilePhase::Type,
                message: e.message.clone(),
                span: e.span.clone(),
            });
        }
        return Err(errors);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
