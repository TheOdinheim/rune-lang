// ═══════════════════════════════════════════════════════════════════════
// Top-level Compilation Pipeline
//
// Unifies the full RUNE compilation pipeline:
//   source → lex → parse → type check → lower to IR → compile to WASM
//
// Returns WASM bytes on success, or a list of CompileErrors on failure.
// ═══════════════════════════════════════════════════════════════════════

pub mod edition;
pub mod module_loader;

use std::path::Path;

use crate::codegen::wasm_gen::compile_to_wasm;
use crate::ir::lower::Lowerer;
use crate::lexer::scanner::Lexer;
use crate::lexer::token::Span;
use crate::manifest::RuneManifest;
use crate::parser::parser::Parser;
use crate::types::checker::TypeChecker;
use crate::types::context::TypeContext;

use self::edition::Edition;
use self::module_loader::ModuleLoader;

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

// ── Edition resolution ────────────────────────────────────────────────

/// Try to read the edition from rune.toml in the project root.
/// Returns Edition2026 (default) if no manifest is found.
fn resolve_edition(root_file: &Path) -> Result<Edition, Vec<CompileError>> {
    let dir = root_file.parent().unwrap_or(Path::new("."));
    let manifest_path = dir.join("rune.toml");
    if !manifest_path.exists() {
        return Ok(Edition::default());
    }
    let toml_str = std::fs::read_to_string(&manifest_path).map_err(|e| {
        vec![CompileError {
            phase: CompilePhase::Lex,
            message: format!("cannot read rune.toml: {}", e),
            span: Span::new(0, 0, 0, 0, 0),
        }]
    })?;
    let manifest = RuneManifest::from_str(&toml_str).map_err(|e| {
        vec![CompileError {
            phase: CompilePhase::Lex,
            message: format!("invalid rune.toml: {}", e),
            span: Span::new(0, 0, 0, 0, 0),
        }]
    })?;
    let edition_str = manifest.package.edition.as_deref().unwrap_or("2026");
    Edition::from_str(edition_str).map_err(|e| {
        vec![CompileError {
            phase: CompilePhase::Lex,
            message: e,
            span: Span::new(0, 0, 0, 0, 0),
        }]
    })
}

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

/// Compile a RUNE project from a root file, loading file-based modules.
///
/// This is the multi-file compilation entry point. When the root file
/// contains `mod crypto;`, the compiler will look for `crypto.rune` or
/// `crypto/mod.rune` relative to the root file and compile it as part
/// of the same WASM module.
pub fn compile_project(root_file: &Path) -> Result<Vec<u8>, Vec<CompileError>> {
    let source = std::fs::read_to_string(root_file).map_err(|e| {
        vec![CompileError {
            phase: CompilePhase::Lex,
            message: format!("cannot read {}: {}", root_file.display(), e),
            span: Span::new(0, 0, 0, 0, 0),
        }]
    })?;

    let edition = resolve_edition(root_file)?;
    let mut errors = Vec::new();
    let mut loader = ModuleLoader::new(root_file, 0);

    // Phase 1: Lex.
    let (tokens, lex_errors) = Lexer::new(&source, 0).tokenize();
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

    // Phase 3: Type check with module loader.
    let mut ctx = TypeContext::new();
    {
        let mut checker = TypeChecker::new(&mut ctx);
        checker.set_edition(edition);
        checker.set_module_loader(&mut loader);
        checker.set_current_file(root_file);
        checker.check_source_file(&file);
    }
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

    // Phase 4: Lower to IR (includes module functions).
    let mut lowerer = Lowerer::new();
    let ir_module = lowerer.lower_source_file(&file);

    // Phase 5: Compile to WASM.
    let wasm_bytes = compile_to_wasm(&ir_module);

    Ok(wasm_bytes)
}

/// Check a RUNE project from a root file without generating WASM.
///
/// Like compile_project but stops after type checking. File-based modules
/// are loaded and type-checked.
pub fn check_project(root_file: &Path) -> Result<(), Vec<CompileError>> {
    let source = std::fs::read_to_string(root_file).map_err(|e| {
        vec![CompileError {
            phase: CompilePhase::Lex,
            message: format!("cannot read {}: {}", root_file.display(), e),
            span: Span::new(0, 0, 0, 0, 0),
        }]
    })?;

    let edition = resolve_edition(root_file)?;
    let mut errors = Vec::new();
    let mut loader = ModuleLoader::new(root_file, 0);

    // Phase 1: Lex.
    let (tokens, lex_errors) = Lexer::new(&source, 0).tokenize();
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

    // Phase 3: Type check with module loader.
    let mut ctx = TypeContext::new();
    {
        let mut checker = TypeChecker::new(&mut ctx);
        checker.set_edition(edition);
        checker.set_module_loader(&mut loader);
        checker.set_current_file(root_file);
        checker.check_source_file(&file);
    }
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

// ── LLVM native compilation (feature-gated) ─────────────────────────

/// Compile RUNE source code to native object code via LLVM.
///
/// Returns the native object file bytes on success, or compile errors.
/// Requires the `llvm` feature to be enabled.
#[cfg(feature = "llvm")]
pub fn compile_to_native(source: &str, file_id: u32) -> Result<Vec<u8>, Vec<CompileError>> {
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

    // Phase 3: Type check.
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

    // Phase 5: Compile to native via LLVM.
    let llvm_context = inkwell::context::Context::create();
    let mut codegen = crate::codegen::llvm_gen::LlvmCodegen::new(&llvm_context, "rune_module");
    codegen.compile_module(&ir_module);

    codegen.verify().map_err(|e| vec![CompileError {
        phase: CompilePhase::Type,
        message: format!("LLVM verification failed: {e}"),
        span: Span::new(0, 0, 0, 0, 0),
    }])?;

    codegen.emit_object_bytes().map_err(|e| vec![CompileError {
        phase: CompilePhase::Type,
        message: format!("LLVM object emission failed: {e}"),
        span: Span::new(0, 0, 0, 0, 0),
    }])
}

/// Compile RUNE source code to a native object file on disk.
#[cfg(feature = "llvm")]
pub fn compile_to_native_file(
    source: &str,
    file_id: u32,
    output: &Path,
) -> Result<(), Vec<CompileError>> {
    let mut errors = Vec::new();

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

    let mut lowerer = Lowerer::new();
    let ir_module = lowerer.lower_source_file(&file);

    let llvm_context = inkwell::context::Context::create();
    let mut codegen = crate::codegen::llvm_gen::LlvmCodegen::new(&llvm_context, "rune_module");
    codegen.compile_module(&ir_module);

    codegen.verify().map_err(|e| vec![CompileError {
        phase: CompilePhase::Type,
        message: format!("LLVM verification failed: {e}"),
        span: Span::new(0, 0, 0, 0, 0),
    }])?;

    codegen.emit_object_file(output).map_err(|e| vec![CompileError {
        phase: CompilePhase::Type,
        message: format!("LLVM object emission failed: {e}"),
        span: Span::new(0, 0, 0, 0, 0),
    }])
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod multifile_tests;
