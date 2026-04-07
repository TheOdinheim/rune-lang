// ═══════════════════════════════════════════════════════════════════════
// RUNE Playground — Browser WASM API
//
// Exposes a Bronze-level RUNE compiler to JavaScript via wasm-bindgen.
// Compiles without Z3 (SMT), wasmtime, or tower-lsp — runs entirely
// in the browser's native WebAssembly runtime.
//
// Pillar: No Single Points of Failure — RUNE is accessible without
// installing any toolchain. Any browser becomes a RUNE environment.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(feature = "playground")]
use wasm_bindgen::prelude::*;

use crate::compiler::{compile_source, check_source};
use crate::formatter::format_source;

// ── Internal functions (testable without wasm-bindgen) ──────────────

/// Type-check RUNE source. Returns JSON string.
pub fn check_internal(source: &str) -> String {
    match check_source(source, 0) {
        Ok(()) => r#"{"success":true,"errors":[]}"#.to_string(),
        Err(errors) => {
            let error_strs: Vec<String> = errors
                .iter()
                .map(|e| {
                    format!(
                        "{}:{}: {} error: {}",
                        e.span.line, e.span.column, e.phase_tag(), e.message
                    )
                })
                .collect();
            let errors_json: Vec<String> = error_strs
                .iter()
                .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect();
            format!(
                "{{\"success\":false,\"errors\":[{}]}}",
                errors_json.join(",")
            )
        }
    }
}

/// Compile RUNE source to WASM bytes.
pub fn compile_internal(source: &str) -> Vec<u8> {
    match compile_source(source, 0) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    }
}

/// Format RUNE source. Returns JSON string.
pub fn format_internal(source: &str) -> String {
    match format_source(source) {
        Ok(formatted) => {
            let escaped = formatted.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            format!("{{\"success\":true,\"formatted\":\"{}\"}}", escaped)
        }
        Err(errors) => {
            let error_strs: Vec<String> = errors
                .iter()
                .map(|e| format!("{}:{}: {}", e.span.line, e.span.column, e.message))
                .collect();
            let errors_json: Vec<String> = error_strs
                .iter()
                .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect();
            format!(
                "{{\"success\":false,\"errors\":[{}]}}",
                errors_json.join(",")
            )
        }
    }
}

// ── wasm-bindgen exports ────────────────────────────────────────────

/// Type-check RUNE source code. Returns a JSON string:
/// `{ "success": true, "errors": [] }` or
/// `{ "success": false, "errors": ["line:col: phase error: message", ...] }`
#[cfg(feature = "playground")]
#[wasm_bindgen]
pub fn check(source: &str) -> String {
    check_internal(source)
}

/// Compile RUNE source code to WASM bytecode.
/// Returns the raw WASM bytes (received as Uint8Array in JS).
/// Returns empty array on compilation error.
#[cfg(feature = "playground")]
#[wasm_bindgen]
pub fn compile(source: &str) -> Vec<u8> {
    compile_internal(source)
}

/// Format RUNE source code with canonical style. Returns a JSON string:
/// `{ "success": true, "formatted": "..." }` or
/// `{ "success": false, "errors": [...] }`
#[cfg(feature = "playground")]
#[wasm_bindgen]
pub fn format(source: &str) -> String {
    format_internal(source)
}

// ── Tests (run without wasm-bindgen) ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_valid_source_returns_success() {
        let result = check_internal("policy access { rule allow() { permit } }");
        assert!(result.contains("\"success\":true"), "result: {result}");
    }

    #[test]
    fn test_check_invalid_source_returns_errors() {
        let result = check_internal("fn bad( { }");
        assert!(result.contains("\"success\":false"), "result: {result}");
        assert!(result.contains("\"errors\":["), "result: {result}");
    }

    #[test]
    fn test_compile_valid_source_returns_wasm_bytes() {
        let bytes = compile_internal("policy access { rule allow() { permit } }");
        assert!(!bytes.is_empty());
        // WASM magic bytes: \0asm
        assert_eq!(&bytes[0..4], &[0x00, 0x61, 0x73, 0x6D]);
    }

    #[test]
    fn test_compile_invalid_source_returns_empty() {
        let bytes = compile_internal("fn bad( { }");
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_format_valid_source_returns_formatted() {
        let result = format_internal("policy access{rule allow(){permit}}");
        assert!(result.contains("\"success\":true"), "result: {result}");
        assert!(result.contains("\"formatted\":"), "result: {result}");
    }

    #[test]
    fn test_format_reformats_source() {
        let result = format_internal("policy  access  { rule  allow()  { permit } }");
        assert!(result.contains("\"success\":true"), "result: {result}");
        assert!(result.contains("policy access"), "result: {result}");
    }
}
