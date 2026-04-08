#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::compiler::{compile_project, check_project};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn create_project_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "rune_multifile_{}_{}", std::process::id(), n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ═════════════════════════════════════════════════════════════════
    // Multi-file type checking
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_file_module_loads_and_resolves() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod crypto;
            fn main() -> Bool { crypto::verify() }
        "#).unwrap();
        fs::write(dir.join("crypto.rune"), r#"
            pub fn verify() -> Bool { true }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_module_private_function_error() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod crypto;
            fn main() -> Bool { crypto::internal() }
        "#).unwrap();
        fs::write(dir.join("crypto.rune"), r#"
            fn internal() -> Bool { false }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.message.contains("private")),
            "expected privacy error: {:?}", errors
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_mod_file() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod rules;
            fn main() -> Bool { rules::check() }
        "#).unwrap();
        let rules_dir = dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("mod.rune"), r#"
            pub fn check() -> Bool { true }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_nested_file_modules() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod rules;
            fn main() -> Int { rules::access::level() }
        "#).unwrap();

        let rules_dir = dir.join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(rules_dir.join("mod.rune"), r#"
            pub mod access;
        "#).unwrap();
        fs::write(rules_dir.join("access.rune"), r#"
            pub fn level() -> Int { 42 }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_use_import_from_file_module() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod crypto;
            use crypto::verify;
            fn main() -> Bool { verify() }
        "#).unwrap();
        fs::write(dir.join("crypto.rune"), r#"
            pub fn verify() -> Bool { true }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_type_error_in_loaded_module() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod bad;
        "#).unwrap();
        fs::write(dir.join("bad.rune"), r#"
            pub fn broken() -> Int { "not an int" }
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.message.contains("String") || e.message.contains("Int")),
            "expected type error from loaded module: {:?}", errors
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_not_found_error() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod nonexistent;
        "#).unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.message.contains("file not found")),
            "expected file not found error: {:?}", errors
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_empty_file_module() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod empty;
            fn main() -> Int { 42 }
        "#).unwrap();
        fs::write(dir.join("empty.rune"), "").unwrap();

        let result = check_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    // ═════════════════════════════════════════════════════════════════
    // Multi-file compilation (end-to-end)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_compile_two_file_project() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod math;
            fn add_ten(x: Int) -> Int { math::add(x, 10) }
        "#).unwrap();
        fs::write(dir.join("math.rune"), r#"
            pub fn add(a: Int, b: Int) -> Int { a + b }
        "#).unwrap();

        let result = compile_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());
        let wasm = result.unwrap();
        assert!(!wasm.is_empty(), "WASM output should not be empty");
        // Check for WASM magic bytes.
        assert_eq!(&wasm[0..4], &[0x00, 0x61, 0x73, 0x6D]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compile_policy_across_files() {
        let dir = create_project_dir();
        fs::write(dir.join("main.rune"), r#"
            mod helpers;
            policy access {
                rule check(score: Int) {
                    if score > 80 { deny } else { permit }
                }
            }
        "#).unwrap();
        fs::write(dir.join("helpers.rune"), r#"
            pub fn is_high(score: Int) -> Bool { score > 80 }
        "#).unwrap();

        let result = compile_project(&dir.join("main.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    // ═════════════════════════════════════════════════════════════════
    // Backward compatibility
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_single_file_via_compile_project() {
        let dir = create_project_dir();
        fs::write(dir.join("single.rune"), r#"
            fn add(a: Int, b: Int) -> Int { a + b }
            policy access { rule allow() { permit } }
        "#).unwrap();

        let result = compile_project(&dir.join("single.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_project_single_file() {
        let dir = create_project_dir();
        fs::write(dir.join("single.rune"), r#"
            fn greet() -> Int { 42 }
        "#).unwrap();

        let result = check_project(&dir.join("single.rune"));
        assert!(result.is_ok(), "errors: {:?}", result.unwrap_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
