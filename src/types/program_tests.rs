#[cfg(test)]
mod tests {
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;
    use crate::types::checker::TypeChecker;
    use crate::types::context::TypeContext;

    /// Parse and type-check a complete source file.
    fn check_program(source: &str) -> Vec<String> {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        let mut ctx = TypeContext::new();
        {
            let mut checker = TypeChecker::new(&mut ctx);
            checker.check_source_file(&file);
        }
        ctx.errors.iter().map(|e| e.message.clone()).collect()
    }

    /// Parse and type-check, expecting no errors.
    fn check_program_ok(source: &str) -> Vec<String> {
        let errors = check_program(source);
        assert!(errors.is_empty(), "unexpected type errors: {errors:?}");
        errors
    }

    // ═════════════════════════════════════════════════════════════════
    // Basic function declarations
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_simple_function() {
        check_program_ok("fn greet() { 42 }");
    }

    #[test]
    fn test_function_with_return_type() {
        check_program_ok("fn add(a: Int, b: Int) -> Int { let c = a + b; c }");
    }

    #[test]
    fn test_function_wrong_return_type() {
        let errors = check_program(r#"fn get_name() -> Int { "hello" }"#);
        assert!(
            errors.iter().any(|e| e.contains("get_name") && e.contains("Int") && e.contains("String")),
            "expected return type mismatch: {errors:?}"
        );
    }

    #[test]
    fn test_function_unit_return_type_implicit() {
        // No return type declared, body is Unit — should pass.
        check_program_ok("fn side_effect() { let x = 1; }");
    }

    // ═════════════════════════════════════════════════════════════════
    // Forward references between functions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_forward_reference() {
        // Function A calls function B which is defined AFTER A.
        let source = r#"
fn caller() -> Int {
    callee(42)
}
fn callee(x: Int) -> Int {
    x
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_mutual_forward_references() {
        let source = r#"
fn is_even(n: Int) -> Bool {
    if n == 0 { true } else { is_odd(n) }
}
fn is_odd(n: Int) -> Bool {
    if n == 0 { false } else { is_even(n) }
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Policy and rule checking — RUNE's core
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_policy_rule_returns_permit() {
        let source = r#"
policy access_control {
    rule allow_all() {
        permit
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_policy_rule_returns_deny() {
        let source = r#"
policy access_control {
    rule deny_all() {
        deny
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_policy_rule_conditional_decision() {
        let source = r#"
policy model_check {
    rule check_trust(trusted: Bool) {
        if trusted { permit } else { deny }
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_policy_rule_non_decision_error() {
        let source = r#"
policy bad_policy {
    rule check_model(score: Int) {
        score + 1
    }
}
"#;
        let errors = check_program(source);
        assert!(
            errors.iter().any(|e|
                e.contains("check_model")
                && e.contains("governance decision")
                && e.contains("permit, deny, escalate, or quarantine")
                && e.contains("Int")),
            "expected governance-aware error message: {errors:?}"
        );
    }

    #[test]
    fn test_policy_rule_with_when_clause() {
        let source = r#"
policy access {
    rule admin_only(is_admin: Bool) when is_admin {
        permit
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_policy_rule_when_clause_non_bool_error() {
        let source = r#"
policy access {
    rule bad_guard(level: Int) when level {
        permit
    }
}
"#;
        let errors = check_program(source);
        assert!(
            errors.iter().any(|e| e.contains("when-clause") && e.contains("Bool") && e.contains("Int")),
            "expected when-clause type error: {errors:?}"
        );
    }

    #[test]
    fn test_policy_multiple_rules() {
        let source = r#"
policy model_governance {
    rule allow_trusted(trusted: Bool) when trusted {
        permit
    }
    rule deny_untrusted(trusted: Bool) {
        if trusted { escalate } else { quarantine }
    }
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Struct definitions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_struct_registration() {
        // Struct registered as a type — function can reference it in return type.
        let source = r#"
struct Config {
    timeout: Int,
}
fn get_timeout() -> Int {
    42
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Enum definitions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_enum_registration() {
        let source = r#"
enum Status {
    Active,
    Inactive,
}
fn check() -> Bool {
    true
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Const declarations
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_const_correct_type() {
        let source = "const MAX_RETRIES: Int = 3;";
        check_program_ok(source);
    }

    #[test]
    fn test_const_wrong_type() {
        let source = r#"const NAME: Int = "hello";"#;
        let errors = check_program(source);
        assert!(
            errors.iter().any(|e| e.contains("NAME") && e.contains("Int") && e.contains("String")),
            "expected const type mismatch: {errors:?}"
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Effect integration (Layer 3)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_function_with_effects_declared() {
        let source = r#"
effect Network {
    fn fetch(url: String) -> String;
}
fn do_fetch(url: String) -> String with effects { Network } {
    url
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Capability integration (Layer 3b)
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_capability_declaration_and_usage() {
        let source = r#"
capability FileSystem {
    fn read(path: String) -> String;
    fn write(path: String, data: String);
}
fn load_config(fs: FileSystem) -> Int {
    42
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Type alias
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_type_alias() {
        let source = r#"
type Score = Int;
fn get_score() -> Score {
    100
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Trait + impl
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_trait_with_default_method_checked() {
        let source = r#"
trait Validator {
    fn validate(x: Int) -> Bool {
        true
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_impl_block_methods_checked() {
        let source = r#"
struct Counter {
    value: Int,
}
impl Counter {
    fn new() -> Int {
        0
    }
    fn increment(self: Counter) -> Int {
        1
    }
}
"#;
        check_program_ok(source);
    }

    // ═════════════════════════════════════════════════════════════════
    // Full integration: realistic multi-declaration RUNE program
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_full_integration_governance_program() {
        let source = r#"
effect Network {
    fn fetch(url: String) -> String;
}

capability FileSystem {
    fn read(path: String) -> String;
}

struct ModelConfig {
    name: String,
    threshold: Float,
}

const DEFAULT_THRESHOLD: Float = 0.95;

fn validate_score(score: Float) -> Bool {
    score == score
}

policy model_governance {
    rule check_model(score: Float, trusted: Bool) when trusted {
        if validate_score(score) {
            permit
        } else {
            quarantine
        }
    }

    rule reject_untrusted(trusted: Bool) {
        if trusted { escalate } else { deny }
    }
}

fn evaluate(score: Float, trusted: Bool) -> PolicyDecision {
    if trusted {
        if validate_score(score) { permit } else { quarantine }
    } else {
        deny
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_full_integration_errors_collected() {
        // Multiple errors in different items — all should be reported.
        let source = r#"
fn bad_return() -> Bool { 42 }

policy broken {
    rule bad_rule() { 123 }
}

const WRONG: Bool = 42;
"#;
        let errors = check_program(source);
        // Should have at least 3 errors: return type, rule type, const type.
        assert!(
            errors.len() >= 3,
            "expected at least 3 errors, got {}: {errors:?}",
            errors.len()
        );
        assert!(errors.iter().any(|e| e.contains("bad_return")));
        assert!(errors.iter().any(|e| e.contains("bad_rule") && e.contains("governance decision")));
        assert!(errors.iter().any(|e| e.contains("WRONG")));
    }
}
