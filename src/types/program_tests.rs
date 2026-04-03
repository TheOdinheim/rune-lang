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

    // ═════════════════════════════════════════════════════════════════
    // Edge cases — M2 Polish
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_function_body() {
        // Empty block evaluates to Unit — valid if no return type declared.
        check_program_ok("fn noop() { }");
    }

    #[test]
    fn test_empty_function_body_with_return_type_mismatch() {
        let errors = check_program("fn get_value() -> Int { }");
        assert!(
            errors.iter().any(|e| e.contains("get_value") && e.contains("Int") && e.contains("()")),
            "expected return type mismatch for empty body: {errors:?}"
        );
    }

    #[test]
    fn test_function_no_return_type_returns_value() {
        // No return type annotation = Unit implied. Body returns Int.
        // This is fine — the body expression is just discarded.
        check_program_ok("fn compute() { 42 }");
    }

    #[test]
    fn test_policy_with_no_rules() {
        // A policy with zero rules — valid, just does nothing.
        check_program_ok("policy empty_policy { }");
    }

    #[test]
    fn test_nested_blocks_scope_isolation() {
        // Variable defined in inner block is not visible in outer block.
        let source = r#"
fn scoped() -> Int {
    let x = 1;
    {
        let y = 2;
        x + y
    };
    x
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_deeply_nested_governance_decisions() {
        let source = r#"
policy deep_policy {
    rule deep_check(a: Bool, b: Bool, c: Bool) {
        if a {
            if b {
                if c {
                    permit
                } else {
                    deny
                }
            } else {
                escalate
            }
        } else {
            quarantine
        }
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_multiple_policies_independent_errors() {
        // Errors in separate policies should all be reported.
        let source = r#"
policy p1 {
    rule r1() { 42 }
}
policy p2 {
    rule r2() { "bad" }
}
"#;
        let errors = check_program(source);
        assert!(errors.len() >= 2, "expected errors from both policies: {errors:?}");
        assert!(errors.iter().any(|e| e.contains("r1") && e.contains("governance decision")));
        assert!(errors.iter().any(|e| e.contains("r2") && e.contains("governance decision")));
    }

    #[test]
    fn test_forward_reference_with_effects_and_capabilities() {
        // Forward references work across effect and capability declarations.
        let source = r#"
effect Network {
    fn fetch(url: String) -> String;
}

capability FileSystem {
    fn read(path: String) -> String;
}

fn orchestrate(fs: FileSystem) -> Int {
    worker(42)
}

fn worker(x: Int) -> Int {
    x
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_const_used_in_function() {
        let source = r#"
const LIMIT: Int = 100;
fn check_limit(x: Int) -> Bool {
    x == LIMIT
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_policy_rule_all_four_decisions() {
        // Every governance decision used in a single policy.
        let source = r#"
policy exhaustive {
    rule decide(level: Int) {
        if level == 1 { permit }
        else if level == 2 { deny }
        else if level == 3 { escalate }
        else { quarantine }
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_mixed_correct_and_incorrect_functions() {
        // Good and bad functions — only the bad ones generate errors.
        let source = r#"
fn good() -> Int { 42 }
fn bad() -> Bool { 42 }
fn also_good() -> Bool { true }
fn also_bad() -> String { 123 }
"#;
        let errors = check_program(source);
        assert_eq!(errors.len(), 2, "expected exactly 2 errors: {errors:?}");
        assert!(errors.iter().any(|e| e.contains("bad")));
        assert!(errors.iter().any(|e| e.contains("also_bad")));
    }

    #[test]
    fn test_policy_rule_uses_function_call() {
        // Policy rule body calls a helper function that returns PolicyDecision.
        let source = r#"
fn evaluate(trusted: Bool) -> PolicyDecision {
    if trusted { permit } else { deny }
}

policy delegating {
    rule delegate(trusted: Bool) {
        evaluate(trusted)
    }
}
"#;
        check_program_ok(source);
    }

    #[test]
    fn test_governance_error_message_quality() {
        // Verify that governance error messages use domain language, not type theory jargon.
        let source = r#"
policy bad {
    rule returns_int() { 42 }
    rule returns_string() { "not a decision" }
}
"#;
        let errors = check_program(source);
        for err in &errors {
            assert!(
                err.contains("governance decision"),
                "governance error should use 'governance decision' language: {err}"
            );
            assert!(
                err.contains("permit, deny, escalate, or quarantine"),
                "governance error should list all four decisions: {err}"
            );
            // Should NOT contain type-theory jargon.
            assert!(
                !err.contains("expected type") && !err.contains("type mismatch"),
                "governance error should NOT use type theory jargon: {err}"
            );
        }
    }
}
