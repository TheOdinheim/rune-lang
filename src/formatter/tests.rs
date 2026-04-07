#[cfg(test)]
mod tests {
    use crate::formatter::format_source;

    /// Assert formatted output matches expected exactly.
    fn assert_formats_to(input: &str, expected: &str) {
        let result = format_source(input).expect("format_source failed");
        assert_eq!(result, expected, "\n--- got ---\n{result}\n--- expected ---\n{expected}");
    }

    /// Assert formatting is idempotent: format(format(x)) == format(x).
    fn assert_idempotent(input: &str) {
        let first = format_source(input).expect("first format failed");
        let second = format_source(&first).expect("second format failed");
        assert_eq!(first, second, "\n--- first ---\n{first}\n--- second ---\n{second}");
    }

    // ═════════════════════════════════════════════════════════════════
    // Simple policy formatting
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_simple_policy_formatting() {
        assert_formats_to(
            "policy   access{rule   allow()   {permit}}",
            "policy access {\n    rule allow() {\n        permit\n    }\n}\n",
        );
    }

    #[test]
    fn test_simple_policy_idempotent() {
        assert_idempotent("policy access { rule allow() { permit } }");
    }

    // ═════════════════════════════════════════════════════════════════
    // Function declaration
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_function_with_params_and_return() {
        assert_formats_to(
            "fn  add( a:Int , b:Int ) ->Int { a+b }",
            "fn add(a: Int, b: Int) -> Int {\n    a + b\n}\n",
        );
    }

    #[test]
    fn test_function_idempotent() {
        assert_idempotent("fn add(a: Int, b: Int) -> Int { a + b }");
    }

    // ═════════════════════════════════════════════════════════════════
    // Type constraint with where clause
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_type_constraint_where_clause() {
        let input = "type RiskScore = Int where { value >= 0, value <= 100 };";
        let result = format_source(input).expect("format failed");
        assert!(result.contains("type RiskScore = Int where {"));
        assert!(result.contains("    value >= 0,"));
        assert!(result.contains("    value <= 100"));
        assert!(result.contains("};"));
        assert_idempotent(input);
    }

    // ═════════════════════════════════════════════════════════════════
    // If/else expressions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_if_else_formatting() {
        assert_formats_to(
            "fn check(x: Int) -> Int { if x>0 {1} else {0} }",
            "fn check(x: Int) -> Int {\n    if x > 0 {\n        1\n    } else {\n        0\n    }\n}\n",
        );
    }

    #[test]
    fn test_nested_if_else() {
        let input = r#"fn classify(x: Int) -> Int {
    if x > 90 { 3 } else { if x > 50 { 2 } else { 1 } }
}"#;
        let result = format_source(input).expect("format failed");
        assert!(result.contains("if x > 90"), "missing outer if: {result}");
        assert!(result.contains("if x > 50"), "missing inner if: {result}");
        assert!(result.contains("} else {"), "missing else: {result}");
        assert_idempotent(input);
    }

    // ═════════════════════════════════════════════════════════════════
    // Governance decisions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_governance_decisions_standalone() {
        assert_formats_to(
            "policy g{rule a(){permit}rule b(){deny}rule c(){escalate}rule d(){quarantine}}",
            concat!(
                "policy g {\n",
                "    rule a() {\n        permit\n    }\n\n",
                "    rule b() {\n        deny\n    }\n\n",
                "    rule c() {\n        escalate\n    }\n\n",
                "    rule d() {\n        quarantine\n    }\n",
                "}\n",
            ),
        );
    }

    #[test]
    fn test_governance_decisions_inline_in_if() {
        let input = "policy risk { rule check(score: Int) { if score > 80 { escalate } else { permit } } }";
        let result = format_source(input).expect("format failed");
        assert!(result.contains("if score > 80 {"));
        assert!(result.contains("escalate"));
        assert!(result.contains("} else {"));
        assert!(result.contains("permit"));
    }

    // ═════════════════════════════════════════════════════════════════
    // Binary expressions — operator spacing
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_binary_expression_spacing() {
        assert_formats_to(
            "fn calc(a: Int, b: Int) -> Int { a+b*2 }",
            "fn calc(a: Int, b: Int) -> Int {\n    a + b * 2\n}\n",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple top-level declarations — blank line separation
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_declarations_blank_line() {
        let input = "fn a() -> Int { 1 }\nfn b() -> Int { 2 }\npolicy p { rule r() { permit } }";
        let result = format_source(input).expect("format failed");
        // Should have blank lines between declarations.
        assert!(result.contains("}\n\nfn b"));
        assert!(result.contains("}\n\npolicy"));
    }

    // ═════════════════════════════════════════════════════════════════
    // Comments
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_comments_preserved() {
        let input = "// This is a comment\npolicy access { rule allow() { permit } }";
        let result = format_source(input).expect("format failed");
        assert!(result.contains("// This is a comment"));
    }

    // ═════════════════════════════════════════════════════════════════
    // Idempotency
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_idempotency_policy() {
        assert_idempotent("policy access { rule allow() { permit } }");
    }

    #[test]
    fn test_idempotency_complex() {
        assert_idempotent(r#"
fn is_high_risk(score: Int) -> Bool {
    score > 80
}

policy governance {
    rule risk_check(risk_score: Int) {
        if risk_score > 90 { quarantine } else { if risk_score > 70 { escalate } else { permit } }
    }
}
"#);
    }

    // ═════════════════════════════════════════════════════════════════
    // Trailing whitespace and newlines
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_no_trailing_whitespace() {
        let input = "fn x() -> Int { 42 }";
        let result = format_source(input).expect("format failed");
        for line in result.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace on: '{line}'");
        }
    }

    #[test]
    fn test_file_ends_with_one_newline() {
        let input = "fn x() -> Int { 42 }";
        let result = format_source(input).expect("format failed");
        assert!(result.ends_with('\n'), "should end with newline");
        assert!(!result.ends_with("\n\n"), "should not end with double newline");
    }

    // ═════════════════════════════════════════════════════════════════
    // Empty policy body
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_policy_body() {
        assert_formats_to(
            "policy empty {}",
            "policy empty {\n}\n",
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Complex real-world policy
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_complex_real_world_policy() {
        let input = r#"fn is_high_risk(score:Int)->Bool{score>80}
policy eu_ai_act{rule risk_assessment(risk_score:Int){if risk_score>90{quarantine}else{if risk_score>70{escalate}else{permit}}}rule transparency(resource:Int){if resource==0{deny}else{permit}}}"#;
        let result = format_source(input).expect("format failed");
        // Verify structure.
        assert!(result.contains("fn is_high_risk(score: Int) -> Bool"));
        assert!(result.contains("policy eu_ai_act {"));
        assert!(result.contains("    rule risk_assessment(risk_score: Int)"));
        assert!(result.contains("    rule transparency(resource: Int)"));
        // Verify proper indentation inside rule bodies.
        assert!(result.contains("        if risk_score > 90"));
        assert!(result.contains("        if resource == 0"));
        assert_idempotent(&result);
    }

    // ═════════════════════════════════════════════════════════════════
    // Error handling
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_format_source_error_on_invalid_syntax() {
        let result = format_source("fn bad( { }");
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(!errors.is_empty());
    }

    // ═════════════════════════════════════════════════════════════════
    // Let statements with type annotations
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_let_statement_formatting() {
        assert_formats_to(
            "fn example() -> Int { let  x :  Int =42; x }",
            "fn example() -> Int {\n    let x: Int = 42;\n    x\n}\n",
        );
    }
}
