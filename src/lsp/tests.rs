#[cfg(test)]
mod tests {
    use crate::lsp::*;
    use tower_lsp::lsp_types::*;

    // ═════════════════════════════════════════════════════════════════
    // find_word_at_position
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_find_word_at_identifier() {
        let source = "fn hello() -> Int { 42 }";
        assert_eq!(find_word_at_position(source, 0, 3), Some("hello".to_string()));
    }

    #[test]
    fn test_find_word_at_keyword() {
        let source = "fn hello() -> Int { 42 }";
        assert_eq!(find_word_at_position(source, 0, 0), Some("fn".to_string()));
    }

    #[test]
    fn test_find_word_at_type() {
        let source = "fn hello() -> Int { 42 }";
        assert_eq!(find_word_at_position(source, 0, 14), Some("Int".to_string()));
    }

    #[test]
    fn test_find_word_at_whitespace_returns_none() {
        let source = "fn hello() -> Int { 42 }";
        assert_eq!(find_word_at_position(source, 0, 2), None); // space between fn and hello
    }

    #[test]
    fn test_find_word_at_operator_returns_none() {
        let source = "let x = a + b;";
        assert_eq!(find_word_at_position(source, 0, 10), None); // the + operator
    }

    #[test]
    fn test_find_word_at_start_of_line() {
        let source = "policy access {}";
        assert_eq!(find_word_at_position(source, 0, 0), Some("policy".to_string()));
    }

    #[test]
    fn test_find_word_at_end_of_line() {
        let source = "fn test() -> Bool";
        assert_eq!(find_word_at_position(source, 0, 14), Some("Bool".to_string()));
    }

    #[test]
    fn test_find_word_past_end_returns_none() {
        let source = "fn test()";
        assert_eq!(find_word_at_position(source, 0, 100), None);
    }

    #[test]
    fn test_find_word_empty_line_returns_none() {
        let source = "fn test()\n\nfn other()";
        assert_eq!(find_word_at_position(source, 1, 0), None);
    }

    #[test]
    fn test_find_word_multiline() {
        let source = "fn test() -> Int {\n    let x: Int = 42;\n    x\n}";
        // "    let x: Int = 42;" — x at col 8, Int at col 11
        assert_eq!(find_word_at_position(source, 1, 11), Some("Int".to_string()));
        assert_eq!(find_word_at_position(source, 2, 4), Some("x".to_string()));
    }

    // ═════════════════════════════════════════════════════════════════
    // Diagnostics conversion
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_diagnostic_line_column_conversion() {
        // RUNE uses 1-based; LSP uses 0-based.
        let error = crate::compiler::CompileError {
            phase: crate::compiler::CompilePhase::Parse,
            message: "test error".to_string(),
            span: crate::lexer::token::Span {
                file_id: 0,
                start: 0,
                end: 1,
                line: 1,
                column: 5,
            },
        };
        let diag = compile_error_to_diagnostic(&error);
        assert_eq!(diag.range.start.line, 0); // 1 -> 0
        assert_eq!(diag.range.start.character, 4); // 5 -> 4
    }

    #[test]
    fn test_diagnostics_multiple_errors() {
        let source = "fn bad( { } fn also_bad( { }";
        let diags = compile_diagnostics(source);
        assert!(diags.len() >= 1, "expected at least 1 diagnostic, got {}", diags.len());
        for d in &diags {
            assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
            assert_eq!(d.source, Some("rune".to_string()));
        }
    }

    #[test]
    fn test_diagnostics_valid_source_zero_diagnostics() {
        let source = "policy access { rule allow() { permit } }";
        let diags = compile_diagnostics(source);
        assert_eq!(diags.len(), 0);
    }

    #[test]
    fn test_diagnostics_invalid_source_has_error() {
        let source = "fn bad( { }";
        let diags = compile_diagnostics(source);
        assert!(!diags.is_empty());
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    // ═════════════════════════════════════════════════════════════════
    // Keyword hover
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_keyword_hover_policy() {
        let doc = keyword_hover("policy");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("policy"));
    }

    #[test]
    fn test_keyword_hover_permit() {
        let doc = keyword_hover("permit");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Governance decision"));
    }

    #[test]
    fn test_keyword_hover_deny() {
        assert!(keyword_hover("deny").is_some());
    }

    #[test]
    fn test_keyword_hover_escalate() {
        assert!(keyword_hover("escalate").is_some());
    }

    #[test]
    fn test_keyword_hover_quarantine() {
        assert!(keyword_hover("quarantine").is_some());
    }

    #[test]
    fn test_keyword_hover_unknown_returns_none() {
        assert!(keyword_hover("foobar").is_none());
    }

    #[test]
    fn test_keyword_hover_types() {
        assert!(keyword_hover("Int").is_some());
        assert!(keyword_hover("Float").is_some());
        assert!(keyword_hover("Bool").is_some());
        assert!(keyword_hover("String").is_some());
    }

    // ═════════════════════════════════════════════════════════════════
    // Completions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_keyword_completions_contains_governance() {
        let items = keyword_completions();
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"policy"));
        assert!(labels.contains(&"rule"));
        assert!(labels.contains(&"permit"));
        assert!(labels.contains(&"deny"));
        assert!(labels.contains(&"escalate"));
        assert!(labels.contains(&"quarantine"));
    }

    #[test]
    fn test_keyword_completions_contains_type_keywords() {
        let items = keyword_completions();
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"Int"));
        assert!(labels.contains(&"Float"));
        assert!(labels.contains(&"Bool"));
        assert!(labels.contains(&"String"));
    }

    #[test]
    fn test_completion_item_kinds() {
        let items = keyword_completions();

        let policy = items.iter().find(|i| i.label == "policy").unwrap();
        assert_eq!(policy.kind, Some(CompletionItemKind::KEYWORD));

        let int_type = items.iter().find(|i| i.label == "Int").unwrap();
        assert_eq!(int_type.kind, Some(CompletionItemKind::STRUCT));
    }

    #[test]
    fn test_identifier_completions_from_source() {
        let source = "fn helper() -> Int { 42 }\npolicy access { rule allow() { permit } }";
        let items = identifier_completions(source);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"helper"));
        assert!(labels.contains(&"access"));
        assert!(labels.contains(&"allow"));
    }

    #[test]
    fn test_identifier_completion_kinds() {
        let source = "fn helper() -> Int { 42 }\npolicy access { rule allow() { permit } }";
        let items = identifier_completions(source);

        let helper = items.iter().find(|i| i.label == "helper").unwrap();
        assert_eq!(helper.kind, Some(CompletionItemKind::FUNCTION));

        let access = items.iter().find(|i| i.label == "access").unwrap();
        assert_eq!(access.kind, Some(CompletionItemKind::MODULE));
    }

    #[test]
    fn test_identifier_completions_invalid_source_returns_empty() {
        let items = identifier_completions("fn bad( { }");
        assert!(items.is_empty());
    }
}
