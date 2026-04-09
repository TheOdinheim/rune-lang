#[cfg(test)]
mod tests {
    use crate::lexer::scanner::Lexer;
    use crate::lexer::token::TokenKind;

    /// Helper: tokenize source and return just the token kinds (excluding Eof).
    fn kinds(source: &str) -> Vec<TokenKind> {
        let (tokens, errors) = Lexer::new(source, 0).tokenize();
        assert!(errors.is_empty(), "unexpected lexer errors: {errors:?}");
        tokens.into_iter()
            .map(|t| t.kind)
            .filter(|k| !matches!(k, TokenKind::Eof))
            .collect()
    }

    /// Helper: tokenize and expect errors, returning them.
    fn expect_errors(source: &str) -> Vec<String> {
        let (_tokens, errors) = Lexer::new(source, 0).tokenize();
        assert!(!errors.is_empty(), "expected lexer errors but got none");
        errors.into_iter().map(|e| e.message).collect()
    }

    // ── Keywords ─────────────────────────────────────────────────────

    #[test]
    fn test_policy_keywords() {
        assert_eq!(kinds("policy"), vec![TokenKind::Policy]);
        assert_eq!(kinds("rule"), vec![TokenKind::Rule]);
        assert_eq!(kinds("permit"), vec![TokenKind::Permit]);
        assert_eq!(kinds("deny"), vec![TokenKind::Deny]);
        assert_eq!(kinds("escalate"), vec![TokenKind::Escalate]);
        assert_eq!(kinds("quarantine"), vec![TokenKind::Quarantine]);
        assert_eq!(kinds("when"), vec![TokenKind::When]);
        assert_eq!(kinds("unless"), vec![TokenKind::Unless]);
    }

    #[test]
    fn test_type_keywords() {
        assert_eq!(kinds("type"), vec![TokenKind::Type]);
        assert_eq!(kinds("struct"), vec![TokenKind::Struct]);
        assert_eq!(kinds("enum"), vec![TokenKind::Enum]);
        assert_eq!(kinds("fn"), vec![TokenKind::Fn]);
        assert_eq!(kinds("let"), vec![TokenKind::Let]);
        assert_eq!(kinds("mut"), vec![TokenKind::Mut]);
        assert_eq!(kinds("const"), vec![TokenKind::Const]);
        assert_eq!(kinds("impl"), vec![TokenKind::Impl]);
        assert_eq!(kinds("trait"), vec![TokenKind::Trait]);
        assert_eq!(kinds("self"), vec![TokenKind::SelfValue]);
    }

    #[test]
    fn test_capability_keywords() {
        assert_eq!(kinds("capability"), vec![TokenKind::Capability]);
        assert_eq!(kinds("require"), vec![TokenKind::Require]);
        assert_eq!(kinds("grant"), vec![TokenKind::Grant]);
        assert_eq!(kinds("revoke"), vec![TokenKind::Revoke]);
    }

    #[test]
    fn test_effect_keywords() {
        assert_eq!(kinds("effect"), vec![TokenKind::Effect]);
        assert_eq!(kinds("perform"), vec![TokenKind::Perform]);
        assert_eq!(kinds("handle"), vec![TokenKind::Handle]);
        assert_eq!(kinds("pure"), vec![TokenKind::Pure]);
    }

    #[test]
    fn test_control_flow_keywords() {
        assert_eq!(kinds("if"), vec![TokenKind::If]);
        assert_eq!(kinds("else"), vec![TokenKind::Else]);
        assert_eq!(kinds("match"), vec![TokenKind::Match]);
        assert_eq!(kinds("for"), vec![TokenKind::For]);
        assert_eq!(kinds("in"), vec![TokenKind::In]);
        assert_eq!(kinds("while"), vec![TokenKind::While]);
        assert_eq!(kinds("return"), vec![TokenKind::Return]);
        assert_eq!(kinds("break"), vec![TokenKind::Break]);
        assert_eq!(kinds("continue"), vec![TokenKind::Continue]);
    }

    #[test]
    fn test_module_keywords() {
        assert_eq!(kinds("mod"), vec![TokenKind::Mod]);
        assert_eq!(kinds("use"), vec![TokenKind::Use]);
        assert_eq!(kinds("pub"), vec![TokenKind::Pub]);
        assert_eq!(kinds("as"), vec![TokenKind::As]);
    }

    #[test]
    fn test_governance_keywords() {
        assert_eq!(kinds("attest"), vec![TokenKind::Attest]);
        assert_eq!(kinds("audit"), vec![TokenKind::Audit]);
        assert_eq!(kinds("secure_zone"), vec![TokenKind::SecureZone]);
        assert_eq!(kinds("unsafe_ffi"), vec![TokenKind::UnsafeFfi]);
    }

    #[test]
    fn test_boolean_literals() {
        assert_eq!(kinds("true"), vec![TokenKind::True]);
        assert_eq!(kinds("false"), vec![TokenKind::False]);
    }

    // ── Identifiers ──────────────────────────────────────────────────

    #[test]
    fn test_identifiers() {
        assert_eq!(kinds("foo"), vec![TokenKind::Identifier("foo".into())]);
        assert_eq!(kinds("_bar"), vec![TokenKind::Identifier("_bar".into())]);
        assert_eq!(kinds("Baz123"), vec![TokenKind::Identifier("Baz123".into())]);
        assert_eq!(kinds("_"), vec![TokenKind::Identifier("_".into())]);
        assert_eq!(
            kinds("my_var_2"),
            vec![TokenKind::Identifier("my_var_2".into())]
        );
    }

    #[test]
    fn test_keyword_prefix_is_identifier() {
        // "policy_name" should NOT be the keyword `policy`.
        assert_eq!(
            kinds("policy_name"),
            vec![TokenKind::Identifier("policy_name".into())]
        );
        assert_eq!(
            kinds("letter"),
            vec![TokenKind::Identifier("letter".into())]
        );
    }

    // ── Integer literals ─────────────────────────────────────────────

    #[test]
    fn test_decimal_integers() {
        assert_eq!(kinds("0"), vec![TokenKind::IntLiteral("0".into())]);
        assert_eq!(kinds("42"), vec![TokenKind::IntLiteral("42".into())]);
        assert_eq!(
            kinds("1_000_000"),
            vec![TokenKind::IntLiteral("1_000_000".into())]
        );
    }

    #[test]
    fn test_hex_integers() {
        assert_eq!(kinds("0xFF"), vec![TokenKind::IntLiteral("0xFF".into())]);
        assert_eq!(
            kinds("0xDEAD_BEEF"),
            vec![TokenKind::IntLiteral("0xDEAD_BEEF".into())]
        );
    }

    #[test]
    fn test_octal_integers() {
        assert_eq!(kinds("0o77"), vec![TokenKind::IntLiteral("0o77".into())]);
        assert_eq!(
            kinds("0o7_5_3"),
            vec![TokenKind::IntLiteral("0o7_5_3".into())]
        );
    }

    #[test]
    fn test_binary_integers() {
        assert_eq!(
            kinds("0b1010"),
            vec![TokenKind::IntLiteral("0b1010".into())]
        );
        assert_eq!(
            kinds("0b1111_0000"),
            vec![TokenKind::IntLiteral("0b1111_0000".into())]
        );
    }

    // ── Float literals ───────────────────────────────────────────────

    #[test]
    fn test_float_literals() {
        assert_eq!(
            kinds("3.14"),
            vec![TokenKind::FloatLiteral("3.14".into())]
        );
        assert_eq!(
            kinds("0.001"),
            vec![TokenKind::FloatLiteral("0.001".into())]
        );
        assert_eq!(
            kinds("1e10"),
            vec![TokenKind::FloatLiteral("1e10".into())]
        );
        assert_eq!(
            kinds("2.5E-3"),
            vec![TokenKind::FloatLiteral("2.5E-3".into())]
        );
        assert_eq!(
            kinds("1_000.5"),
            vec![TokenKind::FloatLiteral("1_000.5".into())]
        );
    }

    #[test]
    fn test_integer_before_range_not_float() {
        // `1..2` should be IntLiteral(1), DotDot, IntLiteral(2) — not a float.
        assert_eq!(
            kinds("1..2"),
            vec![
                TokenKind::IntLiteral("1".into()),
                TokenKind::DotDot,
                TokenKind::IntLiteral("2".into()),
            ]
        );
    }

    // ── String literals ──────────────────────────────────────────────

    #[test]
    fn test_simple_string() {
        assert_eq!(
            kinds(r#""hello""#),
            vec![TokenKind::StringLiteral("hello".into())]
        );
    }

    #[test]
    fn test_string_escapes() {
        assert_eq!(
            kinds(r#""line\nbreak""#),
            vec![TokenKind::StringLiteral("line\nbreak".into())]
        );
        assert_eq!(
            kinds(r#""tab\there""#),
            vec![TokenKind::StringLiteral("tab\there".into())]
        );
        assert_eq!(
            kinds(r#""escaped\\slash""#),
            vec![TokenKind::StringLiteral("escaped\\slash".into())]
        );
        assert_eq!(
            kinds(r#""escaped\"quote""#),
            vec![TokenKind::StringLiteral("escaped\"quote".into())]
        );
        assert_eq!(
            kinds(r#""null\0byte""#),
            vec![TokenKind::StringLiteral("null\0byte".into())]
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(
            kinds(r#""""#),
            vec![TokenKind::StringLiteral(String::new())]
        );
    }

    // ── Symbols and operators ────────────────────────────────────────

    #[test]
    fn test_braces_and_parens() {
        assert_eq!(
            kinds("{ } ( ) [ ]"),
            vec![
                TokenKind::LeftBrace,
                TokenKind::RightBrace,
                TokenKind::LeftParen,
                TokenKind::RightParen,
                TokenKind::LeftBracket,
                TokenKind::RightBracket,
            ]
        );
    }

    #[test]
    fn test_angle_brackets() {
        assert_eq!(
            kinds("< >"),
            vec![TokenKind::LeftAngle, TokenKind::RightAngle]
        );
    }

    #[test]
    fn test_arithmetic_operators() {
        assert_eq!(
            kinds("+ - * / %"),
            vec![
                TokenKind::Plus,
                TokenKind::Minus,
                TokenKind::Star,
                TokenKind::Slash,
                TokenKind::Percent,
            ]
        );
    }

    #[test]
    fn test_comparison_operators() {
        assert_eq!(
            kinds("== != <= >="),
            vec![
                TokenKind::EqualEqual,
                TokenKind::BangEqual,
                TokenKind::LessEqual,
                TokenKind::GreaterEqual,
            ]
        );
    }

    #[test]
    fn test_logical_operators() {
        assert_eq!(
            kinds("&& || !"),
            vec![TokenKind::AmpAmp, TokenKind::PipePipe, TokenKind::Bang]
        );
    }

    #[test]
    fn test_bitwise_operators() {
        assert_eq!(
            kinds("& | ^ ~ << >>"),
            vec![
                TokenKind::Amp,
                TokenKind::Pipe,
                TokenKind::Caret,
                TokenKind::Tilde,
                TokenKind::LessLess,
                TokenKind::GreaterGreater,
            ]
        );
    }

    #[test]
    fn test_assignment_operators() {
        assert_eq!(
            kinds("= += -= *= /= %="),
            vec![
                TokenKind::Equal,
                TokenKind::PlusEqual,
                TokenKind::MinusEqual,
                TokenKind::StarEqual,
                TokenKind::SlashEqual,
                TokenKind::PercentEqual,
            ]
        );
    }

    #[test]
    fn test_delimiters() {
        assert_eq!(
            kinds("; : , . .. ... -> => :: @"),
            vec![
                TokenKind::Semicolon,
                TokenKind::Colon,
                TokenKind::Comma,
                TokenKind::Dot,
                TokenKind::DotDot,
                TokenKind::DotDotDot,
                TokenKind::Arrow,
                TokenKind::FatArrow,
                TokenKind::ColonColon,
                TokenKind::At,
            ]
        );
    }

    // ── Comments ─────────────────────────────────────────────────────

    #[test]
    fn test_line_comment() {
        assert_eq!(
            kinds("42 // this is a comment\n7"),
            vec![
                TokenKind::IntLiteral("42".into()),
                TokenKind::IntLiteral("7".into()),
            ]
        );
    }

    #[test]
    fn test_block_comment() {
        assert_eq!(
            kinds("42 /* block */ 7"),
            vec![
                TokenKind::IntLiteral("42".into()),
                TokenKind::IntLiteral("7".into()),
            ]
        );
    }

    #[test]
    fn test_nested_block_comment() {
        assert_eq!(
            kinds("42 /* outer /* inner */ still comment */ 7"),
            vec![
                TokenKind::IntLiteral("42".into()),
                TokenKind::IntLiteral("7".into()),
            ]
        );
    }

    // ── Spans / source locations ─────────────────────────────────────

    #[test]
    fn test_span_tracking() {
        let (tokens, errors) = Lexer::new("let x = 42;", 5).tokenize();
        assert!(errors.is_empty());

        // `let` at offset 0, line 1, col 1
        let let_tok = &tokens[0];
        assert_eq!(let_tok.kind, TokenKind::Let);
        assert_eq!(let_tok.span.file_id, 5);
        assert_eq!(let_tok.span.start, 0);
        assert_eq!(let_tok.span.end, 3);
        assert_eq!(let_tok.span.line, 1);
        assert_eq!(let_tok.span.column, 1);

        // `x` at offset 4, line 1, col 5
        let x_tok = &tokens[1];
        assert_eq!(x_tok.kind, TokenKind::Identifier("x".into()));
        assert_eq!(x_tok.span.start, 4);
        assert_eq!(x_tok.span.end, 5);
        assert_eq!(x_tok.span.column, 5);

        // `42` at offset 8, line 1, col 9
        let num_tok = &tokens[3];
        assert_eq!(num_tok.kind, TokenKind::IntLiteral("42".into()));
        assert_eq!(num_tok.span.start, 8);
        assert_eq!(num_tok.span.end, 10);
        assert_eq!(num_tok.span.column, 9);
    }

    #[test]
    fn test_multiline_span_tracking() {
        let source = "let\n  x";
        let (tokens, errors) = Lexer::new(source, 0).tokenize();
        assert!(errors.is_empty());

        // `let` on line 1
        assert_eq!(tokens[0].span.line, 1);
        assert_eq!(tokens[0].span.column, 1);

        // `x` on line 2, column 3
        assert_eq!(tokens[1].span.line, 2);
        assert_eq!(tokens[1].span.column, 3);
    }

    #[test]
    fn test_eof_token() {
        let (tokens, _) = Lexer::new("", 0).tokenize();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, TokenKind::Eof);
    }

    // ── Error handling ───────────────────────────────────────────────

    #[test]
    fn test_unterminated_string() {
        let msgs = expect_errors(r#""unterminated"#);
        assert!(msgs[0].contains("unterminated string"));
    }

    #[test]
    fn test_unknown_escape() {
        let (tokens, errors) = Lexer::new(r#""\q""#, 0).tokenize();
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("unknown escape"));
        // Scanner keeps going — the string still produces a token.
        let string_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| matches!(t.kind, TokenKind::StringLiteral(_)))
            .collect();
        assert_eq!(string_tokens.len(), 1);
    }

    #[test]
    fn test_unexpected_character() {
        let msgs = expect_errors("§");
        assert!(msgs[0].contains("unexpected character"));
    }

    #[test]
    fn test_unterminated_block_comment() {
        let msgs = expect_errors("/* unterminated");
        assert!(msgs[0].contains("unterminated block comment"));
    }

    #[test]
    fn test_invalid_hex_literal() {
        let msgs = expect_errors("0x");
        assert!(msgs[0].contains("expected hexadecimal digit"));
    }

    #[test]
    fn test_invalid_octal_literal() {
        let msgs = expect_errors("0o");
        assert!(msgs[0].contains("expected octal digit"));
    }

    #[test]
    fn test_invalid_binary_literal() {
        let msgs = expect_errors("0b");
        assert!(msgs[0].contains("expected binary digit"));
    }

    #[test]
    fn test_bad_exponent() {
        let msgs = expect_errors("1e");
        assert!(msgs[0].contains("expected digit after exponent"));
    }

    // ── Integration: realistic RUNE snippet ──────────────────────────

    #[test]
    fn test_realistic_rune_snippet() {
        let source = r#"
policy access_control {
    rule check_permission(user: Identity, resource: Resource) -> Decision {
        when user.role == "admin" {
            permit
        }
        unless attest(user.cert) {
            deny
        }
    }
}
"#;
        let (tokens, errors) = Lexer::new(source, 0).tokenize();
        assert!(errors.is_empty(), "errors: {errors:?}");

        let token_kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();

        // Verify the token stream starts correctly.
        assert_eq!(token_kinds[0], &TokenKind::Policy);
        assert_eq!(token_kinds[1], &TokenKind::Identifier("access_control".into()));
        assert_eq!(token_kinds[2], &TokenKind::LeftBrace);
        assert_eq!(token_kinds[3], &TokenKind::Rule);
        assert_eq!(token_kinds[4], &TokenKind::Identifier("check_permission".into()));
        assert_eq!(token_kinds[5], &TokenKind::LeftParen);

        // Verify it ends with Eof
        assert_eq!(token_kinds.last(), Some(&&TokenKind::Eof));
    }

    #[test]
    fn test_capability_snippet() {
        let source = "capability FileRead { require grant revoke }";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Capability,
                TokenKind::Identifier("FileRead".into()),
                TokenKind::LeftBrace,
                TokenKind::Require,
                TokenKind::Grant,
                TokenKind::Revoke,
                TokenKind::RightBrace,
            ]
        );
    }

    #[test]
    fn test_effect_snippet() {
        let source = "effect Log { fn log(msg: String) -> pure () }";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Effect,
                TokenKind::Identifier("Log".into()),
                TokenKind::LeftBrace,
                TokenKind::Fn,
                TokenKind::Identifier("log".into()),
                TokenKind::LeftParen,
                TokenKind::Identifier("msg".into()),
                TokenKind::Colon,
                TokenKind::Identifier("String".into()),
                TokenKind::RightParen,
                TokenKind::Arrow,
                TokenKind::Pure,
                TokenKind::LeftParen,
                TokenKind::RightParen,
                TokenKind::RightBrace,
            ]
        );
    }

    #[test]
    fn test_mixed_operators_and_numbers() {
        let source = "x += 0xFF & 0b1010 | 42";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Identifier("x".into()),
                TokenKind::PlusEqual,
                TokenKind::IntLiteral("0xFF".into()),
                TokenKind::Amp,
                TokenKind::IntLiteral("0b1010".into()),
                TokenKind::Pipe,
                TokenKind::IntLiteral("42".into()),
            ]
        );
    }

    #[test]
    fn test_governance_modifiers() {
        let source = "secure_zone { unsafe_ffi { audit attest } }";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::SecureZone,
                TokenKind::LeftBrace,
                TokenKind::UnsafeFfi,
                TokenKind::LeftBrace,
                TokenKind::Audit,
                TokenKind::Attest,
                TokenKind::RightBrace,
                TokenKind::RightBrace,
            ]
        );
    }

    #[test]
    fn test_fat_arrow_in_match() {
        let source = "match x { 1 => permit, _ => deny }";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Match,
                TokenKind::Identifier("x".into()),
                TokenKind::LeftBrace,
                TokenKind::IntLiteral("1".into()),
                TokenKind::FatArrow,
                TokenKind::Permit,
                TokenKind::Comma,
                TokenKind::Identifier("_".into()),
                TokenKind::FatArrow,
                TokenKind::Deny,
                TokenKind::RightBrace,
            ]
        );
    }

    #[test]
    fn test_path_expression() {
        let source = "std::collections::HashMap";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Identifier("std".into()),
                TokenKind::ColonColon,
                TokenKind::Identifier("collections".into()),
                TokenKind::ColonColon,
                TokenKind::Identifier("HashMap".into()),
            ]
        );
    }

    #[test]
    fn test_whitespace_variations() {
        // Tabs, multiple spaces, carriage returns should all be handled.
        let source = "let\t\tx  =\r\n  42";
        let k = kinds(source);
        assert_eq!(
            k,
            vec![
                TokenKind::Let,
                TokenKind::Identifier("x".into()),
                TokenKind::Equal,
                TokenKind::IntLiteral("42".into()),
            ]
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // M8: Extern keyword
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_extern_keyword() {
        assert_eq!(kinds("extern"), vec![TokenKind::Extern]);
    }

    #[test]
    fn test_extern_fn_tokens() {
        assert_eq!(
            kinds("extern fn sha256();"),
            vec![
                TokenKind::Extern,
                TokenKind::Fn,
                TokenKind::Identifier("sha256".into()),
                TokenKind::LeftParen,
                TokenKind::RightParen,
                TokenKind::Semicolon,
            ]
        );
    }

    #[test]
    fn test_extern_block_tokens() {
        let k = kinds("extern { fn hash(); }");
        assert!(k.contains(&TokenKind::Extern));
        assert!(k.contains(&TokenKind::LeftBrace));
        assert!(k.contains(&TokenKind::Fn));
        assert!(k.contains(&TokenKind::RightBrace));
    }

    #[test]
    fn test_extern_with_abi_string() {
        let k = kinds(r#"extern "C" fn hash();"#);
        assert_eq!(k[0], TokenKind::Extern);
        assert!(matches!(k[1], TokenKind::StringLiteral(ref s) if s == "C"));
        assert_eq!(k[2], TokenKind::Fn);
    }
}
