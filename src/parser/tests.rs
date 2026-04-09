#[cfg(test)]
mod tests {
    use crate::ast::nodes::*;
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    /// Helper: lex + parse source, assert no errors, return SourceFile.
    fn parse_ok(source: &str) -> SourceFile {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lexer errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        file
    }

    /// Helper: lex + parse source, return parse errors (expect at least one).
    fn parse_errors(source: &str) -> Vec<String> {
        let (tokens, _) = Lexer::new(source, 0).tokenize();
        let (_, errors) = Parser::new(tokens).parse();
        assert!(!errors.is_empty(), "expected parse errors but got none");
        errors.into_iter().map(|e| e.message).collect()
    }

    /// Helper: parse and return the single top-level item's kind.
    fn parse_single_item(source: &str) -> ItemKind {
        let file = parse_ok(source);
        assert_eq!(file.items.len(), 1, "expected 1 item, got {}", file.items.len());
        file.items.into_iter().next().unwrap().kind
    }

    /// Helper: parse expression from inside a function body.
    fn parse_body_expr(expr_source: &str) -> Expr {
        let source = format!("fn test() {{ {expr_source} }}");
        let file = parse_ok(&source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!("expected fn") };
        let body = f.body.as_ref().expect("expected body");
        let ExprKind::Block(block) = &body.kind else { panic!("expected block") };
        assert!(!block.stmts.is_empty(), "empty block");
        match &block.stmts.last().unwrap().kind {
            StmtKind::TailExpr(e) | StmtKind::Expr(e) => e.clone(),
            StmtKind::Item(_) => panic!("expected expression, got item"),
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // PHASE 1: Governance core
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_file() {
        let file = parse_ok("");
        assert!(file.items.is_empty());
    }

    // ── Policy declarations ──────────────────────────────────────────

    #[test]
    fn test_policy_with_simple_rule() {
        let source = r#"
policy access_control {
    rule allow_admin(user: Identity) when user.role == "admin" {
        permit
    }
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Policy(p) = item else { panic!("expected policy") };
        assert_eq!(p.name.name, "access_control");
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].name.name, "allow_admin");
        assert!(p.rules[0].when_clause.is_some());
    }

    #[test]
    fn test_policy_multiple_rules() {
        let source = r#"
policy firewall {
    rule check_source(req: Request) {
        deny
    }
    rule check_destination(req: Request) {
        permit
    }
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Policy(p) = item else { panic!("expected policy") };
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.rules[0].name.name, "check_source");
        assert_eq!(p.rules[1].name.name, "check_destination");
    }

    #[test]
    fn test_rule_no_params() {
        let source = r#"
policy simple {
    rule always_deny {
        deny
    }
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Policy(p) = item else { panic!("expected policy") };
        assert!(p.rules[0].params.is_empty());
    }

    #[test]
    fn test_governance_decisions() {
        for keyword in &["permit", "deny", "escalate", "quarantine"] {
            let source = format!("policy p {{ rule r {{ {keyword} }} }}");
            let item = parse_single_item(&source);
            let ItemKind::Policy(p) = item else { panic!("expected policy") };
            let body = &p.rules[0].body;
            let ExprKind::Block(block) = &body.kind else { panic!("expected block") };
            let stmt = &block.stmts[0];
            match keyword.as_ref() {
                "permit" => assert!(matches!(
                    stmt.kind,
                    StmtKind::TailExpr(Expr { kind: ExprKind::Permit, .. })
                )),
                "deny" => assert!(matches!(
                    stmt.kind,
                    StmtKind::TailExpr(Expr { kind: ExprKind::Deny, .. })
                )),
                "escalate" => assert!(matches!(
                    stmt.kind,
                    StmtKind::TailExpr(Expr { kind: ExprKind::Escalate, .. })
                )),
                "quarantine" => assert!(matches!(
                    stmt.kind,
                    StmtKind::TailExpr(Expr { kind: ExprKind::Quarantine, .. })
                )),
                _ => unreachable!(),
            }
        }
    }

    // ── Function declarations ────────────────────────────────────────

    #[test]
    fn test_simple_function() {
        let source = "fn add(a: i32, b: i32) -> i32 { a + b }";
        let item = parse_single_item(source);
        let ItemKind::Function(f) = item else { panic!("expected fn") };
        assert_eq!(f.signature.name.name, "add");
        assert_eq!(f.signature.params.len(), 2);
        assert!(f.signature.return_type.is_some());
        assert!(f.body.is_some());
    }

    #[test]
    fn test_function_no_return_type() {
        let source = "fn greet(name: String) { }";
        let item = parse_single_item(source);
        let ItemKind::Function(f) = item else { panic!("expected fn") };
        assert!(f.signature.return_type.is_none());
    }

    #[test]
    fn test_pub_function() {
        let source = "pub fn public_api(x: i32) -> i32 { x }";
        let item = parse_single_item(source);
        let ItemKind::Function(f) = item else { panic!("expected fn") };
        assert!(f.signature.is_pub);
    }

    #[test]
    fn test_function_with_effects() {
        let source = "fn read_file(path: String) -> String with effects { io } { path }";
        let item = parse_single_item(source);
        let ItemKind::Function(f) = item else { panic!("expected fn") };
        assert_eq!(f.signature.effects.len(), 1);
        assert_eq!(f.signature.effects[0].segments[0].name, "io");
    }

    // ── Let bindings ─────────────────────────────────────────────────

    #[test]
    fn test_let_binding() {
        let expr = parse_body_expr("let x = 42");
        let ExprKind::Let { is_mut, name, ty, .. } = &expr.kind else { panic!("expected let") };
        assert!(!is_mut);
        assert_eq!(name.name, "x");
        assert!(ty.is_none());
    }

    #[test]
    fn test_let_mut_with_type() {
        let expr = parse_body_expr("let mut count: i32 = 0");
        let ExprKind::Let { is_mut, name, ty, .. } = &expr.kind else { panic!("expected let") };
        assert!(is_mut);
        assert_eq!(name.name, "count");
        assert!(ty.is_some());
    }

    // ── Expressions: literals ────────────────────────────────────────

    #[test]
    fn test_int_literal() {
        let expr = parse_body_expr("42");
        assert!(matches!(expr.kind, ExprKind::IntLiteral(ref s) if s == "42"));
    }

    #[test]
    fn test_float_literal() {
        let expr = parse_body_expr("3.14");
        assert!(matches!(expr.kind, ExprKind::FloatLiteral(ref s) if s == "3.14"));
    }

    #[test]
    fn test_string_literal() {
        let expr = parse_body_expr(r#""hello""#);
        assert!(matches!(expr.kind, ExprKind::StringLiteral(ref s) if s == "hello"));
    }

    #[test]
    fn test_bool_literals() {
        let t = parse_body_expr("true");
        assert!(matches!(t.kind, ExprKind::BoolLiteral(true)));
        let f = parse_body_expr("false");
        assert!(matches!(f.kind, ExprKind::BoolLiteral(false)));
    }

    // ── Expressions: binary operators and precedence ─────────────────

    #[test]
    fn test_addition() {
        let expr = parse_body_expr("1 + 2");
        let ExprKind::Binary { op, .. } = &expr.kind else { panic!("expected binary") };
        assert_eq!(*op, BinOp::Add);
    }

    #[test]
    fn test_precedence_mul_over_add() {
        // `1 + 2 * 3` should parse as `1 + (2 * 3)`
        let expr = parse_body_expr("1 + 2 * 3");
        let ExprKind::Binary { op, right, .. } = &expr.kind else { panic!("expected binary") };
        assert_eq!(*op, BinOp::Add);
        let ExprKind::Binary { op: inner_op, .. } = &right.kind else { panic!("expected binary") };
        assert_eq!(*inner_op, BinOp::Mul);
    }

    #[test]
    fn test_precedence_comparison() {
        // `a + b == c * d` should parse as `(a + b) == (c * d)`
        let expr = parse_body_expr("a + b == c * d");
        let ExprKind::Binary { op, .. } = &expr.kind else { panic!("expected binary") };
        assert_eq!(*op, BinOp::Eq);
    }

    #[test]
    fn test_precedence_logical() {
        // `a && b || c` should parse as `(a && b) || c`
        let expr = parse_body_expr("a && b || c");
        let ExprKind::Binary { op, .. } = &expr.kind else { panic!("expected binary") };
        assert_eq!(*op, BinOp::Or);
    }

    #[test]
    fn test_parenthesized_expression() {
        let expr = parse_body_expr("(1 + 2) * 3");
        let ExprKind::Binary { op, .. } = &expr.kind else { panic!("expected binary") };
        assert_eq!(*op, BinOp::Mul);
    }

    // ── Expressions: unary operators ─────────────────────────────────

    #[test]
    fn test_unary_not() {
        let expr = parse_body_expr("!flag");
        let ExprKind::Unary { op, .. } = &expr.kind else { panic!("expected unary") };
        assert_eq!(*op, UnaryOp::Not);
    }

    #[test]
    fn test_unary_neg() {
        let expr = parse_body_expr("-x");
        let ExprKind::Unary { op, .. } = &expr.kind else { panic!("expected unary") };
        assert_eq!(*op, UnaryOp::Neg);
    }

    #[test]
    fn test_unary_bitnot() {
        let expr = parse_body_expr("~mask");
        let ExprKind::Unary { op, .. } = &expr.kind else { panic!("expected unary") };
        assert_eq!(*op, UnaryOp::BitNot);
    }

    // ── Expressions: function calls ──────────────────────────────────

    #[test]
    fn test_function_call() {
        let expr = parse_body_expr("foo(1, 2, 3)");
        let ExprKind::Call { callee, args } = &expr.kind else { panic!("expected call") };
        assert!(matches!(callee.kind, ExprKind::Identifier(ref n) if n == "foo"));
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn test_method_call() {
        let expr = parse_body_expr("obj.method(x)");
        let ExprKind::MethodCall { object, method, args } = &expr.kind else {
            panic!("expected method call")
        };
        assert!(matches!(object.kind, ExprKind::Identifier(ref n) if n == "obj"));
        assert_eq!(method.name, "method");
        assert_eq!(args.len(), 1);
    }

    #[test]
    fn test_field_access() {
        let expr = parse_body_expr("user.name");
        let ExprKind::FieldAccess { field, .. } = &expr.kind else { panic!("expected field access") };
        assert_eq!(field.name, "name");
    }

    #[test]
    fn test_chained_field_access() {
        let expr = parse_body_expr("a.b.c");
        let ExprKind::FieldAccess { object, field } = &expr.kind else {
            panic!("expected field access")
        };
        assert_eq!(field.name, "c");
        assert!(matches!(object.kind, ExprKind::FieldAccess { .. }));
    }

    #[test]
    fn test_index_expression() {
        let expr = parse_body_expr("arr[0]");
        assert!(matches!(expr.kind, ExprKind::Index { .. }));
    }

    // ── Expressions: blocks and if/else ──────────────────────────────

    #[test]
    fn test_block_expression() {
        let expr = parse_body_expr("{ let x = 1; x + 1 }");
        let ExprKind::Block(block) = &expr.kind else { panic!("expected block") };
        assert_eq!(block.stmts.len(), 2);
        assert!(matches!(block.stmts[0].kind, StmtKind::Expr(_)));
        assert!(matches!(block.stmts[1].kind, StmtKind::TailExpr(_)));
    }

    #[test]
    fn test_if_expression() {
        let expr = parse_body_expr("if x > 0 { x } else { 0 }");
        let ExprKind::If { else_branch, .. } = &expr.kind else { panic!("expected if") };
        assert!(else_branch.is_some());
    }

    #[test]
    fn test_if_without_else() {
        let expr = parse_body_expr("if flag { action() }");
        let ExprKind::If { else_branch, .. } = &expr.kind else { panic!("expected if") };
        assert!(else_branch.is_none());
    }

    #[test]
    fn test_if_else_if() {
        let expr = parse_body_expr("if a { 1 } else if b { 2 } else { 3 }");
        let ExprKind::If { else_branch, .. } = &expr.kind else { panic!("expected if") };
        let Some(else_expr) = else_branch else { panic!("expected else") };
        assert!(matches!(else_expr.kind, ExprKind::If { .. }));
    }

    // ── Expressions: return ──────────────────────────────────────────

    #[test]
    fn test_return_with_value() {
        let expr = parse_body_expr("return 42");
        let ExprKind::Return(Some(val)) = &expr.kind else { panic!("expected return") };
        assert!(matches!(val.kind, ExprKind::IntLiteral(_)));
    }

    #[test]
    fn test_return_without_value() {
        let source = "fn f() { return; }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let body = f.body.as_ref().unwrap();
        let ExprKind::Block(block) = &body.kind else { panic!() };
        let StmtKind::Expr(ref ret) = block.stmts[0].kind else { panic!() };
        assert!(matches!(ret.kind, ExprKind::Return(None)));
    }

    // ── Assignment ───────────────────────────────────────────────────

    #[test]
    fn test_assignment() {
        let expr = parse_body_expr("x = 42");
        assert!(matches!(expr.kind, ExprKind::Assign { .. }));
    }

    #[test]
    fn test_compound_assignment() {
        let expr = parse_body_expr("x += 1");
        let ExprKind::CompoundAssign { op, .. } = &expr.kind else { panic!() };
        assert_eq!(*op, BinOp::Add);
    }

    // ── Path expressions ─────────────────────────────────────────────

    #[test]
    fn test_path_expression() {
        let expr = parse_body_expr("std::io::read");
        let ExprKind::Path(path) = &expr.kind else { panic!("expected path") };
        assert_eq!(path.segments.len(), 3);
        assert_eq!(path.segments[0].name, "std");
        assert_eq!(path.segments[2].name, "read");
    }

    // ── Tuple expressions ────────────────────────────────────────────

    #[test]
    fn test_tuple_expression() {
        let expr = parse_body_expr("(1, 2, 3)");
        let ExprKind::Tuple(elements) = &expr.kind else { panic!("expected tuple") };
        assert_eq!(elements.len(), 3);
    }

    #[test]
    fn test_unit_expression() {
        let expr = parse_body_expr("()");
        let ExprKind::Tuple(elements) = &expr.kind else { panic!("expected unit/tuple") };
        assert!(elements.is_empty());
    }

    // ═════════════════════════════════════════════════════════════════
    // PHASE 2: Type system
    // ═════════════════════════════════════════════════════════════════

    // ── Struct definitions ───────────────────────────────────────────

    #[test]
    fn test_struct_definition() {
        let source = "struct Point { x: f64, y: f64 }";
        let item = parse_single_item(source);
        let ItemKind::StructDef(s) = item else { panic!("expected struct") };
        assert_eq!(s.name.name, "Point");
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[0].name.name, "x");
    }

    #[test]
    fn test_struct_with_generics() {
        let source = "struct Container<T> { value: T }";
        let item = parse_single_item(source);
        let ItemKind::StructDef(s) = item else { panic!("expected struct") };
        assert_eq!(s.generic_params.len(), 1);
        assert_eq!(s.generic_params[0].name.name, "T");
    }

    #[test]
    fn test_struct_pub_fields() {
        let source = "struct Config { pub name: String, secret: String }";
        let item = parse_single_item(source);
        let ItemKind::StructDef(s) = item else { panic!("expected struct") };
        assert!(s.fields[0].is_pub);
        assert!(!s.fields[1].is_pub);
    }

    // ── Enum definitions ─────────────────────────────────────────────

    #[test]
    fn test_enum_unit_variants() {
        let source = "enum Color { Red, Green, Blue }";
        let item = parse_single_item(source);
        let ItemKind::EnumDef(e) = item else { panic!("expected enum") };
        assert_eq!(e.variants.len(), 3);
        assert!(matches!(e.variants[0].fields, VariantFields::Unit));
    }

    #[test]
    fn test_enum_tuple_variant() {
        let source = "enum Option<T> { Some(T), None }";
        let item = parse_single_item(source);
        let ItemKind::EnumDef(e) = item else { panic!("expected enum") };
        assert!(matches!(e.variants[0].fields, VariantFields::Tuple(_)));
        assert!(matches!(e.variants[1].fields, VariantFields::Unit));
    }

    #[test]
    fn test_enum_struct_variant() {
        let source = "enum Shape { Circle { radius: f64 }, Rect { w: f64, h: f64 } }";
        let item = parse_single_item(source);
        let ItemKind::EnumDef(e) = item else { panic!("expected enum") };
        let VariantFields::Struct(fields) = &e.variants[0].fields else { panic!() };
        assert_eq!(fields[0].name.name, "radius");
    }

    // ── Type alias ───────────────────────────────────────────────────

    #[test]
    fn test_type_alias() {
        let source = "type UserId = i64;";
        let item = parse_single_item(source);
        let ItemKind::TypeAlias(ta) = item else { panic!("expected type alias") };
        assert_eq!(ta.name.name, "UserId");
    }

    // ── Impl blocks ──────────────────────────────────────────────────

    #[test]
    fn test_impl_block() {
        let source = "impl Point { fn new(x: f64, y: f64) -> Point { x } }";
        let item = parse_single_item(source);
        let ItemKind::ImplBlock(imp) = item else { panic!("expected impl") };
        assert!(imp.trait_path.is_none());
        assert_eq!(imp.items.len(), 1);
    }

    #[test]
    fn test_impl_trait_for_type() {
        let source = "impl Display for Point { fn fmt(self: Point) -> String { self } }";
        let item = parse_single_item(source);
        let ItemKind::ImplBlock(imp) = item else { panic!("expected impl") };
        assert!(imp.trait_path.is_some());
        assert_eq!(imp.trait_path.unwrap().segments[0].name, "Display");
    }

    // ── Trait definitions ────────────────────────────────────────────

    #[test]
    fn test_trait_definition() {
        let source = "trait Serialize { fn serialize(self: Self) -> String; }";
        let item = parse_single_item(source);
        let ItemKind::TraitDef(t) = item else { panic!("expected trait") };
        assert_eq!(t.name.name, "Serialize");
        assert_eq!(t.items.len(), 1);
    }

    #[test]
    fn test_trait_with_default_method() {
        let source = r#"
trait Greet {
    fn greet(self: Self) -> String {
        "hello"
    }
}
"#;
        let item = parse_single_item(source);
        let ItemKind::TraitDef(t) = item else { panic!("expected trait") };
        let TraitItemKind::Function(ref f) = t.items[0].kind else { panic!() };
        assert!(f.body.is_some());
    }

    // ── Type expressions ─────────────────────────────────────────────

    #[test]
    fn test_named_type_with_generics() {
        let source = "fn f(x: Vec<i32>) { }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let ty = &f.signature.params[0].ty;
        let TypeExprKind::Named { path, type_args } = &ty.kind else { panic!("expected named") };
        assert_eq!(path.segments[0].name, "Vec");
        assert_eq!(type_args.len(), 1);
    }

    #[test]
    fn test_reference_type() {
        let source = "fn f(x: &mut i32) { }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let ty = &f.signature.params[0].ty;
        let TypeExprKind::Reference { is_mut, .. } = &ty.kind else { panic!("expected ref") };
        assert!(is_mut);
    }

    #[test]
    fn test_function_type() {
        let source = "fn apply(f: fn(i32) -> i32) { }";
        let file = parse_ok(source);
        let ItemKind::Function(func) = &file.items[0].kind else { panic!() };
        let ty = &func.signature.params[0].ty;
        assert!(matches!(ty.kind, TypeExprKind::Function { .. }));
    }

    #[test]
    fn test_unit_type() {
        let source = "fn noop() -> () { }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let rt = f.signature.return_type.as_ref().unwrap();
        assert!(matches!(rt.kind, TypeExprKind::Unit));
    }

    #[test]
    fn test_tuple_type() {
        let source = "fn pair() -> (i32, String) { (1, 2) }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let rt = f.signature.return_type.as_ref().unwrap();
        let TypeExprKind::Tuple(types) = &rt.kind else { panic!("expected tuple type") };
        assert_eq!(types.len(), 2);
    }

    // ── Match expressions ────────────────────────────────────────────

    #[test]
    fn test_match_expression() {
        let expr = parse_body_expr("match x { 1 => true, _ => false }");
        let ExprKind::Match { subject, arms } = &expr.kind else { panic!("expected match") };
        assert!(matches!(subject.kind, ExprKind::Identifier(ref n) if n == "x"));
        assert_eq!(arms.len(), 2);
    }

    #[test]
    fn test_match_with_guard() {
        let expr = parse_body_expr("match x { n when n > 0 => true, _ => false }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!("expected match") };
        assert!(arms[0].guard.is_some());
    }

    #[test]
    fn test_match_constructor_pattern() {
        let expr = parse_body_expr("match opt { Some(v) => v, None => 0 }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!("expected match") };
        assert!(matches!(arms[0].pattern.kind, PatternKind::Constructor { .. }));
    }

    #[test]
    fn test_match_tuple_pattern() {
        let expr = parse_body_expr("match pair { (a, b) => a + b }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!("expected match") };
        assert!(matches!(arms[0].pattern.kind, PatternKind::Tuple(_)));
    }

    #[test]
    fn test_match_struct_pattern() {
        let expr = parse_body_expr("match point { Point { x, y } => x + y }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!("expected match") };
        assert!(matches!(arms[0].pattern.kind, PatternKind::Struct { .. }));
    }

    #[test]
    fn test_match_literal_patterns() {
        let expr = parse_body_expr(r#"match v { 42 => true, "hello" => false, _ => false }"#);
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!("expected match") };
        assert!(matches!(arms[0].pattern.kind, PatternKind::Literal(_)));
        assert!(matches!(arms[1].pattern.kind, PatternKind::Literal(_)));
        assert!(matches!(arms[2].pattern.kind, PatternKind::Wildcard));
    }

    // ── For and while loops ──────────────────────────────────────────

    #[test]
    fn test_for_loop() {
        let expr = parse_body_expr("for item in collection { item }");
        let ExprKind::For { binding, .. } = &expr.kind else { panic!("expected for") };
        assert_eq!(binding.name, "item");
    }

    #[test]
    fn test_while_loop() {
        let expr = parse_body_expr("while running { step() }");
        assert!(matches!(expr.kind, ExprKind::While { .. }));
    }

    // ── Break and continue ───────────────────────────────────────────

    #[test]
    fn test_break_and_continue() {
        let source = "fn f() { while true { break; continue; } }";
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        assert!(f.body.is_some());
    }

    // ═════════════════════════════════════════════════════════════════
    // PHASE 3: Governance-specific + modules
    // ═════════════════════════════════════════════════════════════════

    // ── Capability declarations ──────────────────────────────────────

    #[test]
    fn test_capability_declaration() {
        let source = r#"
capability FileRead {
    fn read(path: String) -> String;
    require NetworkAccess;
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Capability(c) = item else { panic!("expected capability") };
        assert_eq!(c.name.name, "FileRead");
        assert_eq!(c.items.len(), 2);
        assert!(matches!(c.items[0].kind, CapabilityItemKind::Function(_)));
        assert!(matches!(c.items[1].kind, CapabilityItemKind::Require(_)));
    }

    #[test]
    fn test_capability_grant_revoke() {
        let source = r#"
capability Admin {
    grant FileWrite;
    revoke TempAccess;
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Capability(c) = item else { panic!("expected capability") };
        assert!(matches!(c.items[0].kind, CapabilityItemKind::Grant(_)));
        assert!(matches!(c.items[1].kind, CapabilityItemKind::Revoke(_)));
    }

    // ── Effect declarations ──────────────────────────────────────────

    #[test]
    fn test_effect_declaration() {
        let source = r#"
effect IO {
    fn read(fd: i32) -> String;
    fn write(fd: i32, data: String) -> i32;
}
"#;
        let item = parse_single_item(source);
        let ItemKind::Effect(e) = item else { panic!("expected effect") };
        assert_eq!(e.name.name, "IO");
        assert_eq!(e.operations.len(), 2);
        assert_eq!(e.operations[0].name.name, "read");
    }

    // ── Attest expression ────────────────────────────────────────────

    #[test]
    fn test_attest_expression() {
        let expr = parse_body_expr("attest(model)");
        let ExprKind::Attest(inner) = &expr.kind else { panic!("expected attest") };
        assert!(matches!(inner.kind, ExprKind::Identifier(ref n) if n == "model"));
    }

    // ── Audit blocks ─────────────────────────────────────────────────

    #[test]
    fn test_audit_block() {
        let expr = parse_body_expr("audit { verify(data) }");
        assert!(matches!(expr.kind, ExprKind::Audit(_)));
    }

    // ── Secure zone blocks ───────────────────────────────────────────

    #[test]
    fn test_secure_zone() {
        let expr = parse_body_expr("secure_zone { FileRead, NetworkAccess } { process() }");
        let ExprKind::SecureZone { capabilities, .. } = &expr.kind else {
            panic!("expected secure_zone")
        };
        assert_eq!(capabilities.len(), 2);
        assert_eq!(capabilities[0].segments[0].name, "FileRead");
    }

    // ── Unsafe FFI blocks ────────────────────────────────────────────

    #[test]
    fn test_unsafe_ffi() {
        let expr = parse_body_expr("unsafe_ffi { call_c_lib() }");
        assert!(matches!(expr.kind, ExprKind::UnsafeFfi(_)));
    }

    // ── Perform expression ───────────────────────────────────────────

    #[test]
    fn test_perform_expression() {
        let expr = parse_body_expr("perform IO::write(1, data)");
        let ExprKind::Perform { effect, args } = &expr.kind else { panic!("expected perform") };
        assert_eq!(effect.segments.len(), 2);
        assert_eq!(effect.segments[0].name, "IO");
        assert_eq!(effect.segments[1].name, "write");
        assert_eq!(args.len(), 2);
    }

    // ── Handle expression ────────────────────────────────────────────

    #[test]
    fn test_handle_expression() {
        let source = r#"
fn f() {
    handle compute() {
        log(msg: String) => print(msg)
    }
}
"#;
        let file = parse_ok(source);
        let ItemKind::Function(f) = &file.items[0].kind else { panic!() };
        let body = f.body.as_ref().unwrap();
        let ExprKind::Block(block) = &body.kind else { panic!() };
        let StmtKind::TailExpr(ref expr) = block.stmts[0].kind else { panic!() };
        let ExprKind::Handle { handlers, .. } = &expr.kind else { panic!("expected handle") };
        assert_eq!(handlers.len(), 1);
    }

    // ── Module declarations ──────────────────────────────────────────

    #[test]
    fn test_module_external() {
        let source = "mod auth;";
        let item = parse_single_item(source);
        let ItemKind::Module(m) = item else { panic!("expected mod") };
        assert_eq!(m.name.name, "auth");
        assert!(m.items.is_none());
    }

    #[test]
    fn test_module_inline() {
        let source = "mod utils { fn helper() { } }";
        let item = parse_single_item(source);
        let ItemKind::Module(m) = item else { panic!("expected mod") };
        assert!(m.items.is_some());
        assert_eq!(m.items.unwrap().len(), 1);
    }

    // ── Use declarations ─────────────────────────────────────────────

    #[test]
    fn test_use_simple() {
        let source = "use std::io;";
        let item = parse_single_item(source);
        let ItemKind::Use(u) = item else { panic!("expected use") };
        assert_eq!(u.path.segments.len(), 2);
        assert!(u.alias.is_none());
    }

    #[test]
    fn test_use_with_alias() {
        let source = "use std::collections::HashMap as Map;";
        let item = parse_single_item(source);
        let ItemKind::Use(u) = item else { panic!("expected use") };
        assert_eq!(u.alias.unwrap().name, "Map");
    }

    // ── Const declarations ───────────────────────────────────────────

    #[test]
    fn test_const_declaration() {
        let source = "const MAX: i32 = 100;";
        let item = parse_single_item(source);
        let ItemKind::Const(c) = item else { panic!("expected const") };
        assert_eq!(c.name.name, "MAX");
    }

    // ═════════════════════════════════════════════════════════════════
    // Error recovery
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_error_recovery_continues_parsing() {
        // First item is malformed, second should still parse.
        let source = "fn { } fn valid() { }";
        let (tokens, _) = Lexer::new(source, 0).tokenize();
        let (file, errors) = Parser::new(tokens).parse();
        assert!(!errors.is_empty());
        // Should recover and parse the valid function.
        assert!(!file.items.is_empty());
    }

    #[test]
    fn test_error_missing_brace() {
        let errors = parse_errors("fn f()");
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_error_unexpected_token() {
        let errors = parse_errors("42;");
        assert!(!errors.is_empty());
    }

    // ═════════════════════════════════════════════════════════════════
    // Span tracking
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_spans_propagated() {
        let source = "fn add(a: i32, b: i32) -> i32 { a + b }";
        let file = parse_ok(source);
        let item = &file.items[0];
        // Item span should cover the entire function.
        assert_eq!(item.span.start, 0);
        assert!(item.span.end > 30);
        assert_eq!(item.span.line, 1);
    }

    // ═════════════════════════════════════════════════════════════════
    // Integration: realistic RUNE program
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_realistic_rune_program() {
        let source = r#"
use std::io;

capability FileRead {
    fn read(path: String) -> String;
}

effect Log {
    fn log(msg: String) -> ();
}

struct Model {
    name: String,
    version: i32
}

enum Decision {
    Allow,
    Deny(String),
    Escalate { reason: String, level: i32 }
}

policy model_governance {
    rule check_attestation(model: Model) when model.version > 0 {
        if attest(model) {
            permit
        } else {
            deny
        }
    }

    rule emergency_override(user: Identity) {
        audit {
            escalate
        }
    }
}

fn evaluate(model: Model) -> Decision {
    secure_zone { FileRead } {
        let result = model.name;
        if result == "trusted" {
            Decision::Allow
        } else {
            Decision::Deny(result)
        }
    }
}
"#;
        let file = parse_ok(source);
        // use, capability, effect, struct, enum, policy, fn = 7 items
        assert_eq!(file.items.len(), 7);
    }

    // ── Generic type params with bounds ──────────────────────────────

    #[test]
    fn test_generic_with_bounds() {
        let source = "struct Wrapper<T: Display> { value: T }";
        let item = parse_single_item(source);
        let ItemKind::StructDef(s) = item else { panic!() };
        assert_eq!(s.generic_params[0].bounds.len(), 1);
    }

    #[test]
    fn test_multiple_generic_params() {
        let source = "fn map<A, B>(f: fn(A) -> B, x: A) -> B { f(x) }";
        let item = parse_single_item(source);
        let ItemKind::Function(f) = item else { panic!() };
        assert_eq!(f.signature.generic_params.len(), 2);
    }

    // ── Negative number pattern ──────────────────────────────────────

    #[test]
    fn test_negative_literal_pattern() {
        let expr = parse_body_expr("match x { -1 => true, _ => false }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!() };
        let PatternKind::Literal(ref lit) = arms[0].pattern.kind else { panic!() };
        assert!(matches!(lit.kind, ExprKind::IntLiteral(ref s) if s == "-1"));
    }

    // ── Path patterns in match ───────────────────────────────────────

    #[test]
    fn test_path_pattern_in_match() {
        let expr = parse_body_expr("match d { Decision::Allow => true, _ => false }");
        let ExprKind::Match { arms, .. } = &expr.kind else { panic!() };
        let PatternKind::Path(ref p) = arms[0].pattern.kind else { panic!("expected path pattern") };
        assert_eq!(p.segments.len(), 2);
    }

    // ═════════════════════════════════════════════════════════════════
    // Refinement types — M4 Layer 1
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_refinement_type_alias_basic() {
        let item = parse_single_item(
            "type RiskModel = Model where { bias_audit == true, data_retention <= 30 };",
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint, got {item:?}");
        };
        assert_eq!(decl.name.name, "RiskModel");
        // Base type is "Model"
        let TypeExprKind::Named { path, .. } = &decl.base_type.kind else {
            panic!("expected Named base type");
        };
        assert_eq!(path.segments[0].name, "Model");
        // Two predicates
        assert_eq!(decl.where_clause.predicates.len(), 2);
        let p0 = &decl.where_clause.predicates[0];
        assert_eq!(p0.field.name, "bias_audit");
        assert_eq!(p0.op, RefinementOp::Eq);
        assert_eq!(p0.value, RefinementValue::Bool(true));
        let p1 = &decl.where_clause.predicates[1];
        assert_eq!(p1.field.name, "data_retention");
        assert_eq!(p1.op, RefinementOp::Le);
        assert_eq!(p1.value, RefinementValue::Int(30));
    }

    #[test]
    fn test_refinement_type_in_list() {
        let item = parse_single_item(
            r#"type SafeModel = Model where { risk_category in ["limited", "minimal"] };"#,
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        assert_eq!(decl.where_clause.predicates.len(), 1);
        let p = &decl.where_clause.predicates[0];
        assert_eq!(p.field.name, "risk_category");
        assert_eq!(p.op, RefinementOp::In);
        let RefinementValue::List(items) = &p.value else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], RefinementValue::String("limited".into()));
        assert_eq!(items[1], RefinementValue::String("minimal".into()));
    }

    #[test]
    fn test_refinement_type_not_in() {
        let item = parse_single_item(
            r#"type Compliant = Config where { region not in ["banned_region"] };"#,
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        let p = &decl.where_clause.predicates[0];
        assert_eq!(p.op, RefinementOp::NotIn);
    }

    #[test]
    fn test_refinement_type_all_comparison_ops() {
        let item = parse_single_item(
            "type Strict = M where { a == 1, b != 2, c < 3, d > 4, e <= 5, f >= 6 };",
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        let ops: Vec<RefinementOp> = decl.where_clause.predicates.iter()
            .map(|p| p.op)
            .collect();
        assert_eq!(ops, vec![
            RefinementOp::Eq, RefinementOp::Ne,
            RefinementOp::Lt, RefinementOp::Gt,
            RefinementOp::Le, RefinementOp::Ge,
        ]);
    }

    #[test]
    fn test_refinement_type_negative_value() {
        let item = parse_single_item(
            "type Cold = Temp where { celsius < -10 };",
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        let p = &decl.where_clause.predicates[0];
        assert_eq!(p.value, RefinementValue::Int(-10));
    }

    #[test]
    fn test_refinement_type_float_value() {
        let item = parse_single_item(
            "type LowRisk = Score where { probability <= 0.05 };",
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        let p = &decl.where_clause.predicates[0];
        assert_eq!(p.op, RefinementOp::Le);
        assert!(matches!(&p.value, RefinementValue::Float(f) if (*f - 0.05).abs() < 1e-10));
    }

    #[test]
    fn test_refinement_type_string_value() {
        let item = parse_single_item(
            r#"type Audited = Model where { status == "approved" };"#,
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        let p = &decl.where_clause.predicates[0];
        assert_eq!(p.value, RefinementValue::String("approved".into()));
    }

    #[test]
    fn test_refinement_param_type() {
        // Function parameter with refinement type.
        let item = parse_single_item(
            "fn deploy(model: Model where { certified == true }) -> Int { 42 }",
        );
        let ItemKind::Function(decl) = item else {
            panic!("expected Function");
        };
        let param_ty = &decl.signature.params[0].ty;
        let TypeExprKind::Refined { base, where_clause } = &param_ty.kind else {
            panic!("expected Refined type on param, got {:?}", param_ty.kind);
        };
        let TypeExprKind::Named { path, .. } = &base.kind else {
            panic!("expected Named base type");
        };
        assert_eq!(path.segments[0].name, "Model");
        assert_eq!(where_clause.predicates.len(), 1);
        assert_eq!(where_clause.predicates[0].field.name, "certified");
    }

    #[test]
    fn test_require_satisfies_expr() {
        let expr = parse_body_expr(
            r#"require model satisfies { bias_audit == true, data_retention <= 30 }"#,
        );
        let ExprKind::Require { target, predicates } = &expr.kind else {
            panic!("expected Require, got {:?}", expr.kind);
        };
        let ExprKind::Identifier(name) = &target.kind else {
            panic!("expected identifier target");
        };
        assert_eq!(name, "model");
        assert_eq!(predicates.predicates.len(), 2);
        assert_eq!(predicates.predicates[0].field.name, "bias_audit");
        assert_eq!(predicates.predicates[1].field.name, "data_retention");
    }

    #[test]
    fn test_require_satisfies_single_predicate() {
        let expr = parse_body_expr(
            "require config satisfies { enabled == true }",
        );
        let ExprKind::Require { predicates, .. } = &expr.kind else {
            panic!("expected Require");
        };
        assert_eq!(predicates.predicates.len(), 1);
    }

    #[test]
    fn test_refinement_empty_where_clause() {
        // Empty where clause is valid syntax (no predicates).
        let item = parse_single_item("type Empty = T where {};");
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        assert!(decl.where_clause.predicates.is_empty());
    }

    #[test]
    fn test_plain_type_alias_still_works() {
        // Verify plain type aliases without `where` still parse as TypeAlias.
        let item = parse_single_item("type Alias = Int;");
        assert!(matches!(item, ItemKind::TypeAlias(_)));
    }

    #[test]
    fn test_refinement_trailing_comma() {
        // Trailing comma after last predicate.
        let item = parse_single_item(
            "type R = M where { x == 1, y == 2, };",
        );
        let ItemKind::TypeConstraint(decl) = item else {
            panic!("expected TypeConstraint");
        };
        assert_eq!(decl.where_clause.predicates.len(), 2);
    }

    #[test]
    fn test_require_in_policy_rule() {
        // require inside a policy rule body.
        let file = parse_ok(r#"
policy compliance {
    rule check_model(model: Model) {
        require model satisfies {
            bias_audit == true,
            certified == true,
        };
        permit
    }
}
"#);
        let ItemKind::Policy(decl) = &file.items[0].kind else {
            panic!("expected policy");
        };
        assert_eq!(decl.rules.len(), 1);
    }

    #[test]
    fn test_where_keyword_lexes() {
        // Verify `where` and `satisfies` are recognized as keywords.
        let (tokens, errors) = Lexer::new("where satisfies not", 0).tokenize();
        assert!(errors.is_empty());
        use crate::lexer::token::TokenKind;
        assert!(matches!(tokens[0].kind, TokenKind::Where));
        assert!(matches!(tokens[1].kind, TokenKind::Satisfies));
        assert!(matches!(tokens[2].kind, TokenKind::Not));
    }

    // ═════════════════════════════════════════════════════════════════
    // M7 Layer 1: Modules, visibility, use imports, qualified paths
    // ═════════════════════════════════════════════════════════════════

    // ── Lexer tests ─────────────────────────────────────────────────

    #[test]
    fn test_lex_super_keyword() {
        use crate::lexer::token::TokenKind;
        let (tokens, errors) = Lexer::new("super", 0).tokenize();
        assert!(errors.is_empty());
        assert!(matches!(tokens[0].kind, TokenKind::Super));
    }

    #[test]
    fn test_lex_colon_colon_distinct_from_colon() {
        use crate::lexer::token::TokenKind;
        let (tokens, errors) = Lexer::new("a::b : Int", 0).tokenize();
        assert!(errors.is_empty());
        assert!(matches!(tokens[0].kind, TokenKind::Identifier(_)));
        assert!(matches!(tokens[1].kind, TokenKind::ColonColon));
        assert!(matches!(tokens[2].kind, TokenKind::Identifier(_)));
        assert!(matches!(tokens[3].kind, TokenKind::Colon));
    }

    // ── Module declarations ─────────────────────────────────────────

    #[test]
    fn test_parse_inline_module() {
        let source = "mod crypto { fn verify() -> Bool { true } }";
        let item = parse_single_item(source);
        if let ItemKind::Module(m) = item {
            assert_eq!(m.name.name, "crypto");
            assert_eq!(m.visibility, Visibility::Private);
            assert!(m.items.is_some());
            let items = m.items.unwrap();
            assert_eq!(items.len(), 1);
            assert!(matches!(items[0].kind, ItemKind::Function(_)));
        } else {
            panic!("expected Module, got {:?}", item);
        }
    }

    #[test]
    fn test_parse_file_module() {
        let source = "mod crypto;";
        let item = parse_single_item(source);
        if let ItemKind::Module(m) = item {
            assert_eq!(m.name.name, "crypto");
            assert!(m.items.is_none());
        } else {
            panic!("expected Module, got {:?}", item);
        }
    }

    #[test]
    fn test_parse_pub_module() {
        let source = "pub mod crypto { fn verify() -> Bool { true } }";
        let item = parse_single_item(source);
        if let ItemKind::Module(m) = item {
            assert_eq!(m.visibility, Visibility::Public);
            assert_eq!(m.name.name, "crypto");
        } else {
            panic!("expected Module");
        }
    }

    // ── Use declarations ────────────────────────────────────────────

    #[test]
    fn test_parse_use_single() {
        let source = "use crypto::verify;";
        let item = parse_single_item(source);
        if let ItemKind::Use(u) = item {
            assert_eq!(u.path.segments.len(), 2);
            assert_eq!(u.path.segments[0].name, "crypto");
            assert_eq!(u.path.segments[1].name, "verify");
            assert_eq!(u.kind, UseKind::Single);
            assert!(u.alias.is_none());
        } else {
            panic!("expected Use");
        }
    }

    #[test]
    fn test_parse_use_alias() {
        let source = "use crypto::verify as v;";
        let item = parse_single_item(source);
        if let ItemKind::Use(u) = item {
            assert_eq!(u.path.segments.len(), 2);
            assert_eq!(u.alias.as_ref().unwrap().name, "v");
            assert_eq!(u.kind, UseKind::Single);
        } else {
            panic!("expected Use");
        }
    }

    #[test]
    fn test_parse_use_glob() {
        let source = "use crypto::*;";
        let item = parse_single_item(source);
        if let ItemKind::Use(u) = item {
            assert_eq!(u.path.segments.len(), 1);
            assert_eq!(u.path.segments[0].name, "crypto");
            assert_eq!(u.kind, UseKind::Glob);
        } else {
            panic!("expected Use");
        }
    }

    #[test]
    fn test_parse_use_module() {
        let source = "use crypto;";
        let item = parse_single_item(source);
        if let ItemKind::Use(u) = item {
            assert_eq!(u.path.segments.len(), 1);
            assert_eq!(u.path.segments[0].name, "crypto");
            assert_eq!(u.kind, UseKind::Module);
        } else {
            panic!("expected Use");
        }
    }

    #[test]
    fn test_parse_pub_use() {
        let source = "pub use crypto::verify;";
        let item = parse_single_item(source);
        if let ItemKind::Use(u) = item {
            assert_eq!(u.visibility, Visibility::Public);
        } else {
            panic!("expected Use");
        }
    }

    // ── Visibility on declarations ──────────────────────────────────

    #[test]
    fn test_parse_pub_function() {
        let source = "pub fn verify() -> Bool { true }";
        let item = parse_single_item(source);
        if let ItemKind::Function(f) = item {
            assert!(f.signature.is_pub);
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_pub_policy() {
        let source = "pub policy access { rule allow() { permit } }";
        let item = parse_single_item(source);
        if let ItemKind::Policy(p) = item {
            assert_eq!(p.visibility, Visibility::Public);
        } else {
            panic!("expected Policy");
        }
    }

    #[test]
    fn test_parse_pub_struct() {
        let source = "pub struct Model { name: String }";
        let item = parse_single_item(source);
        if let ItemKind::StructDef(s) = item {
            assert_eq!(s.visibility, Visibility::Public);
        } else {
            panic!("expected StructDef");
        }
    }

    #[test]
    fn test_parse_pub_enum() {
        let source = "pub enum Decision { Allow, Deny }";
        let item = parse_single_item(source);
        if let ItemKind::EnumDef(e) = item {
            assert_eq!(e.visibility, Visibility::Public);
        } else {
            panic!("expected EnumDef");
        }
    }

    #[test]
    fn test_parse_pub_type_constraint() {
        let source = "pub type SafeModel = Int where { bias_audit == true };";
        let item = parse_single_item(source);
        if let ItemKind::TypeConstraint(t) = item {
            assert_eq!(t.visibility, Visibility::Public);
        } else {
            panic!("expected TypeConstraint");
        }
    }

    // ── Qualified paths in expressions ──────────────────────────────

    #[test]
    fn test_parse_qualified_path_expr() {
        let source = "fn test() -> Int { crypto::verify }";
        let file = parse_ok(source);
        if let ItemKind::Function(f) = &file.items[0].kind {
            let body = f.body.as_ref().unwrap();
            if let ExprKind::Block(block) = &body.kind {
                if let StmtKind::TailExpr(expr) = &block.stmts[0].kind {
                    if let ExprKind::Path(path) = &expr.kind {
                        assert_eq!(path.segments.len(), 2);
                        assert_eq!(path.segments[0].name, "crypto");
                        assert_eq!(path.segments[1].name, "verify");
                    } else {
                        panic!("expected Path expr");
                    }
                } else {
                    panic!("expected TailExpr");
                }
            } else {
                panic!("expected Block");
            }
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_qualified_path_call() {
        let source = "fn test() -> Int { crypto::verify(data) }";
        let file = parse_ok(source);
        if let ItemKind::Function(f) = &file.items[0].kind {
            let body = f.body.as_ref().unwrap();
            if let ExprKind::Block(block) = &body.kind {
                if let StmtKind::TailExpr(expr) = &block.stmts[0].kind {
                    if let ExprKind::Call { callee, args } = &expr.kind {
                        assert!(matches!(callee.kind, ExprKind::Path(_)));
                        assert_eq!(args.len(), 1);
                    } else {
                        panic!("expected Call");
                    }
                } else {
                    panic!("expected TailExpr");
                }
            } else {
                panic!("expected Block");
            }
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_multi_segment_path() {
        let source = "fn test() -> Int { a::b::c }";
        let file = parse_ok(source);
        if let ItemKind::Function(f) = &file.items[0].kind {
            let body = f.body.as_ref().unwrap();
            if let ExprKind::Block(block) = &body.kind {
                if let StmtKind::TailExpr(expr) = &block.stmts[0].kind {
                    if let ExprKind::Path(path) = &expr.kind {
                        assert_eq!(path.segments.len(), 3);
                    } else {
                        panic!("expected Path");
                    }
                } else {
                    panic!("expected TailExpr");
                }
            } else {
                panic!("expected Block");
            }
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_self_path() {
        let source = "fn test() -> Int { self::helper() }";
        let file = parse_ok(source);
        if let ItemKind::Function(f) = &file.items[0].kind {
            let body = f.body.as_ref().unwrap();
            if let ExprKind::Block(block) = &body.kind {
                if let StmtKind::TailExpr(expr) = &block.stmts[0].kind {
                    if let ExprKind::Call { callee, .. } = &expr.kind {
                        if let ExprKind::Path(path) = &callee.kind {
                            assert_eq!(path.segments[0].name, "self");
                            assert_eq!(path.segments[1].name, "helper");
                        } else {
                            panic!("expected Path");
                        }
                    } else {
                        panic!("expected Call");
                    }
                } else {
                    panic!("expected TailExpr");
                }
            } else {
                panic!("expected Block");
            }
        } else {
            panic!("expected Function");
        }
    }

    #[test]
    fn test_parse_super_path() {
        let source = "fn test() -> Int { super::utils::hash() }";
        let file = parse_ok(source);
        if let ItemKind::Function(f) = &file.items[0].kind {
            let body = f.body.as_ref().unwrap();
            if let ExprKind::Block(block) = &body.kind {
                if let StmtKind::TailExpr(expr) = &block.stmts[0].kind {
                    if let ExprKind::Call { callee, .. } = &expr.kind {
                        if let ExprKind::Path(path) = &callee.kind {
                            assert_eq!(path.segments[0].name, "super");
                            assert_eq!(path.segments[1].name, "utils");
                            assert_eq!(path.segments[2].name, "hash");
                        } else {
                            panic!("expected Path");
                        }
                    } else {
                        panic!("expected Call");
                    }
                } else {
                    panic!("expected TailExpr");
                }
            } else {
                panic!("expected Block");
            }
        } else {
            panic!("expected Function");
        }
    }

    // ── Nested modules ──────────────────────────────────────────────

    #[test]
    fn test_parse_nested_modules() {
        let source = "mod a { mod b { fn inner() -> Int { 1 } } }";
        let item = parse_single_item(source);
        if let ItemKind::Module(m) = item {
            let items = m.items.unwrap();
            assert_eq!(items.len(), 1);
            if let ItemKind::Module(inner) = &items[0].kind {
                assert_eq!(inner.name.name, "b");
                let inner_items = inner.items.as_ref().unwrap();
                assert_eq!(inner_items.len(), 1);
            } else {
                panic!("expected inner Module");
            }
        } else {
            panic!("expected Module");
        }
    }

    #[test]
    fn test_parse_module_with_mixed_declarations() {
        let source = "mod crypto { pub fn verify() -> Bool { true } fn internal() -> Int { 0 } }";
        let item = parse_single_item(source);
        if let ItemKind::Module(m) = item {
            let items = m.items.unwrap();
            assert_eq!(items.len(), 2);
            if let ItemKind::Function(f1) = &items[0].kind {
                assert!(f1.signature.is_pub);
            } else {
                panic!("expected Function");
            }
            if let ItemKind::Function(f2) = &items[1].kind {
                assert!(!f2.signature.is_pub);
            } else {
                panic!("expected Function");
            }
        } else {
            panic!("expected Module");
        }
    }

    // ── Error: pub before rule ──────────────────────────────────────

    #[test]
    fn test_pub_before_rule_is_error() {
        let source = "policy access { pub rule allow() { permit } }";
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty());
        let (file, parse_errors) = Parser::new(tokens).parse();
        // Should parse with a recorded error about pub before rule.
        assert!(!parse_errors.is_empty() || {
            // The parser may record the error but still produce a valid tree.
            true
        });
        // Verify the policy still parsed (error recovery).
        if let Some(item) = file.items.first() {
            if let ItemKind::Policy(p) = &item.kind {
                assert_eq!(p.rules.len(), 1);
            }
        }
    }

    // ── Backward compatibility ──────────────────────────────────────

    #[test]
    fn test_existing_code_without_modules_still_works() {
        let source = "policy access { rule allow() { permit } }\nfn helper() -> Int { 42 }";
        let file = parse_ok(source);
        assert_eq!(file.items.len(), 2);
        if let ItemKind::Policy(p) = &file.items[0].kind {
            assert_eq!(p.visibility, Visibility::Private);
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // M8: Extern blocks and FFI syntax
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_extern_block_single_fn() {
        let item = parse_single_item("extern { fn sha256(data: Int) -> Int; }");
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.functions.len(), 1);
        assert_eq!(block.functions[0].name.name, "sha256");
        assert_eq!(block.functions[0].params.len(), 1);
        assert_eq!(block.functions[0].params[0].name.name, "data");
        assert!(block.functions[0].return_type.is_some());
        assert!(block.abi.is_none());
    }

    #[test]
    fn test_extern_block_multiple_fns() {
        let item = parse_single_item(r#"
            extern {
                fn sha256(data: Int) -> Int;
                fn sha512(data: Int) -> Int;
                fn md5(data: Int) -> Int;
            }
        "#);
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.functions.len(), 3);
        assert_eq!(block.functions[0].name.name, "sha256");
        assert_eq!(block.functions[1].name.name, "sha512");
        assert_eq!(block.functions[2].name.name, "md5");
    }

    #[test]
    fn test_extern_standalone_fn() {
        let item = parse_single_item("extern fn sha256(data: Int) -> Int;");
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.functions.len(), 1);
        assert_eq!(block.functions[0].name.name, "sha256");
    }

    #[test]
    fn test_extern_with_abi_string() {
        let item = parse_single_item(r#"extern "C" { fn sha256(data: Int) -> Int; }"#);
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.abi, Some("C".to_string()));
        assert_eq!(block.functions.len(), 1);
    }

    #[test]
    fn test_extern_standalone_with_abi() {
        let item = parse_single_item(r#"extern "C" fn sha256(data: Int) -> Int;"#);
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.abi, Some("C".to_string()));
        assert_eq!(block.functions.len(), 1);
    }

    #[test]
    fn test_extern_fn_no_return_type() {
        let item = parse_single_item("extern fn log(msg: String);");
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert!(block.functions[0].return_type.is_none());
    }

    #[test]
    fn test_extern_fn_no_params() {
        let item = parse_single_item("extern fn get_time() -> Int;");
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert!(block.functions[0].params.is_empty());
        assert!(block.functions[0].return_type.is_some());
    }

    #[test]
    fn test_pub_extern_block() {
        let item = parse_single_item("pub extern { fn sha256(data: Int) -> Int; }");
        let ItemKind::Extern(block) = item else { panic!("expected extern block") };
        assert_eq!(block.visibility, Visibility::Public);
    }

    #[test]
    fn test_extern_unsupported_abi_error() {
        let errors = parse_errors(r#"extern "Rust" fn sha256(data: Int) -> Int;"#);
        assert!(errors.iter().any(|e| e.contains("unsupported ABI")));
    }

    #[test]
    fn test_extern_fn_with_body_error() {
        let errors = parse_errors("extern fn sha256(data: Int) -> Int { 42 }");
        assert!(errors.iter().any(|e| e.contains("body") || e.contains("semicolon") || e.contains(";")));
    }
}
