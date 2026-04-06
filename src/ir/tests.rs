#[cfg(test)]
mod tests {
    use crate::ir::lower::Lowerer;
    use crate::ir::nodes::*;
    use crate::lexer::scanner::Lexer;
    use crate::parser::parser::Parser;

    /// Parse source and lower to IR.
    fn lower(source: &str) -> IrModule {
        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {parse_errors:?}");
        let mut lowerer = Lowerer::new();
        lowerer.lower_source_file(&file)
    }

    /// Get the first function from the module.
    fn first_fn(module: &IrModule) -> &IrFunction {
        &module.functions[0]
    }

    // ═════════════════════════════════════════════════════════════════
    // Simple function lowering
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_simple_add() {
        let module = lower("fn add(a: Int, b: Int) -> Int { a + b }");
        assert_eq!(module.functions.len(), 1);

        let func = first_fn(&module);
        assert_eq!(func.name, "add");
        assert_eq!(func.params.len(), 2);
        assert_eq!(func.params[0].name, "a");
        assert_eq!(func.params[0].ty, IrType::Int);
        assert_eq!(func.params[1].name, "b");
        assert_eq!(func.return_type, IrType::Int);

        // Should have one block (entry).
        assert_eq!(func.blocks.len(), 1);

        // The block should end with a Return terminator.
        let entry = &func.blocks[0];
        assert!(matches!(entry.terminator, Terminator::Return(_)));

        // Should contain: audit_entry, alloca a, store a, alloca b, store b,
        // load a, load b, add, audit_exit — then return.
        let has_add = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Add(_, _)));
        assert!(has_add, "expected Add instruction in: {}", func);
    }

    #[test]
    fn test_lower_function_with_let() {
        let module = lower("fn compute(x: Int) -> Int { let y = x; y }");
        let func = first_fn(&module);
        assert_eq!(func.name, "compute");

        let entry = &func.blocks[0];
        // Should have Alloca and Store for the let binding.
        let has_alloca = entry.instructions.iter().any(|i| {
            matches!(&i.kind, InstKind::Alloca { name, .. } if name == "y")
        });
        assert!(has_alloca, "expected Alloca for 'y' in: {}", func);
    }

    #[test]
    fn test_lower_function_parameters() {
        let module = lower("fn greet(name: String) -> String { name }");
        let func = first_fn(&module);
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.params[0].ty, IrType::String);
        assert_eq!(func.return_type, IrType::String);
    }

    // ═════════════════════════════════════════════════════════════════
    // Governance decisions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_governance_decisions() {
        let module = lower(r#"
policy access {
    rule allow_all() { permit }
}
"#);
        assert_eq!(module.functions.len(), 1);

        let func = first_fn(&module);
        assert_eq!(func.name, "access::allow_all");
        assert_eq!(func.return_type, IrType::PolicyDecision);

        // Should contain a GovernanceDecision(Permit).
        let has_permit = func.blocks.iter().any(|b| {
            b.instructions.iter().any(|i| {
                matches!(&i.kind, InstKind::GovernanceDecision(DecisionKind::Permit))
            })
        });
        assert!(has_permit, "expected Permit decision in: {}", func);
    }

    #[test]
    fn test_lower_all_four_decisions() {
        let module = lower(r#"
policy gov {
    rule decide(level: Int) {
        if level == 1 { permit }
        else if level == 2 { deny }
        else if level == 3 { escalate }
        else { quarantine }
    }
}
"#);
        let func = first_fn(&module);

        // Should contain all four decision types.
        let decisions: Vec<&DecisionKind> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| match &i.kind {
                InstKind::GovernanceDecision(d) => Some(d),
                _ => None,
            })
            .collect();

        assert!(decisions.contains(&&DecisionKind::Permit), "missing Permit");
        assert!(decisions.contains(&&DecisionKind::Deny), "missing Deny");
        assert!(decisions.contains(&&DecisionKind::Escalate), "missing Escalate");
        assert!(decisions.contains(&&DecisionKind::Quarantine), "missing Quarantine");
    }

    #[test]
    fn test_lower_policy_rule_with_params() {
        let module = lower(r#"
policy check {
    rule verify(trusted: Bool) {
        if trusted { permit } else { deny }
    }
}
"#);
        let func = first_fn(&module);
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.params[0].name, "trusted");
        assert_eq!(func.params[0].ty, IrType::Bool);
    }

    // ═════════════════════════════════════════════════════════════════
    // If/else control flow — proper block structure
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_if_else_blocks() {
        let module = lower(r#"
fn pick(x: Bool) -> Int {
    if x { 1 } else { 2 }
}
"#);
        let func = first_fn(&module);

        // Should have multiple blocks: entry, then, else, merge (at least 4).
        assert!(
            func.blocks.len() >= 4,
            "expected at least 4 blocks for if/else, got {}: {}",
            func.blocks.len(),
            func,
        );

        // Entry block should end with CondBranch.
        let entry = &func.blocks[0];
        assert!(
            matches!(entry.terminator, Terminator::CondBranch { .. }),
            "expected CondBranch terminator in entry block: {}",
            func,
        );
    }

    #[test]
    fn test_lower_if_without_else() {
        let module = lower(r#"
fn maybe(x: Bool) -> Int {
    if x { 42 }; 0
}
"#);
        let func = first_fn(&module);
        // Should still produce blocks with CondBranch.
        let has_cond = func.blocks.iter().any(|b| {
            matches!(b.terminator, Terminator::CondBranch { .. })
        });
        assert!(has_cond, "expected CondBranch for if without else: {}", func);
    }

    // ═════════════════════════════════════════════════════════════════
    // Nested expressions — verify flattening to sequential instructions
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_nested_arithmetic() {
        // (a + b) * (a - b) should flatten to: load a, load b, add, load a, load b, sub, mul
        let module = lower("fn calc(a: Int, b: Int) -> Int { (a + b) * (a - b) }");
        let func = first_fn(&module);
        let entry = &func.blocks[0];

        let has_add = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Add(_, _)));
        let has_sub = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Sub(_, _)));
        let has_mul = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Mul(_, _)));

        assert!(has_add, "expected Add in: {}", func);
        assert!(has_sub, "expected Sub in: {}", func);
        assert!(has_mul, "expected Mul in: {}", func);

        // All operations should be in a single block (no control flow).
        assert_eq!(func.blocks.len(), 1, "nested arithmetic should be one block: {}", func);
    }

    #[test]
    fn test_lower_nested_comparison() {
        let module = lower("fn check(a: Int, b: Int) -> Bool { a + 1 == b - 1 }");
        let func = first_fn(&module);
        let entry = &func.blocks[0];

        let has_add = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Add(_, _)));
        let has_sub = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Sub(_, _)));
        let has_eq = entry.instructions.iter().any(|i| matches!(i.kind, InstKind::Eq(_, _)));

        assert!(has_add && has_sub && has_eq,
            "expected Add, Sub, Eq in: {}", func);
    }

    // ═════════════════════════════════════════════════════════════════
    // Audit marks — verify instrumentation at decision points
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_audit_marks_on_function() {
        let module = lower("fn process(x: Int) -> Int { x }");
        let func = first_fn(&module);

        let audit_marks: Vec<&AuditKind> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| match &i.kind {
                InstKind::AuditMark(k) => Some(k),
                _ => None,
            })
            .collect();

        // Should have function entry and exit marks.
        let has_entry = audit_marks.iter().any(|k| {
            matches!(k, AuditKind::FunctionEntry { name } if name == "process")
        });
        let has_exit = audit_marks.iter().any(|k| {
            matches!(k, AuditKind::FunctionExit { name } if name == "process")
        });

        assert!(has_entry, "expected FunctionEntry audit mark: {}", func);
        assert!(has_exit, "expected FunctionExit audit mark: {}", func);
    }

    #[test]
    fn test_audit_marks_on_governance_decision() {
        let module = lower(r#"
policy audit_test {
    rule check() { permit }
}
"#);
        let func = first_fn(&module);

        let decision_marks: Vec<&AuditKind> = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter_map(|i| match &i.kind {
                InstKind::AuditMark(k @ AuditKind::Decision { .. }) => Some(k),
                _ => None,
            })
            .collect();

        assert!(
            !decision_marks.is_empty(),
            "expected Decision audit mark at governance decision point: {}",
            func,
        );
    }

    #[test]
    fn test_audit_marks_on_policy_rule() {
        let module = lower(r#"
policy my_policy {
    rule my_rule(x: Bool) { if x { permit } else { deny } }
}
"#);
        let func = first_fn(&module);

        // Should have function entry mark.
        let has_entry = func.blocks.iter().any(|b| {
            b.instructions.iter().any(|i| matches!(
                &i.kind,
                InstKind::AuditMark(AuditKind::FunctionEntry { name })
                if name == "my_policy::my_rule"
            ))
        });
        assert!(has_entry, "expected entry audit mark for policy rule: {}", func);

        // Should have decision marks for both permit and deny.
        let decision_count = func.blocks.iter()
            .flat_map(|b| b.instructions.iter())
            .filter(|i| matches!(&i.kind, InstKind::AuditMark(AuditKind::Decision { .. })))
            .count();
        assert!(
            decision_count >= 2,
            "expected at least 2 decision audit marks (permit + deny), got {}: {}",
            decision_count,
            func,
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // Pretty-printing — verify human-readable output
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_pretty_print_simple_function() {
        let module = lower("fn add(a: Int, b: Int) -> Int { a + b }");
        let output = format!("{}", module);

        assert!(output.contains("fn add("), "should contain function name: {}", output);
        assert!(output.contains("a: i64"), "should contain param a: {}", output);
        assert!(output.contains("b: i64"), "should contain param b: {}", output);
        assert!(output.contains("-> i64"), "should contain return type: {}", output);
        assert!(output.contains("bb0:"), "should contain block label: {}", output);
        assert!(output.contains("add %"), "should contain add instruction: {}", output);
        assert!(output.contains("return %"), "should contain return: {}", output);
    }

    #[test]
    fn test_pretty_print_governance() {
        let module = lower(r#"
policy p {
    rule r() { permit }
}
"#);
        let output = format!("{}", module);

        assert!(output.contains("fn p::r("), "should contain policy rule name: {}", output);
        assert!(output.contains("-> decision"), "should contain decision return type: {}", output);
        assert!(output.contains("decision.permit"), "should contain permit decision: {}", output);
        assert!(output.contains("audit."), "should contain audit marks: {}", output);
    }

    #[test]
    fn test_pretty_print_if_else() {
        let module = lower(r#"
fn pick(x: Bool) -> Int {
    if x { 1 } else { 2 }
}
"#);
        let output = format!("{}", module);

        // Should have multiple blocks and a condbr.
        assert!(output.contains("condbr"), "should contain condbr: {}", output);
        assert!(output.contains("bb1:"), "should have then block: {}", output);
        assert!(output.contains("bb2:"), "should have else block: {}", output);
    }

    // ═════════════════════════════════════════════════════════════════
    // Multiple items — full program lowering
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_multiple_functions() {
        let module = lower(r#"
fn helper(x: Int) -> Int { x }
fn main_fn(a: Int) -> Int { helper(a) }
"#);
        assert_eq!(module.functions.len(), 2);
        assert_eq!(module.functions[0].name, "helper");
        assert_eq!(module.functions[1].name, "main_fn");
    }

    #[test]
    fn test_lower_mixed_functions_and_policies() {
        let module = lower(r#"
fn validate(score: Float) -> Bool { true }

policy governance {
    rule check_score(score: Float) {
        permit
    }
    rule deny_low() {
        deny
    }
}
"#);
        assert_eq!(module.functions.len(), 3);
        assert_eq!(module.functions[0].name, "validate");
        assert_eq!(module.functions[1].name, "governance::check_score");
        assert_eq!(module.functions[2].name, "governance::deny_low");
    }

    #[test]
    fn test_lower_const_declaration() {
        let module = lower("const MAX: Int = 100;");
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.functions[0].name, "const::MAX");

        let func = first_fn(&module);
        let has_int_const = func.blocks[0].instructions.iter().any(|i| {
            matches!(&i.kind, InstKind::IntConst(100))
        });
        assert!(has_int_const, "expected IntConst(100): {}", func);
    }

    // ═════════════════════════════════════════════════════════════════
    // Function calls
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_function_call() {
        let module = lower(r#"
fn callee(x: Int) -> Int { x }
fn caller() -> Int { callee(42) }
"#);
        let caller = &module.functions[1];
        let has_call = caller.blocks.iter().any(|b| {
            b.instructions.iter().any(|i| {
                matches!(&i.kind, InstKind::Call { func, .. } if func == "callee")
            })
        });
        assert!(has_call, "expected call to 'callee': {}", caller);
    }

    // ═════════════════════════════════════════════════════════════════
    // Policy rule with when-clause
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_lower_when_clause() {
        let module = lower(r#"
policy access {
    rule admin_only(is_admin: Bool) when is_admin {
        permit
    }
}
"#);
        let func = first_fn(&module);

        // When clause generates a CondBranch.
        let has_cond = func.blocks.iter().any(|b| {
            matches!(b.terminator, Terminator::CondBranch { .. })
        });
        assert!(has_cond, "expected CondBranch for when-clause: {}", func);

        // Should have at least 3 blocks: entry (with cond), body, deny-fallback.
        assert!(
            func.blocks.len() >= 3,
            "expected at least 3 blocks for when-clause, got {}: {}",
            func.blocks.len(),
            func,
        );
    }

    // ═════════════════════════════════════════════════════════════════
    // IR type mapping
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_ir_type_display() {
        assert_eq!(format!("{}", IrType::Int), "i64");
        assert_eq!(format!("{}", IrType::Float), "f64");
        assert_eq!(format!("{}", IrType::Bool), "bool");
        assert_eq!(format!("{}", IrType::String), "str");
        assert_eq!(format!("{}", IrType::Unit), "()");
        assert_eq!(format!("{}", IrType::PolicyDecision), "decision");
        assert_eq!(format!("{}", IrType::Ptr), "ptr");
        assert_eq!(format!("{}", IrType::FuncRef), "funcref");
    }

    #[test]
    fn test_value_display() {
        assert_eq!(format!("{}", Value(0)), "%0");
        assert_eq!(format!("{}", Value(42)), "%42");
    }

    #[test]
    fn test_block_id_display() {
        assert_eq!(format!("{}", BlockId(0)), "bb0");
        assert_eq!(format!("{}", BlockId(3)), "bb3");
    }
}
