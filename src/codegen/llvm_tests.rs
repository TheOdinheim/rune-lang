// ═══════════════════════════════════════════════════════════════════════
// LLVM Codegen Tests
//
// Only compiled and run with: cargo test --features llvm
// ═══════════════════════════════════════════════════════════════════════

#[cfg(all(test, feature = "llvm"))]
mod tests {
    use crate::codegen::llvm_gen::LlvmCodegen;
    use crate::ir::nodes::*;

    // ── Helpers ──────────────────────────────────────────────────

    fn simple_return_int(n: i64) -> IrModule {
        IrModule {
            functions: vec![IrFunction {
                name: "return_int".into(),
                params: vec![],
                return_type: IrType::Int,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::Int,
                        kind: InstKind::IntConst(n),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        }
    }

    /// Two-param function that applies a binary op — prevents LLVM constant folding.
    fn param_binop_module(op_fn: fn(Value, Value) -> InstKind, ret_ty: IrType, param_ty: IrType) -> IrModule {
        IrModule {
            functions: vec![IrFunction {
                name: "binop".into(),
                params: vec![
                    IrParam { name: "a".into(), ty: param_ty.clone(), value: Value(0) },
                    IrParam { name: "b".into(), ty: param_ty, value: Value(1) },
                ],
                return_type: ret_ty,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(2),
                        ty: ret_ty.clone(),
                        kind: op_fn(Value(0), Value(1)),
                    }],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        }
    }

    /// One-param function that applies a unary op.
    fn param_unaryop_module(op_fn: fn(Value) -> InstKind, ret_ty: IrType, param_ty: IrType) -> IrModule {
        IrModule {
            functions: vec![IrFunction {
                name: "unop".into(),
                params: vec![
                    IrParam { name: "a".into(), ty: param_ty, value: Value(0) },
                ],
                return_type: ret_ty,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(1),
                        ty: ret_ty.clone(),
                        kind: op_fn(Value(0)),
                    }],
                    terminator: Terminator::Return(Value(1)),
                }],
            }],
        }
    }

    fn compile_and_get_ir(module: &IrModule) -> String {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(module);
        codegen.emit_llvm_ir()
    }

    fn compile_source_to_llvm_ir(source: &str) -> String {
        use crate::ir::lower::Lowerer;
        use crate::lexer::scanner::Lexer;
        use crate::parser::parser::Parser;
        use crate::types::checker::TypeChecker;
        use crate::types::context::TypeContext;

        let (tokens, _) = Lexer::new(source, 0).tokenize();
        let (file, _) = Parser::new(tokens).parse();
        let mut ctx = TypeContext::new();
        let mut checker = TypeChecker::new(&mut ctx);
        checker.check_source_file(&file);
        let mut lowerer = Lowerer::new();
        let ir_module = lowerer.lower_source_file(&file);

        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&ir_module);
        assert!(codegen.verify().is_ok(), "LLVM verification failed");
        codegen.emit_llvm_ir()
    }

    // ═════════════════════════════════════════════════════════════
    // PART 0: Fixed Layer 1 tests (use params to prevent constant folding)
    // ═════════════════════════════════════════════════════════════

    // ── Constant tests ───────────────────────────────────────────

    #[test]
    fn test_int_constant() {
        let ir = compile_and_get_ir(&simple_return_int(42));
        assert!(ir.contains("ret i64 42"), "LLVM IR should contain ret i64 42: {ir}");
    }

    #[test]
    fn test_float_constant() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "return_float".into(),
                params: vec![],
                return_type: IrType::Float,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::Float,
                        kind: InstKind::FloatConst(3.14),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret double"), "LLVM IR should contain ret double: {ir}");
    }

    #[test]
    fn test_bool_constant() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "return_bool".into(),
                params: vec![],
                return_type: IrType::Bool,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::Bool,
                        kind: InstKind::BoolConst(true),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret i1 true"), "LLVM IR should contain ret i1 true: {ir}");
    }

    #[test]
    fn test_string_constant() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "return_str".into(),
                params: vec![],
                return_type: IrType::String,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::String,
                        kind: InstKind::StringConst("hello".into()),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("hello"), "LLVM IR should contain the string: {ir}");
    }

    // ── Arithmetic tests (params prevent constant folding) ───────

    #[test]
    fn test_int_addition() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Add, IrType::Int, IrType::Int));
        assert!(ir.contains("add i64"), "LLVM IR should contain add i64: {ir}");
    }

    #[test]
    fn test_int_subtraction() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Sub, IrType::Int, IrType::Int));
        assert!(ir.contains("sub i64"), "LLVM IR should contain sub i64: {ir}");
    }

    #[test]
    fn test_int_multiplication() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Mul, IrType::Int, IrType::Int));
        assert!(ir.contains("mul i64"), "LLVM IR should contain mul i64: {ir}");
    }

    #[test]
    fn test_int_division() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Div, IrType::Int, IrType::Int));
        assert!(ir.contains("sdiv i64"), "LLVM IR should contain sdiv i64: {ir}");
    }

    // ── Comparison tests (params prevent constant folding) ───────

    #[test]
    fn test_comparison_eq() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Eq, IrType::Bool, IrType::Int));
        assert!(ir.contains("icmp eq i64"), "LLVM IR should contain icmp eq: {ir}");
    }

    #[test]
    fn test_comparison_ne() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Ne, IrType::Bool, IrType::Int));
        assert!(ir.contains("icmp ne i64"), "LLVM IR should contain icmp ne: {ir}");
    }

    #[test]
    fn test_comparison_lt() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Lt, IrType::Bool, IrType::Int));
        assert!(ir.contains("icmp slt i64"), "LLVM IR should contain icmp slt: {ir}");
    }

    #[test]
    fn test_comparison_gt() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Gt, IrType::Bool, IrType::Int));
        assert!(ir.contains("icmp sgt i64"), "LLVM IR should contain icmp sgt: {ir}");
    }

    // ── Boolean tests (params prevent constant folding) ──────────

    #[test]
    fn test_bool_and() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::And, IrType::Bool, IrType::Bool));
        assert!(ir.contains("and i1"), "LLVM IR should contain and i1: {ir}");
    }

    #[test]
    fn test_bool_or() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Or, IrType::Bool, IrType::Bool));
        assert!(ir.contains("or i1"), "LLVM IR should contain or i1: {ir}");
    }

    #[test]
    fn test_bool_not() {
        let ir = compile_and_get_ir(&param_unaryop_module(InstKind::Not, IrType::Bool, IrType::Bool));
        assert!(ir.contains("xor i1"), "LLVM IR should contain xor (not): {ir}");
    }

    // ── Float arithmetic (params prevent constant folding) ───────

    #[test]
    fn test_float_addition() {
        let ir = compile_and_get_ir(&param_binop_module(InstKind::Add, IrType::Float, IrType::Float));
        assert!(ir.contains("fadd double"), "LLVM IR should contain fadd: {ir}");
    }

    // ── Parameter tests ──────────────────────────────────────────

    #[test]
    fn test_function_with_params() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "add_params".into(),
                params: vec![
                    IrParam { name: "a".into(), ty: IrType::Int, value: Value(0) },
                    IrParam { name: "b".into(), ty: IrType::Int, value: Value(1) },
                ],
                return_type: IrType::Int,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(2),
                        ty: IrType::Int,
                        kind: InstKind::Add(Value(0), Value(1)),
                    }],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("define i64 @add_params(i64"), "should have correct param types: {ir}");
        assert!(ir.contains("add i64"), "should contain add: {ir}");
    }

    // ── Function call tests ──────────────────────────────────────

    #[test]
    fn test_function_call() {
        let module = IrModule {
            functions: vec![
                IrFunction {
                    name: "callee".into(),
                    params: vec![IrParam { name: "x".into(), ty: IrType::Int, value: Value(0) }],
                    return_type: IrType::Int,
                    blocks: vec![BasicBlock {
                        id: BlockId(0),
                        instructions: vec![],
                        terminator: Terminator::Return(Value(0)),
                    }],
                },
                IrFunction {
                    name: "caller".into(),
                    params: vec![],
                    return_type: IrType::Int,
                    blocks: vec![BasicBlock {
                        id: BlockId(0),
                        instructions: vec![
                            Instruction { result: Value(0), ty: IrType::Int, kind: InstKind::IntConst(42) },
                            Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::Call {
                                func: "callee".into(),
                                args: vec![Value(0)],
                                ret_ty: IrType::Int,
                            }},
                        ],
                        terminator: Terminator::Return(Value(1)),
                    }],
                },
            ],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("call i64 @callee"), "should contain call: {ir}");
    }

    // ── Variable tests ───────────────────────────────────────────

    #[test]
    fn test_let_binding() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "let_bind".into(),
                params: vec![],
                return_type: IrType::Int,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Ptr, kind: InstKind::Alloca { name: "x".into(), ty: IrType::Int } },
                        Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(42) },
                        Instruction { result: Value(2), ty: IrType::Unit, kind: InstKind::Store { ptr: Value(0), value: Value(1) } },
                        Instruction { result: Value(3), ty: IrType::Int, kind: InstKind::Load { ptr: Value(0), ty: IrType::Int } },
                    ],
                    terminator: Terminator::Return(Value(3)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("alloca i64"), "should contain alloca: {ir}");
        assert!(ir.contains("store i64"), "should contain store: {ir}");
        assert!(ir.contains("load i64"), "should contain load: {ir}");
    }

    // ── Governance decision tests ────────────────────────────────

    #[test]
    fn test_governance_decision_deny() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "policy_deny".into(),
                params: vec![],
                return_type: IrType::PolicyDecision,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::PolicyDecision,
                        kind: InstKind::GovernanceDecision(DecisionKind::Deny),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret i32 1"), "Deny should be i32 1: {ir}");
    }

    #[test]
    fn test_governance_decision_permit() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "policy_permit".into(),
                params: vec![],
                return_type: IrType::PolicyDecision,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::PolicyDecision,
                        kind: InstKind::GovernanceDecision(DecisionKind::Permit),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret i32 0"), "Permit should be i32 0: {ir}");
    }

    #[test]
    fn test_governance_decision_escalate() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "policy_esc".into(),
                params: vec![],
                return_type: IrType::PolicyDecision,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::PolicyDecision,
                        kind: InstKind::GovernanceDecision(DecisionKind::Escalate),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret i32 2"), "Escalate should be i32 2: {ir}");
    }

    #[test]
    fn test_governance_decision_quarantine() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "policy_quar".into(),
                params: vec![],
                return_type: IrType::PolicyDecision,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![Instruction {
                        result: Value(0),
                        ty: IrType::PolicyDecision,
                        kind: InstKind::GovernanceDecision(DecisionKind::Quarantine),
                    }],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("ret i32 3"), "Quarantine should be i32 3: {ir}");
    }

    // ═════════════════════════════════════════════════════════════
    // PART 1: Control flow tests
    // ═════════════════════════════════════════════════════════════

    #[test]
    fn test_if_else_conditional_branch() {
        // if (param) { return 1 } else { return 2 }
        let module = IrModule {
            functions: vec![IrFunction {
                name: "if_else".into(),
                params: vec![IrParam { name: "cond".into(), ty: IrType::Bool, value: Value(0) }],
                return_type: IrType::Int,
                blocks: vec![
                    BasicBlock {
                        id: BlockId(0),
                        instructions: vec![],
                        terminator: Terminator::CondBranch {
                            cond: Value(0),
                            true_block: BlockId(1),
                            false_block: BlockId(2),
                        },
                    },
                    BasicBlock {
                        id: BlockId(1),
                        instructions: vec![Instruction {
                            result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(1),
                        }],
                        terminator: Terminator::Return(Value(1)),
                    },
                    BasicBlock {
                        id: BlockId(2),
                        instructions: vec![Instruction {
                            result: Value(2), ty: IrType::Int, kind: InstKind::IntConst(2),
                        }],
                        terminator: Terminator::Return(Value(2)),
                    },
                ],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("br i1"), "should contain conditional branch: {ir}");
        assert!(ir.contains("bb1"), "should reference then block: {ir}");
        assert!(ir.contains("bb2"), "should reference else block: {ir}");
    }

    #[test]
    fn test_nested_if_else() {
        // Three tiers: if cond → bb1, else → bb2 (which branches to bb3 or bb4)
        let module = IrModule {
            functions: vec![IrFunction {
                name: "nested".into(),
                params: vec![
                    IrParam { name: "c1".into(), ty: IrType::Bool, value: Value(0) },
                    IrParam { name: "c2".into(), ty: IrType::Bool, value: Value(1) },
                ],
                return_type: IrType::Int,
                blocks: vec![
                    BasicBlock { id: BlockId(0), instructions: vec![],
                        terminator: Terminator::CondBranch { cond: Value(0), true_block: BlockId(1), false_block: BlockId(2) } },
                    BasicBlock { id: BlockId(1),
                        instructions: vec![Instruction { result: Value(2), ty: IrType::Int, kind: InstKind::IntConst(10) }],
                        terminator: Terminator::Return(Value(2)) },
                    BasicBlock { id: BlockId(2), instructions: vec![],
                        terminator: Terminator::CondBranch { cond: Value(1), true_block: BlockId(3), false_block: BlockId(4) } },
                    BasicBlock { id: BlockId(3),
                        instructions: vec![Instruction { result: Value(3), ty: IrType::Int, kind: InstKind::IntConst(20) }],
                        terminator: Terminator::Return(Value(3)) },
                    BasicBlock { id: BlockId(4),
                        instructions: vec![Instruction { result: Value(4), ty: IrType::Int, kind: InstKind::IntConst(30) }],
                        terminator: Terminator::Return(Value(4)) },
                ],
            }],
        };
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&module);
        assert!(codegen.verify().is_ok(), "nested if/else should verify");
        let ir = codegen.emit_llvm_ir();
        // Should have two conditional branches
        assert!(ir.matches("br i1").count() >= 2, "should have 2+ conditional branches: {ir}");
    }

    #[test]
    fn test_while_loop_back_edge() {
        // bb0: branch to bb1 (header)
        // bb1: cond branch to bb2 (body) or bb3 (exit)
        // bb2: branch back to bb1 (back-edge)
        // bb3: return
        let module = IrModule {
            functions: vec![IrFunction {
                name: "loop_fn".into(),
                params: vec![IrParam { name: "n".into(), ty: IrType::Bool, value: Value(0) }],
                return_type: IrType::Int,
                blocks: vec![
                    BasicBlock { id: BlockId(0), instructions: vec![],
                        terminator: Terminator::Branch(BlockId(1)) },
                    BasicBlock { id: BlockId(1), instructions: vec![],
                        terminator: Terminator::CondBranch { cond: Value(0), true_block: BlockId(2), false_block: BlockId(3) } },
                    BasicBlock { id: BlockId(2), instructions: vec![],
                        terminator: Terminator::Branch(BlockId(1)) },
                    BasicBlock { id: BlockId(3),
                        instructions: vec![Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(0) }],
                        terminator: Terminator::Return(Value(1)) },
                ],
            }],
        };
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&module);
        assert!(codegen.verify().is_ok(), "loop should verify");
        let ir = codegen.emit_llvm_ir();
        assert!(ir.contains("br label %bb1"), "should have back-edge to header: {ir}");
    }

    #[test]
    fn test_multiple_basic_blocks_verify() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "multi_block".into(),
                params: vec![IrParam { name: "x".into(), ty: IrType::Bool, value: Value(0) }],
                return_type: IrType::Int,
                blocks: vec![
                    BasicBlock { id: BlockId(0), instructions: vec![],
                        terminator: Terminator::CondBranch { cond: Value(0), true_block: BlockId(1), false_block: BlockId(2) } },
                    BasicBlock { id: BlockId(1),
                        instructions: vec![Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(100) }],
                        terminator: Terminator::Branch(BlockId(3)) },
                    BasicBlock { id: BlockId(2),
                        instructions: vec![Instruction { result: Value(2), ty: IrType::Int, kind: InstKind::IntConst(200) }],
                        terminator: Terminator::Branch(BlockId(3)) },
                    BasicBlock { id: BlockId(3),
                        instructions: vec![Instruction { result: Value(3), ty: IrType::Int, kind: InstKind::IntConst(0) }],
                        terminator: Terminator::Return(Value(3)) },
                ],
            }],
        };
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&module);
        assert!(codegen.verify().is_ok(), "multi-block function should verify");
    }

    // ═════════════════════════════════════════════════════════════
    // PART 2: Policy decision compilation via full pipeline
    // ═════════════════════════════════════════════════════════════

    #[test]
    fn test_risk_policy_has_conditional_branch() {
        let ir = compile_source_to_llvm_ir(r#"
            policy risk_based {
                rule check_risk(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 50 { deny } else { permit }
                }
            }
        "#);
        assert!(ir.contains("br i1"), "risk policy should have conditional branch: {ir}");
        assert!(ir.contains("define i32 @risk_based__check_risk"), "should have rule function: {ir}");
    }

    // ═════════════════════════════════════════════════════════════
    // PART 3: Evaluate entry point tests
    // ═════════════════════════════════════════════════════════════

    #[test]
    fn test_evaluate_entry_exists() {
        let ir = compile_source_to_llvm_ir(
            "policy access { rule allow(s: Int, a: Int, r: Int, risk: Int) { permit } }"
        );
        assert!(ir.contains("define i32 @evaluate(i64"), "evaluate function should exist: {ir}");
    }

    #[test]
    fn test_evaluate_calls_rules() {
        let ir = compile_source_to_llvm_ir(
            "policy access { rule allow(s: Int, a: Int, r: Int, risk: Int) { permit } }"
        );
        assert!(ir.contains("call i32 @access__allow"), "evaluate should call rule: {ir}");
    }

    #[test]
    fn test_evaluate_returns_i32() {
        let ir = compile_source_to_llvm_ir(
            "policy access { rule allow(s: Int, a: Int, r: Int, risk: Int) { permit } }"
        );
        // The evaluate function should return i32 (the exit block returns i32 0 = Permit)
        assert!(ir.contains("define i32 @evaluate("), "evaluate should return i32: {ir}");
    }

    #[test]
    fn test_evaluate_first_non_permit_wins() {
        let ir = compile_source_to_llvm_ir(r#"
            policy multi {
                rule first(s: Int, a: Int, r: Int, risk: Int) { permit }
                rule second(s: Int, a: Int, r: Int, risk: Int) { deny }
            }
        "#);
        // Should call both rules and have the "is_not_permit" check
        assert!(ir.contains("is_not_permit"), "should check for non-permit: {ir}");
        assert!(ir.contains("call i32 @multi__first"), "should call first rule: {ir}");
        assert!(ir.contains("call i32 @multi__second"), "should call second rule: {ir}");
    }

    // ═════════════════════════════════════════════════════════════
    // PART 4: Cross-backend equivalence tests (structural)
    // ═════════════════════════════════════════════════════════════

    #[test]
    fn test_cross_backend_permit_structure() {
        // Verify WASM produces Permit
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest};
        let source = "policy access { rule allow(s: Int, a: Int, r: Int, risk: Int) { permit } }";

        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, crate::runtime::evaluator::PolicyDecision::Permit);

        // Verify LLVM IR structure matches
        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("define i32 @evaluate(i64"), "should have evaluate entry");
        assert!(ir.contains("ret i32 0"), "should return Permit (0)");
    }

    #[test]
    fn test_cross_backend_deny_structure() {
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest};
        let source = "policy access { rule block(s: Int, a: Int, r: Int, risk: Int) { deny } }";

        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, crate::runtime::evaluator::PolicyDecision::Deny);

        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("define i32 @evaluate(i64"), "should have evaluate entry");
        assert!(ir.contains("ret i32 1"), "should return Deny (1)");
    }

    #[test]
    fn test_cross_backend_risk_structure() {
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest, PolicyDecision};
        let source = r#"
            policy risk_based {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 50 { deny } else { permit }
                }
            }
        "#;

        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();

        // Low risk → Permit
        let r1 = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 30)).unwrap();
        assert_eq!(r1.decision, PolicyDecision::Permit);

        // High risk → Deny
        let r2 = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 80)).unwrap();
        assert_eq!(r2.decision, PolicyDecision::Deny);

        // LLVM IR should have the conditional structure
        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("define i32 @evaluate(i64"), "evaluate entry point");
        assert!(ir.contains("br i1"), "conditional branch for risk check");
        assert!(ir.contains("icmp sgt i64"), "signed greater-than comparison");
    }

    #[test]
    fn test_cross_backend_escalate_structure() {
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest};
        let source = "policy access { rule esc(s: Int, a: Int, r: Int, risk: Int) { escalate } }";

        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, crate::runtime::evaluator::PolicyDecision::Escalate);

        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("ret i32 2"), "should return Escalate (2)");
    }

    #[test]
    fn test_cross_backend_quarantine_structure() {
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest};
        let source = "policy access { rule quar(s: Int, a: Int, r: Int, risk: Int) { quarantine } }";

        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, crate::runtime::evaluator::PolicyDecision::Quarantine);

        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("ret i32 3"), "should return Quarantine (3)");
    }

    #[test]
    fn test_cross_backend_multi_rule() {
        use crate::compiler::compile_source;
        use crate::runtime::evaluator::{PolicyModule, PolicyRequest, PolicyDecision};
        let source = r#"
            policy multi {
                rule first(s: Int, a: Int, r: Int, risk: Int) { permit }
                rule second(s: Int, a: Int, r: Int, risk: Int) { deny }
            }
        "#;

        // WASM: first-non-permit-wins → second rule returns Deny → overall Deny
        let wasm = compile_source(source, 0).unwrap();
        let module = PolicyModule::from_bytes(&wasm).unwrap();
        let evaluator = module.evaluator().unwrap();
        let result = evaluator.evaluate(&PolicyRequest::new(0, 0, 0, 0)).unwrap();
        assert_eq!(result.decision, PolicyDecision::Deny);

        // LLVM: evaluate calls both rules with first-non-permit-wins logic
        let ir = compile_source_to_llvm_ir(source);
        assert!(ir.contains("call i32 @multi__first"), "calls first rule");
        assert!(ir.contains("call i32 @multi__second"), "calls second rule");
        assert!(ir.contains("is_not_permit"), "has permit check");
    }

    // ═════════════════════════════════════════════════════════════
    // Verification and output tests
    // ═════════════════════════════════════════════════════════════

    #[test]
    fn test_module_verification() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "verify_test");
        codegen.compile_module(&simple_return_int(42));
        assert!(codegen.verify().is_ok(), "LLVM module should verify");
    }

    #[test]
    fn test_correct_return_type() {
        let ir = compile_and_get_ir(&simple_return_int(42));
        assert!(ir.contains("define i64 @return_int()"), "should return i64: {ir}");
    }

    #[test]
    fn test_correct_param_count() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "three_params".into(),
                params: vec![
                    IrParam { name: "a".into(), ty: IrType::Int, value: Value(0) },
                    IrParam { name: "b".into(), ty: IrType::Float, value: Value(1) },
                    IrParam { name: "c".into(), ty: IrType::Bool, value: Value(2) },
                ],
                return_type: IrType::Int,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![],
                    terminator: Terminator::Return(Value(0)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(
            ir.contains("define i64 @three_params(i64") && ir.contains("double") && ir.contains("i1"),
            "should have three params of correct types: {ir}"
        );
    }

    #[test]
    fn test_emit_object_bytes() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "obj_test");
        codegen.compile_module(&simple_return_int(42));
        let bytes = codegen.emit_object_bytes().unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "should be ELF");
    }

    #[test]
    fn test_emit_object_file() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "file_test");
        codegen.compile_module(&simple_return_int(42));
        let path = std::env::temp_dir().join("test_rune_output.o");
        codegen.emit_object_file(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_emit_llvm_ir_contains_define() {
        let ir = compile_and_get_ir(&simple_return_int(42));
        assert!(ir.contains("define"), "should contain 'define': {ir}");
    }

    // ── Pipeline integration tests ───────────────────────────────

    #[test]
    fn test_full_pipeline_to_native() {
        use crate::compiler::compile_to_native;
        let source = "fn add(a: Int, b: Int) -> Int { a + b }";
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "pipeline should succeed: {:?}", result.err());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "should produce ELF");
    }

    #[test]
    fn test_full_pipeline_invalid_source() {
        use crate::compiler::compile_to_native;
        let result = compile_to_native("this is not valid {{{", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_pipeline_with_params() {
        use crate::compiler::compile_to_native;
        let source = "fn multiply(x: Int, y: Int) -> Int { x * y }";
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "pipeline should succeed: {:?}", result.err());
        assert_eq!(&result.unwrap()[..4], &[0x7f, 0x45, 0x4c, 0x46]);
    }

    #[test]
    fn test_full_pipeline_policy_to_native() {
        use crate::compiler::compile_to_native;
        let source = r#"
            policy risk_based {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 50 { deny } else { permit }
                }
            }
        "#;
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "policy pipeline should succeed: {:?}", result.err());
        assert_eq!(&result.unwrap()[..4], &[0x7f, 0x45, 0x4c, 0x46]);
    }

    // ── Main wrapper tests ──────────────────────────────────────────

    #[test]
    fn test_main_wrapper_in_llvm_ir() {
        let source = r#"
            policy access {
                rule allow(subject: Int, action: Int, resource: Int, risk: Int) {
                    permit
                }
            }
        "#;
        let ir = compile_source_to_llvm_ir_with_main(source);
        assert!(ir.contains("define i32 @main()"), "should contain main function");
        assert!(ir.contains("call i32 @evaluate"), "main should call evaluate");
    }

    #[test]
    fn test_main_wrapper_without_evaluate() {
        // A module with no policy rules gets no evaluate, so main returns 1 (Deny).
        let ir_module = IrModule {
            functions: vec![make_simple_function("standalone", IrType::Int)],
        };

        let context = Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&ir_module);
        codegen.compile_main_wrapper();
        codegen.verify().expect("main without evaluate should verify");

        let ir = codegen.emit_llvm_ir();
        assert!(ir.contains("define i32 @main()"));
        // Should return 1 (Deny) as fail-closed.
        assert!(ir.contains("ret i32 1"));
    }

    fn compile_source_to_llvm_ir_with_main(source: &str) -> String {
        use crate::ir::lower::Lowerer;
        use crate::lexer::scanner::Lexer;
        use crate::parser::parser::Parser;
        use crate::types::checker::TypeChecker;
        use crate::types::context::TypeContext;

        let (tokens, lex_errors) = Lexer::new(source, 0).tokenize();
        assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
        let (file, parse_errors) = Parser::new(tokens).parse();
        assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
        let mut ctx = TypeContext::new();
        let mut checker = TypeChecker::new(&mut ctx);
        checker.check_source_file(&file);
        assert!(ctx.errors.is_empty(), "type errors: {:?}", ctx.errors);
        let mut lowerer = Lowerer::new();
        let ir_module = lowerer.lower_source_file(&file);

        let context = Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&ir_module);
        codegen.compile_main_wrapper();
        codegen.verify().expect("LLVM module with main should verify");
        codegen.emit_llvm_ir()
    }

    // ── Shared library tests ────────────────────────────────────────

    #[test]
    fn test_shared_library_produces_file() {
        use crate::compiler::compile_to_shared_library;
        let source = r#"
            policy access {
                rule allow(subject: Int, action: Int, resource: Int, risk: Int) {
                    permit
                }
            }
        "#;
        let dir = std::env::temp_dir().join("rune_test_shared_lib");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test_policy.so");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_shared_library(source, 0, &output);
        if let Err(ref errors) = result {
            // If cc is not available, skip the test gracefully.
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "shared lib should compile: {:?}", result.err());
        assert!(output.exists(), "output file should exist");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shared_library_is_elf_shared_object() {
        use crate::compiler::compile_to_shared_library;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_shared_elf");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.so");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_shared_library(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let bytes = std::fs::read(&output).unwrap();
        // ELF magic bytes
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "should be ELF");
        // ELF type at offset 16: ET_DYN (3) for shared objects
        let elf_type = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert_eq!(elf_type, 3, "ELF type should be ET_DYN (shared object)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shared_library_contains_evaluate_symbol() {
        use crate::compiler::compile_to_shared_library;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_shared_sym");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.so");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_shared_library(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        // Use nm to check for the evaluate symbol.
        let nm_output = std::process::Command::new("nm")
            .arg("-D")
            .arg(&output)
            .output();
        if let Ok(out) = nm_output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("evaluate"), "should export evaluate symbol: {stdout}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shared_library_invalid_source_returns_errors() {
        use crate::compiler::compile_to_shared_library;
        let dir = std::env::temp_dir().join("rune_test_shared_err");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("bad.so");

        let result = compile_to_shared_library("this is not valid {{{", 0, &output);
        assert!(result.is_err(), "invalid source should produce errors");
        assert!(!output.exists(), "no file should be written on error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_shared_library_risk_policy() {
        use crate::compiler::compile_to_shared_library;
        let source = r#"
            policy risk_based {
                rule check(subject: Int, action: Int, resource: Int, risk: Int) {
                    if risk > 50 { deny } else { permit }
                }
            }
        "#;
        let dir = std::env::temp_dir().join("rune_test_shared_risk");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("risk.so");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_shared_library(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());
        let meta = std::fs::metadata(&output).unwrap();
        assert!(meta.len() > 0, "shared library should not be empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Executable tests ────────────────────────────────────────────

    #[test]
    fn test_executable_produces_file() {
        use crate::compiler::compile_to_executable;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_exe_file");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(output.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_executable_is_elf_executable() {
        use crate::compiler::compile_to_executable;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_exe_elf");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "should be ELF");
        // ELF type: ET_EXEC (2) or ET_DYN (3, for PIE executables)
        let elf_type = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert!(elf_type == 2 || elf_type == 3, "ELF type should be ET_EXEC or ET_DYN (PIE), got {elf_type}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_executable_is_executable_permission() {
        use crate::compiler::compile_to_executable;
        use std::os::unix::fs::PermissionsExt;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_exe_perm");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let perms = std::fs::metadata(&output).unwrap().permissions();
        assert!(perms.mode() & 0o111 != 0, "file should be executable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_executable_permit_policy_exits_zero() {
        use crate::compiler::compile_to_executable;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { permit } }";
        let dir = std::env::temp_dir().join("rune_test_exe_permit");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("permit.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let run = std::process::Command::new(&output).output().unwrap();
        assert_eq!(run.status.code(), Some(0), "permit policy should exit 0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_executable_deny_policy_exits_one() {
        use crate::compiler::compile_to_executable;
        let source = "policy a { rule r(s: Int, a: Int, r: Int, k: Int) { deny } }";
        let dir = std::env::temp_dir().join("rune_test_exe_deny");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("deny.bin");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_executable(source, 0, &output);
        if let Err(ref errors) = result {
            if errors.iter().any(|e| e.message.contains("'cc'")) {
                eprintln!("skipping: system linker not available");
                return;
            }
        }
        assert!(result.is_ok(), "{:?}", result.err());

        let run = std::process::Command::new(&output).output().unwrap();
        assert_eq!(run.status.code(), Some(1), "deny policy should exit 1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_executable_invalid_source_returns_errors() {
        use crate::compiler::compile_to_executable;
        let dir = std::env::temp_dir().join("rune_test_exe_err");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("bad.bin");

        let result = compile_to_executable("this is not valid {{{", 0, &output);
        assert!(result.is_err());
        assert!(!output.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Object file backward-compat tests ───────────────────────────

    #[test]
    fn test_native_file_still_produces_object() {
        use crate::compiler::compile_to_native_file;
        let source = "fn id(x: Int) -> Int { x }";
        let dir = std::env::temp_dir().join("rune_test_obj_compat");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.o");
        let _ = std::fs::remove_file(&output);

        let result = compile_to_native_file(source, 0, &output);
        assert!(result.is_ok(), "{:?}", result.err());
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "should be ELF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_native_bytes_still_produces_object() {
        use crate::compiler::compile_to_native;
        let source = "fn id(x: Int) -> Int { x }";
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "{:?}", result.err());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46]);
    }

    // ── PIC object file test ────────────────────────────────────────

    #[test]
    fn test_pic_object_file_emission() {
        let ir_module = IrModule {
            functions: vec![make_simple_function("test_fn", IrType::Int)],
        };

        let context = Context::create();
        let mut codegen = LlvmCodegen::new(&context, "test");
        codegen.compile_module(&ir_module);
        codegen.verify().unwrap();

        let dir = std::env::temp_dir().join("rune_test_pic");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("test.o");
        let result = codegen.emit_object_file_pic(&output);
        assert!(result.is_ok(), "{:?}", result.err());
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
