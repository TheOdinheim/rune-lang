// ═══════════════════════════════════════════════════════════════════════
// LLVM Codegen Tests
//
// Only compiled and run with: cargo test --features llvm
// ═══════════════════════════════════════════════════════════════════════

#[cfg(all(test, feature = "llvm"))]
mod tests {
    use crate::codegen::llvm_gen::LlvmCodegen;
    use crate::ir::nodes::*;

    // ── Test helpers ─────────────────────────────────────────────

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

    fn binary_op_module(op: InstKind) -> IrModule {
        IrModule {
            functions: vec![IrFunction {
                name: "binop".into(),
                params: vec![],
                return_type: IrType::Int,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Int, kind: InstKind::IntConst(10) },
                        Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(3) },
                        Instruction { result: Value(2), ty: IrType::Int, kind: op },
                    ],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        }
    }

    fn comparison_module(op: InstKind) -> IrModule {
        IrModule {
            functions: vec![IrFunction {
                name: "cmp".into(),
                params: vec![],
                return_type: IrType::Bool,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Int, kind: InstKind::IntConst(5) },
                        Instruction { result: Value(1), ty: IrType::Int, kind: InstKind::IntConst(10) },
                        Instruction { result: Value(2), ty: IrType::Bool, kind: op },
                    ],
                    terminator: Terminator::Return(Value(2)),
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

    // ── Arithmetic tests ─────────────────────────────────────────

    #[test]
    fn test_int_addition() {
        let ir = compile_and_get_ir(&binary_op_module(InstKind::Add(Value(0), Value(1))));
        assert!(ir.contains("add i64"), "LLVM IR should contain add i64: {ir}");
    }

    #[test]
    fn test_int_subtraction() {
        let ir = compile_and_get_ir(&binary_op_module(InstKind::Sub(Value(0), Value(1))));
        assert!(ir.contains("sub i64"), "LLVM IR should contain sub i64: {ir}");
    }

    #[test]
    fn test_int_multiplication() {
        let ir = compile_and_get_ir(&binary_op_module(InstKind::Mul(Value(0), Value(1))));
        assert!(ir.contains("mul i64"), "LLVM IR should contain mul i64: {ir}");
    }

    #[test]
    fn test_int_division() {
        let ir = compile_and_get_ir(&binary_op_module(InstKind::Div(Value(0), Value(1))));
        assert!(ir.contains("sdiv i64"), "LLVM IR should contain sdiv i64: {ir}");
    }

    // ── Comparison tests ─────────────────────────────────────────

    #[test]
    fn test_comparison_eq() {
        let ir = compile_and_get_ir(&comparison_module(InstKind::Eq(Value(0), Value(1))));
        assert!(ir.contains("icmp eq i64"), "LLVM IR should contain icmp eq: {ir}");
    }

    #[test]
    fn test_comparison_ne() {
        let ir = compile_and_get_ir(&comparison_module(InstKind::Ne(Value(0), Value(1))));
        assert!(ir.contains("icmp ne i64"), "LLVM IR should contain icmp ne: {ir}");
    }

    #[test]
    fn test_comparison_lt() {
        let ir = compile_and_get_ir(&comparison_module(InstKind::Lt(Value(0), Value(1))));
        assert!(ir.contains("icmp slt i64"), "LLVM IR should contain icmp slt: {ir}");
    }

    #[test]
    fn test_comparison_gt() {
        let ir = compile_and_get_ir(&comparison_module(InstKind::Gt(Value(0), Value(1))));
        assert!(ir.contains("icmp sgt i64"), "LLVM IR should contain icmp sgt: {ir}");
    }

    // ── Boolean tests ────────────────────────────────────────────

    #[test]
    fn test_bool_and() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "bool_and".into(),
                params: vec![],
                return_type: IrType::Bool,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Bool, kind: InstKind::BoolConst(true) },
                        Instruction { result: Value(1), ty: IrType::Bool, kind: InstKind::BoolConst(false) },
                        Instruction { result: Value(2), ty: IrType::Bool, kind: InstKind::And(Value(0), Value(1)) },
                    ],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("and i1"), "LLVM IR should contain and i1: {ir}");
    }

    #[test]
    fn test_bool_or() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "bool_or".into(),
                params: vec![],
                return_type: IrType::Bool,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Bool, kind: InstKind::BoolConst(true) },
                        Instruction { result: Value(1), ty: IrType::Bool, kind: InstKind::BoolConst(false) },
                        Instruction { result: Value(2), ty: IrType::Bool, kind: InstKind::Or(Value(0), Value(1)) },
                    ],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("or i1"), "LLVM IR should contain or i1: {ir}");
    }

    #[test]
    fn test_bool_not() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "bool_not".into(),
                params: vec![],
                return_type: IrType::Bool,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Bool, kind: InstKind::BoolConst(true) },
                        Instruction { result: Value(1), ty: IrType::Bool, kind: InstKind::Not(Value(0)) },
                    ],
                    terminator: Terminator::Return(Value(1)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("xor i1"), "LLVM IR should contain xor (not) i1: {ir}");
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
        assert!(ir.contains("define i64 @add_params(i64"), "LLVM IR should have correct param types: {ir}");
        assert!(ir.contains("add i64"), "LLVM IR should contain add: {ir}");
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
        assert!(ir.contains("call i64 @callee"), "LLVM IR should contain call: {ir}");
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
        assert!(ir.contains("alloca i64"), "LLVM IR should contain alloca: {ir}");
        assert!(ir.contains("store i64"), "LLVM IR should contain store: {ir}");
        assert!(ir.contains("load i64"), "LLVM IR should contain load: {ir}");
    }

    // ── Float arithmetic tests ───────────────────────────────────

    #[test]
    fn test_float_addition() {
        let module = IrModule {
            functions: vec![IrFunction {
                name: "float_add".into(),
                params: vec![],
                return_type: IrType::Float,
                blocks: vec![BasicBlock {
                    id: BlockId(0),
                    instructions: vec![
                        Instruction { result: Value(0), ty: IrType::Float, kind: InstKind::FloatConst(1.5) },
                        Instruction { result: Value(1), ty: IrType::Float, kind: InstKind::FloatConst(2.5) },
                        Instruction { result: Value(2), ty: IrType::Float, kind: InstKind::Add(Value(0), Value(1)) },
                    ],
                    terminator: Terminator::Return(Value(2)),
                }],
            }],
        };
        let ir = compile_and_get_ir(&module);
        assert!(ir.contains("fadd double"), "LLVM IR should contain fadd: {ir}");
    }

    // ── Governance decision tests ────────────────────────────────

    #[test]
    fn test_governance_decision() {
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
        assert!(ir.contains("ret i32 1"), "LLVM IR should contain ret i32 1 (Deny): {ir}");
    }

    // ── Verification tests ───────────────────────────────────────

    #[test]
    fn test_module_verification() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "verify_test");
        codegen.compile_module(&simple_return_int(42));
        assert!(codegen.verify().is_ok(), "LLVM module should verify successfully");
    }

    #[test]
    fn test_correct_return_type() {
        let ir = compile_and_get_ir(&simple_return_int(42));
        assert!(ir.contains("define i64 @return_int()"), "Function should return i64: {ir}");
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
            "Function should have three params of correct types: {ir}"
        );
    }

    // ── Object file output tests ─────────────────────────────────

    #[test]
    fn test_emit_object_bytes() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "obj_test");
        codegen.compile_module(&simple_return_int(42));
        let bytes = codegen.emit_object_bytes().unwrap();
        assert!(!bytes.is_empty(), "Object bytes should be non-empty");
        // ELF magic: 0x7f ELF
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "Should be ELF format");
    }

    #[test]
    fn test_emit_object_file() {
        let context = inkwell::context::Context::create();
        let mut codegen = LlvmCodegen::new(&context, "file_test");
        codegen.compile_module(&simple_return_int(42));
        let dir = std::env::temp_dir();
        let path = dir.join("test_rune_output.o");
        codegen.emit_object_file(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(metadata.len() > 0, "Object file should be non-empty");
        // Read and verify ELF magic.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_emit_llvm_ir_contains_define() {
        let ir = compile_and_get_ir(&simple_return_int(42));
        assert!(ir.contains("define"), "LLVM IR should contain 'define': {ir}");
    }

    // ── Pipeline integration tests ───────────────────────────────

    #[test]
    fn test_full_pipeline_to_native() {
        use crate::compiler::compile_to_native;
        let source = "fn add(a: Int, b: Int) -> Int { a + b }";
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "Full pipeline should succeed: {:?}", result.err());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46], "Should produce ELF");
    }

    #[test]
    fn test_full_pipeline_invalid_source() {
        use crate::compiler::compile_to_native;
        let result = compile_to_native("this is not valid {{{", 0);
        assert!(result.is_err(), "Invalid source should return errors");
    }

    #[test]
    fn test_full_pipeline_with_params() {
        use crate::compiler::compile_to_native;
        let source = r#"
            fn multiply(x: Int, y: Int) -> Int {
                x * y
            }
        "#;
        let result = compile_to_native(source, 0);
        assert!(result.is_ok(), "Pipeline with params should succeed: {:?}", result.err());
        let bytes = result.unwrap();
        assert_eq!(&bytes[..4], &[0x7f, 0x45, 0x4c, 0x46]);
    }
}
