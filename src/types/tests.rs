#[cfg(test)]
mod tests {
    use crate::ast::nodes::*;
    use crate::lexer::token::Span;
    use crate::types::context::TypeContext;
    use crate::types::scope::{ScopeStack, Symbol};
    use crate::types::ty::{Type, TypeId, TypeTable, TypeVarId};

    fn dummy_span() -> Span {
        Span::new(0, 0, 0, 1, 1)
    }

    fn span_at(line: u32, col: u32) -> Span {
        Span::new(0, 0, 0, line, col)
    }

    // ═════════════════════════════════════════════════════════════════
    // TypeTable tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_intern_and_retrieve() {
        let mut table = TypeTable::new();
        let id = table.intern(Type::Int);
        assert_eq!(*table.get(id), Type::Int);
    }

    #[test]
    fn test_intern_deduplicates_primitives() {
        let mut table = TypeTable::new();
        let id1 = table.intern(Type::Int);
        let id2 = table.intern(Type::Int);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_intern_different_types_get_different_ids() {
        let mut table = TypeTable::new();
        let int_id = table.intern(Type::Int);
        let bool_id = table.intern(Type::Bool);
        assert_ne!(int_id, bool_id);
    }

    #[test]
    fn test_intern_complex_type() {
        let mut table = TypeTable::new();
        let int_id = table.intern(Type::Int);
        let tuple_id = table.intern(Type::Tuple(vec![int_id, int_id]));
        let ty = table.get(tuple_id);
        assert!(matches!(ty, Type::Tuple(elems) if elems.len() == 2));
    }

    #[test]
    fn test_intern_function_type() {
        let mut table = TypeTable::new();
        let int_id = table.intern(Type::Int);
        let fn_id = table.intern(Type::Function {
            params: vec![int_id, int_id],
            return_type: int_id,
            effects: vec!["io".to_string()],
        });
        let ty = table.get(fn_id);
        match ty {
            Type::Function { params, effects, .. } => {
                assert_eq!(params.len(), 2);
                assert_eq!(effects, &["io".to_string()]);
            }
            _ => panic!("expected function type"),
        }
    }

    #[test]
    fn test_intern_governance_types() {
        let mut table = TypeTable::new();

        let pd = table.intern(Type::PolicyDecision);
        assert_eq!(*table.get(pd), Type::PolicyDecision);

        let cap = table.intern(Type::Capability {
            name: "FileRead".to_string(),
            operations: Vec::new(),
        });
        match table.get(cap) {
            Type::Capability { name, .. } => assert_eq!(name, "FileRead"),
            _ => panic!("expected capability"),
        }

        let int_id = table.intern(Type::Int);
        let attested = table.intern(Type::AttestedModel {
            signer: int_id,
            policy: int_id,
            architecture: int_id,
        });
        assert!(matches!(table.get(attested), Type::AttestedModel { .. }));

        let effect = table.intern(Type::Effect {
            name: "IO".to_string(),
            operations: Vec::new(),
        });
        match table.get(effect) {
            Type::Effect { name, .. } => assert_eq!(name, "IO"),
            _ => panic!("expected effect"),
        }
    }

    #[test]
    fn test_intern_error_type() {
        let mut table = TypeTable::new();
        let err = table.intern(Type::Error);
        assert!(table.get(err).is_error());
    }

    #[test]
    fn test_intern_type_var() {
        let mut table = TypeTable::new();
        let var = table.intern(Type::Var(TypeVarId(0)));
        assert!(matches!(table.get(var), Type::Var(TypeVarId(0))));
    }

    #[test]
    fn test_type_display() {
        assert_eq!(format!("{}", Type::Int), "Int");
        assert_eq!(format!("{}", Type::Unit), "()");
        assert_eq!(format!("{}", Type::Error), "<error>");
        assert_eq!(format!("{}", Type::PolicyDecision), "PolicyDecision");
        assert_eq!(format!("{}", Type::Var(TypeVarId(3))), "?T3");
    }

    // ═════════════════════════════════════════════════════════════════
    // ScopeStack tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_scope_define_and_lookup() {
        let mut scopes = ScopeStack::new();
        let span = dummy_span();
        scopes
            .define("x", Symbol::Variable { ty: TypeId(0), is_mut: false, span }, span)
            .unwrap();
        assert!(scopes.lookup("x").is_some());
        assert!(scopes.lookup("y").is_none());
    }

    #[test]
    fn test_scope_chain_lookup() {
        let mut scopes = ScopeStack::new();
        let span = dummy_span();

        // Define in global scope.
        scopes
            .define("global_var", Symbol::Variable { ty: TypeId(0), is_mut: false, span }, span)
            .unwrap();

        // Enter a child scope.
        scopes.enter_scope();
        scopes
            .define("local_var", Symbol::Variable { ty: TypeId(1), is_mut: true, span }, span)
            .unwrap();

        // Child scope can see both.
        assert!(scopes.lookup("global_var").is_some());
        assert!(scopes.lookup("local_var").is_some());

        // Exit child scope.
        scopes.exit_scope();

        // Global scope can see global but not local.
        assert!(scopes.lookup("global_var").is_some());
        assert!(scopes.lookup("local_var").is_none());
    }

    #[test]
    fn test_scope_shadowing() {
        let mut scopes = ScopeStack::new();
        let span = dummy_span();

        scopes
            .define("x", Symbol::Variable { ty: TypeId(0), is_mut: false, span }, span)
            .unwrap();

        scopes.enter_scope();
        // Shadowing across scopes is allowed.
        scopes
            .define("x", Symbol::Variable { ty: TypeId(1), is_mut: true, span }, span)
            .unwrap();

        // Inner scope sees the shadow.
        let sym = scopes.lookup("x").unwrap();
        match sym {
            Symbol::Variable { ty, is_mut, .. } => {
                assert_eq!(*ty, TypeId(1));
                assert!(*is_mut);
            }
            _ => panic!("expected variable"),
        }

        scopes.exit_scope();

        // Outer scope sees the original.
        let sym = scopes.lookup("x").unwrap();
        match sym {
            Symbol::Variable { ty, .. } => assert_eq!(*ty, TypeId(0)),
            _ => panic!("expected variable"),
        }
    }

    #[test]
    fn test_scope_redefinition_error() {
        let mut scopes = ScopeStack::new();
        let span1 = span_at(1, 1);
        let span2 = span_at(2, 5);

        scopes
            .define("x", Symbol::Variable { ty: TypeId(0), is_mut: false, span: span1 }, span1)
            .unwrap();

        // Same scope, same name → error.
        let err = scopes
            .define("x", Symbol::Variable { ty: TypeId(1), is_mut: false, span: span2 }, span2)
            .unwrap_err();

        assert!(err.message.contains("already defined"));
        assert!(err.message.contains("line 1"));
    }

    #[test]
    fn test_scope_depth() {
        let mut scopes = ScopeStack::new();
        assert_eq!(scopes.depth(), 0);
        scopes.enter_scope();
        assert_eq!(scopes.depth(), 1);
        scopes.enter_scope();
        assert_eq!(scopes.depth(), 2);
        scopes.exit_scope();
        assert_eq!(scopes.depth(), 1);
    }

    #[test]
    fn test_scope_lookup_current_only() {
        let mut scopes = ScopeStack::new();
        let span = dummy_span();

        scopes
            .define("x", Symbol::Variable { ty: TypeId(0), is_mut: false, span }, span)
            .unwrap();

        scopes.enter_scope();

        // lookup finds it in parent.
        assert!(scopes.lookup("x").is_some());
        // lookup_current does not.
        assert!(scopes.lookup_current("x").is_none());
    }

    #[test]
    fn test_scope_different_symbol_kinds() {
        let mut scopes = ScopeStack::new();
        let span = dummy_span();

        scopes
            .define(
                "MyType",
                Symbol::Type { ty: TypeId(0), span },
                span,
            )
            .unwrap();
        scopes
            .define(
                "my_fn",
                Symbol::Function {
                    params: vec![TypeId(0)],
                    return_type: TypeId(1),
                    effects: vec!["io".into()],
                    required_capabilities: Vec::new(),
                    span,
                },
                span,
            )
            .unwrap();
        scopes
            .define(
                "FileRead",
                Symbol::Capability { ty: TypeId(2), span },
                span,
            )
            .unwrap();
        scopes
            .define(
                "IO",
                Symbol::Effect { ty: TypeId(3), span },
                span,
            )
            .unwrap();

        assert!(matches!(scopes.lookup("MyType"), Some(Symbol::Type { .. })));
        assert!(matches!(scopes.lookup("my_fn"), Some(Symbol::Function { .. })));
        assert!(matches!(scopes.lookup("FileRead"), Some(Symbol::Capability { .. })));
        assert!(matches!(scopes.lookup("IO"), Some(Symbol::Effect { .. })));
    }

    #[test]
    #[should_panic(expected = "cannot exit the global scope")]
    fn test_exit_global_scope_panics() {
        let mut scopes = ScopeStack::new();
        scopes.exit_scope(); // should panic
    }

    // ═════════════════════════════════════════════════════════════════
    // TypeContext tests
    // ═════════════════════════════════════════════════════════════════

    #[test]
    fn test_context_builtins_registered() {
        let ctx = TypeContext::new();
        // Primitives should be in scope.
        assert!(ctx.lookup("Int").is_some());
        assert!(ctx.lookup("Float").is_some());
        assert!(ctx.lookup("Bool").is_some());
        assert!(ctx.lookup("String").is_some());
        assert!(ctx.lookup("PolicyDecision").is_some());
        // Lowercase aliases.
        assert!(ctx.lookup("i32").is_some());
        assert!(ctx.lookup("f64").is_some());
        assert!(ctx.lookup("bool").is_some());
    }

    #[test]
    fn test_context_intern_and_get() {
        let mut ctx = TypeContext::new();
        let id = ctx.intern_type(Type::Bool);
        assert_eq!(*ctx.get_type(id), Type::Bool);
    }

    #[test]
    fn test_context_fresh_type_var() {
        let mut ctx = TypeContext::new();
        let v1 = ctx.fresh_type_var();
        let v2 = ctx.fresh_type_var();
        assert_ne!(v1, v2);
        assert!(matches!(ctx.get_type(v1), Type::Var(TypeVarId(0))));
        assert!(matches!(ctx.get_type(v2), Type::Var(TypeVarId(1))));
    }

    #[test]
    fn test_context_scope_delegation() {
        let mut ctx = TypeContext::new();
        let span = dummy_span();

        ctx.enter_scope();
        ctx.define(
            "x",
            Symbol::Variable { ty: TypeId(0), is_mut: false, span },
            span,
        )
        .unwrap();
        assert!(ctx.lookup("x").is_some());
        ctx.exit_scope();
        assert!(ctx.lookup("x").is_none());
    }

    // ── resolve_type_expr tests ──────────────────────────────────────

    fn make_named_type_expr(name: &str) -> TypeExpr {
        TypeExpr {
            kind: TypeExprKind::Named {
                path: Path::from_ident(Ident::new(name.to_string(), dummy_span())),
                type_args: Vec::new(),
            },
            span: dummy_span(),
        }
    }

    fn make_named_with_args(name: &str, args: Vec<TypeExpr>) -> TypeExpr {
        TypeExpr {
            kind: TypeExprKind::Named {
                path: Path::from_ident(Ident::new(name.to_string(), dummy_span())),
                type_args: args,
            },
            span: dummy_span(),
        }
    }

    #[test]
    fn test_resolve_primitive_type() {
        let mut ctx = TypeContext::new();
        let id = ctx.resolve_type_expr(&make_named_type_expr("Int"));
        assert_eq!(*ctx.get_type(id), Type::Int);
        assert!(ctx.errors.is_empty());
    }

    #[test]
    fn test_resolve_alias_type() {
        let mut ctx = TypeContext::new();
        let id = ctx.resolve_type_expr(&make_named_type_expr("i32"));
        assert_eq!(*ctx.get_type(id), Type::Int);
    }

    #[test]
    fn test_resolve_undefined_type_produces_error() {
        let mut ctx = TypeContext::new();
        let id = ctx.resolve_type_expr(&make_named_type_expr("NonExistent"));
        assert!(ctx.get_type(id).is_error());
        assert_eq!(ctx.errors.len(), 1);
        assert!(ctx.errors[0].message.contains("undefined type"));
    }

    #[test]
    fn test_resolve_unit_type() {
        let mut ctx = TypeContext::new();
        let expr = TypeExpr { kind: TypeExprKind::Unit, span: dummy_span() };
        let id = ctx.resolve_type_expr(&expr);
        assert_eq!(*ctx.get_type(id), Type::Unit);
    }

    #[test]
    fn test_resolve_tuple_type() {
        let mut ctx = TypeContext::new();
        let expr = TypeExpr {
            kind: TypeExprKind::Tuple(vec![
                make_named_type_expr("Int"),
                make_named_type_expr("Bool"),
            ]),
            span: dummy_span(),
        };
        let id = ctx.resolve_type_expr(&expr);
        let ty = ctx.get_type(id);
        match ty {
            Type::Tuple(elems) => {
                assert_eq!(elems.len(), 2);
                assert_eq!(*ctx.get_type(elems[0]), Type::Int);
                assert_eq!(*ctx.get_type(elems[1]), Type::Bool);
            }
            _ => panic!("expected tuple, got {ty:?}"),
        }
    }

    #[test]
    fn test_resolve_function_type() {
        let mut ctx = TypeContext::new();
        let expr = TypeExpr {
            kind: TypeExprKind::Function {
                params: vec![make_named_type_expr("Int")],
                return_type: Box::new(make_named_type_expr("Bool")),
            },
            span: dummy_span(),
        };
        let id = ctx.resolve_type_expr(&expr);
        match ctx.get_type(id) {
            Type::Function { params, return_type, .. } => {
                assert_eq!(params.len(), 1);
                assert_eq!(*ctx.get_type(*return_type), Type::Bool);
            }
            other => panic!("expected function, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_reference_type() {
        let mut ctx = TypeContext::new();
        let expr = TypeExpr {
            kind: TypeExprKind::Reference {
                is_mut: true,
                inner: Box::new(make_named_type_expr("Int")),
            },
            span: dummy_span(),
        };
        let id = ctx.resolve_type_expr(&expr);
        match ctx.get_type(id) {
            Type::Ref { is_mut, inner } => {
                assert!(*is_mut);
                assert_eq!(*ctx.get_type(*inner), Type::Int);
            }
            other => panic!("expected ref, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_named_with_generic_args() {
        let mut ctx = TypeContext::new();
        let span = dummy_span();

        // Register a user type "Vec" so it can be found.
        let vec_id = ctx.intern_type(Type::Named {
            name: "Vec".to_string(),
            args: Vec::new(),
        });
        ctx.define("Vec", Symbol::Type { ty: vec_id, span }, span).unwrap();

        let expr = make_named_with_args("Vec", vec![make_named_type_expr("Int")]);
        let id = ctx.resolve_type_expr(&expr);
        match ctx.get_type(id) {
            Type::Named { name, args } => {
                assert_eq!(name, "Vec");
                assert_eq!(args.len(), 1);
                assert_eq!(*ctx.get_type(args[0]), Type::Int);
            }
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_non_type_symbol_produces_error() {
        let mut ctx = TypeContext::new();
        let span = dummy_span();

        // Define "x" as a variable, not a type.
        ctx.define(
            "x",
            Symbol::Variable { ty: TypeId(0), is_mut: false, span },
            span,
        )
        .unwrap();

        let id = ctx.resolve_type_expr(&make_named_type_expr("x"));
        assert!(ctx.get_type(id).is_error());
        assert!(ctx.errors[0].message.contains("is not a type"));
    }

    #[test]
    fn test_resolve_user_defined_type() {
        let mut ctx = TypeContext::new();
        let span = dummy_span();

        // Simulate: `struct Point { x: Float, y: Float }`
        let point_id = ctx.intern_type(Type::Named {
            name: "Point".to_string(),
            args: Vec::new(),
        });
        ctx.define("Point", Symbol::Type { ty: point_id, span }, span).unwrap();

        let resolved = ctx.resolve_type_expr(&make_named_type_expr("Point"));
        assert_eq!(resolved, point_id);
        assert!(ctx.errors.is_empty());
    }

    #[test]
    fn test_nested_scopes_type_resolution() {
        let mut ctx = TypeContext::new();
        let span = dummy_span();

        // Global: define struct Outer
        let outer_id = ctx.intern_type(Type::Named {
            name: "Outer".to_string(),
            args: Vec::new(),
        });
        ctx.define("Outer", Symbol::Type { ty: outer_id, span }, span).unwrap();

        ctx.enter_scope();

        // Inner: define struct Inner
        let inner_id = ctx.intern_type(Type::Named {
            name: "Inner".to_string(),
            args: Vec::new(),
        });
        ctx.define("Inner", Symbol::Type { ty: inner_id, span }, span).unwrap();

        // Both visible from inner scope.
        assert_eq!(ctx.resolve_type_expr(&make_named_type_expr("Outer")), outer_id);
        assert_eq!(ctx.resolve_type_expr(&make_named_type_expr("Inner")), inner_id);

        ctx.exit_scope();

        // Only Outer visible from global scope.
        assert_eq!(ctx.resolve_type_expr(&make_named_type_expr("Outer")), outer_id);
        let _ = ctx.resolve_type_expr(&make_named_type_expr("Inner"));
        assert!(ctx.errors.last().unwrap().message.contains("undefined type `Inner`"));
    }

    #[test]
    fn test_error_type_does_not_cascade() {
        let mut ctx = TypeContext::new();

        // Resolving an undefined type gives Error.
        let err_id = ctx.resolve_type_expr(&make_named_type_expr("NoSuchType"));
        assert!(ctx.get_type(err_id).is_error());

        // Using the error type in a tuple should still work (no panic).
        let int_id = ctx.resolve_type_expr(&make_named_type_expr("Int"));
        let tuple_id = ctx.intern_type(Type::Tuple(vec![err_id, int_id]));
        let ty = ctx.get_type(tuple_id);
        assert!(matches!(ty, Type::Tuple(elems) if elems.len() == 2));
    }
}
