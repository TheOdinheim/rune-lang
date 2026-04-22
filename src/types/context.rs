use crate::ast::nodes::{Path, TypeExpr, TypeExprKind};
use crate::lexer::token::Span;
use crate::types::scope::{ScopeError, ScopeStack, Symbol};
use crate::types::ty::{Type, TypeId, TypeTable, TypeVarId};

// ═══════════════════════════════════════════════════════════════════════
// Type errors
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub struct TypeError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "type error at line {}, column {}: {}",
            self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for TypeError {}

// ═══════════════════════════════════════════════════════════════════════
// TypeContext — owns type table, scope stack, and type variable state
// ═══════════════════════════════════════════════════════════════════════

/// Central context for the type system. Owns the interned type table,
/// the lexical scope stack, and the inference variable counter.
///
/// This is the entry point for all type operations: interning, looking
/// up names, resolving AST type expressions into internal TypeIds, and
/// creating fresh type variables for inference.
pub struct TypeContext {
    pub types: TypeTable,
    pub scopes: ScopeStack,
    next_var_id: u32,
    pub errors: Vec<TypeError>,
}

impl TypeContext {
    pub fn new() -> Self {
        let mut ctx = Self {
            types: TypeTable::new(),
            scopes: ScopeStack::new(),
            next_var_id: 0,
            errors: Vec::new(),
        };
        ctx.register_builtins();
        ctx
    }

    /// Register the built-in primitive types in the global scope.
    fn register_builtins(&mut self) {
        let builtins = [
            ("Int", Type::Int),
            ("Float", Type::Float),
            ("Bool", Type::Bool),
            ("String", Type::String),
            ("PolicyDecision", Type::PolicyDecision),
        ];

        let span = Span::new(0, 0, 0, 0, 0); // synthetic span for builtins

        for (name, ty) in builtins {
            let id = self.types.intern(ty);
            // Builtin registration cannot fail (global scope, no conflicts).
            let _ = self.scopes.define(
                name,
                Symbol::Type { ty: id, span },
                span,
            );
        }

        // Also register lowercase aliases for convenience.
        let aliases = [
            ("i32", Type::Int),
            ("i64", Type::Int),
            ("f32", Type::Float),
            ("f64", Type::Float),
            ("bool", Type::Bool),
        ];
        for (name, ty) in aliases {
            let id = self.types.intern(ty);
            let _ = self.scopes.define(
                name,
                Symbol::Type { ty: id, span },
                span,
            );
        }
    }

    // ── Type interning ───────────────────────────────────────────────

    /// Intern a type and return its handle.
    pub fn intern_type(&mut self, ty: Type) -> TypeId {
        self.types.intern(ty)
    }

    /// Look up an interned type by handle.
    pub fn get_type(&self, id: TypeId) -> &Type {
        self.types.get(id)
    }

    // ── Type variables ───────────────────────────────────────────────

    /// Create a fresh type variable for inference.
    pub fn fresh_type_var(&mut self) -> TypeId {
        let var_id = TypeVarId(self.next_var_id);
        self.next_var_id += 1;
        self.types.intern(Type::Var(var_id))
    }

    // ── Scope delegation ─────────────────────────────────────────────

    pub fn enter_scope(&mut self) {
        self.scopes.enter_scope();
    }

    pub fn exit_scope(&mut self) {
        self.scopes.exit_scope();
    }

    pub fn define(
        &mut self,
        name: &str,
        symbol: Symbol,
        span: Span,
    ) -> Result<(), ScopeError> {
        self.scopes.define(name, symbol, span)
    }

    pub fn lookup(&self, name: &str) -> Option<&Symbol> {
        self.scopes.lookup(name)
    }

    // ── AST TypeExpr → internal TypeId resolution ────────────────────

    /// Resolve an AST `TypeExpr` into an internal `TypeId`.
    ///
    /// This is the bridge between syntax and semantics: it looks up named
    /// types in the scope chain and recursively resolves generic arguments,
    /// tuple elements, function parameters, and references.
    ///
    /// On failure (undefined type name), records an error and returns the
    /// Error type so that checking can continue.
    pub fn resolve_type_expr(&mut self, expr: &TypeExpr) -> TypeId {
        match &expr.kind {
            TypeExprKind::Unit => self.intern_type(Type::Unit),

            TypeExprKind::Named { path, type_args } => {
                self.resolve_named_type(path, type_args, expr.span)
            }

            TypeExprKind::Tuple(elems) => {
                let resolved: Vec<TypeId> = elems
                    .iter()
                    .map(|e| self.resolve_type_expr(e))
                    .collect();
                self.intern_type(Type::Tuple(resolved))
            }

            TypeExprKind::Function { params, return_type } => {
                let resolved_params: Vec<TypeId> = params
                    .iter()
                    .map(|p| self.resolve_type_expr(p))
                    .collect();
                let resolved_ret = self.resolve_type_expr(return_type);
                self.intern_type(Type::Function {
                    params: resolved_params,
                    return_type: resolved_ret,
                    effects: Vec::new(), // effects resolved separately
                })
            }

            TypeExprKind::Reference { is_mut, inner } => {
                let resolved_inner = self.resolve_type_expr(inner);
                self.intern_type(Type::Ref {
                    is_mut: *is_mut,
                    inner: resolved_inner,
                })
            }
            TypeExprKind::Refined { base, .. } => {
                // Resolve to the base type. Predicate checking deferred to M4 Layer 2.
                self.resolve_type_expr(base)
            }
            TypeExprKind::Qualified { inner, .. } => {
                // Linearity is a compile-time qualifier, not part of the
                // interned type. Resolve to the inner type.
                self.resolve_type_expr(inner)
            }
        }
    }

    /// Resolve a named type path to its TypeId.
    fn resolve_named_type(
        &mut self,
        path: &Path,
        type_args: &[TypeExpr],
        span: Span,
    ) -> TypeId {
        // For now, single-segment paths only. Multi-segment paths
        // (module::Type) will be resolved in the module system pass.
        let name = &path.segments.last().expect("empty path").name;

        match self.scopes.lookup(name) {
            Some(Symbol::Type { ty, .. }) => {
                if type_args.is_empty() {
                    *ty
                } else {
                    // Resolve generic arguments and create a specialized Named type.
                    let resolved_args: Vec<TypeId> = type_args
                        .iter()
                        .map(|a| self.resolve_type_expr(a))
                        .collect();
                    self.intern_type(Type::Named {
                        name: name.clone(),
                        args: resolved_args,
                    })
                }
            }
            // Capabilities and effects are first-class types in RUNE.
            Some(Symbol::Capability { ty, .. }) | Some(Symbol::Effect { ty, .. }) => *ty,
            Some(_) => {
                // Found but not a type.
                self.errors.push(TypeError {
                    message: format!("`{name}` is not a type"),
                    span,
                });
                self.intern_type(Type::Error)
            }
            None => {
                self.errors.push(TypeError {
                    message: format!("undefined type `{name}`"),
                    span,
                });
                self.intern_type(Type::Error)
            }
        }
    }
}

impl Default for TypeContext {
    fn default() -> Self {
        Self::new()
    }
}
