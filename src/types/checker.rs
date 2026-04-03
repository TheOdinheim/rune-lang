use crate::ast::nodes::*;
use crate::lexer::token::Span;
use crate::types::context::{TypeContext, TypeError};
use crate::types::scope::Symbol;
use crate::types::ty::{Type, TypeId};

/// Type checker for RUNE expressions and statements.
///
/// Walks AST nodes, assigns types to expressions, and reports type errors.
/// Errors are collected rather than aborting so that multiple issues can
/// be reported in a single pass.
///
/// This is Pass 1 of M2 Layer 2: expressions and statements only.
/// Top-level declarations (structs, enums, traits, impls) come in Pass 2.
pub struct TypeChecker<'ctx> {
    pub ctx: &'ctx mut TypeContext,
}

impl<'ctx> TypeChecker<'ctx> {
    pub fn new(ctx: &'ctx mut TypeContext) -> Self {
        Self { ctx }
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn error(&mut self, message: impl Into<String>, span: Span) {
        self.ctx.errors.push(TypeError {
            message: message.into(),
            span,
        });
    }

    fn intern(&mut self, ty: Type) -> TypeId {
        self.ctx.intern_type(ty)
    }

    fn get(&self, id: TypeId) -> &Type {
        self.ctx.get_type(id)
    }

    /// Check structural type compatibility. Error is compatible with everything.
    fn types_compatible(&self, a: TypeId, b: TypeId) -> bool {
        if a == b {
            return true;
        }
        let ta = self.get(a);
        let tb = self.get(b);
        if ta.is_error() || tb.is_error() {
            return true;
        }
        // Structural equality after deref.
        ta == tb
    }

    fn type_name(&self, id: TypeId) -> String {
        format!("{}", self.get(id))
    }

    fn error_type(&mut self) -> TypeId {
        self.intern(Type::Error)
    }

    fn unit_type(&mut self) -> TypeId {
        self.intern(Type::Unit)
    }

    fn int_type(&mut self) -> TypeId {
        self.intern(Type::Int)
    }

    fn float_type(&mut self) -> TypeId {
        self.intern(Type::Float)
    }

    fn bool_type(&mut self) -> TypeId {
        self.intern(Type::Bool)
    }

    fn string_type(&mut self) -> TypeId {
        self.intern(Type::String)
    }

    fn policy_decision_type(&mut self) -> TypeId {
        self.intern(Type::PolicyDecision)
    }

    // ── Expression type checking ─────────────────────────────────────

    /// Check an expression and return its type.
    pub fn check_expr(&mut self, expr: &Expr) -> TypeId {
        match &expr.kind {
            // ── Literals ─────────────────────────────────────────
            ExprKind::IntLiteral(_) => self.int_type(),
            ExprKind::FloatLiteral(_) => self.float_type(),
            ExprKind::StringLiteral(_) => self.string_type(),
            ExprKind::BoolLiteral(_) => self.bool_type(),

            // ── Identifiers and paths ────────────────────────────
            ExprKind::Identifier(name) => self.check_identifier(name, expr.span),
            ExprKind::Path(path) => self.check_path(path),

            // ── Operators ────────────────────────────────────────
            ExprKind::Binary { op, left, right } => {
                self.check_binary(*op, left, right, expr.span)
            }
            ExprKind::Unary { op, operand } => {
                self.check_unary(*op, operand, expr.span)
            }

            // ── Function call ────────────────────────────────────
            ExprKind::Call { callee, args } => {
                self.check_call(callee, args, expr.span)
            }

            // ── Field access ─────────────────────────────────────
            ExprKind::FieldAccess { object, field } => {
                self.check_field_access(object, field, expr.span)
            }

            // ── Method call ──────────────────────────────────────
            ExprKind::MethodCall { object, method, args } => {
                // For now, treat like field access + call. Full method
                // resolution comes with impl blocks in Pass 2.
                let _obj_ty = self.check_expr(object);
                for arg in args {
                    self.check_expr(arg);
                }
                // Without impl resolution, we can't know the return type.
                self.error(
                    format!("method `{}` — method resolution not yet implemented", method.name),
                    expr.span,
                );
                self.error_type()
            }

            // ── Index ────────────────────────────────────────────
            ExprKind::Index { object, index } => {
                self.check_expr(object);
                self.check_expr(index);
                // Full index resolution requires operator overloading.
                self.error_type()
            }

            // ── Control flow ─────────────────────────────────────
            ExprKind::If { condition, then_branch, else_branch } => {
                self.check_if(condition, then_branch, else_branch.as_deref(), expr.span)
            }
            ExprKind::Match { subject, arms } => {
                self.check_match(subject, arms, expr.span)
            }
            ExprKind::Block(block) => self.check_block(block),
            ExprKind::For { binding, iterator, body } => {
                self.check_for(binding, iterator, body, expr.span)
            }
            ExprKind::While { condition, body } => {
                self.check_while(condition, body, expr.span)
            }
            ExprKind::Return(value) => {
                if let Some(val) = value {
                    self.check_expr(val);
                }
                // Return diverges; its type is compatible with anything.
                // For now, return Unit as the expression type.
                self.unit_type()
            }
            ExprKind::Break(value) => {
                if let Some(val) = value {
                    self.check_expr(val);
                }
                self.unit_type()
            }
            ExprKind::Continue => self.unit_type(),

            // ── Let binding ──────────────────────────────────────
            ExprKind::Let { is_mut, name, ty, value } => {
                self.check_let(*is_mut, name, ty.as_ref(), value, expr.span)
            }

            // ── Assignment ───────────────────────────────────────
            ExprKind::Assign { target, value } => {
                let target_ty = self.check_expr(target);
                let value_ty = self.check_expr(value);
                if !self.types_compatible(target_ty, value_ty) {
                    self.error(
                        format!(
                            "cannot assign `{}` to variable of type `{}`",
                            self.type_name(value_ty),
                            self.type_name(target_ty),
                        ),
                        expr.span,
                    );
                }
                self.unit_type()
            }
            ExprKind::CompoundAssign { op, target, value } => {
                let target_ty = self.check_expr(target);
                let value_ty = self.check_expr(value);
                // Compound assignment requires compatible numeric types.
                self.check_binary_op_types(*op, target_ty, value_ty, expr.span);
                self.unit_type()
            }

            // ── Governance decisions ─────────────────────────────
            ExprKind::Permit
            | ExprKind::Deny
            | ExprKind::Escalate
            | ExprKind::Quarantine => self.policy_decision_type(),

            // ── Governance expressions ───────────────────────────
            ExprKind::Attest(inner) => {
                self.check_expr(inner);
                self.bool_type()
            }
            ExprKind::Audit(body) => self.check_expr(body),
            ExprKind::SecureZone { body, .. } => self.check_expr(body),
            ExprKind::UnsafeFfi(body) => self.check_expr(body),

            // ── Effects ──────────────────────────────────────────
            ExprKind::Perform { effect: _, args } => {
                for arg in args {
                    self.check_expr(arg);
                }
                // Full effect resolution comes later.
                self.unit_type()
            }
            ExprKind::Handle { expr: inner, handlers } => {
                self.check_expr(inner);
                for handler in handlers {
                    self.check_expr(&handler.body);
                }
                self.unit_type()
            }

            // ── Tuple ────────────────────────────────────────────
            ExprKind::Tuple(elements) => {
                if elements.is_empty() {
                    return self.unit_type();
                }
                let elem_types: Vec<TypeId> = elements
                    .iter()
                    .map(|e| self.check_expr(e))
                    .collect();
                self.intern(Type::Tuple(elem_types))
            }

            // ── Struct literal, range — deferred to Pass 2 ──────
            ExprKind::StructLiteral { .. } => self.error_type(),
            ExprKind::Range { start, end, .. } => {
                if let Some(s) = start { self.check_expr(s); }
                if let Some(e) = end { self.check_expr(e); }
                self.error_type()
            }
        }
    }

    // ── Identifier lookup ────────────────────────────────────────────

    fn check_identifier(&mut self, name: &str, span: Span) -> TypeId {
        match self.ctx.lookup(name) {
            Some(Symbol::Variable { ty, .. }) => *ty,
            Some(Symbol::Function { return_type, params, effects, .. }) => {
                // An identifier referencing a function yields the function type.
                let params = params.clone();
                let return_type = *return_type;
                let effects = effects.clone();
                self.intern(Type::Function { params, return_type, effects })
            }
            Some(Symbol::Type { .. }) => {
                // Using a type name as an expression (e.g., enum constructor).
                // This is valid in some contexts; return Error for now.
                self.error_type()
            }
            Some(Symbol::Capability { ty, .. }) | Some(Symbol::Effect { ty, .. }) => *ty,
            None => {
                self.error(format!("undefined variable `{name}`"), span);
                self.error_type()
            }
        }
    }

    fn check_path(&mut self, path: &Path) -> TypeId {
        // For now, treat multi-segment paths as identifier lookup on the last segment.
        let name = &path.segments.last().expect("empty path").name;
        self.check_identifier(name, path.span)
    }

    // ── Binary operators ─────────────────────────────────────────────

    fn check_binary(
        &mut self,
        op: BinOp,
        left: &Expr,
        right: &Expr,
        span: Span,
    ) -> TypeId {
        let left_ty = self.check_expr(left);
        let right_ty = self.check_expr(right);
        self.check_binary_op_types(op, left_ty, right_ty, span)
    }

    fn check_binary_op_types(
        &mut self,
        op: BinOp,
        left_ty: TypeId,
        right_ty: TypeId,
        span: Span,
    ) -> TypeId {
        let lt = self.get(left_ty);
        let rt = self.get(right_ty);

        // Error propagation.
        if lt.is_error() || rt.is_error() {
            return self.error_type();
        }

        match op {
            // Arithmetic: both operands must be numeric, same type.
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                if !self.is_numeric(left_ty) {
                    self.error(
                        format!(
                            "arithmetic operator requires numeric type, found `{}`",
                            self.type_name(left_ty)
                        ),
                        span,
                    );
                    return self.error_type();
                }
                if !self.types_compatible(left_ty, right_ty) {
                    self.error(
                        format!(
                            "mismatched types in arithmetic: `{}` and `{}`",
                            self.type_name(left_ty),
                            self.type_name(right_ty),
                        ),
                        span,
                    );
                    return self.error_type();
                }
                left_ty
            }

            // Comparison: operands must be same type, result is Bool.
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
                if !self.types_compatible(left_ty, right_ty) {
                    self.error(
                        format!(
                            "cannot compare `{}` with `{}`",
                            self.type_name(left_ty),
                            self.type_name(right_ty),
                        ),
                        span,
                    );
                    return self.error_type();
                }
                self.bool_type()
            }

            // Logical: both must be Bool, result is Bool.
            BinOp::And | BinOp::Or => {
                let bool_ty = self.bool_type();
                if !self.types_compatible(left_ty, bool_ty) {
                    self.error(
                        format!(
                            "logical operator requires Bool, found `{}`",
                            self.type_name(left_ty)
                        ),
                        span,
                    );
                }
                if !self.types_compatible(right_ty, bool_ty) {
                    self.error(
                        format!(
                            "logical operator requires Bool, found `{}`",
                            self.type_name(right_ty)
                        ),
                        span,
                    );
                }
                bool_ty
            }

            // Bitwise: both must be Int, result is Int.
            BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Shl | BinOp::Shr => {
                let int_ty = self.int_type();
                if !self.types_compatible(left_ty, int_ty) {
                    self.error(
                        format!(
                            "bitwise operator requires Int, found `{}`",
                            self.type_name(left_ty)
                        ),
                        span,
                    );
                }
                if !self.types_compatible(right_ty, int_ty) {
                    self.error(
                        format!(
                            "bitwise operator requires Int, found `{}`",
                            self.type_name(right_ty)
                        ),
                        span,
                    );
                }
                int_ty
            }
        }
    }

    fn is_numeric(&self, ty: TypeId) -> bool {
        matches!(self.get(ty), Type::Int | Type::Float)
    }

    // ── Unary operators ──────────────────────────────────────────────

    fn check_unary(&mut self, op: UnaryOp, operand: &Expr, span: Span) -> TypeId {
        let operand_ty = self.check_expr(operand);

        if self.get(operand_ty).is_error() {
            return self.error_type();
        }

        match op {
            UnaryOp::Neg => {
                if !self.is_numeric(operand_ty) {
                    self.error(
                        format!(
                            "unary `-` requires numeric type, found `{}`",
                            self.type_name(operand_ty)
                        ),
                        span,
                    );
                    self.error_type()
                } else {
                    operand_ty
                }
            }
            UnaryOp::Not => {
                let bool_ty = self.bool_type();
                if !self.types_compatible(operand_ty, bool_ty) {
                    self.error(
                        format!(
                            "unary `!` requires Bool, found `{}`",
                            self.type_name(operand_ty)
                        ),
                        span,
                    );
                    self.error_type()
                } else {
                    bool_ty
                }
            }
            UnaryOp::BitNot => {
                let int_ty = self.int_type();
                if !self.types_compatible(operand_ty, int_ty) {
                    self.error(
                        format!(
                            "unary `~` requires Int, found `{}`",
                            self.type_name(operand_ty)
                        ),
                        span,
                    );
                    self.error_type()
                } else {
                    int_ty
                }
            }
        }
    }

    // ── Function calls ───────────────────────────────────────────────

    fn check_call(&mut self, callee: &Expr, args: &[Expr], span: Span) -> TypeId {
        let callee_ty = self.check_expr(callee);
        let arg_types: Vec<TypeId> = args.iter().map(|a| self.check_expr(a)).collect();

        let callee_resolved = self.get(callee_ty).clone();

        match callee_resolved {
            Type::Function { params, return_type, .. } => {
                if params.len() != arg_types.len() {
                    self.error(
                        format!(
                            "function expects {} argument(s), found {}",
                            params.len(),
                            arg_types.len(),
                        ),
                        span,
                    );
                    return self.error_type();
                }
                for (i, (param_ty, arg_ty)) in
                    params.iter().zip(arg_types.iter()).enumerate()
                {
                    if !self.types_compatible(*param_ty, *arg_ty) {
                        self.error(
                            format!(
                                "argument {} has type `{}`, expected `{}`",
                                i + 1,
                                self.type_name(*arg_ty),
                                self.type_name(*param_ty),
                            ),
                            args[i].span,
                        );
                    }
                }
                return_type
            }
            Type::Error => self.error_type(),
            _ => {
                self.error(
                    format!(
                        "cannot call `{}` — it is not a function",
                        self.type_name(callee_ty)
                    ),
                    span,
                );
                self.error_type()
            }
        }
    }

    // ── Field access ─────────────────────────────────────────────────

    fn check_field_access(
        &mut self,
        object: &Expr,
        field: &Ident,
        span: Span,
    ) -> TypeId {
        let obj_ty = self.check_expr(object);

        if self.get(obj_ty).is_error() {
            return self.error_type();
        }

        // Field access resolution requires struct definitions (Pass 2).
        // For now, report that field access can't be resolved yet on
        // non-error types, but don't block on it.
        self.error(
            format!(
                "field `{}` on type `{}` — struct field resolution not yet implemented",
                field.name,
                self.type_name(obj_ty),
            ),
            span,
        );
        self.error_type()
    }

    // ── If expression ────────────────────────────────────────────────

    fn check_if(
        &mut self,
        condition: &Expr,
        then_branch: &Expr,
        else_branch: Option<&Expr>,
        span: Span,
    ) -> TypeId {
        let cond_ty = self.check_expr(condition);
        let bool_ty = self.bool_type();
        if !self.types_compatible(cond_ty, bool_ty) {
            self.error(
                format!(
                    "`if` condition must be Bool, found `{}`",
                    self.type_name(cond_ty)
                ),
                condition.span,
            );
        }

        let then_ty = self.check_expr(then_branch);

        if let Some(else_expr) = else_branch {
            let else_ty = self.check_expr(else_expr);
            if !self.types_compatible(then_ty, else_ty) {
                self.error(
                    format!(
                        "`if` and `else` branches have incompatible types: `{}` and `{}`",
                        self.type_name(then_ty),
                        self.type_name(else_ty),
                    ),
                    span,
                );
                self.error_type()
            } else {
                then_ty
            }
        } else {
            // `if` without `else` has type Unit.
            self.unit_type()
        }
    }

    // ── Match expression ─────────────────────────────────────────────

    fn check_match(
        &mut self,
        subject: &Expr,
        arms: &[MatchArm],
        span: Span,
    ) -> TypeId {
        let _subject_ty = self.check_expr(subject);

        if arms.is_empty() {
            self.error("match expression must have at least one arm", span);
            return self.error_type();
        }

        // Check all arm bodies and verify they have compatible types.
        let first_ty = self.check_expr(&arms[0].body);

        for arm in &arms[1..] {
            let arm_ty = self.check_expr(&arm.body);
            if !self.types_compatible(first_ty, arm_ty) {
                self.error(
                    format!(
                        "match arms have incompatible types: `{}` and `{}`",
                        self.type_name(first_ty),
                        self.type_name(arm_ty),
                    ),
                    arm.span,
                );
            }
        }

        // Check guards are Bool.
        for arm in arms {
            if let Some(guard) = &arm.guard {
                let guard_ty = self.check_expr(guard);
                let bool_ty = self.bool_type();
                if !self.types_compatible(guard_ty, bool_ty) {
                    self.error(
                        format!(
                            "match guard must be Bool, found `{}`",
                            self.type_name(guard_ty)
                        ),
                        guard.span,
                    );
                }
            }
        }

        first_ty
    }

    // ── Block expression ─────────────────────────────────────────────

    pub fn check_block(&mut self, block: &Block) -> TypeId {
        self.ctx.enter_scope();

        let mut result_ty = self.unit_type();

        for stmt in &block.stmts {
            result_ty = self.check_stmt(stmt);
        }

        self.ctx.exit_scope();
        result_ty
    }

    // ── Statement checking ───────────────────────────────────────────

    fn check_stmt(&mut self, stmt: &Stmt) -> TypeId {
        match &stmt.kind {
            StmtKind::Expr(expr) => {
                self.check_expr(expr);
                self.unit_type()
            }
            StmtKind::TailExpr(expr) => self.check_expr(expr),
            StmtKind::Item(_) => {
                // Items inside blocks handled in Pass 2.
                self.unit_type()
            }
        }
    }

    // ── Let binding ──────────────────────────────────────────────────

    fn check_let(
        &mut self,
        is_mut: bool,
        name: &Ident,
        ty_annotation: Option<&TypeExpr>,
        value: &Expr,
        span: Span,
    ) -> TypeId {
        let value_ty = self.check_expr(value);

        let declared_ty = if let Some(ty_expr) = ty_annotation {
            let resolved = self.ctx.resolve_type_expr(ty_expr);
            if !self.types_compatible(resolved, value_ty) {
                self.error(
                    format!(
                        "type annotation `{}` does not match initializer type `{}`",
                        self.type_name(resolved),
                        self.type_name(value_ty),
                    ),
                    span,
                );
            }
            resolved
        } else {
            value_ty
        };

        // Register the binding in the current scope.
        let define_result = self.ctx.define(
            &name.name,
            Symbol::Variable {
                ty: declared_ty,
                is_mut,
                span: name.span,
            },
            name.span,
        );

        if let Err(e) = define_result {
            self.error(e.message, e.span);
        }

        self.unit_type()
    }

    // ── For loop ─────────────────────────────────────────────────────

    fn check_for(
        &mut self,
        binding: &Ident,
        iterator: &Expr,
        body: &Expr,
        _span: Span,
    ) -> TypeId {
        let _iter_ty = self.check_expr(iterator);

        // Enter scope for the loop body and register the binding.
        // Without iterator trait resolution, the binding type is unknown.
        self.ctx.enter_scope();
        let binding_ty = self.error_type();
        let _ = self.ctx.define(
            &binding.name,
            Symbol::Variable {
                ty: binding_ty,
                is_mut: false,
                span: binding.span,
            },
            binding.span,
        );

        self.check_expr(body);
        self.ctx.exit_scope();

        self.unit_type()
    }

    // ── While loop ───────────────────────────────────────────────────

    fn check_while(
        &mut self,
        condition: &Expr,
        body: &Expr,
        _span: Span,
    ) -> TypeId {
        let cond_ty = self.check_expr(condition);
        let bool_ty = self.bool_type();
        if !self.types_compatible(cond_ty, bool_ty) {
            self.error(
                format!(
                    "`while` condition must be Bool, found `{}`",
                    self.type_name(cond_ty)
                ),
                condition.span,
            );
        }
        self.check_expr(body);
        self.unit_type()
    }
}
