use crate::ast::nodes::*;
use crate::lexer::token::Span;
use crate::types::context::{TypeContext, TypeError};
use crate::types::scope::Symbol;
use crate::types::ty::{Type, TypeId};

// ═══════════════════════════════════════════════════════════════════════
// Effect context — tracks which effects are allowed in the current scope
// ═══════════════════════════════════════════════════════════════════════

/// A single frame in the effect context stack.
///
/// Each function body pushes a frame with its declared effects.
/// `unsafe_ffi` blocks push a frame that suppresses all effect checking.
#[derive(Debug, Clone)]
struct EffectFrame {
    /// The name of the function/context (for error messages).
    context_name: String,
    /// Effects declared by this function. Empty = pure.
    allowed_effects: Vec<String>,
    /// True inside `unsafe_ffi { ... }` blocks — suppresses all checking.
    suppress_checking: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Capability context — tracks which capabilities are available in scope
// ═══════════════════════════════════════════════════════════════════════

/// A single frame in the capability context stack.
///
/// Each function body pushes a frame with capabilities from its parameters.
/// `secure_zone` blocks push a frame with the listed capabilities.
#[derive(Debug, Clone)]
struct CapabilityFrame {
    /// The name of the function/context (for error messages).
    context_name: String,
    /// Capabilities available in this scope.
    available_capabilities: Vec<String>,
}

/// Type checker for RUNE expressions and statements.
///
/// Walks AST nodes, assigns types to expressions, and reports type errors.
/// Errors are collected rather than aborting so that multiple issues can
/// be reported in a single pass.
///
/// Effect tracking (M2 Layer 3): every function call is checked against
/// the current function's declared effects. Undeclared effects are type
/// errors — this is the "Security Baked In" pillar enforcement.
///
/// Capability checking (M2 Layer 3b): every function call that requires
/// capabilities is checked against the current scope's available capabilities.
/// Missing capabilities are type errors — this is the "Zero Trust Throughout"
/// pillar enforcement.
pub struct TypeChecker<'ctx> {
    pub ctx: &'ctx mut TypeContext,
    /// Stack of effect frames. The top frame is the current function context.
    effect_stack: Vec<EffectFrame>,
    /// Stack of capability frames. Tracks available capabilities per scope.
    capability_stack: Vec<CapabilityFrame>,
}

impl<'ctx> TypeChecker<'ctx> {
    pub fn new(ctx: &'ctx mut TypeContext) -> Self {
        Self {
            ctx,
            effect_stack: Vec::new(),
            capability_stack: Vec::new(),
        }
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

    // ── Effect context management ─────────────────────────────────────

    /// Enter a function body with the given declared effects.
    pub fn enter_function_effects(&mut self, name: &str, effects: Vec<String>) {
        self.effect_stack.push(EffectFrame {
            context_name: name.to_string(),
            allowed_effects: effects,
            suppress_checking: false,
        });
    }

    /// Exit the current function's effect context.
    pub fn exit_function_effects(&mut self) {
        self.effect_stack.pop();
    }

    /// Push a suppressed frame (for `unsafe_ffi` blocks).
    fn enter_unsafe_ffi(&mut self) {
        self.effect_stack.push(EffectFrame {
            context_name: "<unsafe_ffi>".to_string(),
            allowed_effects: Vec::new(),
            suppress_checking: true,
        });
    }

    /// Push a frame that adds the `audit` effect to current allowed set.
    fn enter_audit_block(&mut self) {
        let mut allowed = self.current_allowed_effects();
        if !allowed.contains(&"audit".to_string()) {
            allowed.push("audit".to_string());
        }
        self.effect_stack.push(EffectFrame {
            context_name: "<audit>".to_string(),
            allowed_effects: allowed,
            suppress_checking: false,
        });
    }

    fn exit_effect_frame(&mut self) {
        self.effect_stack.pop();
    }

    /// Get the current allowed effects (from top of stack).
    fn current_allowed_effects(&self) -> Vec<String> {
        if let Some(frame) = self.effect_stack.last() {
            frame.allowed_effects.clone()
        } else {
            // No effect context = no constraints (top-level, not in a function).
            Vec::new()
        }
    }

    /// Whether effect checking is currently suppressed (inside unsafe_ffi).
    fn effects_suppressed(&self) -> bool {
        self.effect_stack.iter().rev().any(|f| f.suppress_checking)
    }

    /// Whether we are currently inside a function's effect context.
    fn in_effect_context(&self) -> bool {
        !self.effect_stack.is_empty()
    }

    /// Get the name of the current function context (for error messages).
    fn current_context_name(&self) -> String {
        for frame in self.effect_stack.iter().rev() {
            if !frame.context_name.starts_with('<') {
                return frame.context_name.clone();
            }
        }
        "<unknown>".to_string()
    }

    /// Check that calling a function with the given effects is allowed
    /// in the current context.
    fn check_callee_effects(
        &mut self,
        callee_name: &str,
        callee_effects: &[String],
        span: Span,
    ) {
        if !self.in_effect_context() || self.effects_suppressed() || callee_effects.is_empty() {
            return;
        }

        let allowed = self.current_allowed_effects();
        let ctx_name = self.current_context_name();

        // Check if the current context is pure (no declared effects).
        let is_pure = allowed.is_empty();

        if is_pure {
            self.error(
                format!(
                    "pure function `{}` cannot call `{}` which performs effects [{}]",
                    ctx_name,
                    callee_name,
                    callee_effects.join(", "),
                ),
                span,
            );
            return;
        }

        // Report each missing effect individually.
        for effect in callee_effects {
            if !allowed.contains(effect) {
                self.error(
                    format!(
                        "function `{}` performs effect `{}`, but the current function `{}` does not declare this effect",
                        callee_name, effect, ctx_name,
                    ),
                    span,
                );
            }
        }
    }

    /// Check that a `perform` expression's effect is allowed.
    fn check_perform_effect(&mut self, effect_name: &str, span: Span) {
        if !self.in_effect_context() || self.effects_suppressed() {
            return;
        }

        let allowed = self.current_allowed_effects();
        let ctx_name = self.current_context_name();

        if allowed.is_empty() {
            self.error(
                format!(
                    "pure function `{}` cannot perform effect `{}`",
                    ctx_name, effect_name,
                ),
                span,
            );
            return;
        }

        if !allowed.contains(&effect_name.to_string()) {
            self.error(
                format!(
                    "effect `{}` is not declared by function `{}`",
                    effect_name, ctx_name,
                ),
                span,
            );
        }
    }

    // ── Capability context management ──────────────────────────────────

    /// Enter a function body with the given available capabilities
    /// (derived from capability-typed parameters).
    pub fn enter_function_capabilities(&mut self, name: &str, capabilities: Vec<String>) {
        self.capability_stack.push(CapabilityFrame {
            context_name: name.to_string(),
            available_capabilities: capabilities,
        });
    }

    /// Exit the current function's capability context.
    pub fn exit_function_capabilities(&mut self) {
        self.capability_stack.pop();
    }

    /// Push a capability frame for a `secure_zone` block.
    fn enter_secure_zone(&mut self, capabilities: Vec<String>) {
        // Secure zone inherits parent capabilities and adds its own.
        let mut all = self.current_available_capabilities();
        for cap in capabilities {
            if !all.contains(&cap) {
                all.push(cap);
            }
        }
        self.capability_stack.push(CapabilityFrame {
            context_name: "<secure_zone>".to_string(),
            available_capabilities: all,
        });
    }

    fn exit_capability_frame(&mut self) {
        self.capability_stack.pop();
    }

    /// Get the current available capabilities (from top of stack).
    fn current_available_capabilities(&self) -> Vec<String> {
        if let Some(frame) = self.capability_stack.last() {
            frame.available_capabilities.clone()
        } else {
            Vec::new()
        }
    }

    /// Whether we are currently inside a capability-tracked context.
    fn in_capability_context(&self) -> bool {
        !self.capability_stack.is_empty()
    }

    /// Get the name of the current function context for capability errors.
    fn current_capability_context_name(&self) -> String {
        for frame in self.capability_stack.iter().rev() {
            if !frame.context_name.starts_with('<') {
                return frame.context_name.clone();
            }
        }
        "<unknown>".to_string()
    }

    /// Check that calling a function requiring specific capabilities is
    /// allowed in the current context.
    fn check_callee_capabilities(
        &mut self,
        callee_name: &str,
        required_capabilities: &[String],
        span: Span,
    ) {
        if !self.in_capability_context() || required_capabilities.is_empty() {
            return;
        }

        let available = self.current_available_capabilities();
        let ctx_name = self.current_capability_context_name();

        for cap in required_capabilities {
            if !available.contains(cap) {
                self.error(
                    format!(
                        "function `{}` requires capability `{}`, but `{}` does not hold this capability",
                        callee_name, cap, ctx_name,
                    ),
                    span,
                );
            }
        }
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
            ExprKind::Audit(body) => {
                // Audit blocks implicitly carry the `audit` effect.
                self.enter_audit_block();
                let ty = self.check_expr(body);
                self.exit_effect_frame();
                ty
            }
            ExprKind::SecureZone { capabilities, body } => {
                // secure_zone provides listed capabilities to the body.
                let cap_names: Vec<String> = capabilities
                    .iter()
                    .filter_map(|p| p.segments.last().map(|s| s.name.clone()))
                    .collect();
                self.enter_secure_zone(cap_names);
                let ty = self.check_expr(body);
                self.exit_capability_frame();
                ty
            }
            ExprKind::UnsafeFfi(body) => {
                // unsafe_ffi suppresses effect checking inside the block.
                self.enter_unsafe_ffi();
                let ty = self.check_expr(body);
                self.exit_effect_frame();
                ty
            }

            // ── Effects ──────────────────────────────────────────
            ExprKind::Perform { effect, args } => {
                for arg in args {
                    self.check_expr(arg);
                }
                // Extract the effect name from the path (e.g., "Network" from Network::fetch).
                let effect_name = if let Some(first) = effect.segments.first() {
                    first.name.clone()
                } else {
                    "<unknown>".to_string()
                };
                self.check_perform_effect(&effect_name, expr.span);
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
        // Extract callee name for effect/capability error messages.
        let callee_name = match &callee.kind {
            ExprKind::Identifier(name) => Some(name.clone()),
            ExprKind::Path(path) => path.segments.last().map(|s| s.name.clone()),
            _ => None,
        };

        // Look up required_capabilities from the symbol table before type-checking
        // the callee expression (which yields a Type::Function without capability info).
        let required_caps: Vec<String> = if let Some(ref name) = callee_name {
            if let Some(Symbol::Function { required_capabilities, .. }) = self.ctx.lookup(name) {
                required_capabilities.clone()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let callee_ty = self.check_expr(callee);
        let arg_types: Vec<TypeId> = args.iter().map(|a| self.check_expr(a)).collect();

        let callee_resolved = self.get(callee_ty).clone();

        match callee_resolved {
            Type::Function { params, return_type, ref effects } => {
                // ── Effect checking (M2 Layer 3) ────────────────
                if !effects.is_empty() {
                    let name = callee_name.as_deref().unwrap_or("<anonymous>");
                    self.check_callee_effects(name, effects, span);
                }

                // ── Capability checking (M2 Layer 3b) ───────────
                if !required_caps.is_empty() {
                    let name = callee_name.as_deref().unwrap_or("<anonymous>");
                    self.check_callee_capabilities(name, &required_caps, span);
                }

                // ── Arity and type checking ─────────────────────
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
