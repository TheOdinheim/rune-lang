// ═══════════════════════════════════════════════════════════════════════
// AST-to-IR Lowering
//
// Walks the type-checked AST and produces IR:
// - Expressions become sequences of IR instructions
// - let bindings → Alloca + Store
// - Variable references → Load
// - if/else → CondBranch with two basic blocks and a merge block
// - Function calls → Call instructions
// - Governance decisions → GovernanceDecision instructions
// - Policy rules → functions returning PolicyDecision
// - Audit instrumentation → AuditMark at function entry/exit and decisions
// ═══════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};

use crate::ast::nodes::*;
use crate::ir::nodes::*;

/// AST-to-IR lowering engine. Builds an IrModule from a SourceFile.
pub struct Lowerer {
    /// Next value ID for SSA values.
    next_value: u32,
    /// Next block ID.
    next_block: u32,
    /// Current function's blocks being built.
    blocks: Vec<BasicBlock>,
    /// Instructions for the current block.
    current_insts: Vec<Instruction>,
    /// Current block ID.
    current_block: BlockId,
    /// Variable name → pointer Value (for let bindings).
    variables: HashMap<String, (Value, IrType)>,
    /// Value → IrType mapping for tracking types of emitted values.
    value_types: HashMap<Value, IrType>,
    /// Function name → return type (pre-collected for forward references).
    function_return_types: HashMap<String, IrType>,
    /// The name of the current function/rule being lowered (for audit marks).
    current_fn_name: String,
    /// Whether the current block has been terminated.
    block_terminated: bool,
    /// Stack of loop contexts for break/continue. Each entry is (header_block, exit_block, result_ptr).
    loop_stack: Vec<LoopContext>,
    /// Set of extern function names for FFI audit instrumentation.
    extern_functions: HashSet<String>,
}

/// Context for a loop being lowered, enabling break/continue.
struct LoopContext {
    /// Block ID of the loop header (continue target).
    header: BlockId,
    /// Block ID of the loop exit (break target).
    exit: BlockId,
    /// Variable pointer for the loop result value (if any).
    result_ptr: Option<Value>,
}

impl Lowerer {
    pub fn new() -> Self {
        Self {
            next_value: 0,
            next_block: 0,
            blocks: Vec::new(),
            current_insts: Vec::new(),
            current_block: BlockId(0),
            variables: HashMap::new(),
            value_types: HashMap::new(),
            function_return_types: HashMap::new(),
            current_fn_name: String::new(),
            block_terminated: false,
            loop_stack: Vec::new(),
            extern_functions: HashSet::new(),
        }
    }

    /// Lower a complete source file into an IR module.
    pub fn lower_source_file(&mut self, file: &SourceFile) -> IrModule {
        // Pre-collect function return types for forward references in calls.
        for item in &file.items {
            match &item.kind {
                ItemKind::Function(decl) => {
                    let ret_ty = self.return_type_from_sig(&decl.signature);
                    self.function_return_types
                        .insert(decl.signature.name.name.clone(), ret_ty);
                }
                ItemKind::Policy(decl) => {
                    for rule in &decl.rules {
                        let fn_name = format!("{}::{}", decl.name.name, rule.name.name);
                        self.function_return_types
                            .insert(fn_name, IrType::PolicyDecision);
                    }
                }
                ItemKind::Module(decl) => {
                    if let Some(items) = &decl.items {
                        self.pre_collect_module_return_types(items, &decl.name.name);
                    }
                }
                ItemKind::Extern(block) => {
                    for ext_fn in &block.functions {
                        let ret_ty = ext_fn.return_type.as_ref()
                            .map(|t| self.map_type_expr(t))
                            .unwrap_or(IrType::Unit);
                        self.function_return_types.insert(ext_fn.name.name.clone(), ret_ty);
                        self.extern_functions.insert(ext_fn.name.name.clone());
                    }
                }
                _ => {}
            }
        }

        let mut functions = Vec::new();

        for item in &file.items {
            match &item.kind {
                ItemKind::Function(decl) => {
                    if let Some(func) = self.lower_function(decl) {
                        functions.push(func);
                    }
                }
                ItemKind::Policy(decl) => {
                    for rule in &decl.rules {
                        let func = self.lower_policy_rule(rule, &decl.name.name);
                        functions.push(func);
                    }
                }
                ItemKind::Const(decl) => {
                    if let Some(func) = self.lower_const(decl) {
                        functions.push(func);
                    }
                }
                ItemKind::Module(decl) => {
                    if let Some(items) = &decl.items {
                        self.lower_module_items(items, &decl.name.name, &mut functions);
                    }
                    // File-based modules: items were inlined during type checking
                    // into the AST as inline modules. If items is None, there's
                    // nothing to lower (module file loading is handled by the
                    // type checker which produces Symbol::Module).
                }
                // Types, capabilities, effects, traits, impls, use —
                // no runtime code to lower (declarations only).
                _ => {}
            }
        }

        IrModule { functions }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn fresh_value(&mut self) -> Value {
        let v = Value(self.next_value);
        self.next_value += 1;
        v
    }

    fn fresh_block(&mut self) -> BlockId {
        let b = BlockId(self.next_block);
        self.next_block += 1;
        b
    }

    fn emit(&mut self, kind: InstKind, ty: IrType) -> Value {
        let result = self.fresh_value();
        self.value_types.insert(result, ty.clone());
        self.current_insts.push(Instruction {
            result,
            ty,
            kind,
        });
        result
    }

    fn terminate(&mut self, terminator: Terminator) {
        if self.block_terminated {
            return;
        }
        let block = BasicBlock {
            id: self.current_block,
            instructions: std::mem::take(&mut self.current_insts),
            terminator,
        };
        self.blocks.push(block);
        self.block_terminated = true;
    }

    fn start_block(&mut self, id: BlockId) {
        self.current_block = id;
        self.current_insts.clear();
        self.block_terminated = false;
    }

    /// Reset state for a new function.
    fn reset_for_function(&mut self) {
        self.next_value = 0;
        self.next_block = 0;
        self.blocks.clear();
        self.current_insts.clear();
        self.variables.clear();
        self.value_types.clear();
        self.block_terminated = false;
        self.loop_stack.clear();
    }

    // ── Type mapping ─────────────────────────────────────────────────────

    fn map_type_expr(&self, ty: &TypeExpr) -> IrType {
        match &ty.kind {
            TypeExprKind::Unit => IrType::Unit,
            TypeExprKind::Named { path, .. } => {
                let name = path.segments.last()
                    .map(|s| s.name.as_str())
                    .unwrap_or("");
                match name {
                    "Int" | "i32" | "i64" => IrType::Int,
                    "Float" | "f32" | "f64" => IrType::Float,
                    "Bool" | "bool" => IrType::Bool,
                    "String" => IrType::String,
                    "PolicyDecision" => IrType::PolicyDecision,
                    _ => IrType::Ptr, // user-defined types → arena pointer
                }
            }
            TypeExprKind::Tuple(_) => IrType::Ptr,
            TypeExprKind::Function { .. } => IrType::FuncRef,
            TypeExprKind::Reference { .. } => IrType::Ptr,
            TypeExprKind::Refined { base, .. } => self.map_type_expr(base),
        }
    }

    fn return_type_from_sig(&self, sig: &FnSignature) -> IrType {
        sig.return_type.as_ref()
            .map(|t| self.map_type_expr(t))
            .unwrap_or(IrType::Unit)
    }

    // ── Module lowering ────────────────────────────────────────────────

    /// Pre-collect function return types from items inside a module (for forward references).
    fn pre_collect_module_return_types(&mut self, items: &[Item], prefix: &str) {
        for item in items {
            match &item.kind {
                ItemKind::Function(decl) => {
                    let ret_ty = self.return_type_from_sig(&decl.signature);
                    let mangled = format!("{}::{}", prefix, decl.signature.name.name);
                    self.function_return_types.insert(mangled, ret_ty);
                }
                ItemKind::Policy(decl) => {
                    for rule in &decl.rules {
                        let fn_name = format!("{}::{}::{}", prefix, decl.name.name, rule.name.name);
                        self.function_return_types.insert(fn_name, IrType::PolicyDecision);
                    }
                }
                ItemKind::Module(decl) => {
                    if let Some(inner_items) = &decl.items {
                        let nested_prefix = format!("{}::{}", prefix, decl.name.name);
                        self.pre_collect_module_return_types(inner_items, &nested_prefix);
                    }
                }
                _ => {}
            }
        }
    }

    /// Lower all items inside a module, name-mangling functions with the module prefix.
    fn lower_module_items(&mut self, items: &[Item], prefix: &str, functions: &mut Vec<IrFunction>) {
        for item in items {
            match &item.kind {
                ItemKind::Function(decl) => {
                    if let Some(mut func) = self.lower_function(decl) {
                        func.name = format!("{}::{}", prefix, func.name);
                        functions.push(func);
                    }
                }
                ItemKind::Policy(decl) => {
                    for rule in &decl.rules {
                        let mut func = self.lower_policy_rule(rule, &decl.name.name);
                        func.name = format!("{}::{}", prefix, func.name);
                        functions.push(func);
                    }
                }
                ItemKind::Const(decl) => {
                    if let Some(mut func) = self.lower_const(decl) {
                        func.name = format!("{}::{}", prefix, func.name);
                        functions.push(func);
                    }
                }
                ItemKind::Module(decl) => {
                    if let Some(inner_items) = &decl.items {
                        let nested_prefix = format!("{}::{}", prefix, decl.name.name);
                        self.lower_module_items(inner_items, &nested_prefix, functions);
                    }
                }
                _ => {}
            }
        }
    }

    // ── Function lowering ────────────────────────────────────────────────

    fn lower_function(&mut self, decl: &FnDecl) -> Option<IrFunction> {
        let body = decl.body.as_ref()?;
        let sig = &decl.signature;
        self.reset_for_function();
        self.current_fn_name = sig.name.name.clone();

        let ret_ty = self.return_type_from_sig(sig);

        // Create parameters as Values.
        let mut params = Vec::new();
        for param in &sig.params {
            let value = self.fresh_value();
            let ty = self.map_type_expr(&param.ty);
            params.push(IrParam {
                name: param.name.name.clone(),
                ty: ty.clone(),
                value,
            });
        }

        // Start entry block.
        let entry = self.fresh_block();
        self.start_block(entry);

        // Insert audit mark at function entry.
        self.emit(
            InstKind::AuditMark(AuditKind::FunctionEntry {
                name: sig.name.name.clone(),
            }),
            IrType::Unit,
        );

        // Register parameters as variables (alloca + store).
        for p in &params {
            let ptr = self.emit(
                InstKind::Alloca { name: p.name.clone(), ty: p.ty.clone() },
                IrType::Ptr,
            );
            self.emit(
                InstKind::Store { ptr, value: p.value },
                IrType::Unit,
            );
            self.variables.insert(p.name.clone(), (ptr, p.ty.clone()));
        }

        // Lower the body expression.
        let result = self.lower_expr(body);

        // Insert audit mark at function exit.
        if !self.block_terminated {
            self.emit(
                InstKind::AuditMark(AuditKind::FunctionExit {
                    name: sig.name.name.clone(),
                }),
                IrType::Unit,
            );
            self.terminate(Terminator::Return(result));
        }

        Some(IrFunction {
            name: sig.name.name.clone(),
            params,
            return_type: ret_ty,
            blocks: std::mem::take(&mut self.blocks),
        })
    }

    // ── Policy rule lowering ─────────────────────────────────────────────

    fn lower_policy_rule(&mut self, rule: &RuleDef, policy_name: &str) -> IrFunction {
        self.reset_for_function();
        let fn_name = format!("{}::{}", policy_name, rule.name.name);
        self.current_fn_name = fn_name.clone();

        // Create parameters.
        let mut params = Vec::new();
        for param in &rule.params {
            let value = self.fresh_value();
            let ty = self.map_type_expr(&param.ty);
            params.push(IrParam {
                name: param.name.name.clone(),
                ty: ty.clone(),
                value,
            });
        }

        // Start entry block.
        let entry = self.fresh_block();
        self.start_block(entry);

        // Audit mark: function entry.
        self.emit(
            InstKind::AuditMark(AuditKind::FunctionEntry { name: fn_name.clone() }),
            IrType::Unit,
        );

        // Register parameters.
        for p in &params {
            let ptr = self.emit(
                InstKind::Alloca { name: p.name.clone(), ty: p.ty.clone() },
                IrType::Ptr,
            );
            self.emit(
                InstKind::Store { ptr, value: p.value },
                IrType::Unit,
            );
            self.variables.insert(p.name.clone(), (ptr, p.ty.clone()));
        }

        // Lower when-clause (if present): if guard is false, return deny.
        if let Some(when_expr) = &rule.when_clause {
            let cond = self.lower_expr(when_expr);
            let body_block = self.fresh_block();
            let deny_block = self.fresh_block();
            self.terminate(Terminator::CondBranch {
                cond,
                true_block: body_block,
                false_block: deny_block,
            });

            // Deny block: when clause failed → deny.
            self.start_block(deny_block);
            let deny_val = self.emit(
                InstKind::GovernanceDecision(DecisionKind::Deny),
                IrType::PolicyDecision,
            );
            self.emit(
                InstKind::AuditMark(AuditKind::Decision { rule_name: fn_name.clone() }),
                IrType::Unit,
            );
            self.emit(
                InstKind::AuditMark(AuditKind::FunctionExit { name: fn_name.clone() }),
                IrType::Unit,
            );
            self.terminate(Terminator::Return(deny_val));

            // Continue with body block.
            self.start_block(body_block);
        }

        // Lower rule body.
        let result = self.lower_expr(&rule.body);

        // Audit mark: decision point and function exit.
        if !self.block_terminated {
            self.emit(
                InstKind::AuditMark(AuditKind::Decision { rule_name: fn_name.clone() }),
                IrType::Unit,
            );
            self.emit(
                InstKind::AuditMark(AuditKind::FunctionExit { name: fn_name.clone() }),
                IrType::Unit,
            );
            self.terminate(Terminator::Return(result));
        }

        IrFunction {
            name: fn_name,
            params,
            return_type: IrType::PolicyDecision,
            blocks: std::mem::take(&mut self.blocks),
        }
    }

    // ── Const lowering ───────────────────────────────────────────────────

    fn lower_const(&mut self, decl: &ConstDecl) -> Option<IrFunction> {
        self.reset_for_function();
        self.current_fn_name = format!("const::{}", decl.name.name);

        let ret_ty = self.map_type_expr(&decl.ty);
        let entry = self.fresh_block();
        self.start_block(entry);

        let result = self.lower_expr(&decl.value);
        self.terminate(Terminator::Return(result));

        Some(IrFunction {
            name: format!("const::{}", decl.name.name),
            params: Vec::new(),
            return_type: ret_ty,
            blocks: std::mem::take(&mut self.blocks),
        })
    }

    // ── Expression lowering ──────────────────────────────────────────────

    fn lower_expr(&mut self, expr: &Expr) -> Value {
        match &expr.kind {
            // ── Literals ────────────────────────────────────────────
            ExprKind::IntLiteral(s) => {
                let val: i64 = s.replace('_', "").parse().unwrap_or(0);
                self.emit(InstKind::IntConst(val), IrType::Int)
            }
            ExprKind::FloatLiteral(s) => {
                let val: f64 = s.replace('_', "").parse().unwrap_or(0.0);
                self.emit(InstKind::FloatConst(val), IrType::Float)
            }
            ExprKind::StringLiteral(s) => {
                self.emit(InstKind::StringConst(s.clone()), IrType::String)
            }
            ExprKind::BoolLiteral(b) => {
                self.emit(InstKind::BoolConst(*b), IrType::Bool)
            }

            // ── Identifiers ─────────────────────────────────────────
            ExprKind::Identifier(name) => {
                if let Some((ptr, ty)) = self.variables.get(name).cloned() {
                    self.emit(InstKind::Load { ptr, ty }, self.variables[name].1.clone())
                } else {
                    // Unknown variable — emit unit as fallback.
                    self.emit(InstKind::UnitConst, IrType::Unit)
                }
            }
            ExprKind::Path(path) => {
                let name = path.segments.last()
                    .map(|s| s.name.as_str())
                    .unwrap_or("");
                if let Some((ptr, ty)) = self.variables.get(name).cloned() {
                    self.emit(InstKind::Load { ptr, ty }, self.variables[name].1.clone())
                } else {
                    self.emit(InstKind::UnitConst, IrType::Unit)
                }
            }

            // ── Binary operators ────────────────────────────────────
            ExprKind::Binary { op, left, right } => {
                let l = self.lower_expr(left);
                let r = self.lower_expr(right);
                self.lower_binop(*op, l, r)
            }

            // ── Unary operators ─────────────────────────────────────
            ExprKind::Unary { op, operand } => {
                let v = self.lower_expr(operand);
                self.lower_unaryop(*op, v)
            }

            // ── Function call ───────────────────────────────────────
            ExprKind::Call { callee, args } => {
                let arg_vals: Vec<Value> = args.iter()
                    .map(|a| self.lower_expr(a))
                    .collect();
                let func_name = match &callee.kind {
                    ExprKind::Identifier(name) => name.clone(),
                    ExprKind::Path(path) => path.segments.last()
                        .map(|s| s.name.clone())
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    _ => "<indirect>".to_string(),
                };
                let ret_ty = self.function_return_types.get(&func_name)
                    .cloned()
                    .unwrap_or(IrType::Unit);

                let is_extern = self.extern_functions.contains(&func_name);
                if is_extern {
                    self.emit(
                        InstKind::AuditMark(AuditKind::FfiCallStart {
                            function_name: func_name.clone(),
                        }),
                        IrType::Unit,
                    );
                }

                let result = self.emit(
                    InstKind::Call { func: func_name.clone(), args: arg_vals, ret_ty: ret_ty.clone() },
                    ret_ty.clone(),
                );

                if is_extern {
                    self.emit(
                        InstKind::AuditMark(AuditKind::FfiCallEnd {
                            function_name: func_name,
                        }),
                        IrType::Unit,
                    );
                }

                result
            }

            // ── If/else ─────────────────────────────────────────────
            ExprKind::If { condition, then_branch, else_branch } => {
                self.lower_if(condition, then_branch, else_branch.as_deref())
            }

            // ── Block ───────────────────────────────────────────────
            ExprKind::Block(block) => self.lower_block(block),

            // ── Let binding ─────────────────────────────────────────
            ExprKind::Let { name, value, .. } => {
                let val = self.lower_expr(value);
                let ty = self.value_types.get(&val).cloned()
                    .unwrap_or_else(|| self.infer_value_type(value));
                let ptr = self.emit(
                    InstKind::Alloca { name: name.name.clone(), ty: ty.clone() },
                    IrType::Ptr,
                );
                self.emit(
                    InstKind::Store { ptr, value: val },
                    IrType::Unit,
                );
                self.variables.insert(name.name.clone(), (ptr, ty));
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Assignment ──────────────────────────────────────────
            ExprKind::Assign { target, value } => {
                let val = self.lower_expr(value);
                if let ExprKind::Identifier(name) = &target.kind {
                    if let Some((ptr, _ty)) = self.variables.get(name).cloned() {
                        self.emit(InstKind::Store { ptr, value: val }, IrType::Unit);
                    }
                }
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Governance decisions ────────────────────────────────
            ExprKind::Permit => {
                let v = self.emit(
                    InstKind::GovernanceDecision(DecisionKind::Permit),
                    IrType::PolicyDecision,
                );
                self.emit(
                    InstKind::AuditMark(AuditKind::Decision {
                        rule_name: self.current_fn_name.clone(),
                    }),
                    IrType::Unit,
                );
                v
            }
            ExprKind::Deny => {
                let v = self.emit(
                    InstKind::GovernanceDecision(DecisionKind::Deny),
                    IrType::PolicyDecision,
                );
                self.emit(
                    InstKind::AuditMark(AuditKind::Decision {
                        rule_name: self.current_fn_name.clone(),
                    }),
                    IrType::Unit,
                );
                v
            }
            ExprKind::Escalate => {
                let v = self.emit(
                    InstKind::GovernanceDecision(DecisionKind::Escalate),
                    IrType::PolicyDecision,
                );
                self.emit(
                    InstKind::AuditMark(AuditKind::Decision {
                        rule_name: self.current_fn_name.clone(),
                    }),
                    IrType::Unit,
                );
                v
            }
            ExprKind::Quarantine => {
                let v = self.emit(
                    InstKind::GovernanceDecision(DecisionKind::Quarantine),
                    IrType::PolicyDecision,
                );
                self.emit(
                    InstKind::AuditMark(AuditKind::Decision {
                        rule_name: self.current_fn_name.clone(),
                    }),
                    IrType::Unit,
                );
                v
            }

            // ── Governance blocks (audit, secure_zone, unsafe_ffi) ──
            ExprKind::Audit(body) | ExprKind::UnsafeFfi(body) => {
                self.lower_expr(body)
            }
            ExprKind::SecureZone { body, .. } => {
                self.lower_expr(body)
            }

            // ── Attest ──────────────────────────────────────────────
            ExprKind::Attest(inner) => {
                self.lower_expr(inner);
                self.emit(InstKind::BoolConst(true), IrType::Bool)
            }

            // ── Return ──────────────────────────────────────────────
            ExprKind::Return(value) => {
                let val = if let Some(v) = value {
                    self.lower_expr(v)
                } else {
                    self.emit(InstKind::UnitConst, IrType::Unit)
                };
                self.emit(
                    InstKind::AuditMark(AuditKind::FunctionExit {
                        name: self.current_fn_name.clone(),
                    }),
                    IrType::Unit,
                );
                self.terminate(Terminator::Return(val));
                val
            }

            // ── Match expression ────────────────────────────────────
            ExprKind::Match { subject, arms } => {
                self.lower_match(subject, arms)
            }

            // ── While loop ─────────────────────────────────────────
            ExprKind::While { condition, body } => {
                self.lower_while(condition, body)
            }

            // ── For loop (integer ranges only) ─────────────────────
            ExprKind::For { binding, iterator, body } => {
                self.lower_for(binding, iterator, body)
            }

            // ── Break ──────────────────────────────────────────────
            ExprKind::Break(value) => {
                if let Some(ctx) = self.loop_stack.last() {
                    let exit = ctx.exit;
                    let result_ptr = ctx.result_ptr;
                    if let Some(val_expr) = value {
                        let val = self.lower_expr(val_expr);
                        if let Some(ptr) = result_ptr {
                            self.emit(InstKind::Store { ptr, value: val }, IrType::Unit);
                        }
                    }
                    if !self.block_terminated {
                        self.terminate(Terminator::Branch(exit));
                    }
                }
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Continue ───────────────────────────────────────────
            ExprKind::Continue => {
                if let Some(ctx) = self.loop_stack.last() {
                    let header = ctx.header;
                    if !self.block_terminated {
                        self.terminate(Terminator::Branch(header));
                    }
                }
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Compound assignment ────────────────────────────────
            ExprKind::CompoundAssign { op, target, value } => {
                let rhs = self.lower_expr(value);
                if let ExprKind::Identifier(name) = &target.kind {
                    if let Some((ptr, ty)) = self.variables.get(name).cloned() {
                        let current = self.emit(InstKind::Load { ptr, ty: ty.clone() }, ty);
                        let result = self.lower_binop(*op, current, rhs);
                        self.emit(InstKind::Store { ptr, value: result }, IrType::Unit);
                    }
                }
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Range (used inside for, not standalone) ────────────
            ExprKind::Range { .. } => {
                // Range is handled as part of for-loop lowering.
                self.emit(InstKind::UnitConst, IrType::Unit)
            }

            // ── Require expression — predicates verified at compile time,
            // lowers to Bool true (the check passed statically).
            ExprKind::Require { target, .. } => {
                self.lower_expr(target);
                self.emit(InstKind::BoolConst(true), IrType::Bool)
            }

            // ── Constructs deferred for later layers ───────────────
            ExprKind::FieldAccess { .. }
            | ExprKind::MethodCall { .. }
            | ExprKind::Index { .. }
            | ExprKind::Perform { .. }
            | ExprKind::Handle { .. }
            | ExprKind::StructLiteral { .. }
            | ExprKind::Tuple(_) => {
                self.emit(InstKind::UnitConst, IrType::Unit)
            }
        }
    }

    // ── Binary operator lowering ─────────────────────────────────────────

    fn lower_binop(&mut self, op: BinOp, l: Value, r: Value) -> Value {
        match op {
            BinOp::Add => self.emit(InstKind::Add(l, r), IrType::Int),
            BinOp::Sub => self.emit(InstKind::Sub(l, r), IrType::Int),
            BinOp::Mul => self.emit(InstKind::Mul(l, r), IrType::Int),
            BinOp::Div => self.emit(InstKind::Div(l, r), IrType::Int),
            BinOp::Mod => self.emit(InstKind::Mod(l, r), IrType::Int),
            BinOp::Eq => self.emit(InstKind::Eq(l, r), IrType::Bool),
            BinOp::Ne => self.emit(InstKind::Ne(l, r), IrType::Bool),
            BinOp::Lt => self.emit(InstKind::Lt(l, r), IrType::Bool),
            BinOp::Gt => self.emit(InstKind::Gt(l, r), IrType::Bool),
            BinOp::Le => self.emit(InstKind::Le(l, r), IrType::Bool),
            BinOp::Ge => self.emit(InstKind::Ge(l, r), IrType::Bool),
            BinOp::And => self.emit(InstKind::And(l, r), IrType::Bool),
            BinOp::Or => self.emit(InstKind::Or(l, r), IrType::Bool),
            BinOp::BitAnd => self.emit(InstKind::BitAnd(l, r), IrType::Int),
            BinOp::BitOr => self.emit(InstKind::BitOr(l, r), IrType::Int),
            BinOp::BitXor => self.emit(InstKind::BitXor(l, r), IrType::Int),
            BinOp::Shl => self.emit(InstKind::Shl(l, r), IrType::Int),
            BinOp::Shr => self.emit(InstKind::Shr(l, r), IrType::Int),
        }
    }

    // ── Unary operator lowering ──────────────────────────────────────────

    fn lower_unaryop(&mut self, op: UnaryOp, v: Value) -> Value {
        match op {
            UnaryOp::Neg => self.emit(InstKind::Neg(v), IrType::Int),
            UnaryOp::Not => self.emit(InstKind::Not(v), IrType::Bool),
            UnaryOp::BitNot => self.emit(InstKind::BitNot(v), IrType::Int),
        }
    }

    // ── If/else lowering ─────────────────────────────────────────────────

    fn lower_if(
        &mut self,
        condition: &Expr,
        then_branch: &Expr,
        else_branch: Option<&Expr>,
    ) -> Value {
        let cond = self.lower_expr(condition);

        let then_block = self.fresh_block();
        let else_block = self.fresh_block();
        let merge_block = self.fresh_block();

        self.terminate(Terminator::CondBranch {
            cond,
            true_block: then_block,
            false_block: else_block,
        });

        // Then block.
        self.start_block(then_block);
        let then_val = self.lower_expr(then_branch);
        let then_terminated = self.block_terminated;
        if !self.block_terminated {
            self.terminate(Terminator::Branch(merge_block));
        }

        // Else block.
        self.start_block(else_block);
        let else_val = if let Some(else_expr) = else_branch {
            self.lower_expr(else_expr)
        } else {
            self.emit(InstKind::UnitConst, IrType::Unit)
        };
        let else_terminated = self.block_terminated;
        if !self.block_terminated {
            self.terminate(Terminator::Branch(merge_block));
        }

        // Merge block.
        self.start_block(merge_block);

        if then_terminated || else_terminated {
            // One or both branches have early returns — no Select needed.
            // The merge block is only reachable from the non-returning branch.
            self.emit(InstKind::UnitConst, IrType::Unit)
        } else {
            // Both branches flow to merge — select the result.
            let select_ty = self.value_types.get(&then_val).cloned()
                .unwrap_or(IrType::Unit);
            self.emit(
                InstKind::Select { cond, true_val: then_val, false_val: else_val },
                select_ty,
            )
        }
    }

    // ── Match lowering ────────────────────────────────────────────────────

    fn lower_match(&mut self, subject: &Expr, arms: &[MatchArm]) -> Value {
        let subject_val = self.lower_expr(subject);
        let merge_block = self.fresh_block();

        // Infer result type from the first arm's body.
        let result_ty = self.infer_match_result_type(arms);
        let result_ptr = self.emit(
            InstKind::Alloca { name: "__match_result".to_string(), ty: result_ty.clone() },
            IrType::Ptr,
        );

        for (i, arm) in arms.iter().enumerate() {
            let is_last = i == arms.len() - 1;
            let body_block = self.fresh_block();
            let next_block = if is_last { merge_block } else { self.fresh_block() };

            match &arm.pattern.kind {
                PatternKind::Wildcard | PatternKind::Binding { .. } => {
                    // Wildcard or binding always matches. If binding, store subject.
                    if let PatternKind::Binding { name, .. } = &arm.pattern.kind {
                        let bind_ptr = self.emit(
                            InstKind::Alloca { name: name.name.clone(), ty: IrType::Int },
                            IrType::Ptr,
                        );
                        self.emit(InstKind::Store { ptr: bind_ptr, value: subject_val }, IrType::Unit);
                        self.variables.insert(name.name.clone(), (bind_ptr, IrType::Int));
                    }
                    if !self.block_terminated {
                        self.terminate(Terminator::Branch(body_block));
                    }
                }
                PatternKind::Literal(lit_expr) => {
                    let lit_val = self.lower_expr(lit_expr);
                    let cmp = self.emit(InstKind::Eq(subject_val, lit_val), IrType::Bool);

                    // Check guard if present.
                    let cond = if let Some(guard) = &arm.guard {
                        let guard_val = self.lower_expr(guard);
                        self.emit(InstKind::And(cmp, guard_val), IrType::Bool)
                    } else {
                        cmp
                    };

                    self.terminate(Terminator::CondBranch {
                        cond,
                        true_block: body_block,
                        false_block: next_block,
                    });
                }
                _ => {
                    // For unsupported patterns (constructor, struct, tuple, path),
                    // fall through to next arm.
                    self.terminate(Terminator::Branch(next_block));
                }
            }

            // Body block.
            self.start_block(body_block);
            let body_val = self.lower_expr(&arm.body);
            if !self.block_terminated {
                self.emit(InstKind::Store { ptr: result_ptr, value: body_val }, IrType::Unit);
                self.terminate(Terminator::Branch(merge_block));
            }

            // Start next arm's test block (if not last).
            if !is_last {
                self.start_block(next_block);
            }
        }

        // If there are no arms, jump to merge.
        if arms.is_empty() && !self.block_terminated {
            self.terminate(Terminator::Branch(merge_block));
        }

        // Merge block: load the result.
        self.start_block(merge_block);
        self.emit(InstKind::Load { ptr: result_ptr, ty: result_ty.clone() }, result_ty)
    }

    // ── While loop lowering ─────────────────────────────────────────────

    fn lower_while(&mut self, condition: &Expr, body: &Expr) -> Value {
        let header_block = self.fresh_block();
        let body_block = self.fresh_block();
        let exit_block = self.fresh_block();

        // Jump to header.
        if !self.block_terminated {
            self.terminate(Terminator::Branch(header_block));
        }

        // Header: evaluate condition.
        self.start_block(header_block);
        let cond = self.lower_expr(condition);
        self.terminate(Terminator::CondBranch {
            cond,
            true_block: body_block,
            false_block: exit_block,
        });

        // Body.
        self.start_block(body_block);
        self.loop_stack.push(LoopContext {
            header: header_block,
            exit: exit_block,
            result_ptr: None,
        });
        self.lower_expr(body);
        self.loop_stack.pop();

        if !self.block_terminated {
            self.terminate(Terminator::Branch(header_block));
        }

        // Exit block.
        self.start_block(exit_block);
        self.emit(InstKind::UnitConst, IrType::Unit)
    }

    // ── For loop lowering (integer ranges) ──────────────────────────────

    fn lower_for(&mut self, binding: &Ident, iterator: &Expr, body: &Expr) -> Value {
        // Extract range bounds: for i in start..end { body }
        let (start_expr, end_expr) = match &iterator.kind {
            ExprKind::Range { start: Some(s), end: Some(e), .. } => (s.as_ref(), e.as_ref()),
            _ => {
                // Non-range iterators not yet supported.
                return self.emit(InstKind::UnitConst, IrType::Unit);
            }
        };

        let start_val = self.lower_expr(start_expr);
        let end_val = self.lower_expr(end_expr);

        // Allocate loop variable.
        let var_ptr = self.emit(
            InstKind::Alloca { name: binding.name.clone(), ty: IrType::Int },
            IrType::Ptr,
        );
        self.emit(InstKind::Store { ptr: var_ptr, value: start_val }, IrType::Unit);
        self.variables.insert(binding.name.clone(), (var_ptr, IrType::Int));

        let header_block = self.fresh_block();
        let body_block = self.fresh_block();
        let exit_block = self.fresh_block();

        // Jump to header.
        self.terminate(Terminator::Branch(header_block));

        // Header: check i < end.
        self.start_block(header_block);
        let current = self.emit(InstKind::Load { ptr: var_ptr, ty: IrType::Int }, IrType::Int);
        let cond = self.emit(InstKind::Lt(current, end_val), IrType::Bool);
        self.terminate(Terminator::CondBranch {
            cond,
            true_block: body_block,
            false_block: exit_block,
        });

        // Body.
        self.start_block(body_block);
        self.loop_stack.push(LoopContext {
            header: header_block,
            exit: exit_block,
            result_ptr: None,
        });
        self.lower_expr(body);
        self.loop_stack.pop();

        // Increment loop variable: i = i + 1.
        if !self.block_terminated {
            let current = self.emit(InstKind::Load { ptr: var_ptr, ty: IrType::Int }, IrType::Int);
            let one = self.emit(InstKind::IntConst(1), IrType::Int);
            let next = self.emit(InstKind::Add(current, one), IrType::Int);
            self.emit(InstKind::Store { ptr: var_ptr, value: next }, IrType::Unit);
            self.terminate(Terminator::Branch(header_block));
        }

        // Exit block.
        self.start_block(exit_block);
        self.emit(InstKind::UnitConst, IrType::Unit)
    }

    // ── Block lowering ───────────────────────────────────────────────────

    fn lower_block(&mut self, block: &Block) -> Value {
        let mut result = self.emit(InstKind::UnitConst, IrType::Unit);
        for stmt in &block.stmts {
            result = self.lower_stmt(stmt);
        }
        result
    }

    fn lower_stmt(&mut self, stmt: &Stmt) -> Value {
        match &stmt.kind {
            StmtKind::Expr(expr) => {
                self.lower_expr(expr);
                self.emit(InstKind::UnitConst, IrType::Unit)
            }
            StmtKind::TailExpr(expr) => self.lower_expr(expr),
            StmtKind::Item(_) => {
                self.emit(InstKind::UnitConst, IrType::Unit)
            }
        }
    }

    // ── Type inference helper ────────────────────────────────────────────

    /// Infer the result type of a match expression from its arms' bodies.
    fn infer_match_result_type(&self, arms: &[MatchArm]) -> IrType {
        for arm in arms {
            let ty = self.infer_value_type(&arm.body);
            if ty != IrType::Unit {
                return ty;
            }
        }
        IrType::Int
    }

    fn infer_value_type(&self, expr: &Expr) -> IrType {
        match &expr.kind {
            ExprKind::IntLiteral(_) => IrType::Int,
            ExprKind::FloatLiteral(_) => IrType::Float,
            ExprKind::StringLiteral(_) => IrType::String,
            ExprKind::BoolLiteral(_) => IrType::Bool,
            ExprKind::Permit | ExprKind::Deny
            | ExprKind::Escalate | ExprKind::Quarantine => IrType::PolicyDecision,
            ExprKind::Identifier(name) => {
                self.variables.get(name.as_str())
                    .map(|(_, ty)| ty.clone())
                    .unwrap_or(IrType::Unit)
            }
            _ => IrType::Unit,
        }
    }
}

impl Default for Lowerer {
    fn default() -> Self {
        Self::new()
    }
}
