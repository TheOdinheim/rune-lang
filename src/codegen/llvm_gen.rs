// ═══════════════════════════════════════════════════════════════════════
// LLVM Code Generator
//
// Translates RUNE IR to LLVM IR via inkwell, then compiles to native
// object code. This is the native compilation backend, complementing the
// WASM backend for deployment scenarios requiring bare-metal performance.
//
// Pillar: Security Baked In — governance decisions are first-class i32
// constants matching the C ABI (0=Permit, 1=Deny, 2=Escalate, 3=Quarantine).
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::path::Path;

use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::module::Module;
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetMachine,
};
use inkwell::module::Linkage;
use inkwell::types::{BasicMetadataTypeEnum, BasicType, BasicTypeEnum};
use inkwell::values::{BasicMetadataValueEnum, BasicValueEnum, FunctionValue, PointerValue};
use inkwell::IntPredicate;
use inkwell::OptimizationLevel;

use crate::ir::nodes::*;

// ── LlvmCodegen ──────────────────────────────────────────────────────

pub struct LlvmCodegen<'ctx> {
    pub context: &'ctx Context,
    pub module: Module<'ctx>,
    pub builder: Builder<'ctx>,
    function_map: HashMap<String, FunctionValue<'ctx>>,
    value_map: HashMap<u32, BasicValueEnum<'ctx>>,
    variable_map: HashMap<String, PointerValue<'ctx>>,
    block_map: HashMap<u32, inkwell::basic_block::BasicBlock<'ctx>>,
}

impl<'ctx> LlvmCodegen<'ctx> {
    pub fn new(context: &'ctx Context, module_name: &str) -> Self {
        let module = context.create_module(module_name);
        let builder = context.create_builder();
        Self {
            context,
            module,
            builder,
            function_map: HashMap::new(),
            value_map: HashMap::new(),
            variable_map: HashMap::new(),
            block_map: HashMap::new(),
        }
    }

    // ── Type mapping ─────────────────────────────────────────────

    fn ir_type_to_llvm(&self, ty: &IrType) -> BasicTypeEnum<'ctx> {
        match ty {
            IrType::Int => self.context.i64_type().into(),
            IrType::Float => self.context.f64_type().into(),
            IrType::Bool => self.context.bool_type().into(),
            IrType::String => self.context.ptr_type(inkwell::AddressSpace::default()).into(),
            IrType::Unit => self.context.i8_type().into(),
            IrType::PolicyDecision => self.context.i32_type().into(),
            IrType::Ptr => self.context.ptr_type(inkwell::AddressSpace::default()).into(),
            IrType::FuncRef => self.context.i32_type().into(),
        }
    }

    fn ir_type_to_metadata(&self, ty: &IrType) -> BasicMetadataTypeEnum<'ctx> {
        self.ir_type_to_llvm(ty).into()
    }

    fn is_void_type(ty: &IrType) -> bool {
        matches!(ty, IrType::Unit)
    }

    fn is_float_type(ty: &IrType) -> bool {
        matches!(ty, IrType::Float)
    }

    // ── Module compilation ───────────────────────────────────────

    pub fn compile_module(&mut self, ir_module: &IrModule) {
        // First pass: declare all functions (so calls can reference them).
        for func in &ir_module.functions {
            self.declare_function(func);
        }

        // Second pass: compile function bodies.
        for func in &ir_module.functions {
            self.compile_function(func);
        }

        // Third pass: generate evaluate entry point if policy rules exist.
        let policy_rules: Vec<&IrFunction> = ir_module
            .functions
            .iter()
            .filter(|f| f.return_type == IrType::PolicyDecision && f.name.contains("::"))
            .collect();

        if !policy_rules.is_empty() {
            self.compile_evaluate_wrapper(&policy_rules);
        }
    }

    // ── Evaluate entry point ─────────────────────────────────────

    fn compile_evaluate_wrapper(&mut self, policy_rules: &[&IrFunction]) {
        let i64_ty = self.context.i64_type();
        let i32_ty = self.context.i32_type();

        // evaluate(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> i32
        let fn_type = i32_ty.fn_type(
            &[i64_ty.into(), i64_ty.into(), i64_ty.into(), i64_ty.into()],
            false,
        );
        let eval_fn = self.module.add_function("evaluate", fn_type, Some(Linkage::External));
        self.function_map.insert("evaluate".to_string(), eval_fn);

        let entry_bb = self.context.append_basic_block(eval_fn, "entry");
        self.builder.position_at_end(entry_bb);

        // For each policy rule: call it, check if result != Permit (0),
        // if so return the result immediately (first-non-permit-wins).
        for rule in policy_rules {
            let callee_name = rule.name.replace("::", "__");
            let callee = match self.module.get_function(&callee_name) {
                Some(f) => f,
                None => continue,
            };

            // Build args: pass evaluate's params to the rule, matching by position.
            let rule_param_count = rule.params.len().min(4);
            let mut args: Vec<BasicMetadataValueEnum<'ctx>> = Vec::new();
            for i in 0..rule_param_count {
                let eval_param = eval_fn.get_nth_param(i as u32).unwrap();
                // Rule params may be i64 (Int) — evaluate params are always i64.
                args.push(eval_param.into());
            }

            let call_result = self.builder.build_call(callee, &args, "rule_result").unwrap();
            let decision = call_result.try_as_basic_value().left().unwrap().into_int_value();

            // if decision != 0 (Permit), return it
            let is_not_permit = self.builder.build_int_compare(
                IntPredicate::NE,
                decision,
                i32_ty.const_zero(),
                "is_not_permit",
            ).unwrap();

            let then_bb = self.context.append_basic_block(eval_fn, "return_decision");
            let cont_bb = self.context.append_basic_block(eval_fn, "next_rule");

            self.builder.build_conditional_branch(is_not_permit, then_bb, cont_bb).unwrap();

            self.builder.position_at_end(then_bb);
            self.builder.build_return(Some(&decision)).unwrap();

            self.builder.position_at_end(cont_bb);
        }

        // All rules returned Permit — return Permit (0).
        self.builder.build_return(Some(&i32_ty.const_zero())).unwrap();
    }

    pub fn verify(&self) -> Result<(), String> {
        self.module
            .verify()
            .map_err(|e| e.to_string())
    }

    // ── Function declaration ─────────────────────────────────────

    fn declare_function(&mut self, func: &IrFunction) {
        let param_types: Vec<BasicMetadataTypeEnum<'ctx>> = func
            .params
            .iter()
            .map(|p| self.ir_type_to_metadata(&p.ty))
            .collect();

        let fn_type = if Self::is_void_type(&func.return_type) {
            self.context.void_type().fn_type(&param_types, false)
        } else {
            let ret_ty = self.ir_type_to_llvm(&func.return_type);
            ret_ty.fn_type(&param_types, false)
        };

        let sanitized_name = func.name.replace("::", "__");
        let llvm_func = self.module.add_function(&sanitized_name, fn_type, None);
        self.function_map.insert(func.name.clone(), llvm_func);
    }

    // ── Function compilation ─────────────────────────────────────

    fn compile_function(&mut self, func: &IrFunction) {
        let llvm_func = *self.function_map.get(&func.name).unwrap();

        // Reset per-function state.
        self.value_map.clear();
        self.variable_map.clear();
        self.block_map.clear();

        // Create all basic blocks first (so branches can reference them).
        for block in &func.blocks {
            let bb = self.context.append_basic_block(
                llvm_func,
                &format!("bb{}", block.id.0),
            );
            self.block_map.insert(block.id.0, bb);
        }

        // Compile entry block: store params into allocas.
        if let Some(entry_block) = func.blocks.first() {
            let entry_bb = self.block_map[&entry_block.id.0];
            self.builder.position_at_end(entry_bb);

            // Allocate and store parameters.
            for (i, param) in func.params.iter().enumerate() {
                let llvm_param = llvm_func.get_nth_param(i as u32).unwrap();
                let alloca = self.builder.build_alloca(
                    self.ir_type_to_llvm(&param.ty),
                    &param.name,
                ).unwrap();
                self.builder.build_store(alloca, llvm_param).unwrap();
                self.variable_map.insert(param.name.clone(), alloca);
                // Map the param Value so instructions can reference it.
                self.value_map.insert(param.value.0, llvm_param);
            }
        }

        // Compile each block.
        for block in &func.blocks {
            self.compile_block(block, llvm_func, func);
        }
    }

    // ── Block compilation ────────────────────────────────────────

    fn compile_block(
        &mut self,
        block: &BasicBlock,
        llvm_func: FunctionValue<'ctx>,
        ir_func: &IrFunction,
    ) {
        let bb = self.block_map[&block.id.0];
        self.builder.position_at_end(bb);

        // Skip re-emitting param allocas for the entry block — already done.
        let is_entry = block.id.0 == ir_func.blocks[0].id.0;

        for inst in &block.instructions {
            if let Some(val) = self.compile_instruction(inst, ir_func, is_entry) {
                self.value_map.insert(inst.result.0, val);
            }
        }

        self.compile_terminator(&block.terminator, ir_func);
    }

    // ── Instruction compilation ──────────────────────────────────

    fn compile_instruction(
        &mut self,
        inst: &Instruction,
        ir_func: &IrFunction,
        _is_entry: bool,
    ) -> Option<BasicValueEnum<'ctx>> {
        match &inst.kind {
            // ── Constants ────────────────────────────────────────
            InstKind::IntConst(n) => {
                Some(self.context.i64_type().const_int(*n as u64, true).into())
            }
            InstKind::FloatConst(f) => {
                Some(self.context.f64_type().const_float(*f).into())
            }
            InstKind::BoolConst(b) => {
                Some(self.context.bool_type().const_int(*b as u64, false).into())
            }
            InstKind::StringConst(s) => {
                let global = self.builder.build_global_string_ptr(s, "str").unwrap();
                Some(global.as_pointer_value().into())
            }
            InstKind::UnitConst => {
                Some(self.context.i8_type().const_zero().into())
            }

            // ── Arithmetic ───────────────────────────────────────
            InstKind::Add(l, r) => {
                let lv = self.get_value(*l);
                let rv = self.get_value(*r);
                if Self::is_float_type(&inst.ty) {
                    Some(self.builder.build_float_add(lv.into_float_value(), rv.into_float_value(), "fadd").unwrap().into())
                } else {
                    Some(self.builder.build_int_add(lv.into_int_value(), rv.into_int_value(), "add").unwrap().into())
                }
            }
            InstKind::Sub(l, r) => {
                let lv = self.get_value(*l);
                let rv = self.get_value(*r);
                if Self::is_float_type(&inst.ty) {
                    Some(self.builder.build_float_sub(lv.into_float_value(), rv.into_float_value(), "fsub").unwrap().into())
                } else {
                    Some(self.builder.build_int_sub(lv.into_int_value(), rv.into_int_value(), "sub").unwrap().into())
                }
            }
            InstKind::Mul(l, r) => {
                let lv = self.get_value(*l);
                let rv = self.get_value(*r);
                if Self::is_float_type(&inst.ty) {
                    Some(self.builder.build_float_mul(lv.into_float_value(), rv.into_float_value(), "fmul").unwrap().into())
                } else {
                    Some(self.builder.build_int_mul(lv.into_int_value(), rv.into_int_value(), "mul").unwrap().into())
                }
            }
            InstKind::Div(l, r) => {
                let lv = self.get_value(*l);
                let rv = self.get_value(*r);
                if Self::is_float_type(&inst.ty) {
                    Some(self.builder.build_float_div(lv.into_float_value(), rv.into_float_value(), "fdiv").unwrap().into())
                } else {
                    Some(self.builder.build_int_signed_div(lv.into_int_value(), rv.into_int_value(), "sdiv").unwrap().into())
                }
            }
            InstKind::Mod(l, r) => {
                let lv = self.get_value(*l);
                let rv = self.get_value(*r);
                Some(self.builder.build_int_signed_rem(lv.into_int_value(), rv.into_int_value(), "srem").unwrap().into())
            }
            InstKind::Neg(v) => {
                let val = self.get_value(*v);
                if Self::is_float_type(&inst.ty) {
                    Some(self.builder.build_float_neg(val.into_float_value(), "fneg").unwrap().into())
                } else {
                    Some(self.builder.build_int_neg(val.into_int_value(), "neg").unwrap().into())
                }
            }

            // ── Comparison ───────────────────────────────────────
            InstKind::Eq(l, r) => self.build_int_cmp(IntPredicate::EQ, *l, *r, "eq"),
            InstKind::Ne(l, r) => self.build_int_cmp(IntPredicate::NE, *l, *r, "ne"),
            InstKind::Lt(l, r) => self.build_int_cmp(IntPredicate::SLT, *l, *r, "lt"),
            InstKind::Gt(l, r) => self.build_int_cmp(IntPredicate::SGT, *l, *r, "gt"),
            InstKind::Le(l, r) => self.build_int_cmp(IntPredicate::SLE, *l, *r, "le"),
            InstKind::Ge(l, r) => self.build_int_cmp(IntPredicate::SGE, *l, *r, "ge"),

            // ── Logical ──────────────────────────────────────────
            InstKind::And(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_and(lv, rv, "and").unwrap().into())
            }
            InstKind::Or(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_or(lv, rv, "or").unwrap().into())
            }
            InstKind::Not(v) => {
                let val = self.get_value(*v).into_int_value();
                Some(self.builder.build_not(val, "not").unwrap().into())
            }

            // ── Bitwise ──────────────────────────────────────────
            InstKind::BitAnd(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_and(lv, rv, "bitand").unwrap().into())
            }
            InstKind::BitOr(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_or(lv, rv, "bitor").unwrap().into())
            }
            InstKind::BitXor(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_xor(lv, rv, "bitxor").unwrap().into())
            }
            InstKind::Shl(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_left_shift(lv, rv, "shl").unwrap().into())
            }
            InstKind::Shr(l, r) => {
                let lv = self.get_value(*l).into_int_value();
                let rv = self.get_value(*r).into_int_value();
                Some(self.builder.build_right_shift(lv, rv, true, "shr").unwrap().into())
            }
            InstKind::BitNot(v) => {
                let val = self.get_value(*v).into_int_value();
                Some(self.builder.build_not(val, "bitnot").unwrap().into())
            }

            // ── Variables ────────────────────────────────────────
            InstKind::Alloca { name, ty } => {
                let llvm_ty = self.ir_type_to_llvm(ty);
                let alloca = self.builder.build_alloca(llvm_ty, name).unwrap();
                self.variable_map.insert(name.clone(), alloca);
                Some(alloca.into())
            }
            InstKind::Store { ptr, value } => {
                let ptr_val = self.get_value(*ptr).into_pointer_value();
                let val = self.get_value(*value);
                self.builder.build_store(ptr_val, val).unwrap();
                Some(self.context.i8_type().const_zero().into())
            }
            InstKind::Load { ptr, ty } => {
                let ptr_val = self.get_value(*ptr).into_pointer_value();
                let llvm_ty = self.ir_type_to_llvm(ty);
                Some(self.builder.build_load(llvm_ty, ptr_val, "load").unwrap())
            }

            // ── Function calls ───────────────────────────────────
            InstKind::Call { func, args, ret_ty: _ } => {
                let callee_name = func.replace("::", "__");
                let llvm_func = self.module.get_function(&callee_name);
                if let Some(callee) = llvm_func {
                    let llvm_args: Vec<BasicMetadataValueEnum<'ctx>> = args
                        .iter()
                        .map(|a| self.get_value(*a).into())
                        .collect();
                    let call = self.builder.build_call(callee, &llvm_args, "call").unwrap();
                    call.try_as_basic_value().left()
                } else {
                    // Unknown function — return zero for robustness.
                    Some(self.context.i64_type().const_zero().into())
                }
            }

            // ── Governance ───────────────────────────────────────
            InstKind::GovernanceDecision(kind) => {
                let val = match kind {
                    DecisionKind::Permit => 0u64,
                    DecisionKind::Deny => 1,
                    DecisionKind::Escalate => 2,
                    DecisionKind::Quarantine => 3,
                };
                Some(self.context.i32_type().const_int(val, false).into())
            }

            // ── Select ───────────────────────────────────────────
            InstKind::Select { cond, true_val, false_val } => {
                let cv = self.get_value(*cond).into_int_value();
                let tv = self.get_value(*true_val);
                let fv = self.get_value(*false_val);
                Some(self.builder.build_select(cv, tv, fv, "select").unwrap())
            }

            // ── Copy ─────────────────────────────────────────────
            InstKind::Copy(v) => {
                Some(self.get_value(*v))
            }

            // ── Nops (audit marks, struct fields — Layer 2+) ─────
            InstKind::AuditMark(_) => {
                Some(self.context.i8_type().const_zero().into())
            }
            InstKind::StructField { .. } => {
                Some(self.context.i64_type().const_zero().into())
            }
        }
    }

    // ── Terminator compilation ───────────────────────────────────

    fn compile_terminator(&mut self, term: &Terminator, ir_func: &IrFunction) {
        match term {
            Terminator::Return(val) => {
                if Self::is_void_type(&ir_func.return_type) {
                    self.builder.build_return(None).unwrap();
                } else {
                    let ret_val = self.get_value(*val);
                    self.builder.build_return(Some(&ret_val)).unwrap();
                }
            }
            Terminator::Branch(target) => {
                let target_bb = self.block_map[&target.0];
                self.builder.build_unconditional_branch(target_bb).unwrap();
            }
            Terminator::CondBranch { cond, true_block, false_block } => {
                let cond_val = self.get_value(*cond).into_int_value();
                let true_bb = self.block_map[&true_block.0];
                let false_bb = self.block_map[&false_block.0];
                self.builder.build_conditional_branch(cond_val, true_bb, false_bb).unwrap();
            }
            Terminator::Unreachable => {
                self.builder.build_unreachable().unwrap();
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────

    fn get_value(&self, val: Value) -> BasicValueEnum<'ctx> {
        *self.value_map.get(&val.0).unwrap_or_else(|| {
            panic!("LLVM codegen: no value for %{}", val.0);
        })
    }

    fn build_int_cmp(
        &mut self,
        pred: IntPredicate,
        l: Value,
        r: Value,
        name: &str,
    ) -> Option<BasicValueEnum<'ctx>> {
        let lv = self.get_value(l).into_int_value();
        let rv = self.get_value(r).into_int_value();
        Some(self.builder.build_int_compare(pred, lv, rv, name).unwrap().into())
    }

    // ── Output ──────────────────────────────────────────────────

    pub fn emit_llvm_ir(&self) -> String {
        self.module.print_to_string().to_string()
    }

    pub fn emit_bitcode(&self, path: &Path) -> Result<(), String> {
        if self.module.write_bitcode_to_path(path) {
            Ok(())
        } else {
            Err(format!("failed to write bitcode to {}", path.display()))
        }
    }

    pub fn emit_object_file(&self, path: &Path) -> Result<(), String> {
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|e| format!("failed to initialize native target: {e}"))?;

        let triple = TargetMachine::get_default_triple();
        let target = Target::from_triple(&triple)
            .map_err(|e| format!("failed to get target from triple: {e}"))?;

        let cpu = TargetMachine::get_host_cpu_name();
        let features = TargetMachine::get_host_cpu_features();

        let target_machine = target
            .create_target_machine(
                &triple,
                cpu.to_str().unwrap_or("generic"),
                features.to_str().unwrap_or(""),
                OptimizationLevel::Default,
                RelocMode::Default,
                CodeModel::Default,
            )
            .ok_or_else(|| "failed to create target machine".to_string())?;

        target_machine
            .write_to_file(&self.module, FileType::Object, path)
            .map_err(|e| format!("failed to write object file: {e}"))
    }

    pub fn emit_object_bytes(&self) -> Result<Vec<u8>, String> {
        Target::initialize_native(&InitializationConfig::default())
            .map_err(|e| format!("failed to initialize native target: {e}"))?;

        let triple = TargetMachine::get_default_triple();
        let target = Target::from_triple(&triple)
            .map_err(|e| format!("failed to get target from triple: {e}"))?;

        let cpu = TargetMachine::get_host_cpu_name();
        let features = TargetMachine::get_host_cpu_features();

        let target_machine = target
            .create_target_machine(
                &triple,
                cpu.to_str().unwrap_or("generic"),
                features.to_str().unwrap_or(""),
                OptimizationLevel::Default,
                RelocMode::Default,
                CodeModel::Default,
            )
            .ok_or_else(|| "failed to create target machine".to_string())?;

        let buf = target_machine
            .write_to_memory_buffer(&self.module, FileType::Object)
            .map_err(|e| format!("failed to write object to memory: {e}"))?;

        Ok(buf.as_slice().to_vec())
    }
}
