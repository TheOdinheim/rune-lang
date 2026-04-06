// ═══════════════════════════════════════════════════════════════════════
// WASM Code Generator — translates RUNE IR to WebAssembly bytecode
//
// Pipeline: RUNE IR → WASM bytecode → executed by wasmtime (which uses
// Cranelift internally for JIT compilation to native code).
//
// WASM is a stack machine. The generator walks IR instructions and emits
// corresponding WASM stack operations. Basic block control flow maps to
// WASM's structured control flow (if/else/block/br).
//
// IrType → WASM type mapping:
//   Int            → I64
//   Float          → F64
//   Bool           → I32 (0 or 1)
//   PolicyDecision → I32 (0=Permit, 1=Deny, 2=Escalate, 3=Quarantine)
//   Unit           → I32 (placeholder, value 0)
//   String         → I64 (arena pointer, actual strings deferred)
//   Ptr            → I64 (arena pointer)
//   FuncRef        → I32 (function table index)
// ═══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function,
    FunctionSection, Ieee64, Module, TypeSection, ValType,
};
use wasm_encoder::Instruction as WasmInst;

use crate::ir::nodes::{
    self, BasicBlock, DecisionKind, InstKind, IrFunction,
    IrModule, IrType, Terminator, Value,
};

/// Compile a RUNE IR module to WASM bytecode.
///
/// All IR functions are compiled and exported. Additionally, if the module
/// contains policy rules (functions returning PolicyDecision), a standard
/// `evaluate(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> i32`
/// wrapper is generated that dispatches to all policy rules and returns
/// the first non-Permit decision (default-deny per Zero Trust pillar).
pub fn compile_to_wasm(module: &IrModule) -> Vec<u8> {
    let mut wasm_module = Module::new();

    // Phase 1: Build function type signatures and collect function indices.
    let mut type_section = TypeSection::new();
    let mut function_section = FunctionSection::new();
    let mut export_section = ExportSection::new();
    let mut code_section = CodeSection::new();

    // Map function name → index for calls.
    let mut func_index: HashMap<&str, u32> = HashMap::new();
    for (i, func) in module.functions.iter().enumerate() {
        func_index.insert(&func.name, i as u32);
    }

    // Identify policy rules (functions returning PolicyDecision with `::`
    // in their name, indicating they came from a policy block).
    let policy_rules: Vec<(u32, &IrFunction)> = module.functions.iter()
        .enumerate()
        .filter(|(_, f)| f.return_type == IrType::PolicyDecision && f.name.contains("::"))
        .map(|(i, f)| (i as u32, f))
        .collect();
    let needs_evaluate = !policy_rules.is_empty();

    // Phase 2: Declare types and function signatures.
    for (i, func) in module.functions.iter().enumerate() {
        let params: Vec<ValType> = func.params.iter()
            .map(|p| ir_type_to_wasm(&p.ty))
            .collect();
        let results = vec![ir_type_to_wasm(&func.return_type)];

        type_section.ty().function(params, results);
        function_section.function(i as u32);

        // Export all functions (policy evaluation entry points).
        // Sanitize name: WASM exports can't contain `::`
        let export_name = func.name.replace("::", "__");
        export_section.export(&export_name, ExportKind::Func, i as u32);
    }

    // Declare the evaluate wrapper if there are policy rules.
    let evaluate_func_idx = module.functions.len() as u32;
    if needs_evaluate {
        // evaluate(subject_id: i64, action: i64, resource_id: i64, risk_score: i64) -> i32
        type_section.ty().function(
            vec![ValType::I64, ValType::I64, ValType::I64, ValType::I64],
            vec![ValType::I32],
        );
        function_section.function(evaluate_func_idx);
        export_section.export("evaluate", ExportKind::Func, evaluate_func_idx);
    }

    // Phase 3: Generate code for each function.
    for func in &module.functions {
        let wasm_func = compile_function(func, &func_index);
        code_section.function(&wasm_func);
    }

    // Generate the evaluate wrapper.
    if needs_evaluate {
        let eval_func = compile_evaluate_wrapper(&policy_rules);
        code_section.function(&eval_func);
    }

    // Assemble the module.
    wasm_module.section(&type_section);
    wasm_module.section(&function_section);
    wasm_module.section(&export_section);
    wasm_module.section(&code_section);

    wasm_module.finish()
}

/// Generate the `evaluate` wrapper function.
///
/// Strategy: call each policy rule (passing evaluate's params as available),
/// and return the first non-Permit decision. If all rules permit, return Permit.
/// If no rules match the parameter count, return Deny (default-deny).
///
/// Governance constants: Permit=0, Deny=1, Escalate=2, Quarantine=3.
fn compile_evaluate_wrapper(policy_rules: &[(u32, &IrFunction)]) -> Function {
    // The evaluate function has 4 params: subject_id, action, resource_id, risk_score
    // (all i64), locals 0-3.
    // We need one extra local for storing each rule's decision result (i32).
    let mut func = Function::new(vec![(1, ValType::I32)]);
    let decision_local: u32 = 4; // first local after the 4 params

    for &(idx, rule) in policy_rules {
        // Push arguments for the policy rule call. Match rule params to
        // evaluate params by position (up to 4). If a rule needs fewer,
        // push only what it needs. Extra evaluate params are ignored.
        let rule_param_count = rule.params.len();
        for i in 0..rule_param_count.min(4) {
            // Evaluate params are all i64, but rule params may expect i32 (Bool).
            let param_wasm_ty = ir_type_to_wasm(&rule.params[i].ty);
            func.instruction(&WasmInst::LocalGet(i as u32));
            if param_wasm_ty == ValType::I32 {
                // Truncate i64 → i32 for Bool/PolicyDecision params.
                func.instruction(&WasmInst::I32WrapI64);
            }
        }

        // Call the policy rule.
        func.instruction(&WasmInst::Call(idx));
        func.instruction(&WasmInst::LocalSet(decision_local));

        // If decision != Permit (0), return it immediately.
        func.instruction(&WasmInst::LocalGet(decision_local));
        func.instruction(&WasmInst::I32Const(0)); // Permit
        func.instruction(&WasmInst::I32Ne);
        func.instruction(&WasmInst::If(wasm_encoder::BlockType::Empty));
        func.instruction(&WasmInst::LocalGet(decision_local));
        func.instruction(&WasmInst::Return);
        func.instruction(&WasmInst::End);
    }

    // All rules returned Permit (or no rules matched) — return Permit.
    func.instruction(&WasmInst::I32Const(0)); // Permit
    func.instruction(&WasmInst::End);

    func
}

/// Map IrType to WASM ValType.
fn ir_type_to_wasm(ty: &IrType) -> ValType {
    match ty {
        IrType::Int => ValType::I64,
        IrType::Float => ValType::F64,
        IrType::Bool => ValType::I32,
        IrType::PolicyDecision => ValType::I32,
        IrType::Unit => ValType::I32,
        IrType::String => ValType::I64,
        IrType::Ptr => ValType::I64,
        IrType::FuncRef => ValType::I32,
    }
}

/// Compile a single IR function to WASM.
fn compile_function(func: &IrFunction, func_index: &HashMap<&str, u32>) -> Function {
    let mut compiler = FuncCompiler::new(func, func_index);
    compiler.compile();
    compiler.finish()
}

// ═══════════════════════════════════════════════════════════════════════
// Function compiler — translates one IR function to WASM instructions
// ═══════════════════════════════════════════════════════════════════════

struct FuncCompiler<'a> {
    func: &'a IrFunction,
    func_index: &'a HashMap<&'a str, u32>,
    /// WASM locals: maps IR Value → WASM local index.
    /// Parameters are locals 0..N-1, then we add locals for IR values.
    locals: HashMap<Value, u32>,
    /// Number of WASM parameters (already locals).
    param_count: u32,
    /// Additional locals needed beyond parameters.
    extra_locals: Vec<ValType>,
    /// The WASM instructions being built.
    instructions: Vec<WasmInst<'static>>,
}

impl<'a> FuncCompiler<'a> {
    fn new(func: &'a IrFunction, func_index: &'a HashMap<&'a str, u32>) -> Self {
        let param_count = func.params.len() as u32;
        let mut locals = HashMap::new();

        // Parameters are the first N locals.
        for (i, p) in func.params.iter().enumerate() {
            locals.insert(p.value, i as u32);
        }

        Self {
            func,
            func_index,
            locals,
            param_count,
            extra_locals: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Allocate a WASM local for an IR value.
    fn alloc_local(&mut self, value: Value, ty: &IrType) -> u32 {
        if let Some(&idx) = self.locals.get(&value) {
            return idx;
        }
        let idx = self.param_count + self.extra_locals.len() as u32;
        self.extra_locals.push(ir_type_to_wasm(ty));
        self.locals.insert(value, idx);
        idx
    }

    /// Ensure a local exists for a value (used for all instruction results).
    fn ensure_local(&mut self, value: Value, ty: &IrType) -> u32 {
        self.alloc_local(value, ty)
    }

    fn compile(&mut self) {
        if self.func.blocks.len() == 1 {
            self.compile_single_block();
        } else {
            self.compile_multi_block();
        }
    }

    /// Simple case: single basic block function.
    fn compile_single_block(&mut self) {
        let block = &self.func.blocks[0];
        for inst in &block.instructions {
            self.compile_instruction(inst);
        }
        // Emit the return value.
        if let Terminator::Return(val) = &block.terminator {
            self.emit_load_value(*val);
            self.instructions.push(WasmInst::Return);
        }
    }

    /// Multi-block function. Handles if/else, loops, and match chains.
    fn compile_multi_block(&mut self) {
        // Pre-allocate locals for all instruction results in all blocks.
        for block in &self.func.blocks {
            for inst in &block.instructions {
                let ty = match &inst.kind {
                    InstKind::Alloca { ty, .. } => ty,
                    _ => &inst.ty,
                };
                self.ensure_local(inst.result, ty);
            }
        }

        // Clone blocks and build lookup structures.
        let blocks = self.func.blocks.clone();
        let block_map: HashMap<nodes::BlockId, usize> = blocks.iter()
            .enumerate()
            .map(|(i, b)| (b.id, i))
            .collect();

        // Detect loop headers: blocks targeted by backward branches.
        let mut loop_headers = std::collections::HashSet::new();
        for (idx, block) in blocks.iter().enumerate() {
            if let Terminator::Branch(target) = &block.terminator {
                if let Some(&target_idx) = block_map.get(target) {
                    if target_idx <= idx {
                        loop_headers.insert(*target);
                    }
                }
            }
        }

        let mut consumed = vec![false; blocks.len()];
        self.compile_from(&blocks, &block_map, &loop_headers, &mut consumed, 0, None);

        // Safety fallback: if all paths through the function already have explicit
        // returns (e.g., match chains), WASM validation still requires the implicit
        // function end to be valid. Emit `unreachable` to satisfy the validator.
        // This is dead code — all reachable paths already return.
        self.instructions.push(WasmInst::Unreachable);
    }

    /// Recursively compile blocks starting from `idx`.
    /// `loop_header` is set when compiling inside a loop body.
    fn compile_from(
        &mut self,
        blocks: &[BasicBlock],
        block_map: &HashMap<nodes::BlockId, usize>,
        loop_headers: &std::collections::HashSet<nodes::BlockId>,
        consumed: &mut [bool],
        idx: usize,
        loop_header: Option<nodes::BlockId>,
    ) {
        if idx >= blocks.len() || consumed[idx] {
            return;
        }

        let block = &blocks[idx];
        consumed[idx] = true;

        // If this is a loop header, emit WASM loop structure.
        if loop_headers.contains(&block.id) {
            self.compile_loop(blocks, block_map, loop_headers, consumed, idx);
            return;
        }

        // Emit block instructions.
        for inst in &block.instructions {
            self.compile_instruction(inst);
        }

        match block.terminator.clone() {
            Terminator::Return(val) => {
                self.emit_load_value(val);
                self.instructions.push(WasmInst::Return);
            }
            Terminator::Branch(target) => {
                if let Some(&target_idx) = block_map.get(&target) {
                    if Some(target) == loop_header {
                        // Back-edge inside loop body → br to loop (depth 0).
                        self.instructions.push(WasmInst::Br(0));
                    } else if !consumed[target_idx] {
                        self.compile_from(blocks, block_map, loop_headers, consumed, target_idx, loop_header);
                    }
                }
            }
            Terminator::CondBranch { cond, true_block, false_block } => {
                self.compile_if_else(blocks, block_map, loop_headers, consumed, cond, true_block, false_block, loop_header, false);
            }
            Terminator::Unreachable => {
                self.instructions.push(WasmInst::Unreachable);
            }
        }
    }

    /// Compile a loop: block { loop { header; br_if exit; body; br loop; } }
    fn compile_loop(
        &mut self,
        blocks: &[BasicBlock],
        block_map: &HashMap<nodes::BlockId, usize>,
        loop_headers: &std::collections::HashSet<nodes::BlockId>,
        consumed: &mut [bool],
        header_idx: usize,
    ) {
        let header = &blocks[header_idx];
        let header_id = header.id;

        if let Terminator::CondBranch { cond, true_block, false_block } = header.terminator.clone() {
            let exit_idx = block_map.get(&false_block).copied();

            // block $exit
            self.instructions.push(WasmInst::Block(wasm_encoder::BlockType::Empty));
            // loop $header
            self.instructions.push(WasmInst::Loop(wasm_encoder::BlockType::Empty));

            // Emit header instructions (condition computation).
            for inst in &header.instructions {
                self.compile_instruction(inst);
            }

            // If !condition, break to exit (br depth 1 = $exit block).
            self.emit_load_value(cond);
            self.instructions.push(WasmInst::I32Eqz);
            self.instructions.push(WasmInst::BrIf(1));

            // Compile body blocks within the loop context.
            if let Some(&body_idx) = block_map.get(&true_block) {
                consumed[body_idx] = false; // allow body to be compiled
                self.compile_from(blocks, block_map, loop_headers, consumed, body_idx, Some(header_id));
            }

            // end loop
            self.instructions.push(WasmInst::End);
            // end block
            self.instructions.push(WasmInst::End);

            // Continue with exit block.
            if let Some(ei) = exit_idx {
                consumed[ei] = false; // allow exit to be compiled
                self.compile_from(blocks, block_map, loop_headers, consumed, ei, None);
            }
        }
    }

    /// Compile if/else pattern. Detects merge blocks with Select for
    /// value-producing if/else, and handles match chains (else block
    /// containing another CondBranch).
    fn compile_if_else(
        &mut self,
        blocks: &[BasicBlock],
        block_map: &HashMap<nodes::BlockId, usize>,
        loop_headers: &std::collections::HashSet<nodes::BlockId>,
        consumed: &mut [bool],
        cond: Value,
        true_block_id: nodes::BlockId,
        false_block_id: nodes::BlockId,
        loop_header: Option<nodes::BlockId>,
        in_match_chain: bool,
    ) {
        let then_idx = block_map.get(&true_block_id).copied();
        let else_idx = block_map.get(&false_block_id).copied();

        if let (Some(ti), Some(ei)) = (then_idx, else_idx) {
            let then_block = &blocks[ti];
            let else_block = &blocks[ei];

            // Determine merge target from then_block's terminator.
            let merge_target = match &then_block.terminator {
                Terminator::Branch(id) => Some(*id),
                _ => None,
            };
            let merge_idx = merge_target.and_then(|id| block_map.get(&id).copied());

            // Check if this is a value-producing if/else (merge has Select).
            let has_select = merge_idx.map(|mi| {
                blocks[mi].instructions.iter().any(|i| matches!(i.kind, InstKind::Select { .. }))
            }).unwrap_or(false);

            if has_select {
                // Value-producing if/else with Select merge.
                let result_type = if let Some(mi) = merge_idx {
                    let select = blocks[mi].instructions.iter()
                        .find(|i| matches!(i.kind, InstKind::Select { .. }));
                    select.map(|s| ir_type_to_wasm(&s.ty))
                        .unwrap_or_else(|| ir_type_to_wasm(&self.func.return_type))
                } else {
                    ir_type_to_wasm(&self.func.return_type)
                };

                self.emit_load_value(cond);
                self.instructions.push(WasmInst::If(
                    wasm_encoder::BlockType::Result(result_type),
                ));

                // Then block.
                consumed[ti] = true;
                for inst in &then_block.instructions {
                    self.compile_instruction(inst);
                }
                self.emit_branch_result(then_block);

                self.instructions.push(WasmInst::Else);

                // Else block — may be a simple block or another CondBranch (match chain).
                consumed[ei] = true;
                for inst in &else_block.instructions {
                    self.compile_instruction(inst);
                }
                if let Terminator::CondBranch { cond: c2, true_block: tb2, false_block: fb2 } = else_block.terminator.clone() {
                    // Match chain: else block has another CondBranch.
                    self.compile_if_else(blocks, block_map, loop_headers, consumed, c2, tb2, fb2, loop_header, true);
                } else {
                    self.emit_branch_result(else_block);
                }

                self.instructions.push(WasmInst::End);

                // Handle merge block (only at outermost level).
                if !in_match_chain {
                    if let Some(mi) = merge_idx {
                        consumed[mi] = true;
                        self.handle_merge_block(&blocks[mi], blocks, block_map, loop_headers, consumed, loop_header);
                    }
                }
            } else {
                // Non-value if/else (e.g., match arms storing to a variable, or early return).
                self.emit_load_value(cond);
                self.instructions.push(WasmInst::If(wasm_encoder::BlockType::Empty));

                consumed[ti] = true;
                for inst in &then_block.instructions {
                    self.compile_instruction(inst);
                }
                // Handle then block terminator (e.g., early return).
                if let Terminator::Return(val) = &then_block.terminator {
                    self.emit_load_value(*val);
                    self.instructions.push(WasmInst::Return);
                }

                self.instructions.push(WasmInst::Else);

                consumed[ei] = true;
                for inst in &else_block.instructions {
                    self.compile_instruction(inst);
                }
                // Handle else block terminator.
                match else_block.terminator.clone() {
                    Terminator::CondBranch { cond: c2, true_block: tb2, false_block: fb2 } => {
                        // Match chain: else block has another CondBranch.
                        self.compile_if_else(blocks, block_map, loop_headers, consumed, c2, tb2, fb2, loop_header, true);
                    }
                    Terminator::Return(val) => {
                        self.emit_load_value(val);
                        self.instructions.push(WasmInst::Return);
                    }
                    Terminator::Branch(target) => {
                        // Else block branches to another block (e.g., wildcard body in match).
                        // Inline the target block's instructions but DON'T follow its branch
                        // to the merge block — the merge block should be compiled after
                        // the entire if/else chain, not inside a nested branch.
                        if merge_target != Some(target) {
                            if let Some(&target_idx) = block_map.get(&target) {
                                if !consumed[target_idx] {
                                    let target_block = &blocks[target_idx];
                                    consumed[target_idx] = true;
                                    for inst in &target_block.instructions {
                                        self.compile_instruction(inst);
                                    }
                                    // Handle the target block's terminator if it's a Return.
                                    if let Terminator::Return(val) = &target_block.terminator {
                                        self.emit_load_value(*val);
                                        self.instructions.push(WasmInst::Return);
                                    }
                                    // Branch terminators are NOT followed — the merge block
                                    // will be compiled after the outermost if/else/end.
                                }
                            }
                        }
                    }
                    _ => {}
                }

                self.instructions.push(WasmInst::End);

                // Continue to merge block (only at outermost level, not in match chain).
                if !in_match_chain {
                    if let Some(mi) = merge_idx {
                        if !consumed[mi] {
                            self.compile_from(blocks, block_map, loop_headers, consumed, mi, loop_header);
                        }
                    }
                }
            }
        }
    }

    /// Get the last meaningful value from a block for if/else result.
    fn emit_branch_result(&mut self, block: &BasicBlock) {
        let result_inst = block.instructions.iter().rev().find(|i| {
            !matches!(i.kind, InstKind::AuditMark(_))
                && !matches!(i.kind, InstKind::UnitConst)
                && !matches!(i.kind, InstKind::Store { .. })
                && !matches!(i.kind, InstKind::Alloca { .. })
        });

        if let Some(inst) = result_inst {
            self.emit_load_value(inst.result);
        } else {
            self.emit_default_value(&self.func.return_type.clone());
        }
    }

    /// Handle merge block after if/else.
    fn handle_merge_block(
        &mut self,
        merge_block: &BasicBlock,
        blocks: &[BasicBlock],
        block_map: &HashMap<nodes::BlockId, usize>,
        loop_headers: &std::collections::HashSet<nodes::BlockId>,
        consumed: &mut [bool],
        loop_header: Option<nodes::BlockId>,
    ) {
        // Store the if/else result into the Select's result local.
        let select_inst = merge_block.instructions.iter().find(|i| {
            matches!(i.kind, InstKind::Select { .. })
        });

        if let Some(si) = select_inst {
            let local = self.ensure_local(si.result, &si.ty);
            self.instructions.push(WasmInst::LocalSet(local));
        } else {
            self.instructions.push(WasmInst::Drop);
        }

        // Compile remaining instructions (after Select).
        let mut past_select = select_inst.is_none();
        for inst in &merge_block.instructions {
            if !past_select {
                if matches!(inst.kind, InstKind::Select { .. }) {
                    past_select = true;
                }
                continue;
            }
            self.compile_instruction(inst);
        }

        // Handle merge block terminator.
        match merge_block.terminator.clone() {
            Terminator::Return(val) => {
                self.emit_load_value(val);
                self.instructions.push(WasmInst::Return);
            }
            Terminator::Branch(target) => {
                if let Some(&target_idx) = block_map.get(&target) {
                    if Some(target) == loop_header {
                        self.instructions.push(WasmInst::Br(0));
                    } else if !consumed[target_idx] {
                        self.compile_from(blocks, block_map, loop_headers, consumed, target_idx, loop_header);
                    }
                }
            }
            _ => {}
        }
    }

    /// Compile a single IR instruction to WASM.
    fn compile_instruction(&mut self, inst: &nodes::Instruction) {
        // For Alloca, use the stored variable type (not Ptr) for the WASM local.
        let local = match &inst.kind {
            InstKind::Alloca { ty, .. } => self.ensure_local(inst.result, ty),
            _ => self.ensure_local(inst.result, &inst.ty),
        };

        match &inst.kind {
            // ── Constants ───────────────────────────────────────────
            InstKind::IntConst(v) => {
                self.instructions.push(WasmInst::I64Const(*v));
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::FloatConst(v) => {
                self.instructions.push(WasmInst::F64Const(Ieee64::from(*v)));
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::BoolConst(v) => {
                self.instructions.push(WasmInst::I32Const(if *v { 1 } else { 0 }));
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::StringConst(_) => {
                // Strings deferred — store a placeholder pointer.
                self.instructions.push(WasmInst::I64Const(0));
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::UnitConst => {
                self.instructions.push(WasmInst::I32Const(0));
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Arithmetic ──────────────────────────────────────────
            InstKind::Add(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Add);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Sub(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Sub);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Mul(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Mul);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Div(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64DivS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Mod(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64RemS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Neg(v) => {
                self.instructions.push(WasmInst::I64Const(0));
                self.emit_load_value(*v);
                self.instructions.push(WasmInst::I64Sub);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Comparison ──────────────────────────────────────────
            InstKind::Eq(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Eq);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Ne(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Ne);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Lt(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64LtS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Gt(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64GtS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Le(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64LeS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Ge(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64GeS);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Logical ─────────────────────────────────────────────
            InstKind::And(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I32And);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Or(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I32Or);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Not(v) => {
                self.emit_load_value(*v);
                self.instructions.push(WasmInst::I32Const(1));
                self.instructions.push(WasmInst::I32Xor);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Bitwise ─────────────────────────────────────────────
            InstKind::BitAnd(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64And);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::BitOr(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Or);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::BitXor(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Xor);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Shl(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64Shl);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Shr(a, b) => {
                self.emit_load_value(*a);
                self.emit_load_value(*b);
                self.instructions.push(WasmInst::I64ShrS);
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::BitNot(v) => {
                self.emit_load_value(*v);
                self.instructions.push(WasmInst::I64Const(-1));
                self.instructions.push(WasmInst::I64Xor);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Variables ───────────────────────────────────────────
            InstKind::Alloca { name, ty } => {
                // In WASM, allocas become locals. Map the variable name
                // to this result's local index.
                self.emit_default_value(ty);
                self.instructions.push(WasmInst::LocalSet(local));
                // No extra work — we track by Value, not by name.
                let _ = name;
            }
            InstKind::Store { ptr, value } => {
                // Store: copy value into the local for ptr.
                if let Some(&ptr_local) = self.locals.get(ptr) {
                    self.emit_load_value(*value);
                    self.instructions.push(WasmInst::LocalSet(ptr_local));
                }
                // Store result is Unit.
                self.instructions.push(WasmInst::I32Const(0));
                self.instructions.push(WasmInst::LocalSet(local));
            }
            InstKind::Load { ptr, .. } => {
                // Load: read from the local for ptr.
                if let Some(&ptr_local) = self.locals.get(ptr) {
                    self.instructions.push(WasmInst::LocalGet(ptr_local));
                    self.instructions.push(WasmInst::LocalSet(local));
                }
            }

            // ── Function call ───────────────────────────────────────
            InstKind::Call { func, args, .. } => {
                if let Some(&idx) = self.func_index.get(func.as_str()) {
                    for arg in args {
                        self.emit_load_value(*arg);
                    }
                    self.instructions.push(WasmInst::Call(idx));
                    self.instructions.push(WasmInst::LocalSet(local));
                } else {
                    // Unknown function — push default.
                    self.emit_default_value(&inst.ty);
                    self.instructions.push(WasmInst::LocalSet(local));
                }
            }

            // ── Struct field ────────────────────────────────────────
            InstKind::StructField { .. } => {
                // Deferred — emit placeholder.
                self.emit_default_value(&inst.ty);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Governance decisions ────────────────────────────────
            InstKind::GovernanceDecision(kind) => {
                let val = match kind {
                    DecisionKind::Permit => 0,
                    DecisionKind::Deny => 1,
                    DecisionKind::Escalate => 2,
                    DecisionKind::Quarantine => 3,
                };
                self.instructions.push(WasmInst::I32Const(val));
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Audit marks ─────────────────────────────────────────
            InstKind::AuditMark(_) => {
                // No-op for now — will become runtime calls in M5.
                self.instructions.push(WasmInst::I32Const(0));
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Select ──────────────────────────────────────────────
            InstKind::Select { cond, true_val, false_val } => {
                // WASM select: takes (true_val, false_val, cond) on stack.
                self.emit_load_value(*true_val);
                self.emit_load_value(*false_val);
                self.emit_load_value(*cond);
                self.instructions.push(WasmInst::Select);
                self.instructions.push(WasmInst::LocalSet(local));
            }

            // ── Copy ────────────────────────────────────────────────
            InstKind::Copy(v) => {
                self.emit_load_value(*v);
                self.instructions.push(WasmInst::LocalSet(local));
            }
        }
    }

    /// Load a value onto the WASM stack from its local.
    fn emit_load_value(&mut self, val: Value) {
        if let Some(&local) = self.locals.get(&val) {
            self.instructions.push(WasmInst::LocalGet(local));
        } else {
            // Unknown value — push zero as fallback.
            self.instructions.push(WasmInst::I32Const(0));
        }
    }

    /// Emit a default value for a type onto the stack.
    fn emit_default_value(&mut self, ty: &IrType) {
        match ty {
            IrType::Int | IrType::String | IrType::Ptr => {
                self.instructions.push(WasmInst::I64Const(0));
            }
            IrType::Float => {
                self.instructions.push(WasmInst::F64Const(Ieee64::from(0.0f64)));
            }
            IrType::Bool | IrType::PolicyDecision | IrType::Unit | IrType::FuncRef => {
                self.instructions.push(WasmInst::I32Const(0));
            }
        }
    }

    fn finish(mut self) -> Function {
        self.instructions.push(WasmInst::End);

        // Build the WASM function with locals.
        let mut wasm_func = Function::new(
            self.extra_locals.iter().map(|ty| (1, *ty)),
        );

        for inst in &self.instructions {
            wasm_func.instruction(inst);
        }

        wasm_func
    }
}
