// ═══════════════════════════════════════════════════════════════════════
// RUNE Intermediate Representation — Data Structures
//
// The IR sits between the type checker and the Cranelift code generator.
// It simplifies the AST's 30+ expression variants and nested control flow
// into flat sequences of typed instructions within basic blocks.
//
// Design principles:
// - SSA-like: each instruction produces a named Value
// - Flat: no nested expressions, all operations on Values
// - Explicit control flow: if/else → conditional branch to blocks
// - Governance-aware: GovernanceDecision and AuditMark are first-class
// - Typed: every Value carries an IrType
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

// ── Value ───────────────────────────────────────────────────────────────

/// A typed SSA value produced by an instruction.
/// Values are referenced by index (e.g., %0, %1, %2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Value(pub u32);

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

// ── Block Label ─────────────────────────────────────────────────────────

/// A label for a basic block (e.g., bb0, bb1, bb2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

// ── IR Types ────────────────────────────────────────────────────────────

/// Simplified type system for code generation. Maps from the full M2
/// Type enum to a minimal set that Cranelift can consume directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrType {
    /// 64-bit signed integer.
    Int,
    /// 64-bit IEEE 754 floating point.
    Float,
    /// Boolean (i8 in Cranelift, 0 or 1).
    Bool,
    /// String (arena-allocated pointer + length).
    String,
    /// Unit type (no value, zero-size).
    Unit,
    /// Governance decision: permit, deny, escalate, quarantine.
    /// Represented as i8 (0-3) in generated code.
    PolicyDecision,
    /// Arena-allocated pointer to a value of another type.
    Ptr,
    /// Reference to a function by name (for indirect calls).
    FuncRef,
}

impl fmt::Display for IrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrType::Int => write!(f, "i64"),
            IrType::Float => write!(f, "f64"),
            IrType::Bool => write!(f, "bool"),
            IrType::String => write!(f, "str"),
            IrType::Unit => write!(f, "()"),
            IrType::PolicyDecision => write!(f, "decision"),
            IrType::Ptr => write!(f, "ptr"),
            IrType::FuncRef => write!(f, "funcref"),
        }
    }
}

// ── Governance Decision Kind ────────────────────────────────────────────

/// The four governance decisions — first-class in RUNE's IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Permit,
    Deny,
    Escalate,
    Quarantine,
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecisionKind::Permit => write!(f, "permit"),
            DecisionKind::Deny => write!(f, "deny"),
            DecisionKind::Escalate => write!(f, "escalate"),
            DecisionKind::Quarantine => write!(f, "quarantine"),
        }
    }
}

// ── Audit Mark Kind ─────────────────────────────────────────────────────

/// Compiler-inserted audit instrumentation points.
/// These become calls to the audit runtime in code generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditKind {
    /// Function entry — records function name and argument hashes.
    FunctionEntry { name: String },
    /// Function exit — records function name and return value hash.
    FunctionExit { name: String },
    /// A governance decision was made — records the decision.
    Decision { rule_name: String },
}

impl fmt::Display for AuditKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditKind::FunctionEntry { name } => write!(f, "fn_entry \"{}\"", name),
            AuditKind::FunctionExit { name } => write!(f, "fn_exit \"{}\"", name),
            AuditKind::Decision { rule_name } => write!(f, "decision \"{}\"", rule_name),
        }
    }
}

// ── Instructions ────────────────────────────────────────────────────────

/// A single IR instruction. Each produces a Value (stored in the
/// containing Instruction struct's `result` field).
#[derive(Debug, Clone, PartialEq)]
pub enum InstKind {
    // ── Constants ───────────────────────────────────────────────────
    IntConst(i64),
    FloatConst(f64),
    BoolConst(bool),
    StringConst(String),
    UnitConst,

    // ── Arithmetic ──────────────────────────────────────────────────
    Add(Value, Value),
    Sub(Value, Value),
    Mul(Value, Value),
    Div(Value, Value),
    Mod(Value, Value),
    Neg(Value),

    // ── Comparison ──────────────────────────────────────────────────
    Eq(Value, Value),
    Ne(Value, Value),
    Lt(Value, Value),
    Gt(Value, Value),
    Le(Value, Value),
    Ge(Value, Value),

    // ── Logical ─────────────────────────────────────────────────────
    And(Value, Value),
    Or(Value, Value),
    Not(Value),

    // ── Bitwise ─────────────────────────────────────────────────────
    BitAnd(Value, Value),
    BitOr(Value, Value),
    BitXor(Value, Value),
    Shl(Value, Value),
    Shr(Value, Value),
    BitNot(Value),

    // ── Variables (arena-allocated) ─────────────────────────────────
    /// Allocate space for a variable in the arena, return its pointer.
    Alloca { name: String, ty: IrType },
    /// Store a value to an arena-allocated variable.
    Store { ptr: Value, value: Value },
    /// Load a value from an arena-allocated variable.
    Load { ptr: Value, ty: IrType },

    // ── Function call ───────────────────────────────────────────────
    /// Call a named function with arguments.
    Call { func: String, args: Vec<Value>, ret_ty: IrType },

    // ── Struct access ───────────────────────────────────────────────
    /// Access a struct field by index.
    StructField { object: Value, index: u32, ty: IrType },

    // ── Governance ──────────────────────────────────────────────────
    /// Produce a governance decision value.
    GovernanceDecision(DecisionKind),

    // ── Audit instrumentation ───────────────────────────────────────
    /// Compiler-inserted audit point. Produces Unit.
    AuditMark(AuditKind),

    // ── Phi / select ────────────────────────────────────────────────
    /// Select between two values based on a condition (used for if/else merge).
    Select { cond: Value, true_val: Value, false_val: Value },

    /// Copy a value (used for block parameter passing at merge points).
    Copy(Value),
}

/// A complete instruction: result value + kind + type of result.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub result: Value,
    pub ty: IrType,
    pub kind: InstKind,
}

// ── Terminators ─────────────────────────────────────────────────────────

/// How a basic block ends. Explicit control flow — no fall-through.
#[derive(Debug, Clone, PartialEq)]
pub enum Terminator {
    /// Return a value from the function.
    Return(Value),
    /// Unconditional jump to another block.
    Branch(BlockId),
    /// Conditional jump: if cond is true, go to true_block; else false_block.
    CondBranch {
        cond: Value,
        true_block: BlockId,
        false_block: BlockId,
    },
    /// This block should never be reached. Used after returns in branches.
    Unreachable,
}

// ── Basic Block ─────────────────────────────────────────────────────────

/// A basic block: a straight-line sequence of instructions ending with
/// a terminator. No nested control flow within a block.
#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

// ── Function ────────────────────────────────────────────────────────────

/// An IR function parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct IrParam {
    pub name: String,
    pub ty: IrType,
    pub value: Value,
}

/// An IR function: name, parameters, return type, and a body of basic blocks.
/// The first block (blocks[0]) is the entry block.
#[derive(Debug, Clone, PartialEq)]
pub struct IrFunction {
    pub name: String,
    pub params: Vec<IrParam>,
    pub return_type: IrType,
    pub blocks: Vec<BasicBlock>,
}

// ── Module ──────────────────────────────────────────────────────────────

/// The top-level IR compilation unit: a list of functions.
/// Policy rules are lowered to functions that return PolicyDecision.
#[derive(Debug, Clone, PartialEq)]
pub struct IrModule {
    pub functions: Vec<IrFunction>,
}
