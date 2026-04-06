// ═══════════════════════════════════════════════════════════════════════
// IR Pretty-Printer — human-readable textual format for debugging
//
// Produces output similar to LLVM IR's textual format:
//
//   fn add(a: i64, b: i64) -> i64 {
//     bb0:
//       %2 = add %0, %1 : i64
//       return %2
//   }
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use crate::ir::nodes::*;

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = ", self.result)?;
        match &self.kind {
            // Constants
            InstKind::IntConst(v) => write!(f, "const {}", v)?,
            InstKind::FloatConst(v) => write!(f, "const {}", v)?,
            InstKind::BoolConst(v) => write!(f, "const {}", v)?,
            InstKind::StringConst(v) => write!(f, "const \"{}\"", v)?,
            InstKind::UnitConst => write!(f, "const ()")?,

            // Arithmetic
            InstKind::Add(a, b) => write!(f, "add {}, {}", a, b)?,
            InstKind::Sub(a, b) => write!(f, "sub {}, {}", a, b)?,
            InstKind::Mul(a, b) => write!(f, "mul {}, {}", a, b)?,
            InstKind::Div(a, b) => write!(f, "div {}, {}", a, b)?,
            InstKind::Mod(a, b) => write!(f, "mod {}, {}", a, b)?,
            InstKind::Neg(v) => write!(f, "neg {}", v)?,

            // Comparison
            InstKind::Eq(a, b) => write!(f, "eq {}, {}", a, b)?,
            InstKind::Ne(a, b) => write!(f, "ne {}, {}", a, b)?,
            InstKind::Lt(a, b) => write!(f, "lt {}, {}", a, b)?,
            InstKind::Gt(a, b) => write!(f, "gt {}, {}", a, b)?,
            InstKind::Le(a, b) => write!(f, "le {}, {}", a, b)?,
            InstKind::Ge(a, b) => write!(f, "ge {}, {}", a, b)?,

            // Logical
            InstKind::And(a, b) => write!(f, "and {}, {}", a, b)?,
            InstKind::Or(a, b) => write!(f, "or {}, {}", a, b)?,
            InstKind::Not(v) => write!(f, "not {}", v)?,

            // Bitwise
            InstKind::BitAnd(a, b) => write!(f, "bitand {}, {}", a, b)?,
            InstKind::BitOr(a, b) => write!(f, "bitor {}, {}", a, b)?,
            InstKind::BitXor(a, b) => write!(f, "bitxor {}, {}", a, b)?,
            InstKind::Shl(a, b) => write!(f, "shl {}, {}", a, b)?,
            InstKind::Shr(a, b) => write!(f, "shr {}, {}", a, b)?,
            InstKind::BitNot(v) => write!(f, "bitnot {}", v)?,

            // Variables
            InstKind::Alloca { name, ty } => write!(f, "alloca {} : {}", name, ty)?,
            InstKind::Store { ptr, value } => write!(f, "store {}, {}", ptr, value)?,
            InstKind::Load { ptr, ty } => write!(f, "load {} : {}", ptr, ty)?,

            // Call
            InstKind::Call { func, args, ret_ty } => {
                write!(f, "call {}(", func)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", arg)?;
                }
                write!(f, ") : {}", ret_ty)?;
            }

            // Struct
            InstKind::StructField { object, index, ty } => {
                write!(f, "field {}.{} : {}", object, index, ty)?;
            }

            // Governance
            InstKind::GovernanceDecision(kind) => write!(f, "decision.{}", kind)?,

            // Audit
            InstKind::AuditMark(kind) => write!(f, "audit.{}", kind)?,

            // Select / Copy
            InstKind::Select { cond, true_val, false_val } => {
                write!(f, "select {}, {}, {}", cond, true_val, false_val)?;
            }
            InstKind::Copy(v) => write!(f, "copy {}", v)?,
        }
        write!(f, " : {}", self.ty)
    }
}

impl fmt::Display for Terminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Terminator::Return(v) => write!(f, "return {}", v),
            Terminator::Branch(label) => write!(f, "br {}", label),
            Terminator::CondBranch { cond, true_block, false_block } => {
                write!(f, "condbr {}, {}, {}", cond, true_block, false_block)
            }
            Terminator::Unreachable => write!(f, "unreachable"),
        }
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  {}:", self.id)?;
        for inst in &self.instructions {
            writeln!(f, "    {}", inst)?;
        }
        writeln!(f, "    {}", self.terminator)
    }
}

impl fmt::Display for IrFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fn {}(", self.name)?;
        for (i, param) in self.params.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{}: {}", param.name, param.ty)?;
        }
        writeln!(f, ") -> {} {{", self.return_type)?;
        for block in &self.blocks {
            write!(f, "{}", block)?;
        }
        writeln!(f, "}}")
    }
}

impl fmt::Display for IrModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, func) in self.functions.iter().enumerate() {
            if i > 0 { writeln!(f)?; }
            write!(f, "{}", func)?;
        }
        Ok(())
    }
}
