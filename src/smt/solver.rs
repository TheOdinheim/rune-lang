// ═══════════════════════════════════════════════════════════════════════
// SMT Solver — Compile-time governance predicate verification
//
// Translates RUNE refinement predicates to Z3 assertions and checks
// satisfiability. If predicates are contradictory (UNSAT), the compiler
// reports an error — governance constraints must be consistent.
//
// Pillar: Security Baked In — governance predicates verified before
// code ever executes. No runtime surprises.
// ═══════════════════════════════════════════════════════════════════════

use std::str::FromStr;

use z3::{SatResult, Solver};

use crate::ast::nodes::{RefinementOp, RefinementPredicate, RefinementValue};

/// Result of SMT satisfiability checking.
#[derive(Debug, Clone, PartialEq)]
pub enum SmtResult {
    /// Predicates are satisfiable — a valid assignment exists.
    Satisfiable,
    /// Predicates are contradictory — no valid assignment exists.
    Unsatisfiable(String),
    /// Solver could not determine satisfiability.
    Unknown(String),
}

/// Verify that a set of refinement predicates is satisfiable.
///
/// Translates each predicate to a Z3 assertion, conjoins them, and checks
/// if any assignment of field values satisfies all constraints simultaneously.
///
/// Returns `SmtResult::Satisfiable` if the predicates are consistent,
/// `SmtResult::Unsatisfiable` with an explanation if contradictory.
pub fn verify_predicates(predicates: &[RefinementPredicate]) -> SmtResult {
    if predicates.is_empty() {
        return SmtResult::Satisfiable;
    }

    let solver = Solver::new();

    for pred in predicates {
        match encode_predicate(pred) {
            Ok(assertion) => solver.assert(&assertion),
            Err(msg) => return SmtResult::Unknown(msg),
        }
    }

    match solver.check() {
        SatResult::Sat => SmtResult::Satisfiable,
        SatResult::Unsat => {
            let explanation = build_unsat_explanation(predicates);
            SmtResult::Unsatisfiable(explanation)
        }
        SatResult::Unknown => {
            SmtResult::Unknown("SMT solver returned unknown".to_string())
        }
    }
}

/// Check whether `caller_predicates` imply `callee_predicates`.
///
/// This verifies refinement subtyping: if a function requires
/// `{ certified == true }`, the caller must provide a value whose
/// predicates are at least as strong.
///
/// Encoding: assert all caller predicates, then check whether callee
/// predicates are entailed. If NOT(callee) is UNSAT under the caller
/// assumptions, the implication holds.
///
/// Returns `SmtResult::Satisfiable` if the implication holds (caller
/// predicates are strong enough), `SmtResult::Unsatisfiable` if not.
pub fn check_implication(
    caller_predicates: &[RefinementPredicate],
    callee_predicates: &[RefinementPredicate],
) -> SmtResult {
    if callee_predicates.is_empty() {
        return SmtResult::Satisfiable;
    }

    let solver = Solver::new();

    // Assert all caller predicates as assumptions.
    for pred in caller_predicates {
        match encode_predicate(pred) {
            Ok(assertion) => solver.assert(&assertion),
            Err(msg) => return SmtResult::Unknown(msg),
        }
    }

    // Encode the conjunction of callee predicates.
    let mut callee_bools = Vec::new();
    for pred in callee_predicates {
        match encode_predicate(pred) {
            Ok(assertion) => callee_bools.push(assertion),
            Err(msg) => return SmtResult::Unknown(msg),
        }
    }

    let callee_refs: Vec<&z3::ast::Bool> = callee_bools.iter().collect();
    let callee_conj = z3::ast::Bool::and(&callee_refs);

    // Assert NOT(callee). If UNSAT, then caller => callee.
    solver.assert(&callee_conj.not());

    match solver.check() {
        SatResult::Unsat => {
            // NOT(callee) is unsatisfiable under caller → implication holds
            SmtResult::Satisfiable
        }
        SatResult::Sat => {
            // Found assignment where caller holds but callee doesn't → insufficient
            let explanation = build_implication_failure(caller_predicates, callee_predicates);
            SmtResult::Unsatisfiable(explanation)
        }
        SatResult::Unknown => {
            SmtResult::Unknown("SMT solver returned unknown for implication check".to_string())
        }
    }
}

/// Build explanation for a failed implication check.
fn build_implication_failure(
    caller: &[RefinementPredicate],
    callee: &[RefinementPredicate],
) -> String {
    let caller_str: Vec<String> = caller
        .iter()
        .map(|p| format!("{} {} {}", p.field.name, op_symbol(&p.op), value_display(&p.value)))
        .collect();
    let callee_str: Vec<String> = callee
        .iter()
        .map(|p| format!("{} {} {}", p.field.name, op_symbol(&p.op), value_display(&p.value)))
        .collect();

    if caller_str.is_empty() {
        format!(
            "no refinement guarantees provided, but requires {{ {} }}",
            callee_str.join(", ")
        )
    } else {
        format!(
            "{{ {} }} does not imply {{ {} }}",
            caller_str.join(", "),
            callee_str.join(", ")
        )
    }
}

/// Encode a single refinement predicate as a Z3 Bool assertion.
fn encode_predicate(pred: &RefinementPredicate) -> Result<z3::ast::Bool, String> {
    let field_name = &pred.field.name;

    match (&pred.op, &pred.value) {
        // ── Bool predicates ────────────────────────────────────────
        (RefinementOp::Eq, RefinementValue::Bool(val)) => {
            let field = z3::ast::Bool::new_const(field_name.as_str());
            let constant = z3::ast::Bool::from_bool(*val);
            Ok(field.eq(&constant))
        }
        (RefinementOp::Ne, RefinementValue::Bool(val)) => {
            let field = z3::ast::Bool::new_const(field_name.as_str());
            let constant = z3::ast::Bool::from_bool(*val);
            Ok(field.eq(&constant).not())
        }

        // ── Int predicates ─────────────────────────────────────────
        (op, RefinementValue::Int(val)) => {
            let field = z3::ast::Int::new_const(field_name.as_str());
            let constant = z3::ast::Int::from_i64(*val);
            Ok(encode_int_comparison(&field, op, &constant))
        }

        // ── Float predicates ───────────────────────────────────────
        (op, RefinementValue::Float(val)) => {
            // Use Z3 Real sort for float comparisons (exact arithmetic).
            let field = z3::ast::Real::new_const(field_name.as_str());
            // Encode as rational: multiply by large factor to preserve precision.
            // For simple decimals, convert to numerator/denominator.
            let (num, den) = float_to_rational(*val);
            let constant = z3::ast::Real::from_rational(num, den);
            Ok(encode_real_comparison(&field, op, &constant))
        }

        // ── String predicates ──────────────────────────────────────
        (RefinementOp::Eq, RefinementValue::String(val)) => {
            let field = z3::ast::String::new_const(field_name.as_str());
            let constant = z3::ast::String::from_str(val)
                .map_err(|e| format!("invalid string constant: {e}"))?;
            Ok(field.eq(&constant))
        }
        (RefinementOp::Ne, RefinementValue::String(val)) => {
            let field = z3::ast::String::new_const(field_name.as_str());
            let constant = z3::ast::String::from_str(val)
                .map_err(|e| format!("invalid string constant: {e}"))?;
            Ok(field.eq(&constant).not())
        }

        // ── In/NotIn with list ─────────────────────────────────────
        (RefinementOp::In, RefinementValue::List(items)) => {
            encode_membership(field_name, items, false)
        }
        (RefinementOp::NotIn, RefinementValue::List(items)) => {
            encode_membership(field_name, items, true)
        }

        // ── Unsupported combinations ───────────────────────────────
        (op, val) => Err(format!(
            "unsupported predicate combination: {field_name} {op:?} {val:?}"
        )),
    }
}

/// Encode an integer comparison.
fn encode_int_comparison(
    field: &z3::ast::Int,
    op: &RefinementOp,
    constant: &z3::ast::Int,
) -> z3::ast::Bool {
    match op {
        RefinementOp::Eq => field.eq(constant),
        RefinementOp::Ne => field.eq(constant).not(),
        RefinementOp::Lt => field.lt(constant),
        RefinementOp::Gt => field.gt(constant),
        RefinementOp::Le => field.le(constant),
        RefinementOp::Ge => field.ge(constant),
        _ => unreachable!("In/NotIn handled separately"),
    }
}

/// Encode a real/float comparison.
fn encode_real_comparison(
    field: &z3::ast::Real,
    op: &RefinementOp,
    constant: &z3::ast::Real,
) -> z3::ast::Bool {
    match op {
        RefinementOp::Eq => field.eq(constant),
        RefinementOp::Ne => field.eq(constant).not(),
        RefinementOp::Lt => field.lt(constant),
        RefinementOp::Gt => field.gt(constant),
        RefinementOp::Le => field.le(constant),
        RefinementOp::Ge => field.ge(constant),
        _ => unreachable!("In/NotIn handled separately"),
    }
}

/// Encode `field in [values]` or `field not in [values]`.
///
/// `in` → OR(field == v1, field == v2, ...)
/// `not in` → AND(field != v1, field != v2, ...)
fn encode_membership(
    field_name: &str,
    items: &[RefinementValue],
    negate: bool,
) -> Result<z3::ast::Bool, String> {
    if items.is_empty() {
        // `in []` is always false, `not in []` is always true.
        return Ok(z3::ast::Bool::from_bool(!negate));
    }

    // Determine type from first element and create equality checks.
    let mut equalities = Vec::new();

    for item in items {
        match item {
            RefinementValue::String(s) => {
                let field = z3::ast::String::new_const(field_name);
                let constant = z3::ast::String::from_str(s)
                    .map_err(|e| format!("invalid string constant: {e}"))?;
                equalities.push(field.eq(&constant));
            }
            RefinementValue::Int(v) => {
                let field = z3::ast::Int::new_const(field_name);
                let constant = z3::ast::Int::from_i64(*v);
                equalities.push(field.eq(&constant));
            }
            RefinementValue::Bool(v) => {
                let field = z3::ast::Bool::new_const(field_name);
                let constant = z3::ast::Bool::from_bool(*v);
                equalities.push(field.eq(&constant));
            }
            RefinementValue::Float(v) => {
                let field = z3::ast::Real::new_const(field_name);
                let (num, den) = float_to_rational(*v);
                let constant = z3::ast::Real::from_rational(num, den);
                equalities.push(field.eq(&constant));
            }
            RefinementValue::List(_) => {
                return Err("nested lists not supported in membership tests".to_string());
            }
        }
    }

    let refs: Vec<&z3::ast::Bool> = equalities.iter().collect();

    if negate {
        // not in → AND(field != v1, field != v2, ...)
        let negated: Vec<z3::ast::Bool> = equalities.iter().map(|e| e.not()).collect();
        let neg_refs: Vec<&z3::ast::Bool> = negated.iter().collect();
        Ok(z3::ast::Bool::and(&neg_refs))
    } else {
        // in → OR(field == v1, field == v2, ...)
        Ok(z3::ast::Bool::or(&refs))
    }
}

/// Build a human-readable explanation for unsatisfiable predicates.
fn build_unsat_explanation(predicates: &[RefinementPredicate]) -> String {
    let constraints: Vec<String> = predicates
        .iter()
        .map(|p| format!("{} {} {}", p.field.name, op_symbol(&p.op), value_display(&p.value)))
        .collect();
    format!(
        "contradictory constraints: {}",
        constraints.join(" AND ")
    )
}

pub fn op_symbol_pub(op: &RefinementOp) -> &'static str {
    op_symbol(op)
}

pub fn value_display_pub(val: &RefinementValue) -> String {
    value_display(val)
}

fn op_symbol(op: &RefinementOp) -> &'static str {
    match op {
        RefinementOp::Eq => "==",
        RefinementOp::Ne => "!=",
        RefinementOp::Lt => "<",
        RefinementOp::Gt => ">",
        RefinementOp::Le => "<=",
        RefinementOp::Ge => ">=",
        RefinementOp::In => "in",
        RefinementOp::NotIn => "not in",
    }
}

fn value_display(val: &RefinementValue) -> String {
    match val {
        RefinementValue::Bool(b) => b.to_string(),
        RefinementValue::Int(n) => n.to_string(),
        RefinementValue::Float(f) => f.to_string(),
        RefinementValue::String(s) => format!("\"{s}\""),
        RefinementValue::List(items) => {
            let inner: Vec<String> = items.iter().map(value_display).collect();
            format!("[{}]", inner.join(", "))
        }
    }
}

/// Convert a float to a rational number (numerator/denominator).
/// Uses a simple approach: multiply by powers of 10 until we get an integer.
fn float_to_rational(f: f64) -> (i64, i64) {
    if f == f.floor() {
        return (f as i64, 1);
    }
    // Find appropriate denominator by counting decimal places.
    let s = format!("{f}");
    let decimals = s.find('.').map(|dot| s.len() - dot - 1).unwrap_or(0);
    let den = 10i64.pow(decimals as u32);
    let num = (f * den as f64).round() as i64;
    // Simplify with GCD.
    let g = gcd(num.unsigned_abs(), den.unsigned_abs()) as i64;
    (num / g, den / g)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}
