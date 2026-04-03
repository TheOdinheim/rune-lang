use std::fmt;

// ═══════════════════════════════════════════════════════════════════════
// TypeId — lightweight handle into the type table
// ═══════════════════════════════════════════════════════════════════════

/// A lightweight, copyable handle into the [`TypeTable`]. Avoids cloning
/// full type trees — pass TypeIds around and resolve them when needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId(pub u32);

// ═══════════════════════════════════════════════════════════════════════
// TypeVarId — identity for inference variables
// ═══════════════════════════════════════════════════════════════════════

/// Unique identifier for a type variable created during inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeVarId(pub u32);

// ═══════════════════════════════════════════════════════════════════════
// Type — the compiler's internal type representation
// ═══════════════════════════════════════════════════════════════════════

/// Internal type representation, distinct from the AST's `TypeExpr`.
///
/// `TypeExpr` is *syntax* — what the user wrote. `Type` is *semantics* —
/// what the compiler resolved it to. A `TypeExpr` like `Vec<i32>` becomes
/// a `Type::Named { name: "Vec", args: [Type::Int] }`.
///
/// Governance-specific types (Capability, AttestedModel, PolicyDecision,
/// Effect) are first-class — they exist at the same level as Int and Bool,
/// not as library wrappers. This is what makes RUNE a governance-first
/// language: the type system *is* the enforcement mechanism.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    // ── Primitives ───────────────────────────────────────────────────
    Int,
    Float,
    Bool,
    String,
    Unit,

    // ── Composite types ──────────────────────────────────────────────

    /// A named type with resolved generic arguments.
    /// After resolution, `Vec<i32>` becomes `Named { name: "Vec", args: [Int] }`.
    Named {
        name: std::string::String,
        args: Vec<TypeId>,
    },

    /// Function type: `fn(A, B) -> C with effects { E1, E2 }`.
    /// Effects are part of the function type — undeclared effects are
    /// type errors, not runtime surprises.
    /// Pillar: Security Baked In.
    Function {
        params: Vec<TypeId>,
        return_type: TypeId,
        effects: Vec<std::string::String>,
    },

    /// Tuple type: `(A, B, C)`.
    Tuple(Vec<TypeId>),

    /// Reference type: `&T` or `&mut T`.
    Ref {
        is_mut: bool,
        inner: TypeId,
    },

    /// A type variable for inference. Created by `fresh_type_var()` and
    /// unified during type checking.
    Var(TypeVarId),

    /// The error type. Produced when type resolution fails. Allows type
    /// checking to continue after an error without cascading false
    /// positives — any operation on Error produces Error.
    Error,

    // ── Governance-specific types ────────────────────────────────────
    // These are what no other language has.

    /// A capability token type. Functions that access a resource must
    /// receive the corresponding capability as a parameter.
    ///
    /// Pillar: Zero Trust Throughout — no ambient authority.
    Capability {
        name: std::string::String,
        operations: Vec<CapabilityOp>,
    },

    /// A model that carries a cryptographic trust chain as type information.
    /// The compiler refuses to invoke an unattested model.
    ///
    /// Pillar: Zero Trust Throughout.
    AttestedModel {
        signer: TypeId,
        policy: TypeId,
        architecture: TypeId,
    },

    /// The type of governance decision expressions: permit, deny,
    /// escalate, quarantine. Rule bodies must evaluate to this type.
    PolicyDecision,

    /// An effect type declaration. Tracked in function signatures
    /// to ensure no undeclared side effects.
    ///
    /// Pillar: Security Baked In.
    Effect {
        name: std::string::String,
        operations: Vec<EffectOp>,
    },
}

/// An operation that a capability enables.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityOp {
    pub name: std::string::String,
    pub params: Vec<TypeId>,
    pub return_type: TypeId,
}

/// An operation declared within an effect type.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectOp {
    pub name: std::string::String,
    pub params: Vec<TypeId>,
    pub return_type: TypeId,
}

impl Type {
    /// Returns true if this type is the error sentinel.
    pub fn is_error(&self) -> bool {
        matches!(self, Type::Error)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Int => write!(f, "Int"),
            Type::Float => write!(f, "Float"),
            Type::Bool => write!(f, "Bool"),
            Type::String => write!(f, "String"),
            Type::Unit => write!(f, "()"),
            Type::Named { name, args } => {
                write!(f, "{name}")?;
                if !args.is_empty() {
                    write!(f, "<")?;
                    for (i, a) in args.iter().enumerate() {
                        if i > 0 { write!(f, ", ")?; }
                        write!(f, "TypeId({})", a.0)?;
                    }
                    write!(f, ">")?;
                }
                Ok(())
            }
            Type::Function { params, return_type, effects } => {
                write!(f, "fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "TypeId({})", p.0)?;
                }
                write!(f, ") -> TypeId({})", return_type.0)?;
                if !effects.is_empty() {
                    write!(f, " with effects {{ {} }}", effects.join(", "))?;
                }
                Ok(())
            }
            Type::Tuple(elems) => {
                write!(f, "(")?;
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "TypeId({})", e.0)?;
                }
                write!(f, ")")
            }
            Type::Ref { is_mut, inner } => {
                if *is_mut {
                    write!(f, "&mut TypeId({})", inner.0)
                } else {
                    write!(f, "&TypeId({})", inner.0)
                }
            }
            Type::Var(id) => write!(f, "?T{}", id.0),
            Type::Error => write!(f, "<error>"),
            Type::Capability { name, .. } => write!(f, "capability {name}"),
            Type::AttestedModel { .. } => write!(f, "AttestedModel<...>"),
            Type::PolicyDecision => write!(f, "PolicyDecision"),
            Type::Effect { name, .. } => write!(f, "effect {name}"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Type table — arena for interned types
// ═══════════════════════════════════════════════════════════════════════

/// Owns all interned types. Types are stored once and referenced by
/// [`TypeId`] everywhere else.
#[derive(Debug)]
pub struct TypeTable {
    types: Vec<Type>,
}

impl TypeTable {
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Intern a type and return its handle.
    pub fn intern(&mut self, ty: Type) -> TypeId {
        // Check for an existing identical type to avoid duplicates for
        // simple types. For complex types this is O(n) but the table
        // is small during M2; we can add a hash index later.
        for (i, existing) in self.types.iter().enumerate() {
            if *existing == ty {
                return TypeId(i as u32);
            }
        }
        let id = TypeId(self.types.len() as u32);
        self.types.push(ty);
        id
    }

    /// Look up a type by its handle. Panics if the id is out of range
    /// (this is a compiler-internal invariant, not user-facing).
    pub fn get(&self, id: TypeId) -> &Type {
        &self.types[id.0 as usize]
    }

    /// Number of interned types.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

impl Default for TypeTable {
    fn default() -> Self {
        Self::new()
    }
}
