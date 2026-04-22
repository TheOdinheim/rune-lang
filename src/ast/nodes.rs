use crate::lexer::token::Span;

// ═══════════════════════════════════════════════════════════════════════
// Top-level program
// ═══════════════════════════════════════════════════════════════════════

/// A complete RUNE source file: a sequence of top-level items.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceFile {
    pub items: Vec<Item>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Visibility
// ═══════════════════════════════════════════════════════════════════════

/// Visibility modifier for declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Declared with `pub` — visible outside the module.
    Public,
    /// No modifier — visible only within the module (default).
    Private,
}

impl Default for Visibility {
    fn default() -> Self {
        Visibility::Private
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Linearity — linear and affine type qualifiers
// ═══════════════════════════════════════════════════════════════════════

/// Linearity qualifier for types.
///
/// - `Unrestricted`: normal value semantics (copy/drop freely).
/// - `Linear`: must be consumed exactly once (no dup, no silent drop).
/// - `Affine`: must be consumed at most once (can drop, cannot dup).
///
/// Pillar: Security Baked In — linear/affine types enforce resource
/// discipline at compile time, preventing use-after-move and resource
/// leaks without runtime overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Linearity {
    #[default]
    Unrestricted,
    Linear,
    Affine,
}

impl std::fmt::Display for Linearity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Linearity::Unrestricted => write!(f, "unrestricted"),
            Linearity::Linear => write!(f, "linear"),
            Linearity::Affine => write!(f, "affine"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Items — top-level declarations
// ═══════════════════════════════════════════════════════════════════════

/// A top-level declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub kind: ItemKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ItemKind {
    // ── Governance ───────────────────────────────────────────────────
    Policy(PolicyDecl),
    Capability(CapabilityDecl),
    Effect(EffectDecl),

    // ── Types ────────────────────────────────────────────────────────
    TypeAlias(TypeAliasDecl),
    StructDef(StructDef),
    EnumDef(EnumDef),
    ImplBlock(ImplBlock),
    TraitDef(TraitDef),

    // ── Functions ────────────────────────────────────────────────────
    Function(FnDecl),

    // ── Modules ──────────────────────────────────────────────────────
    Module(ModuleDecl),
    Use(UseDecl),

    // ── FFI ──────────────────────────────────────────────────────────
    Extern(ExternBlock),

    // ── Constants ────────────────────────────────────────────────────
    Const(ConstDecl),

    // ── Refinement types ────────────────────────────────────────────
    /// `type RiskModel = Model where { predicates }`
    TypeConstraint(TypeConstraintDecl),
}

// ═══════════════════════════════════════════════════════════════════════
// Governance constructs
// ═══════════════════════════════════════════════════════════════════════

/// `[pub] policy <name> { <rules...> }`
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecl {
    pub visibility: Visibility,
    pub name: Ident,
    pub rules: Vec<RuleDef>,
    pub span: Span,
}

/// `rule <name>(<params>) [when <condition>] { <body> }`
///
/// The body evaluates to a governance decision: permit, deny, escalate,
/// or quarantine. The `when` clause is an optional guard condition.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleDef {
    pub name: Ident,
    pub params: Vec<Param>,
    pub when_clause: Option<Box<Expr>>,
    pub body: Box<Expr>,
    pub span: Span,
}

/// `capability <name> { <items...> }`
///
/// Declares a capability type. Functions that access a resource must
/// receive the corresponding capability token as a parameter.
///
/// Pillar: Zero Trust Throughout — no ambient authority.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityDecl {
    pub name: Ident,
    pub items: Vec<CapabilityItem>,
    pub span: Span,
}

/// An item inside a capability declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityItem {
    pub kind: CapabilityItemKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityItemKind {
    /// A function signature this capability enables.
    Function(FnSignature),
    /// `require <capability_path>;`
    Require(Path),
    /// `grant <capability_path>;`
    Grant(Path),
    /// `revoke <capability_path>;`
    Revoke(Path),
}

/// `effect <name> { <fn_signatures...> }`
///
/// Declares an effect type. Functions must declare which effects they
/// may perform; undeclared effects are compile errors.
///
/// Pillar: Security Baked In — all side effects tracked and auditable.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectDecl {
    pub name: Ident,
    pub operations: Vec<FnSignature>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Type definitions
// ═══════════════════════════════════════════════════════════════════════

/// `[pub] type <name> = <type>;`
#[derive(Debug, Clone, PartialEq)]
pub struct TypeAliasDecl {
    pub visibility: Visibility,
    pub name: Ident,
    pub ty: TypeExpr,
    pub span: Span,
}

/// `type RiskModel = Model where { bias_audit == true, ... };`
///
/// A refinement type alias — a named type with compile-time predicates.
///
/// Pillar: Security Baked In — governance constraints are named and reusable.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeConstraintDecl {
    pub visibility: Visibility,
    pub name: Ident,
    pub base_type: TypeExpr,
    pub where_clause: WhereClause,
    pub span: Span,
}

/// `[pub] struct <name> { <fields...> }`
#[derive(Debug, Clone, PartialEq)]
pub struct StructDef {
    pub visibility: Visibility,
    pub name: Ident,
    pub generic_params: Vec<GenericParam>,
    pub fields: Vec<FieldDef>,
    pub span: Span,
}

/// A single struct field: `[pub] <name>: <type>`
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDef {
    pub is_pub: bool,
    pub name: Ident,
    pub ty: TypeExpr,
    pub span: Span,
}

/// `[pub] enum <name> { <variants...> }`
#[derive(Debug, Clone, PartialEq)]
pub struct EnumDef {
    pub visibility: Visibility,
    pub name: Ident,
    pub generic_params: Vec<GenericParam>,
    pub variants: Vec<VariantDef>,
    pub span: Span,
}

/// A single enum variant, optionally carrying data.
#[derive(Debug, Clone, PartialEq)]
pub struct VariantDef {
    pub name: Ident,
    pub fields: VariantFields,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VariantFields {
    /// Unit variant: `None`
    Unit,
    /// Tuple variant: `Some(T)`
    Tuple(Vec<TypeExpr>),
    /// Struct variant: `Pair { x: i32, y: i32 }`
    Struct(Vec<FieldDef>),
}

/// `impl [<trait> for] <type> { <items...> }`
#[derive(Debug, Clone, PartialEq)]
pub struct ImplBlock {
    pub trait_path: Option<Path>,
    pub target_ty: TypeExpr,
    pub generic_params: Vec<GenericParam>,
    pub items: Vec<Item>,
    pub span: Span,
}

/// `trait <name> { <items...> }`
#[derive(Debug, Clone, PartialEq)]
pub struct TraitDef {
    pub name: Ident,
    pub generic_params: Vec<GenericParam>,
    pub items: Vec<TraitItem>,
    pub span: Span,
}

/// An item inside a trait definition.
#[derive(Debug, Clone, PartialEq)]
pub struct TraitItem {
    pub kind: TraitItemKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TraitItemKind {
    /// A method signature (possibly with a default body).
    Function(FnDecl),
    /// An associated type: `type Output;`
    TypeAlias(TypeAliasDecl),
}

/// A generic type parameter: `<T>`, `<T: Bound>`.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericParam {
    pub name: Ident,
    pub bounds: Vec<TypeExpr>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Functions
// ═══════════════════════════════════════════════════════════════════════

/// Full function declaration (signature + optional body).
///
/// ```text
/// [pub] fn <name>(<params>) [-> <return_type>] [with effects { <effects> }] { <body> }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct FnDecl {
    pub signature: FnSignature,
    pub body: Option<Box<Expr>>,
    pub span: Span,
}

/// Function signature without a body (used in traits, capabilities, effects).
#[derive(Debug, Clone, PartialEq)]
pub struct FnSignature {
    pub is_pub: bool,
    pub name: Ident,
    pub generic_params: Vec<GenericParam>,
    pub params: Vec<Param>,
    pub return_type: Option<TypeExpr>,
    pub effects: Vec<Path>,
    pub span: Span,
}

/// A function parameter: `[mut] <name>: <type>`
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    pub is_mut: bool,
    pub name: Ident,
    pub ty: TypeExpr,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Modules
// ═══════════════════════════════════════════════════════════════════════

/// `[pub] mod <name> { <items...> }` or `[pub] mod <name>;` (external file).
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleDecl {
    pub visibility: Visibility,
    pub name: Ident,
    pub items: Option<Vec<Item>>,
    pub span: Span,
}

/// `[pub] use <path> [as <alias>];`
#[derive(Debug, Clone, PartialEq)]
pub struct UseDecl {
    pub visibility: Visibility,
    pub path: Path,
    pub kind: UseKind,
    pub alias: Option<Ident>,
    pub span: Span,
}

/// The kind of use import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseKind {
    /// `use crypto::verify;` — imports one item.
    Single,
    /// `use crypto::*;` — imports everything public.
    Glob,
    /// `use crypto;` — imports the module itself.
    Module,
}

// ═══════════════════════════════════════════════════════════════════════
// FFI — extern blocks
// ═══════════════════════════════════════════════════════════════════════

/// `[pub] extern ["C"] { fn sha256(data: Int) -> Int; ... }`
///
/// Declares foreign functions that are implemented outside RUNE.
/// All extern functions implicitly carry the `ffi` effect.
///
/// Pillar: Security Baked In — the ffi effect must be declared by any
/// caller, creating an auditable boundary at every foreign call site.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternBlock {
    pub visibility: Visibility,
    pub abi: Option<String>,
    pub functions: Vec<ExternFnDecl>,
    pub span: Span,
}

/// A single foreign function declaration inside an extern block.
/// Has no body — the implementation is provided by foreign code at link time.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternFnDecl {
    pub name: Ident,
    pub params: Vec<Param>,
    pub return_type: Option<TypeExpr>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

/// `const <name>: <type> = <expr>;`
#[derive(Debug, Clone, PartialEq)]
pub struct ConstDecl {
    pub name: Ident,
    pub ty: TypeExpr,
    pub value: Box<Expr>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Refinement types — compile-time governance predicate verification
// ═══════════════════════════════════════════════════════════════════════

/// A single refinement predicate: `field op value`.
///
/// Example: `bias_audit == true`, `data_retention <= 30`.
///
/// Pillar: Security Baked In — constraints verified at compile time.
#[derive(Debug, Clone, PartialEq)]
pub struct RefinementPredicate {
    pub field: Ident,
    pub op: RefinementOp,
    pub value: RefinementValue,
    pub span: Span,
}

/// Comparison operator in a refinement predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefinementOp {
    Eq,    // ==
    Ne,    // !=
    Lt,    // <
    Gt,    // >
    Le,    // <=
    Ge,    // >=
    In,    // in [list]
    NotIn, // not in [list]
}

/// A constant value in a refinement predicate.
#[derive(Debug, Clone, PartialEq)]
pub enum RefinementValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<RefinementValue>),
}

/// A where clause: `where { predicate, predicate, ... }`.
#[derive(Debug, Clone, PartialEq)]
pub struct WhereClause {
    pub predicates: Vec<RefinementPredicate>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Type expressions
// ═══════════════════════════════════════════════════════════════════════

/// A type as written in source code.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeExpr {
    pub kind: TypeExprKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeExprKind {
    /// A named type, possibly with generic arguments: `i32`, `Vec<T>`, `std::io::Result`.
    Named {
        path: Path,
        type_args: Vec<TypeExpr>,
    },
    /// A tuple type: `(A, B, C)`.
    Tuple(Vec<TypeExpr>),
    /// A function type: `fn(A, B) -> C`.
    Function {
        params: Vec<TypeExpr>,
        return_type: Box<TypeExpr>,
    },
    /// The unit type: `()`.
    Unit,
    /// A reference: `&T` or `&mut T`.
    Reference {
        is_mut: bool,
        inner: Box<TypeExpr>,
    },
    /// A refinement type: `BaseType where { predicates }`.
    ///
    /// Pillar: Security Baked In — types carry governance constraints
    /// that the SMT solver verifies at compile time.
    Refined {
        base: Box<TypeExpr>,
        where_clause: WhereClause,
    },
    /// A linearity-qualified type: `linear T` or `affine T`.
    ///
    /// Pillar: Security Baked In — linear/affine qualifiers enforce
    /// resource discipline (exactly-once or at-most-once consumption)
    /// at compile time.
    Qualified {
        linearity: Linearity,
        inner: Box<TypeExpr>,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// Expressions
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    // ── Literals ─────────────────────────────────────────────────────
    IntLiteral(String),
    FloatLiteral(String),
    StringLiteral(String),
    BoolLiteral(bool),

    // ── Names and paths ──────────────────────────────────────────────
    Identifier(String),
    Path(Path),

    // ── Operators ────────────────────────────────────────────────────
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        operand: Box<Expr>,
    },

    // ── Function call and field access ───────────────────────────────
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    FieldAccess {
        object: Box<Expr>,
        field: Ident,
    },
    MethodCall {
        object: Box<Expr>,
        method: Ident,
        args: Vec<Expr>,
    },
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },

    // ── Control flow ─────────────────────────────────────────────────
    If {
        condition: Box<Expr>,
        then_branch: Box<Expr>,
        else_branch: Option<Box<Expr>>,
    },
    Match {
        subject: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    Block(Block),
    For {
        binding: Ident,
        iterator: Box<Expr>,
        body: Box<Expr>,
    },
    While {
        condition: Box<Expr>,
        body: Box<Expr>,
    },
    Return(Option<Box<Expr>>),
    Break(Option<Box<Expr>>),
    Continue,

    // ── Let binding (expression-level for blocks) ────────────────────
    Let {
        is_mut: bool,
        name: Ident,
        ty: Option<TypeExpr>,
        value: Box<Expr>,
    },

    // ── Assignment ───────────────────────────────────────────────────
    Assign {
        target: Box<Expr>,
        value: Box<Expr>,
    },
    CompoundAssign {
        op: BinOp,
        target: Box<Expr>,
        value: Box<Expr>,
    },

    // ── Governance expressions ───────────────────────────────────────
    /// `permit` — governance decision.
    Permit,
    /// `deny` — governance decision.
    Deny,
    /// `escalate` — governance decision.
    Escalate,
    /// `quarantine` — governance decision.
    Quarantine,

    /// `attest(<expr>)` — verify model/artifact trust chain.
    /// Pillar: Zero Trust Throughout.
    Attest(Box<Expr>),

    /// `audit { <body> }` — audited block, compiler auto-instruments.
    /// Pillar: Security Baked In.
    Audit(Box<Expr>),

    /// `secure_zone { <capabilities> } { <body> }` — isolation boundary.
    /// Pillar: Assumed Breach.
    SecureZone {
        capabilities: Vec<Path>,
        body: Box<Expr>,
    },

    /// `unsafe_ffi { <body> }` — escape hatch for foreign calls.
    /// Pillar: Security Baked In (auditable escape hatch).
    UnsafeFfi(Box<Expr>),

    // ── Effects ──────────────────────────────────────────────────────
    /// `perform <effect>::<operation>(<args>)`
    Perform {
        effect: Path,
        args: Vec<Expr>,
    },

    /// `handle <expr> { <handlers...> }`
    Handle {
        expr: Box<Expr>,
        handlers: Vec<Handler>,
    },

    /// `require <expr> satisfies { predicates }`
    ///
    /// Runtime assertion that a value meets refinement predicates.
    /// Pillar: Zero Trust Throughout — every value verified before use.
    Require {
        target: Box<Expr>,
        predicates: WhereClause,
    },

    // ── Struct / enum construction ───────────────────────────────────
    StructLiteral {
        path: Path,
        fields: Vec<FieldInit>,
        span: Span,
    },

    /// Tuple expression: `(a, b, c)`
    Tuple(Vec<Expr>),

    /// Range expression: `a..b` or `a...b`
    Range {
        start: Option<Box<Expr>>,
        end: Option<Box<Expr>>,
        inclusive: bool,
    },
}

// ═══════════════════════════════════════════════════════════════════════
// Supporting expression nodes
// ═══════════════════════════════════════════════════════════════════════

/// A block: `{ <statements...> [<trailing_expr>] }`
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

/// A statement within a block.
#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StmtKind {
    /// An item declaration (fn, struct, etc.) inside a block.
    Item(Item),
    /// An expression used as a statement (with trailing semicolon).
    Expr(Expr),
    /// A trailing expression without semicolon (the block's value).
    TailExpr(Expr),
}

/// `match` arm: `<pattern> => <body>`
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Box<Expr>>,
    pub body: Box<Expr>,
    pub span: Span,
}

/// Pattern for match arms and let bindings.
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub kind: PatternKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternKind {
    /// `_` — matches anything.
    Wildcard,
    /// A binding: `x`, `mut x`.
    Binding { is_mut: bool, name: Ident },
    /// A literal pattern: `42`, `"hello"`, `true`.
    Literal(Box<Expr>),
    /// A constructor pattern: `Some(x)`, `Err(e)`.
    Constructor { path: Path, fields: Vec<Pattern> },
    /// A struct pattern: `Point { x, y }`.
    Struct { path: Path, fields: Vec<FieldPattern> },
    /// A tuple pattern: `(a, b)`.
    Tuple(Vec<Pattern>),
    /// A path pattern (for enum unit variants or constants): `None`.
    Path(Path),
}

/// A field within a struct pattern: `name: pattern` or shorthand `name`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldPattern {
    pub name: Ident,
    pub pattern: Option<Pattern>,
    pub span: Span,
}

/// An effect handler entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Handler {
    pub effect: Path,
    pub params: Vec<Param>,
    pub body: Box<Expr>,
    pub span: Span,
}

/// A field initializer in a struct literal: `name: expr` or shorthand `name`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldInit {
    pub name: Ident,
    pub value: Option<Expr>,
    pub span: Span,
}

// ═══════════════════════════════════════════════════════════════════════
// Operators
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    // Arithmetic
    Add,       // +
    Sub,       // -
    Mul,       // *
    Div,       // /
    Mod,       // %

    // Comparison
    Eq,        // ==
    Ne,        // !=
    Lt,        // <
    Gt,        // >
    Le,        // <=
    Ge,        // >=

    // Logical
    And,       // &&
    Or,        // ||

    // Bitwise
    BitAnd,    // &
    BitOr,     // |
    BitXor,    // ^
    Shl,       // <<
    Shr,       // >>
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,       // -
    Not,       // !
    BitNot,    // ~
}

// ═══════════════════════════════════════════════════════════════════════
// Common building blocks
// ═══════════════════════════════════════════════════════════════════════

/// An identifier with its source location.
#[derive(Debug, Clone, PartialEq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

impl Ident {
    pub fn new(name: String, span: Span) -> Self {
        Self { name, span }
    }
}

/// A qualified path: `std::collections::HashMap`.
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub segments: Vec<Ident>,
    pub span: Span,
}

impl Path {
    /// Single-segment path from an identifier.
    pub fn from_ident(ident: Ident) -> Self {
        let span = ident.span;
        Self { segments: vec![ident], span }
    }
}
