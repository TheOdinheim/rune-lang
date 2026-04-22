/// Source location tracking for every token.
///
/// Every token carries a Span so that error messages can point to the exact
/// location in the source file. This is a core requirement for adoption —
/// clear diagnostics depend on accurate spans.
///
/// Pillar: Security Baked In — precise source locations enable auditable
/// diagnostic reporting and prevent misattribution of errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Opaque file identifier (index into a file table maintained by the driver).
    pub file_id: u32,
    /// Byte offset of the first character of this token.
    pub start: u32,
    /// Byte offset one past the last character of this token.
    pub end: u32,
    /// 1-based line number where the token starts.
    pub line: u32,
    /// 1-based column (in bytes) where the token starts.
    pub column: u32,
}

impl Span {
    pub fn new(file_id: u32, start: u32, end: u32, line: u32, column: u32) -> Self {
        Self { file_id, start, end, line, column }
    }

    /// Length of the span in bytes.
    pub fn len(&self) -> u32 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// A token produced by the lexer, pairing a kind with its source location.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// Every distinct token the RUNE lexer can produce.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // ── Governance keywords ──────────────────────────────────────────
    Policy,
    Rule,
    Permit,
    Deny,
    Escalate,
    Quarantine,
    When,
    Unless,

    // ── Type keywords ────────────────────────────────────────────────
    Type,
    Struct,
    Enum,
    Fn,
    Let,
    Mut,
    Const,
    Impl,
    Trait,
    SelfValue, // `self` — the value
    // Note: `Self` (the type) can be added later as SelfType.

    // ── Capability keywords ──────────────────────────────────────────
    Capability,
    Require,
    Grant,
    Revoke,

    // ── Effect keywords ──────────────────────────────────────────────
    Effect,
    Perform,
    Handle,
    Pure,

    // ── Control flow ─────────────────────────────────────────────────
    If,
    Else,
    Match,
    For,
    In,
    While,
    Return,
    Break,
    Continue,

    // ── Module keywords ──────────────────────────────────────────────
    Mod,
    Use,
    Pub,
    As,
    Super,
    Extern,

    // ── Governance modifiers ─────────────────────────────────────────
    Attest,
    Audit,
    SecureZone,  // `secure_zone`
    UnsafeFfi,   // `unsafe_ffi`

    // ── Linearity keywords ────────────────────────────────────────────
    Linear,
    Affine,

    // ── Refinement type keywords ────────────────────────────────────
    Where,
    Satisfies,
    Not,

    // ── Boolean literals ─────────────────────────────────────────────
    True,
    False,

    // ── Literals ─────────────────────────────────────────────────────
    /// Integer literal. The raw text is stored so we can defer base/size
    /// parsing to a later compilation stage.
    IntLiteral(String),
    /// Floating-point literal, stored as raw text.
    FloatLiteral(String),
    /// String literal with escape sequences already resolved.
    StringLiteral(String),

    // ── Identifier ───────────────────────────────────────────────────
    Identifier(String),

    // ── Grouping / brackets ──────────────────────────────────────────
    LeftBrace,    // {
    RightBrace,   // }
    LeftParen,    // (
    RightParen,   // )
    LeftBracket,  // [
    RightBracket, // ]
    LeftAngle,    // <
    RightAngle,   // >

    // ── Arithmetic operators ─────────────────────────────────────────
    Plus,     // +
    Minus,    // -
    Star,     // *
    Slash,    // /
    Percent,  // %

    // ── Comparison operators ─────────────────────────────────────────
    EqualEqual,   // ==
    BangEqual,    // !=
    LessEqual,    // <=
    GreaterEqual, // >=
    // Note: < and > are LeftAngle / RightAngle above.

    // ── Logical operators ────────────────────────────────────────────
    AmpAmp,   // &&
    PipePipe, // ||
    Bang,     // !

    // ── Bitwise operators ────────────────────────────────────────────
    Amp,        // &
    Pipe,       // |
    Caret,      // ^
    Tilde,      // ~
    LessLess,   // <<
    GreaterGreater, // >>

    // ── Assignment operators ─────────────────────────────────────────
    Equal,        // =
    PlusEqual,    // +=
    MinusEqual,   // -=
    StarEqual,    // *=
    SlashEqual,   // /=
    PercentEqual, // %=

    // ── Delimiters / punctuation ─────────────────────────────────────
    Semicolon,   // ;
    Colon,       // :
    ColonColon,  // ::
    Comma,       // ,
    Dot,         // .
    DotDot,      // ..
    DotDotDot,   // ...
    Arrow,       // ->
    FatArrow,    // =>
    At,          // @

    // ── Special ──────────────────────────────────────────────────────
    /// End of file.
    Eof,
}

impl TokenKind {
    /// Try to match an identifier string to a keyword.
    pub fn keyword_from_str(s: &str) -> Option<TokenKind> {
        match s {
            // Policy / governance
            "policy"      => Some(TokenKind::Policy),
            "rule"        => Some(TokenKind::Rule),
            "permit"      => Some(TokenKind::Permit),
            "deny"        => Some(TokenKind::Deny),
            "escalate"    => Some(TokenKind::Escalate),
            "quarantine"  => Some(TokenKind::Quarantine),
            "when"        => Some(TokenKind::When),
            "unless"      => Some(TokenKind::Unless),

            // Types
            "type"   => Some(TokenKind::Type),
            "struct" => Some(TokenKind::Struct),
            "enum"   => Some(TokenKind::Enum),
            "fn"     => Some(TokenKind::Fn),
            "let"    => Some(TokenKind::Let),
            "mut"    => Some(TokenKind::Mut),
            "const"  => Some(TokenKind::Const),
            "impl"   => Some(TokenKind::Impl),
            "trait"  => Some(TokenKind::Trait),
            "self"   => Some(TokenKind::SelfValue),

            // Capabilities
            "capability" => Some(TokenKind::Capability),
            "require"    => Some(TokenKind::Require),
            "grant"      => Some(TokenKind::Grant),
            "revoke"     => Some(TokenKind::Revoke),

            // Effects
            "effect"  => Some(TokenKind::Effect),
            "perform" => Some(TokenKind::Perform),
            "handle"  => Some(TokenKind::Handle),
            "pure"    => Some(TokenKind::Pure),

            // Control flow
            "if"       => Some(TokenKind::If),
            "else"     => Some(TokenKind::Else),
            "match"    => Some(TokenKind::Match),
            "for"      => Some(TokenKind::For),
            "in"       => Some(TokenKind::In),
            "while"    => Some(TokenKind::While),
            "return"   => Some(TokenKind::Return),
            "break"    => Some(TokenKind::Break),
            "continue" => Some(TokenKind::Continue),

            // Modules
            "mod"   => Some(TokenKind::Mod),
            "use"   => Some(TokenKind::Use),
            "pub"   => Some(TokenKind::Pub),
            "as"    => Some(TokenKind::As),
            "super" => Some(TokenKind::Super),
            "extern" => Some(TokenKind::Extern),

            // Governance modifiers
            "attest"      => Some(TokenKind::Attest),
            "audit"       => Some(TokenKind::Audit),
            "secure_zone" => Some(TokenKind::SecureZone),
            "unsafe_ffi"  => Some(TokenKind::UnsafeFfi),

            // Linearity qualifiers
            "linear" => Some(TokenKind::Linear),
            "affine" => Some(TokenKind::Affine),

            // Refinement types
            "where"     => Some(TokenKind::Where),
            "satisfies" => Some(TokenKind::Satisfies),
            "not"       => Some(TokenKind::Not),

            // Boolean literals
            "true"  => Some(TokenKind::True),
            "false" => Some(TokenKind::False),

            _ => None,
        }
    }
}
