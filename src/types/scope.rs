use crate::lexer::token::Span;
use crate::types::ty::TypeId;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════
// Symbol — what a name resolves to
// ═══════════════════════════════════════════════════════════════════════

/// A resolved symbol in the symbol table.
#[derive(Debug, Clone, PartialEq)]
pub enum Symbol {
    /// A local or parameter binding.
    Variable {
        ty: TypeId,
        is_mut: bool,
        span: Span,
    },
    /// A function declaration.
    Function {
        params: Vec<TypeId>,
        return_type: TypeId,
        effects: Vec<String>,
        span: Span,
    },
    /// A type definition (struct, enum, type alias).
    Type {
        ty: TypeId,
        span: Span,
    },
    /// A capability declaration.
    Capability {
        ty: TypeId,
        span: Span,
    },
    /// An effect declaration.
    Effect {
        ty: TypeId,
        span: Span,
    },
}

impl Symbol {
    /// The span where this symbol was defined.
    pub fn definition_span(&self) -> Span {
        match self {
            Symbol::Variable { span, .. }
            | Symbol::Function { span, .. }
            | Symbol::Type { span, .. }
            | Symbol::Capability { span, .. }
            | Symbol::Effect { span, .. } => *span,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Scope — a single lexical scope
// ═══════════════════════════════════════════════════════════════════════

/// A single lexical scope containing name → symbol bindings.
#[derive(Debug)]
struct Scope {
    bindings: HashMap<String, Symbol>,
}

impl Scope {
    fn new() -> Self {
        Self { bindings: HashMap::new() }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ScopeStack — lexical scope chain
// ═══════════════════════════════════════════════════════════════════════

/// A scope error produced by the symbol table.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scope error at line {}, column {}: {}",
            self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for ScopeError {}

/// A stack of lexical scopes. Name lookup walks from the innermost
/// (current) scope outward to the global scope.
///
/// The stack always has at least one scope (the global scope).
///
/// Pillar: Assumed Breach — every module and block gets its own scope
/// boundary, enforcing isolation by construction.
#[derive(Debug)]
pub struct ScopeStack {
    scopes: Vec<Scope>,
}

impl ScopeStack {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::new()], // global scope
        }
    }

    /// Push a new child scope (entering a block, function, module, etc.).
    pub fn enter_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    /// Pop the current scope (leaving a block, function, module, etc.).
    ///
    /// Panics if called on the global scope — this is a compiler-internal
    /// invariant, not a user error.
    pub fn exit_scope(&mut self) {
        assert!(
            self.scopes.len() > 1,
            "cannot exit the global scope"
        );
        self.scopes.pop();
    }

    /// Current nesting depth (0 = global scope).
    pub fn depth(&self) -> usize {
        self.scopes.len() - 1
    }

    /// Define a name in the *current* scope. Returns an error if the
    /// name is already defined in this scope (shadowing across scopes
    /// is allowed, redefinition within the same scope is not).
    pub fn define(
        &mut self,
        name: &str,
        symbol: Symbol,
        span: Span,
    ) -> Result<(), ScopeError> {
        let current = self.scopes.last_mut().expect("scope stack is empty");
        if let Some(existing) = current.bindings.get(name) {
            return Err(ScopeError {
                message: format!(
                    "`{name}` is already defined in this scope (first defined at line {}, column {})",
                    existing.definition_span().line,
                    existing.definition_span().column,
                ),
                span,
            });
        }
        current.bindings.insert(name.to_string(), symbol);
        Ok(())
    }

    /// Look up a name, walking from the innermost scope outward.
    /// Returns `None` if the name is not found in any scope.
    pub fn lookup(&self, name: &str) -> Option<&Symbol> {
        for scope in self.scopes.iter().rev() {
            if let Some(sym) = scope.bindings.get(name) {
                return Some(sym);
            }
        }
        None
    }

    /// Look up a name only in the current (innermost) scope.
    pub fn lookup_current(&self, name: &str) -> Option<&Symbol> {
        self.scopes.last().and_then(|s| s.bindings.get(name))
    }
}

impl Default for ScopeStack {
    fn default() -> Self {
        Self::new()
    }
}
