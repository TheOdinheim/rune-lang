use crate::ast::nodes::*;
use crate::lexer::token::TokenKind;
use crate::parser::parser::{ParseError, Parser};

/// Operator precedence levels for Pratt parsing (lower = binds looser).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Precedence {
    None = 0,
    Assignment = 1,  // = += -= *= /= %=
    Or = 2,          // ||
    And = 3,         // &&
    BitOr = 4,       // |
    BitXor = 5,      // ^
    BitAnd = 6,      // &
    Equality = 7,    // == !=
    Comparison = 8,  // < > <= >=
    Shift = 9,       // << >>
    Term = 10,       // + -
    Factor = 11,     // * / %
    Unary = 12,      // ! - ~
    Call = 13,       // () . []
}

fn infix_precedence(kind: &TokenKind) -> Option<(Precedence, BinOp)> {
    match kind {
        TokenKind::PipePipe => Some((Precedence::Or, BinOp::Or)),
        TokenKind::AmpAmp => Some((Precedence::And, BinOp::And)),
        TokenKind::Pipe => Some((Precedence::BitOr, BinOp::BitOr)),
        TokenKind::Caret => Some((Precedence::BitXor, BinOp::BitXor)),
        TokenKind::Amp => Some((Precedence::BitAnd, BinOp::BitAnd)),
        TokenKind::EqualEqual => Some((Precedence::Equality, BinOp::Eq)),
        TokenKind::BangEqual => Some((Precedence::Equality, BinOp::Ne)),
        TokenKind::LeftAngle => Some((Precedence::Comparison, BinOp::Lt)),
        TokenKind::RightAngle => Some((Precedence::Comparison, BinOp::Gt)),
        TokenKind::LessEqual => Some((Precedence::Comparison, BinOp::Le)),
        TokenKind::GreaterEqual => Some((Precedence::Comparison, BinOp::Ge)),
        TokenKind::LessLess => Some((Precedence::Shift, BinOp::Shl)),
        TokenKind::GreaterGreater => Some((Precedence::Shift, BinOp::Shr)),
        TokenKind::Plus => Some((Precedence::Term, BinOp::Add)),
        TokenKind::Minus => Some((Precedence::Term, BinOp::Sub)),
        TokenKind::Star => Some((Precedence::Factor, BinOp::Mul)),
        TokenKind::Slash => Some((Precedence::Factor, BinOp::Div)),
        TokenKind::Percent => Some((Precedence::Factor, BinOp::Mod)),
        _ => None,
    }
}

fn compound_assign_op(kind: &TokenKind) -> Option<BinOp> {
    match kind {
        TokenKind::PlusEqual => Some(BinOp::Add),
        TokenKind::MinusEqual => Some(BinOp::Sub),
        TokenKind::StarEqual => Some(BinOp::Mul),
        TokenKind::SlashEqual => Some(BinOp::Div),
        TokenKind::PercentEqual => Some(BinOp::Mod),
        _ => None,
    }
}

impl Parser {
    /// Parse an expression. Entry point for all expression parsing.
    pub fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_bp(Precedence::None)
    }

    /// Pratt parser core: parse an expression with the given minimum precedence.
    fn parse_expr_bp(&mut self, min_prec: Precedence) -> Result<Expr, ParseError> {
        let mut left = self.parse_prefix()?;

        loop {
            if self.at_eof() {
                break;
            }

            // Assignment: `expr = value` or `expr += value`
            if min_prec <= Precedence::Assignment {
                if self.check(&TokenKind::Equal) {
                    self.advance();
                    let value = self.parse_expr_bp(Precedence::Assignment)?;
                    let span = self.merge_spans(left.span, value.span);
                    left = Expr {
                        kind: ExprKind::Assign {
                            target: Box::new(left),
                            value: Box::new(value),
                        },
                        span,
                    };
                    continue;
                }
                if let Some(op) = compound_assign_op(self.current_kind()) {
                    self.advance();
                    let value = self.parse_expr_bp(Precedence::Assignment)?;
                    let span = self.merge_spans(left.span, value.span);
                    left = Expr {
                        kind: ExprKind::CompoundAssign {
                            op,
                            target: Box::new(left),
                            value: Box::new(value),
                        },
                        span,
                    };
                    continue;
                }
            }

            // Binary infix operators.
            if let Some((prec, op)) = infix_precedence(self.current_kind()) {
                if prec <= min_prec {
                    break;
                }
                self.advance();
                let right = self.parse_expr_bp(prec)?;
                let span = self.merge_spans(left.span, right.span);
                left = Expr {
                    kind: ExprKind::Binary {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    span,
                };
                continue;
            }

            // Postfix: function call `expr(args...)`
            if self.check(&TokenKind::LeftParen) {
                if min_prec > Precedence::Call {
                    break;
                }
                self.advance();
                let args = self.parse_arg_list()?;
                let end = self.previous_span();
                let span = self.merge_spans(left.span, end);
                left = Expr {
                    kind: ExprKind::Call {
                        callee: Box::new(left),
                        args,
                    },
                    span,
                };
                continue;
            }

            // Postfix: field access `expr.field` or method call `expr.method(args)`
            if self.check(&TokenKind::Dot) {
                if min_prec > Precedence::Call {
                    break;
                }
                self.advance();
                let field = self.expect_identifier()?;
                if self.check(&TokenKind::LeftParen) {
                    self.advance();
                    let args = self.parse_arg_list()?;
                    let end = self.previous_span();
                    let span = self.merge_spans(left.span, end);
                    left = Expr {
                        kind: ExprKind::MethodCall {
                            object: Box::new(left),
                            method: field,
                            args,
                        },
                        span,
                    };
                } else {
                    let span = self.merge_spans(left.span, field.span);
                    left = Expr {
                        kind: ExprKind::FieldAccess {
                            object: Box::new(left),
                            field,
                        },
                        span,
                    };
                }
                continue;
            }

            // Postfix: index `expr[index]`
            if self.check(&TokenKind::LeftBracket) {
                if min_prec > Precedence::Call {
                    break;
                }
                self.advance();
                let index = self.parse_expr()?;
                let end = self.expect(&TokenKind::RightBracket)?;
                let span = self.merge_spans(left.span, end);
                left = Expr {
                    kind: ExprKind::Index {
                        object: Box::new(left),
                        index: Box::new(index),
                    },
                    span,
                };
                continue;
            }

            break;
        }

        Ok(left)
    }

    /// Parse a prefix expression (atoms, unary operators, control flow).
    fn parse_prefix(&mut self) -> Result<Expr, ParseError> {
        match self.current_kind().clone() {
            // ── Literals ─────────────────────────────────────────
            TokenKind::IntLiteral(val) => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::IntLiteral(val), span })
            }
            TokenKind::FloatLiteral(val) => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::FloatLiteral(val), span })
            }
            TokenKind::StringLiteral(val) => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::StringLiteral(val), span })
            }
            TokenKind::True => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::BoolLiteral(true), span })
            }
            TokenKind::False => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::BoolLiteral(false), span })
            }

            // ── Identifiers and paths ────────────────────────────
            TokenKind::Identifier(_) => {
                let start_span = self.current_span();
                let ident = self.expect_identifier()?;

                if self.check(&TokenKind::ColonColon) {
                    // Path expression: foo::bar::baz
                    let mut segments = vec![ident];
                    while self.eat(&TokenKind::ColonColon) {
                        segments.push(self.expect_identifier()?);
                    }
                    let end = self.previous_span();
                    let path = Path {
                        segments,
                        span: self.merge_spans(start_span, end),
                    };
                    Ok(Expr {
                        kind: ExprKind::Path(path.clone()),
                        span: path.span,
                    })
                } else {
                    Ok(Expr {
                        kind: ExprKind::Identifier(ident.name),
                        span: ident.span,
                    })
                }
            }

            // ── self as expression ────────────────────────────────
            TokenKind::SelfValue => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Identifier("self".to_string()), span })
            }

            // ── Unary operators ──────────────────────────────────
            TokenKind::Bang => {
                let start = self.advance().span;
                let operand = self.parse_expr_bp(Precedence::Unary)?;
                let span = self.merge_spans(start, operand.span);
                Ok(Expr {
                    kind: ExprKind::Unary { op: UnaryOp::Not, operand: Box::new(operand) },
                    span,
                })
            }
            TokenKind::Minus => {
                let start = self.advance().span;
                let operand = self.parse_expr_bp(Precedence::Unary)?;
                let span = self.merge_spans(start, operand.span);
                Ok(Expr {
                    kind: ExprKind::Unary { op: UnaryOp::Neg, operand: Box::new(operand) },
                    span,
                })
            }
            TokenKind::Tilde => {
                let start = self.advance().span;
                let operand = self.parse_expr_bp(Precedence::Unary)?;
                let span = self.merge_spans(start, operand.span);
                Ok(Expr {
                    kind: ExprKind::Unary { op: UnaryOp::BitNot, operand: Box::new(operand) },
                    span,
                })
            }

            // ── Parenthesized / tuple expressions ────────────────
            TokenKind::LeftParen => {
                let start = self.advance().span;
                if self.check(&TokenKind::RightParen) {
                    // Unit: ()
                    let end = self.advance().span;
                    return Ok(Expr {
                        kind: ExprKind::Tuple(Vec::new()),
                        span: self.merge_spans(start, end),
                    });
                }

                let first = self.parse_expr()?;
                if self.eat(&TokenKind::Comma) {
                    // Tuple: (a, b, ...)
                    let mut elements = vec![first];
                    while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                        elements.push(self.parse_expr()?);
                        if !self.eat(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let end = self.expect(&TokenKind::RightParen)?;
                    Ok(Expr {
                        kind: ExprKind::Tuple(elements),
                        span: self.merge_spans(start, end),
                    })
                } else {
                    // Grouping: (expr)
                    let end = self.expect(&TokenKind::RightParen)?;
                    Ok(Expr {
                        kind: first.kind,
                        span: self.merge_spans(start, end),
                    })
                }
            }

            // ── Block expression ─────────────────────────────────
            TokenKind::LeftBrace => self.parse_block_expr(),

            // ── If expression ────────────────────────────────────
            TokenKind::If => self.parse_if_expr(),

            // ── Match expression ─────────────────────────────────
            TokenKind::Match => self.parse_match_expr(),

            // ── For expression ───────────────────────────────────
            TokenKind::For => self.parse_for_expr(),

            // ── While expression ─────────────────────────────────
            TokenKind::While => self.parse_while_expr(),

            // ── Return ───────────────────────────────────────────
            TokenKind::Return => {
                let start = self.advance().span;
                let value = if self.is_expr_end() {
                    None
                } else {
                    Some(Box::new(self.parse_expr()?))
                };
                let end = value.as_ref().map(|v| v.span).unwrap_or(start);
                Ok(Expr {
                    kind: ExprKind::Return(value),
                    span: self.merge_spans(start, end),
                })
            }

            // ── Break ────────────────────────────────────────────
            TokenKind::Break => {
                let start = self.advance().span;
                let value = if self.is_expr_end() {
                    None
                } else {
                    Some(Box::new(self.parse_expr()?))
                };
                let end = value.as_ref().map(|v| v.span).unwrap_or(start);
                Ok(Expr {
                    kind: ExprKind::Break(value),
                    span: self.merge_spans(start, end),
                })
            }

            // ── Continue ─────────────────────────────────────────
            TokenKind::Continue => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Continue, span })
            }

            // ── Let binding ──────────────────────────────────────
            TokenKind::Let => self.parse_let_expr(),

            // ── Governance decisions ──────────────────────────────
            TokenKind::Permit => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Permit, span })
            }
            TokenKind::Deny => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Deny, span })
            }
            TokenKind::Escalate => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Escalate, span })
            }
            TokenKind::Quarantine => {
                let span = self.advance().span;
                Ok(Expr { kind: ExprKind::Quarantine, span })
            }

            // ── Governance expressions ───────────────────────────
            TokenKind::Attest => self.parse_attest_expr(),
            TokenKind::Audit => self.parse_audit_expr(),
            TokenKind::SecureZone => self.parse_secure_zone_expr(),
            TokenKind::UnsafeFfi => self.parse_unsafe_ffi_expr(),

            // ── Effect expressions ───────────────────────────────
            TokenKind::Perform => self.parse_perform_expr(),
            TokenKind::Handle => self.parse_handle_expr(),

            // ── Refinement type expressions ─────────────────────
            TokenKind::Require => self.parse_require_expr(),

            _ => Err(self.error_at_current("expected expression")),
        }
    }

    // ── Argument list for function calls ─────────────────────────────

    fn parse_arg_list(&mut self) -> Result<Vec<Expr>, ParseError> {
        let mut args = Vec::new();
        while !self.check(&TokenKind::RightParen) && !self.at_eof() {
            args.push(self.parse_expr()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RightParen)?;
        Ok(args)
    }

    // ── If expression ────────────────────────────────────────────────

    fn parse_if_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `if`
        let condition = Box::new(self.parse_expr_bp(Precedence::None)?);
        let then_branch = Box::new(self.parse_block_expr()?);
        let else_branch = if self.eat(&TokenKind::Else) {
            if self.check(&TokenKind::If) {
                Some(Box::new(self.parse_if_expr()?))
            } else {
                Some(Box::new(self.parse_block_expr()?))
            }
        } else {
            None
        };
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::If { condition, then_branch, else_branch },
            span: self.merge_spans(start, end),
        })
    }

    // ── Match expression ─────────────────────────────────────────────

    fn parse_match_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `match`
        let subject = Box::new(self.parse_expr_bp(Precedence::None)?);
        self.expect(&TokenKind::LeftBrace)?;

        let mut arms = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            arms.push(self.parse_match_arm()?);
            // Allow optional comma between arms.
            self.eat(&TokenKind::Comma);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(Expr {
            kind: ExprKind::Match { subject, arms },
            span: self.merge_spans(start, end),
        })
    }

    fn parse_match_arm(&mut self) -> Result<MatchArm, ParseError> {
        let start_span = self.current_span();
        let pattern = self.parse_pattern()?;
        let guard = if self.eat(&TokenKind::When) {
            Some(Box::new(self.parse_expr()?))
        } else {
            None
        };
        self.expect(&TokenKind::FatArrow)?;
        let body = Box::new(self.parse_expr()?);
        let end = self.previous_span();
        Ok(MatchArm {
            pattern,
            guard,
            body,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── For expression ───────────────────────────────────────────────

    fn parse_for_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `for`
        let binding = self.expect_identifier()?;
        self.expect(&TokenKind::In)?;
        let iterator = Box::new(self.parse_expr_bp(Precedence::None)?);
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::For { binding, iterator, body },
            span: self.merge_spans(start, end),
        })
    }

    // ── While expression ─────────────────────────────────────────────

    fn parse_while_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `while`
        let condition = Box::new(self.parse_expr_bp(Precedence::None)?);
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::While { condition, body },
            span: self.merge_spans(start, end),
        })
    }

    // ── Let binding ──────────────────────────────────────────────────

    fn parse_let_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `let`
        let is_mut = self.eat(&TokenKind::Mut);
        let name = self.expect_identifier()?;
        let ty = if self.eat(&TokenKind::Colon) {
            Some(self.parse_type_expr()?)
        } else {
            None
        };
        self.expect(&TokenKind::Equal)?;
        let value = Box::new(self.parse_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::Let { is_mut, name, ty, value },
            span: self.merge_spans(start, end),
        })
    }

    // ── Governance expressions ───────────────────────────────────────

    fn parse_attest_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `attest`
        self.expect(&TokenKind::LeftParen)?;
        let inner = Box::new(self.parse_expr()?);
        let end = self.expect(&TokenKind::RightParen)?;
        Ok(Expr {
            kind: ExprKind::Attest(inner),
            span: self.merge_spans(start, end),
        })
    }

    fn parse_audit_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `audit`
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::Audit(body),
            span: self.merge_spans(start, end),
        })
    }

    fn parse_secure_zone_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `secure_zone`
        // Parse capability list: { Cap1, Cap2 }
        self.expect(&TokenKind::LeftBrace)?;
        let mut capabilities = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            capabilities.push(self.parse_path()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RightBrace)?;
        // Parse body block
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::SecureZone { capabilities, body },
            span: self.merge_spans(start, end),
        })
    }

    fn parse_unsafe_ffi_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `unsafe_ffi`
        let body = Box::new(self.parse_block_expr()?);
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::UnsafeFfi(body),
            span: self.merge_spans(start, end),
        })
    }

    // ── Effect expressions ───────────────────────────────────────────

    fn parse_perform_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `perform`
        let effect = self.parse_path()?;
        self.expect(&TokenKind::LeftParen)?;
        let args = self.parse_arg_list()?;
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::Perform { effect, args },
            span: self.merge_spans(start, end),
        })
    }

    fn parse_handle_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `handle`
        let expr = Box::new(self.parse_expr_bp(Precedence::None)?);
        self.expect(&TokenKind::LeftBrace)?;

        let mut handlers = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            handlers.push(self.parse_handler()?);
        }
        let end = self.expect(&TokenKind::RightBrace)?;

        Ok(Expr {
            kind: ExprKind::Handle { expr, handlers },
            span: self.merge_spans(start, end),
        })
    }

    fn parse_handler(&mut self) -> Result<Handler, ParseError> {
        let start_span = self.current_span();
        let effect = self.parse_path()?;
        let params = self.parse_param_list()?;
        self.expect(&TokenKind::FatArrow)?;
        let body = Box::new(self.parse_expr()?);
        // Allow optional comma/semicolon.
        self.eat(&TokenKind::Comma);
        let end = self.previous_span();
        Ok(Handler {
            effect,
            params,
            body,
            span: self.merge_spans(start_span, end),
        })
    }

    // ── Refinement type expressions ─────────────────────────────────

    /// Parse `require <expr> satisfies { predicates }`.
    fn parse_require_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.advance().span; // consume `require`
        let target = Box::new(self.parse_expr_bp(Precedence::None)?);
        self.expect(&TokenKind::Satisfies)?;
        let predicates = self.parse_predicate_block()?;
        let end = self.previous_span();
        Ok(Expr {
            kind: ExprKind::Require { target, predicates },
            span: self.merge_spans(start, end),
        })
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /// Check if the current token naturally ends an expression.
    fn is_expr_end(&self) -> bool {
        matches!(
            self.current_kind(),
            TokenKind::Semicolon
                | TokenKind::RightBrace
                | TokenKind::RightParen
                | TokenKind::Comma
                | TokenKind::Eof
        )
    }
}
