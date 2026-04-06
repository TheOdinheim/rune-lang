use crate::ast::nodes::*;
use crate::lexer::token::TokenKind;
use crate::parser::parser::{ParseError, Parser};

impl Parser {
    /// Parse a type expression, including optional `where` clause.
    pub fn parse_type_expr(&mut self) -> Result<TypeExpr, ParseError> {
        let base = self.parse_type_expr_base()?;

        // Check for `where { ... }` refinement clause.
        if self.check(&TokenKind::Where) {
            let where_clause = self.parse_where_clause()?;
            let span = self.merge_spans(base.span, where_clause.span);
            Ok(TypeExpr {
                kind: TypeExprKind::Refined {
                    base: Box::new(base),
                    where_clause,
                },
                span,
            })
        } else {
            Ok(base)
        }
    }

    /// Parse a base type expression (without where clause).
    fn parse_type_expr_base(&mut self) -> Result<TypeExpr, ParseError> {
        match self.current_kind().clone() {
            // Reference type: `&T` or `&mut T`
            TokenKind::Amp => {
                let start = self.advance().span;
                let is_mut = self.eat(&TokenKind::Mut);
                let inner = self.parse_type_expr()?;
                let end = self.previous_span();
                Ok(TypeExpr {
                    kind: TypeExprKind::Reference {
                        is_mut,
                        inner: Box::new(inner),
                    },
                    span: self.merge_spans(start, end),
                })
            }

            // Function type: `fn(A, B) -> C`
            TokenKind::Fn => {
                let start = self.advance().span;
                self.expect(&TokenKind::LeftParen)?;
                let mut params = Vec::new();
                while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                    params.push(self.parse_type_expr()?);
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RightParen)?;
                self.expect(&TokenKind::Arrow)?;
                let return_type = Box::new(self.parse_type_expr()?);
                let end = self.previous_span();
                Ok(TypeExpr {
                    kind: TypeExprKind::Function { params, return_type },
                    span: self.merge_spans(start, end),
                })
            }

            // Tuple or unit type: `()` or `(A, B)`
            TokenKind::LeftParen => {
                let start = self.advance().span;
                if self.check(&TokenKind::RightParen) {
                    let end = self.advance().span;
                    return Ok(TypeExpr {
                        kind: TypeExprKind::Unit,
                        span: self.merge_spans(start, end),
                    });
                }

                let first = self.parse_type_expr()?;
                if self.eat(&TokenKind::Comma) {
                    let mut types = vec![first];
                    while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                        types.push(self.parse_type_expr()?);
                        if !self.eat(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let end = self.expect(&TokenKind::RightParen)?;
                    Ok(TypeExpr {
                        kind: TypeExprKind::Tuple(types),
                        span: self.merge_spans(start, end),
                    })
                } else {
                    // Single type in parens — just unwrap the grouping.
                    let end = self.expect(&TokenKind::RightParen)?;
                    Ok(TypeExpr {
                        kind: first.kind,
                        span: self.merge_spans(start, end),
                    })
                }
            }

            // Named type (possibly with generic args): `i32`, `Vec<T>`, `std::io::Result`
            TokenKind::Identifier(_) => {
                let start_span = self.current_span();
                let path = self.parse_path()?;

                let type_args = if self.check(&TokenKind::LeftAngle) {
                    self.parse_type_arg_list()?
                } else {
                    Vec::new()
                };

                let end = self.previous_span();
                Ok(TypeExpr {
                    kind: TypeExprKind::Named { path, type_args },
                    span: self.merge_spans(start_span, end),
                })
            }

            _ => Err(self.error_expected("type")),
        }
    }

    /// Parse generic type arguments: `<T, U, Vec<W>>`.
    fn parse_type_arg_list(&mut self) -> Result<Vec<TypeExpr>, ParseError> {
        self.expect(&TokenKind::LeftAngle)?;
        let mut args = Vec::new();
        while !self.check(&TokenKind::RightAngle) && !self.at_eof() {
            args.push(self.parse_type_expr()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RightAngle)?;
        Ok(args)
    }

    // ── Refinement type parsing ──────────────────────────────────────

    /// Parse a where clause: `where { predicate, predicate, ... }`
    pub(crate) fn parse_where_clause(&mut self) -> Result<WhereClause, ParseError> {
        let start = self.expect(&TokenKind::Where)?;
        self.expect(&TokenKind::LeftBrace)?;

        let mut predicates = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            predicates.push(self.parse_refinement_predicate()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }

        let end = self.expect(&TokenKind::RightBrace)?;
        Ok(WhereClause {
            predicates,
            span: self.merge_spans(start, end),
        })
    }

    /// Parse a single refinement predicate: `field op value`
    fn parse_refinement_predicate(&mut self) -> Result<RefinementPredicate, ParseError> {
        let start = self.current_span();
        let field = self.expect_identifier()?;

        let op = self.parse_refinement_op()?;
        let value = self.parse_refinement_value(&op)?;

        let end = self.previous_span();
        Ok(RefinementPredicate {
            field,
            op,
            value,
            span: self.merge_spans(start, end),
        })
    }

    /// Parse a refinement comparison operator.
    fn parse_refinement_op(&mut self) -> Result<RefinementOp, ParseError> {
        match self.current_kind().clone() {
            TokenKind::EqualEqual => { self.advance(); Ok(RefinementOp::Eq) }
            TokenKind::BangEqual => { self.advance(); Ok(RefinementOp::Ne) }
            TokenKind::LeftAngle => { self.advance(); Ok(RefinementOp::Lt) }
            TokenKind::RightAngle => { self.advance(); Ok(RefinementOp::Gt) }
            TokenKind::LessEqual => { self.advance(); Ok(RefinementOp::Le) }
            TokenKind::GreaterEqual => { self.advance(); Ok(RefinementOp::Ge) }
            TokenKind::In => { self.advance(); Ok(RefinementOp::In) }
            TokenKind::Not => {
                self.advance();
                self.expect(&TokenKind::In)?;
                Ok(RefinementOp::NotIn)
            }
            _ => Err(self.error_expected("refinement operator (==, !=, <, >, <=, >=, in, not in)")),
        }
    }

    /// Parse a refinement value: literal or list.
    fn parse_refinement_value(&mut self, op: &RefinementOp) -> Result<RefinementValue, ParseError> {
        match op {
            RefinementOp::In | RefinementOp::NotIn => {
                // Expect a list: [value, value, ...]
                self.parse_refinement_list()
            }
            _ => self.parse_refinement_scalar(),
        }
    }

    /// Parse a single refinement scalar value.
    fn parse_refinement_scalar(&mut self) -> Result<RefinementValue, ParseError> {
        match self.current_kind().clone() {
            TokenKind::True => { self.advance(); Ok(RefinementValue::Bool(true)) }
            TokenKind::False => { self.advance(); Ok(RefinementValue::Bool(false)) }
            TokenKind::IntLiteral(s) => {
                let val: i64 = s.replace('_', "").parse().unwrap_or(0);
                self.advance();
                Ok(RefinementValue::Int(val))
            }
            TokenKind::FloatLiteral(s) => {
                let val: f64 = s.replace('_', "").parse().unwrap_or(0.0);
                self.advance();
                Ok(RefinementValue::Float(val))
            }
            TokenKind::StringLiteral(s) => {
                let val = s.clone();
                self.advance();
                Ok(RefinementValue::String(val))
            }
            TokenKind::Minus => {
                // Negative number: -42 or -3.14
                self.advance();
                match self.current_kind().clone() {
                    TokenKind::IntLiteral(s) => {
                        let val: i64 = s.replace('_', "").parse().unwrap_or(0);
                        self.advance();
                        Ok(RefinementValue::Int(-val))
                    }
                    TokenKind::FloatLiteral(s) => {
                        let val: f64 = s.replace('_', "").parse().unwrap_or(0.0);
                        self.advance();
                        Ok(RefinementValue::Float(-val))
                    }
                    _ => Err(self.error_expected("number after '-'")),
                }
            }
            _ => Err(self.error_expected("refinement value (bool, int, float, or string)")),
        }
    }

    /// Parse a refinement value list: `[value, value, ...]`
    fn parse_refinement_list(&mut self) -> Result<RefinementValue, ParseError> {
        self.expect(&TokenKind::LeftBracket)?;
        let mut values = Vec::new();
        while !self.check(&TokenKind::RightBracket) && !self.at_eof() {
            values.push(self.parse_refinement_scalar()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RightBracket)?;
        Ok(RefinementValue::List(values))
    }

    /// Parse a predicate block: `{ predicate, predicate, ... }`
    /// Used by `require expr satisfies { ... }`.
    pub(crate) fn parse_predicate_block(&mut self) -> Result<WhereClause, ParseError> {
        let start = self.expect(&TokenKind::LeftBrace)?;
        let mut predicates = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            predicates.push(self.parse_refinement_predicate()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        let end = self.expect(&TokenKind::RightBrace)?;
        Ok(WhereClause {
            predicates,
            span: self.merge_spans(start, end),
        })
    }
}
