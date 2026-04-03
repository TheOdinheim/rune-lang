use crate::ast::nodes::*;
use crate::lexer::token::TokenKind;
use crate::parser::parser::{ParseError, Parser};

impl Parser {
    /// Parse a type expression.
    pub fn parse_type_expr(&mut self) -> Result<TypeExpr, ParseError> {
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
}
