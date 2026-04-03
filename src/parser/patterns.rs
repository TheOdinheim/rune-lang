use crate::ast::nodes::*;
use crate::lexer::token::TokenKind;
use crate::parser::parser::{ParseError, Parser};

impl Parser {
    /// Parse a pattern (for match arms, future let-destructuring, etc.).
    pub fn parse_pattern(&mut self) -> Result<Pattern, ParseError> {
        match self.current_kind().clone() {
            // Wildcard: `_`
            TokenKind::Identifier(ref name) if name == "_" => {
                let span = self.advance().span;
                Ok(Pattern { kind: PatternKind::Wildcard, span })
            }

            // Mutable binding: `mut x`
            TokenKind::Mut => {
                let start = self.advance().span;
                let name = self.expect_identifier()?;
                let end = name.span;
                Ok(Pattern {
                    kind: PatternKind::Binding { is_mut: true, name },
                    span: self.merge_spans(start, end),
                })
            }

            // Identifier: could be a binding, path, or constructor.
            TokenKind::Identifier(_) => {
                let start_span = self.current_span();
                let ident = self.expect_identifier()?;

                // Path continuation: `Foo::Bar`
                if self.check(&TokenKind::ColonColon) {
                    let mut segments = vec![ident];
                    while self.eat(&TokenKind::ColonColon) {
                        segments.push(self.expect_identifier()?);
                    }
                    let end = self.previous_span();
                    let path = Path {
                        segments,
                        span: self.merge_spans(start_span, end),
                    };

                    return self.parse_pattern_after_path(path);
                }

                // Constructor: `Some(x)`
                if self.check(&TokenKind::LeftParen) {
                    let path = Path::from_ident(ident);
                    return self.parse_pattern_after_path(path);
                }

                // Struct pattern: `Point { x, y }`
                if self.check(&TokenKind::LeftBrace) {
                    let path = Path::from_ident(ident);
                    return self.parse_struct_pattern(path);
                }

                // Simple binding.
                Ok(Pattern {
                    kind: PatternKind::Binding { is_mut: false, name: ident.clone() },
                    span: ident.span,
                })
            }

            // Literal patterns: integers, floats, strings, booleans
            TokenKind::IntLiteral(val) => {
                let span = self.advance().span;
                let expr = Expr { kind: ExprKind::IntLiteral(val), span };
                Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span })
            }
            TokenKind::FloatLiteral(val) => {
                let span = self.advance().span;
                let expr = Expr { kind: ExprKind::FloatLiteral(val), span };
                Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span })
            }
            TokenKind::StringLiteral(val) => {
                let span = self.advance().span;
                let expr = Expr { kind: ExprKind::StringLiteral(val), span };
                Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span })
            }
            TokenKind::True => {
                let span = self.advance().span;
                let expr = Expr { kind: ExprKind::BoolLiteral(true), span };
                Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span })
            }
            TokenKind::False => {
                let span = self.advance().span;
                let expr = Expr { kind: ExprKind::BoolLiteral(false), span };
                Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span })
            }

            // Negative numeric literal: `-42`
            TokenKind::Minus => {
                let start = self.advance().span;
                match self.current_kind().clone() {
                    TokenKind::IntLiteral(val) => {
                        let span = self.advance().span;
                        let text = format!("-{val}");
                        let expr = Expr { kind: ExprKind::IntLiteral(text), span: self.merge_spans(start, span) };
                        Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span: self.merge_spans(start, span) })
                    }
                    TokenKind::FloatLiteral(val) => {
                        let span = self.advance().span;
                        let text = format!("-{val}");
                        let expr = Expr { kind: ExprKind::FloatLiteral(text), span: self.merge_spans(start, span) };
                        Ok(Pattern { kind: PatternKind::Literal(Box::new(expr)), span: self.merge_spans(start, span) })
                    }
                    _ => Err(self.error_expected("numeric literal after `-` in pattern")),
                }
            }

            // Tuple pattern: `(a, b)`
            TokenKind::LeftParen => {
                let start = self.advance().span;
                let mut fields = Vec::new();
                while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                    fields.push(self.parse_pattern()?);
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                let end = self.expect(&TokenKind::RightParen)?;
                Ok(Pattern {
                    kind: PatternKind::Tuple(fields),
                    span: self.merge_spans(start, end),
                })
            }

            _ => Err(self.error_expected("pattern")),
        }
    }

    /// After parsing a path, decide if it's a constructor, struct, or unit pattern.
    fn parse_pattern_after_path(&mut self, path: Path) -> Result<Pattern, ParseError> {
        if self.check(&TokenKind::LeftParen) {
            // Constructor pattern: `Some(x)` or `Result::Ok(v)`
            self.advance();
            let mut fields = Vec::new();
            while !self.check(&TokenKind::RightParen) && !self.at_eof() {
                fields.push(self.parse_pattern()?);
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
            let end = self.expect(&TokenKind::RightParen)?;
            let span = self.merge_spans(path.span, end);
            Ok(Pattern {
                kind: PatternKind::Constructor { path, fields },
                span,
            })
        } else if self.check(&TokenKind::LeftBrace) {
            self.parse_struct_pattern(path)
        } else {
            // Path pattern (enum unit variant): `None`, `Color::Red`
            let span = path.span;
            Ok(Pattern {
                kind: PatternKind::Path(path),
                span,
            })
        }
    }

    /// Parse a struct pattern: `Point { x, y: val }`
    fn parse_struct_pattern(&mut self, path: Path) -> Result<Pattern, ParseError> {
        self.advance(); // consume `{`
        let mut fields = Vec::new();
        while !self.check(&TokenKind::RightBrace) && !self.at_eof() {
            let start_span = self.current_span();
            let name = self.expect_identifier()?;
            let pattern = if self.eat(&TokenKind::Colon) {
                Some(self.parse_pattern()?)
            } else {
                None
            };
            let end = self.previous_span();
            fields.push(FieldPattern {
                name,
                pattern,
                span: self.merge_spans(start_span, end),
            });
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        let end = self.expect(&TokenKind::RightBrace)?;
        let span = self.merge_spans(path.span, end);
        Ok(Pattern {
            kind: PatternKind::Struct { path, fields },
            span,
        })
    }
}
