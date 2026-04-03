use crate::lexer::token::{Span, Token, TokenKind};

/// A diagnostic emitted by the lexer when it encounters invalid input.
#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "error at line {}, column {}: {}",
            self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for LexError {}

/// Single-pass lexer for RUNE source files.
///
/// Converts a source string into a stream of [`Token`]s. Every token carries a
/// [`Span`] for precise error reporting. The scanner never backtracks — it
/// makes a single forward pass over the input.
///
/// Pillar: Security Baked In — actionable diagnostics on every error path.
/// Pillar: Zero Trust Throughout — no implicit assumptions about input validity.
pub struct Lexer<'src> {
    source: &'src str,
    bytes: &'src [u8],
    file_id: u32,

    /// Current byte offset into `source`.
    pos: usize,
    /// 1-based line number.
    line: u32,
    /// 1-based column (byte offset from start of current line).
    column: u32,

    errors: Vec<LexError>,
}

impl<'src> Lexer<'src> {
    pub fn new(source: &'src str, file_id: u32) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            file_id,
            pos: 0,
            line: 1,
            column: 1,
            errors: Vec::new(),
        }
    }

    /// Tokenize the entire source, returning tokens and any errors encountered.
    /// The token stream always ends with an `Eof` token.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<LexError>) {
        let mut tokens = Vec::new();

        loop {
            self.skip_whitespace_and_comments();

            if self.is_at_end() {
                tokens.push(Token::new(
                    TokenKind::Eof,
                    self.span_here(0),
                ));
                break;
            }

            match self.scan_token() {
                Some(token) => tokens.push(token),
                None => {
                    // Error already recorded; advance past the bad byte.
                }
            }
        }

        (tokens, self.errors)
    }

    // ── Character utilities ──────────────────────────────────────────

    fn is_at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> u8 {
        if self.is_at_end() { 0 } else { self.bytes[self.pos] }
    }

    fn peek_next(&self) -> u8 {
        if self.pos + 1 >= self.bytes.len() { 0 } else { self.bytes[self.pos + 1] }
    }

    fn advance(&mut self) -> u8 {
        let ch = self.bytes[self.pos];
        self.pos += 1;
        if ch == b'\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        ch
    }

    fn match_char(&mut self, expected: u8) -> bool {
        if self.is_at_end() || self.bytes[self.pos] != expected {
            return false;
        }
        self.advance();
        true
    }

    /// Build a span starting at the current position with the given byte length.
    fn span_here(&self, len: usize) -> Span {
        Span::new(
            self.file_id,
            self.pos as u32,
            (self.pos + len) as u32,
            self.line,
            self.column,
        )
    }

    /// Build a span from a saved start position to the current position.
    fn span_from(&self, start: usize, start_line: u32, start_col: u32) -> Span {
        Span::new(
            self.file_id,
            start as u32,
            self.pos as u32,
            start_line,
            start_col,
        )
    }

    // ── Whitespace and comments ──────────────────────────────────────

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while !self.is_at_end() && self.peek().is_ascii_whitespace() {
                self.advance();
            }

            if self.is_at_end() {
                return;
            }

            // Line comment
            if self.peek() == b'/' && self.peek_next() == b'/' {
                while !self.is_at_end() && self.peek() != b'\n' {
                    self.advance();
                }
                continue;
            }

            // Block comment (with nesting support)
            if self.peek() == b'/' && self.peek_next() == b'*' {
                self.skip_block_comment();
                continue;
            }

            break;
        }
    }

    fn skip_block_comment(&mut self) {
        let start = self.pos;
        let start_line = self.line;
        let start_col = self.column;

        // Consume the opening /*
        self.advance();
        self.advance();

        let mut depth: u32 = 1;

        while !self.is_at_end() && depth > 0 {
            if self.peek() == b'/' && self.peek_next() == b'*' {
                self.advance();
                self.advance();
                depth += 1;
            } else if self.peek() == b'*' && self.peek_next() == b'/' {
                self.advance();
                self.advance();
                depth -= 1;
            } else {
                self.advance();
            }
        }

        if depth > 0 {
            self.errors.push(LexError {
                message: "unterminated block comment".to_string(),
                span: self.span_from(start, start_line, start_col),
            });
        }
    }

    // ── Main scan dispatch ───────────────────────────────────────────

    fn scan_token(&mut self) -> Option<Token> {
        let start = self.pos;
        let start_line = self.line;
        let start_col = self.column;
        let ch = self.advance();

        let kind = match ch {
            // Single-character tokens
            b'{' => TokenKind::LeftBrace,
            b'}' => TokenKind::RightBrace,
            b'(' => TokenKind::LeftParen,
            b')' => TokenKind::RightParen,
            b'[' => TokenKind::LeftBracket,
            b']' => TokenKind::RightBracket,
            b'~' => TokenKind::Tilde,
            b';' => TokenKind::Semicolon,
            b',' => TokenKind::Comma,
            b'@' => TokenKind::At,

            // Dot: . .. ...
            b'.' => {
                if self.match_char(b'.') {
                    if self.match_char(b'.') {
                        TokenKind::DotDotDot
                    } else {
                        TokenKind::DotDot
                    }
                } else if !self.is_at_end() && self.peek().is_ascii_digit() {
                    // .5 style float — rewind and scan as number
                    self.pos = start;
                    self.line = start_line;
                    self.column = start_col;
                    return self.scan_number();
                } else {
                    TokenKind::Dot
                }
            }

            // Colon: : ::
            b':' => {
                if self.match_char(b':') {
                    TokenKind::ColonColon
                } else {
                    TokenKind::Colon
                }
            }

            // Plus: + +=
            b'+' => {
                if self.match_char(b'=') { TokenKind::PlusEqual } else { TokenKind::Plus }
            }

            // Minus: - -> -=
            b'-' => {
                if self.match_char(b'>') {
                    TokenKind::Arrow
                } else if self.match_char(b'=') {
                    TokenKind::MinusEqual
                } else {
                    TokenKind::Minus
                }
            }

            // Star: * *=
            b'*' => {
                if self.match_char(b'=') { TokenKind::StarEqual } else { TokenKind::Star }
            }

            // Slash: / /=  (comments already handled in skip_whitespace_and_comments)
            b'/' => {
                if self.match_char(b'=') { TokenKind::SlashEqual } else { TokenKind::Slash }
            }

            // Percent: % %=
            b'%' => {
                if self.match_char(b'=') { TokenKind::PercentEqual } else { TokenKind::Percent }
            }

            // Equal: = == =>
            b'=' => {
                if self.match_char(b'=') {
                    TokenKind::EqualEqual
                } else if self.match_char(b'>') {
                    TokenKind::FatArrow
                } else {
                    TokenKind::Equal
                }
            }

            // Bang: ! !=
            b'!' => {
                if self.match_char(b'=') { TokenKind::BangEqual } else { TokenKind::Bang }
            }

            // Less: < <= <<
            b'<' => {
                if self.match_char(b'=') {
                    TokenKind::LessEqual
                } else if self.match_char(b'<') {
                    TokenKind::LessLess
                } else {
                    TokenKind::LeftAngle
                }
            }

            // Greater: > >= >>
            b'>' => {
                if self.match_char(b'=') {
                    TokenKind::GreaterEqual
                } else if self.match_char(b'>') {
                    TokenKind::GreaterGreater
                } else {
                    TokenKind::RightAngle
                }
            }

            // Ampersand: & &&
            b'&' => {
                if self.match_char(b'&') { TokenKind::AmpAmp } else { TokenKind::Amp }
            }

            // Pipe: | ||
            b'|' => {
                if self.match_char(b'|') { TokenKind::PipePipe } else { TokenKind::Pipe }
            }

            // Caret
            b'^' => TokenKind::Caret,

            // String literal
            b'"' => return self.scan_string(start, start_line, start_col),

            // Number literals
            b'0'..=b'9' => {
                self.pos = start;
                self.line = start_line;
                self.column = start_col;
                return self.scan_number();
            }

            // Identifiers and keywords
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                self.pos = start;
                self.line = start_line;
                self.column = start_col;
                return self.scan_identifier();
            }

            _ => {
                self.errors.push(LexError {
                    message: format!("unexpected character: '{}'", ch as char),
                    span: self.span_from(start, start_line, start_col),
                });
                return None;
            }
        };

        Some(Token::new(kind, self.span_from(start, start_line, start_col)))
    }

    // ── Identifier / keyword scanner ─────────────────────────────────

    fn scan_identifier(&mut self) -> Option<Token> {
        let start = self.pos;
        let start_line = self.line;
        let start_col = self.column;

        self.advance(); // first char already validated as [a-zA-Z_]

        while !self.is_at_end()
            && (self.peek().is_ascii_alphanumeric() || self.peek() == b'_')
        {
            self.advance();
        }

        let text = &self.source[start..self.pos];
        let kind = TokenKind::keyword_from_str(text)
            .unwrap_or_else(|| TokenKind::Identifier(text.to_string()));

        Some(Token::new(kind, self.span_from(start, start_line, start_col)))
    }

    // ── Number scanner ───────────────────────────────────────────────

    fn scan_number(&mut self) -> Option<Token> {
        let start = self.pos;
        let start_line = self.line;
        let start_col = self.column;

        let mut is_float = false;

        // Check for prefix: 0x, 0o, 0b
        if self.peek() == b'0' {
            match self.peek_next() {
                b'x' | b'X' => return self.scan_hex(start, start_line, start_col),
                b'o' | b'O' => return self.scan_octal(start, start_line, start_col),
                b'b' | b'B' => return self.scan_binary(start, start_line, start_col),
                _ => {}
            }
        }

        // Leading dot for float (.5)
        if self.peek() == b'.' {
            is_float = true;
            self.advance(); // consume '.'
            self.consume_decimal_digits();
        } else {
            // Decimal integer part
            self.consume_decimal_digits();

            // Fractional part
            if self.peek() == b'.' && self.peek_next() != b'.' {
                // Distinguish `1.2` from `1..2` (range)
                is_float = true;
                self.advance(); // consume '.'
                self.consume_decimal_digits();
            }
        }

        // Exponent
        if self.peek() == b'e' || self.peek() == b'E' {
            is_float = true;
            self.advance();
            if self.peek() == b'+' || self.peek() == b'-' {
                self.advance();
            }
            if !self.peek().is_ascii_digit() {
                self.errors.push(LexError {
                    message: "expected digit after exponent in numeric literal".to_string(),
                    span: self.span_from(start, start_line, start_col),
                });
                return None;
            }
            self.consume_decimal_digits();
        }

        let text = self.source[start..self.pos].to_string();
        let kind = if is_float {
            TokenKind::FloatLiteral(text)
        } else {
            TokenKind::IntLiteral(text)
        };

        Some(Token::new(kind, self.span_from(start, start_line, start_col)))
    }

    fn scan_hex(&mut self, start: usize, start_line: u32, start_col: u32) -> Option<Token> {
        self.advance(); // '0'
        self.advance(); // 'x'

        if !self.peek().is_ascii_hexdigit() {
            self.errors.push(LexError {
                message: "expected hexadecimal digit after '0x'".to_string(),
                span: self.span_from(start, start_line, start_col),
            });
            return None;
        }

        while !self.is_at_end() && (self.peek().is_ascii_hexdigit() || self.peek() == b'_') {
            self.advance();
        }

        let text = self.source[start..self.pos].to_string();
        Some(Token::new(
            TokenKind::IntLiteral(text),
            self.span_from(start, start_line, start_col),
        ))
    }

    fn scan_octal(&mut self, start: usize, start_line: u32, start_col: u32) -> Option<Token> {
        self.advance(); // '0'
        self.advance(); // 'o'

        if self.is_at_end() || !matches!(self.peek(), b'0'..=b'7') {
            self.errors.push(LexError {
                message: "expected octal digit (0-7) after '0o'".to_string(),
                span: self.span_from(start, start_line, start_col),
            });
            return None;
        }

        while !self.is_at_end() && (matches!(self.peek(), b'0'..=b'7') || self.peek() == b'_') {
            self.advance();
        }

        let text = self.source[start..self.pos].to_string();
        Some(Token::new(
            TokenKind::IntLiteral(text),
            self.span_from(start, start_line, start_col),
        ))
    }

    fn scan_binary(&mut self, start: usize, start_line: u32, start_col: u32) -> Option<Token> {
        self.advance(); // '0'
        self.advance(); // 'b'

        if self.is_at_end() || !matches!(self.peek(), b'0' | b'1') {
            self.errors.push(LexError {
                message: "expected binary digit (0 or 1) after '0b'".to_string(),
                span: self.span_from(start, start_line, start_col),
            });
            return None;
        }

        while !self.is_at_end() && (matches!(self.peek(), b'0' | b'1') || self.peek() == b'_') {
            self.advance();
        }

        let text = self.source[start..self.pos].to_string();
        Some(Token::new(
            TokenKind::IntLiteral(text),
            self.span_from(start, start_line, start_col),
        ))
    }

    fn consume_decimal_digits(&mut self) {
        while !self.is_at_end() && (self.peek().is_ascii_digit() || self.peek() == b'_') {
            self.advance();
        }
    }

    // ── String scanner ───────────────────────────────────────────────

    fn scan_string(
        &mut self,
        start: usize,
        start_line: u32,
        start_col: u32,
    ) -> Option<Token> {
        let mut value = String::new();

        loop {
            if self.is_at_end() {
                self.errors.push(LexError {
                    message: "unterminated string literal".to_string(),
                    span: self.span_from(start, start_line, start_col),
                });
                return None;
            }

            let ch = self.advance();

            match ch {
                b'"' => break,
                b'\\' => {
                    if self.is_at_end() {
                        self.errors.push(LexError {
                            message: "unterminated escape sequence in string".to_string(),
                            span: self.span_from(start, start_line, start_col),
                        });
                        return None;
                    }
                    let esc = self.advance();
                    match esc {
                        b'n' => value.push('\n'),
                        b't' => value.push('\t'),
                        b'r' => value.push('\r'),
                        b'\\' => value.push('\\'),
                        b'"' => value.push('"'),
                        b'0' => value.push('\0'),
                        _ => {
                            self.errors.push(LexError {
                                message: format!(
                                    "unknown escape sequence: '\\{}'",
                                    esc as char
                                ),
                                span: self.span_from(
                                    self.pos - 2,
                                    // approximate — escape started 2 bytes ago
                                    start_line,
                                    start_col,
                                ),
                            });
                            // Keep going to find more errors in the string.
                            value.push(esc as char);
                        }
                    }
                }
                _ => {
                    value.push(ch as char);
                }
            }
        }

        Some(Token::new(
            TokenKind::StringLiteral(value),
            self.span_from(start, start_line, start_col),
        ))
    }
}
