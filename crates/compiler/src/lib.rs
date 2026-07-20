#![doc = "`Polytope` compiler front-end primitives."]

/// A byte range in source text, expressed as a half-open interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    /// Inclusive byte offset.
    pub start: usize,
    /// Exclusive byte offset.
    pub end: usize,
}

/// Tokens recognized by the bootstrap lexer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind<'source> {
    /// `fn` declaration keyword.
    Function,
    /// A user-defined name.
    Identifier(&'source str),
    /// An unsigned decimal integer.
    Integer(u64),
    /// `(`.
    LeftParen,
    /// `)`.
    RightParen,
    /// `{`.
    LeftBrace,
    /// `}`.
    RightBrace,
}

/// A token and its original source location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token<'source> {
    /// Semantic token category.
    pub kind: TokenKind<'source>,
    /// Original source byte range.
    pub span: Span,
}

/// A lexical error with a precise source location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LexError {
    /// Unexpected character.
    pub character: char,
    /// Byte offset of the unexpected character.
    pub offset: usize,
}

/// Allocation-free streaming lexer for the Polytope language.
pub struct Lexer<'source> {
    source: &'source str,
    offset: usize,
}

impl<'source> Lexer<'source> {
    /// Creates a lexer over UTF-8 source text.
    #[must_use]
    pub const fn new(source: &'source str) -> Self {
        Self { source, offset: 0 }
    }
}

impl<'source> Iterator for Lexer<'source> {
    type Item = Result<Token<'source>, LexError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(character) = self.source[self.offset..].chars().next() {
            if character.is_whitespace() {
                self.offset += character.len_utf8();
                continue;
            }
            break;
        }
        let start = self.offset;
        let character = self.source[start..].chars().next()?;
        let punctuation = match character {
            '(' => Some(TokenKind::LeftParen),
            ')' => Some(TokenKind::RightParen),
            '{' => Some(TokenKind::LeftBrace),
            '}' => Some(TokenKind::RightBrace),
            _ => None,
        };
        if let Some(kind) = punctuation {
            self.offset += 1;
            return Some(Ok(Token {
                kind,
                span: Span {
                    start,
                    end: self.offset,
                },
            }));
        }
        if character.is_ascii_alphabetic() || character == '_' {
            self.offset += character.len_utf8();
            while let Some(next) = self.source[self.offset..].chars().next() {
                if !(next.is_ascii_alphanumeric() || next == '_') {
                    break;
                }
                self.offset += next.len_utf8();
            }
            let text = &self.source[start..self.offset];
            let kind = if text == "fn" {
                TokenKind::Function
            } else {
                TokenKind::Identifier(text)
            };
            return Some(Ok(Token {
                kind,
                span: Span {
                    start,
                    end: self.offset,
                },
            }));
        }
        if character.is_ascii_digit() {
            let mut value = 0_u64;
            while let Some(next) = self.source[self.offset..].chars().next() {
                let Some(digit) = next.to_digit(10) else {
                    break;
                };
                let Some(updated) = value
                    .checked_mul(10)
                    .and_then(|current| current.checked_add(u64::from(digit)))
                else {
                    return Some(Err(LexError {
                        character: next,
                        offset: self.offset,
                    }));
                };
                value = updated;
                self.offset += next.len_utf8();
            }
            return Some(Ok(Token {
                kind: TokenKind::Integer(value),
                span: Span {
                    start,
                    end: self.offset,
                },
            }));
        }
        self.offset += character.len_utf8();
        Some(Err(LexError {
            character,
            offset: start,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{Lexer, Span, Token, TokenKind};

    #[test]
    fn lexes_function_skeleton_with_spans() {
        let tokens = Lexer::new("fn main() {}")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            tokens[0],
            Token {
                kind: TokenKind::Function,
                span: Span { start: 0, end: 2 }
            }
        );
        assert_eq!(tokens[1].kind, TokenKind::Identifier("main"));
        assert_eq!(tokens.len(), 6);
    }

    #[test]
    fn reports_unrecognized_input() {
        assert_eq!(Lexer::new("@").next().unwrap().unwrap_err().offset, 0);
    }
}
