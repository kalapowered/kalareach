//! A lexer for Rust source that keeps the comments.
//!
//! The compiler's own parser throws comments away, and comments are where this repository keys
//! its tests, so the report reads source with a lexer of its own. It knows exactly as much Rust as
//! finding items and the comments around them needs: comments of every kind (nested block comments
//! included), string, byte-string, raw-string and C-string literals, character literals as against
//! lifetimes, identifiers, numbers and single punctuation characters. It never evaluates anything.

/// What kind of comment a comment token is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentKind {
    /// `//` or `/* */`.
    Plain,
    /// `///` or `/** */`: documentation of the item that follows.
    OuterDoc,
    /// `//!` or `/*! */`: documentation of the enclosing module or item.
    InnerDoc,
}

/// One token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// An identifier or keyword. A raw identifier is given without its `r#`.
    Ident(String),
    /// A lifetime or a loop label.
    Lifetime,
    /// A string literal of any kind: its value where it could be decoded, and whether it was
    /// written with an escape or a line continuation.
    Str(String, bool),
    /// A character or byte literal.
    Char,
    /// A numeric literal.
    Number,
    /// One punctuation character.
    Punct(char),
    /// A comment, with its text after the opening marker and before any closing one.
    Comment(CommentKind, String),
}

/// A token and where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// The token.
    pub tok: Tok,
    /// The line it starts on, from 1.
    pub line: usize,
    /// The line it ends on.
    pub end_line: usize,
}

impl Token {
    /// Whether this is the punctuation character `c`.
    #[must_use]
    pub fn is_punct(&self, c: char) -> bool {
        self.tok == Tok::Punct(c)
    }

    /// The identifier, when this is one.
    #[must_use]
    pub fn ident(&self) -> Option<&str> {
        match &self.tok {
            Tok::Ident(name) => Some(name),
            _ => None,
        }
    }

    /// Whether this is a comment.
    #[must_use]
    pub const fn is_comment(&self) -> bool {
        matches!(self.tok, Tok::Comment(..))
    }
}

/// Why a source file could not be read as Rust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LexError {
    /// The line the problem starts on.
    pub line: usize,
    /// What the problem is.
    pub what: &'static str,
}

/// Splits `source` into tokens.
///
/// # Errors
///
/// Returns where a comment or a literal never ends.
pub fn lex(source: &str) -> Result<Vec<Token>, LexError> {
    let chars: Vec<char> = source.chars().collect();
    let mut lexer = Lexer {
        chars: &chars,
        at: 0,
        line: 1,
        tokens: Vec::new(),
    };
    lexer.run()?;
    Ok(lexer.tokens)
}

struct Lexer<'a> {
    chars: &'a [char],
    at: usize,
    line: usize,
    tokens: Vec<Token>,
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// Whether the first thing `from` characters ahead that is neither whitespace nor a plain
    /// (not documentation) comment is `[`.
    fn bracket_after(&self, from: usize) -> bool {
        let mut at = from;
        loop {
            let third = self.peek(at + 2);
            let fourth = self.peek(at + 3);
            match (self.peek(at), self.peek(at + 1)) {
                (Some('['), _) => return true,
                // The whitespace the compiler skips between tokens.
                (
                    Some(
                        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{85}' | '\u{200e}'
                        | '\u{200f}' | '\u{2028}' | '\u{2029}',
                    ),
                    _,
                ) => at += 1,
                // `//`, but not `///` (unless `////`) and not `//!`.
                (Some('/'), Some('/'))
                    if !matches!(third, Some('/' | '!'))
                        || (third == Some('/') && fourth == Some('/')) =>
                {
                    while self.peek(at).is_some_and(|c| c != '\n') {
                        at += 1;
                    }
                }
                // `/*`, but not `/**` (unless `/***` or `/**/`) and not `/*!`.
                (Some('/'), Some('*'))
                    if !matches!(third, Some('*' | '!'))
                        || (third == Some('*') && matches!(fourth, Some('*' | '/'))) =>
                {
                    at += 2;
                    let mut depth = 1_usize;
                    while depth > 0 {
                        match (self.peek(at), self.peek(at + 1)) {
                            (None, _) => return false,
                            (Some('/'), Some('*')) => {
                                depth += 1;
                                at += 2;
                            }
                            (Some('*'), Some('/')) => {
                                depth -= 1;
                                at += 2;
                            }
                            _ => at += 1,
                        }
                    }
                }
                _ => return false,
            }
        }
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.at).copied()?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn push(&mut self, tok: Tok, line: usize) {
        self.tokens.push(Token {
            tok,
            line,
            end_line: self.line,
        });
    }

    fn run(&mut self) -> Result<(), LexError> {
        // A shebang line is not Rust. As the compiler reads a file's first line, `#!` opens an inner
        // attribute instead when the first thing after it that is neither whitespace nor a plain
        // comment is `[`.
        if self.peek(0) == Some('#') && self.peek(1) == Some('!') && !self.bracket_after(2) {
            while self.peek(0).is_some_and(|c| c != '\n') {
                self.bump();
            }
        }
        while let Some(c) = self.peek(0) {
            let line = self.line;
            if c.is_whitespace() {
                self.bump();
            } else if c == '/' && self.peek(1) == Some('/') {
                self.line_comment(line);
            } else if c == '/' && self.peek(1) == Some('*') {
                self.block_comment(line)?;
            } else if let Some(skip) = self.string_start() {
                self.string(line, skip)?;
            } else if c == '\'' {
                self.quote(line)?;
            } else if c == 'r'
                && self.peek(1) == Some('#')
                && self.peek(2).is_some_and(is_ident_start)
            {
                self.at += 2;
                let name = self.word();
                self.push(Tok::Ident(name), line);
            } else if is_ident_start(c) {
                let name = self.word();
                self.push(Tok::Ident(name), line);
            } else if c.is_ascii_digit() {
                self.number();
                self.push(Tok::Number, line);
            } else {
                self.bump();
                self.push(Tok::Punct(c), line);
            }
        }
        Ok(())
    }

    fn word(&mut self) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek(0).filter(|c| is_ident_continue(*c)) {
            name.push(c);
            self.bump();
        }
        name
    }

    fn number(&mut self) {
        // Digits, underscores, a suffix and an exponent. A full stop is part of the number only when
        // a digit follows it, so `1..2` and `x.0.1` stay what they are.
        while let Some(c) = self.peek(0) {
            let exponent_sign = matches!(c, '+' | '-')
                && self.at > 0
                && matches!(self.chars[self.at - 1], 'e' | 'E')
                && !self.chars[..self.at]
                    .iter()
                    .rev()
                    .take_while(|p| p.is_alphanumeric())
                    .any(|p| matches!(p, 'x' | 'X'));
            if c.is_ascii_alphanumeric()
                || c == '_'
                || exponent_sign
                || (c == '.' && self.peek(1).is_some_and(|n| n.is_ascii_digit()))
            {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn line_comment(&mut self, line: usize) {
        self.at += 2;
        let kind = match (self.peek(0), self.peek(1)) {
            (Some('/'), Some('/')) => CommentKind::Plain,
            (Some('/'), _) => CommentKind::OuterDoc,
            (Some('!'), _) => CommentKind::InnerDoc,
            _ => CommentKind::Plain,
        };
        if kind != CommentKind::Plain {
            self.at += 1;
        }
        let mut text = String::new();
        while let Some(c) = self.peek(0).filter(|c| *c != '\n') {
            text.push(c);
            self.bump();
        }
        self.push(Tok::Comment(kind, text), line);
    }

    fn block_comment(&mut self, line: usize) -> Result<(), LexError> {
        self.at += 2;
        let kind = match (self.peek(0), self.peek(1)) {
            (Some('*'), Some('*' | '/')) => CommentKind::Plain,
            (Some('*'), _) => CommentKind::OuterDoc,
            (Some('!'), _) => CommentKind::InnerDoc,
            _ => CommentKind::Plain,
        };
        if kind != CommentKind::Plain {
            self.at += 1;
        }
        let mut depth = 1_usize;
        let mut text = String::new();
        loop {
            match (self.peek(0), self.peek(1)) {
                (None, _) => {
                    return Err(LexError {
                        line,
                        what: "a block comment that never ends",
                    });
                }
                (Some('/'), Some('*')) => {
                    depth += 1;
                    text.push_str("/*");
                    self.at += 2;
                }
                (Some('*'), Some('/')) => {
                    depth -= 1;
                    self.at += 2;
                    if depth == 0 {
                        break;
                    }
                    text.push_str("*/");
                }
                (Some(c), _) => {
                    text.push(c);
                    self.bump();
                }
            }
        }
        self.push(Tok::Comment(kind, text), line);
        Ok(())
    }

    /// When a string literal starts here, the number of characters before its opening quote or
    /// hashes (`b`, `r`, `br`, `c`, `cr`), else `None`.
    fn string_start(&self) -> Option<usize> {
        let prefix: String = (0..2).filter_map(|i| self.peek(i)).collect();
        let after = |n: usize| self.peek(n);
        match self.peek(0)? {
            '"' => Some(0),
            'b' | 'c' if after(1) == Some('"') => Some(1),
            'r' if matches!(after(1), Some('"')) => Some(1),
            'r' if after(1) == Some('#') && self.raw_quote_after(1) => Some(1),
            _ if (prefix == "br" || prefix == "cr")
                && (after(2) == Some('"')
                    || (after(2) == Some('#') && self.raw_quote_after(2))) =>
            {
                Some(2)
            }
            _ => None,
        }
    }

    /// Whether hashes starting `from` characters ahead end in a quote.
    fn raw_quote_after(&self, from: usize) -> bool {
        let mut i = from;
        while self.peek(i) == Some('#') {
            i += 1;
        }
        self.peek(i) == Some('"')
    }

    fn string(&mut self, line: usize, prefix: usize) -> Result<(), LexError> {
        let raw = (0..prefix).any(|i| self.peek(i) == Some('r'));
        let mut escaped = false;
        self.at += prefix;
        let unterminated = LexError {
            line,
            what: "a string literal that never ends",
        };
        let mut value = String::new();
        if raw {
            let mut hashes = 0;
            while self.peek(0) == Some('#') {
                hashes += 1;
                self.at += 1;
            }
            self.at += 1; // the opening quote
            loop {
                let c = self.bump().ok_or_else(|| unterminated.clone())?;
                if c == '"' && (0..hashes).all(|i| self.peek(i) == Some('#')) {
                    self.at += hashes;
                    break;
                }
                value.push(c);
            }
        } else {
            self.at += 1; // the opening quote
            loop {
                let c = self.bump().ok_or_else(|| unterminated.clone())?;
                match c {
                    '"' => break,
                    '\\' => {
                        escaped = true;
                        let after = self.bump().ok_or_else(|| unterminated.clone())?;
                        match after {
                            'n' => value.push('\n'),
                            't' => value.push('\t'),
                            'r' => value.push('\r'),
                            '0' => value.push('\0'),
                            // A line continuation, after a line feed or a carriage return and one,
                            // skips the ASCII whitespace that starts the next line.
                            '\n' | '\r' if after == '\n' || self.peek(0) == Some('\n') => {
                                while self
                                    .peek(0)
                                    .is_some_and(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
                                {
                                    self.bump();
                                }
                            }
                            'u' => {
                                let mut digits = String::new();
                                while let Some(d) = self.bump() {
                                    if d == '}' {
                                        break;
                                    }
                                    if d != '{' && d != '_' {
                                        digits.push(d);
                                    }
                                }
                                if let Some(c) = u32::from_str_radix(&digits, 16)
                                    .ok()
                                    .and_then(char::from_u32)
                                {
                                    value.push(c);
                                }
                            }
                            'x' => {
                                let digits: String = (0..2).filter_map(|_| self.bump()).collect();
                                if let Some(c) =
                                    u8::from_str_radix(&digits, 16).ok().filter(u8::is_ascii)
                                {
                                    value.push(char::from(c));
                                }
                            }
                            other => value.push(other),
                        }
                    }
                    c => value.push(c),
                }
            }
        }
        self.push(Tok::Str(value, escaped), line);
        Ok(())
    }

    /// A quote starts a character literal or a lifetime, and only what follows it says which.
    fn quote(&mut self, line: usize) -> Result<(), LexError> {
        let is_char = match (self.peek(1), self.peek(2)) {
            (Some('\\'), _) => true,
            (Some(c), Some('\'')) if c != '\'' => true,
            _ => false,
        };
        if !is_char {
            self.bump();
            if self.peek(0).is_some_and(is_ident_start) {
                self.word();
            }
            self.push(Tok::Lifetime, line);
            return Ok(());
        }
        self.bump();
        loop {
            match self.bump() {
                None => {
                    return Err(LexError {
                        line,
                        what: "a character literal that never ends",
                    });
                }
                Some('\\') => {
                    self.bump();
                }
                Some('\'') => break,
                Some(_) => {}
            }
        }
        self.push(Tok::Char, line);
        Ok(())
    }
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<Tok> {
        lex(source)
            .expect("lexes")
            .into_iter()
            .map(|t| t.tok)
            .collect()
    }

    #[test]
    fn every_comment_kind_is_kept_with_its_text() {
        let tokens = kinds(
            "//! inner\n/// outer\n// plain\n//// plain too\n/** block doc */ /*! inner block */ /* a /* nested */ one */",
        );
        assert_eq!(
            tokens,
            [
                Tok::Comment(CommentKind::InnerDoc, " inner".into()),
                Tok::Comment(CommentKind::OuterDoc, " outer".into()),
                Tok::Comment(CommentKind::Plain, " plain".into()),
                Tok::Comment(CommentKind::Plain, "// plain too".into()),
                Tok::Comment(CommentKind::OuterDoc, " block doc ".into()),
                Tok::Comment(CommentKind::InnerDoc, " inner block ".into()),
                Tok::Comment(CommentKind::Plain, " a /* nested */ one ".into()),
            ]
        );
    }

    #[test]
    fn a_comment_marker_inside_a_literal_is_part_of_the_literal() {
        let tokens = kinds(
            r####"let a = "// not a comment"; let b = r#"/* nor "this" */"#; let c = '"'; let d = b"\"//";"####,
        );
        assert!(
            !tokens.iter().any(|t| matches!(t, Tok::Comment(..))),
            "{tokens:?}"
        );
        assert!(tokens.contains(&Tok::Str("// not a comment".into(), false)));
        assert!(tokens.contains(&Tok::Str("/* nor \"this\" */".into(), false)));
    }

    #[test]
    fn a_lifetime_is_not_a_character_literal() {
        let tokens = kinds("fn f<'a>(x: &'a str) -> char { 'x' } // after");
        assert_eq!(tokens.iter().filter(|t| **t == Tok::Lifetime).count(), 2);
        assert_eq!(tokens.iter().filter(|t| **t == Tok::Char).count(), 1);
        assert!(matches!(
            tokens.last(),
            Some(Tok::Comment(CommentKind::Plain, _))
        ));
    }

    #[test]
    fn a_string_value_is_decoded_across_a_line_continuation() {
        let tokens = kinds("\"KR-REQ-08.16 \\\n     row text\\u{21}\"");
        assert_eq!(tokens, [Tok::Str("KR-REQ-08.16 row text!".into(), true)]);
    }

    #[test]
    fn a_string_is_decoded_as_the_compiler_decodes_it() {
        // Underscores may stand among a Unicode escape's digits, and a line continuation after a
        // carriage return and a line feed skips the ASCII whitespace that starts the next line.
        let decoded = |source: &str| match &lex(source).expect("lexes")[0].tok {
            Tok::Str(value, _) => value.clone(),
            other => panic!("a string: {other:?}"),
        };
        assert_eq!(decoded("\"ki\\u{6_4}.rs\""), "kid.rs");
        assert_eq!(decoded("\"a\\\r\n   b\""), "ab");
    }

    #[test]
    fn lines_are_counted_through_every_token() {
        let tokens = lex("/* one\ntwo */\nfn x() {}\n").expect("lexes");
        assert_eq!((tokens[0].line, tokens[0].end_line), (1, 2));
        assert_eq!(tokens[1].line, 3);
    }

    #[test]
    fn an_unterminated_comment_is_an_error_naming_its_line() {
        assert_eq!(lex("\n/* open").unwrap_err().line, 2);
    }

    #[test]
    fn a_first_line_is_a_shebang_only_where_no_attribute_follows_its_bang() {
        // `#!` then `[`, past whitespace and plain comments, opens an inner attribute.
        for source in [
            "#![path = \"x\"]\nmod m;",
            "#! [path = \"x\"]\nmod m;",
            "#! /* a gap */ [path = \"x\"]\nmod m;",
            "#! // a gap\n[path = \"x\"]\nmod m;",
        ] {
            let tokens = kinds(source);
            let significant: Vec<&Tok> = tokens
                .iter()
                .filter(|tok| !matches!(tok, Tok::Comment(..)))
                .take(3)
                .collect();
            assert_eq!(
                significant,
                [&Tok::Punct('#'), &Tok::Punct('!'), &Tok::Punct('[')],
                "{source}"
            );
        }
        // Anything else after it, a documentation comment included, makes the line a shebang,
        // which is dropped.
        for source in [
            "#!/usr/bin/env run\nmod m;",
            "#! //! a document\n[path = \"x\"]\nmod m;",
        ] {
            let tokens = kinds(source);
            assert!(!tokens.contains(&Tok::Punct('#')), "{source}: {tokens:?}");
            assert!(
                tokens.contains(&Tok::Ident("mod".into())),
                "{source}: {tokens:?}"
            );
        }
    }
}
