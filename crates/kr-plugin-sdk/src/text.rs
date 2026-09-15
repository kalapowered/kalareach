//! Bounded human-readable text.
//!
//! Every label a package contributes to the interface is bounded and free of control characters.
//! A catalogue index carries one line of description per entry, a control carries a label and an
//! accessible description, and a disabled control carries the reason a person reads. None of them
//! may carry a line break, a control character or a bidirectional override, because all three let
//! a package present text that does not match what it claims to say.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

/// Text that is empty, too long, or carries a character that cannot appear in a label.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TextError {
    /// The text was empty.
    #[error("{kind} is empty")]
    Empty {
        /// The text kind that was rejected.
        kind: &'static str,
    },
    /// The text was longer than its limit.
    #[error("{kind} is {len} characters, over the {limit} character limit")]
    TooLong {
        /// The text kind that was rejected.
        kind: &'static str,
        /// The character count of the supplied text.
        len: usize,
        /// The permitted character count.
        limit: usize,
    },
    /// The text carried a character that is never permitted in a label.
    #[error("{kind} contains the forbidden character U+{codepoint:04X}")]
    ForbiddenCharacter {
        /// The text kind that was rejected.
        kind: &'static str,
        /// The offending code point.
        codepoint: u32,
    },
}

/// Returns true when a character may never appear in bounded interface text.
///
/// Control characters cover line breaks and terminal escapes. The explicit list covers the
/// bidirectional formatting and isolate characters, which reorder rendered text without changing
/// the characters a reviewer reads, and the zero-width characters that hide inside a name.
#[must_use]
pub fn is_forbidden_text_char(character: char) -> bool {
    if character.is_control() {
        return true;
    }
    matches!(
        character,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

macro_rules! bounded_text {
    ($(#[$meta:meta])* $name:ident, $limit:expr, $kind:literal, $description:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// The permitted character count.
            pub const LIMIT: usize = $limit;

            /// Wraps text after checking the bound and the forbidden characters.
            ///
            /// # Errors
            ///
            /// Returns [`TextError`] when the text is empty, longer than [`Self::LIMIT`]
            /// characters, or carries a control, zero-width or bidirectional character.
            pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
                let value = value.into();
                let len = value.chars().count();
                if len == 0 {
                    return Err(TextError::Empty { kind: $kind });
                }
                if len > $limit {
                    return Err(TextError::TooLong { kind: $kind, len, limit: $limit });
                }
                if let Some(character) = value.chars().find(|c| is_forbidden_text_char(*c)) {
                    return Err(TextError::ForbiddenCharacter {
                        kind: $kind,
                        codepoint: character as u32,
                    });
                }
                Ok(Self(value))
            }

            /// Returns the text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = TextError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::new(text)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": $limit,
                    "description": $description
                })
            }
        }
    };
}

bounded_text!(
    /// A short name shown wherever the package or a control appears.
    Label,
    80,
    "label",
    "A short display name. One line, no control or bidirectional characters."
);

bounded_text!(
    /// The one-line description carried in the catalogue index.
    ///
    /// Section 11 synchronises compact descriptions for every package so catalogue search works
    /// offline. Compact is the point: the whole index for 10,000 packages stays inside the
    /// repository metadata budget.
    CompactDescription,
    200,
    "compact description",
    "The one-line catalogue description. One line, no control or bidirectional characters."
);

bounded_text!(
    /// The description a screen reader announces for a control.
    AccessibleDescription,
    200,
    "accessible description",
    "The description a screen reader announces. One line, no control or bidirectional characters."
);

bounded_text!(
    /// The user-facing reason a control or capability is unavailable.
    DisabledReason,
    200,
    "disabled reason",
    "The user-facing reason something is unavailable. One line, no control or bidirectional characters."
);

bounded_text!(
    /// Longer prose: the package summary in its own manifest.
    Summary,
    1000,
    "summary",
    "The package summary. One line, no control or bidirectional characters."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_over_long_text() {
        assert_eq!(Label::new(""), Err(TextError::Empty { kind: "label" }));
        let long = "x".repeat(Label::LIMIT + 1);
        assert_eq!(
            Label::new(long),
            Err(TextError::TooLong {
                kind: "label",
                len: Label::LIMIT + 1,
                limit: Label::LIMIT
            })
        );
    }

    #[test]
    fn rejects_control_and_bidirectional_characters() {
        assert!(matches!(
            Label::new("two\nlines"),
            Err(TextError::ForbiddenCharacter { .. })
        ));
        // U+202E right-to-left override renders "gpj.exe" as "exe.jpg".
        assert!(matches!(
            Label::new("harmless\u{202E}gpj.exe"),
            Err(TextError::ForbiddenCharacter {
                codepoint: 0x202E,
                ..
            })
        ));
        assert!(matches!(
            Label::new("zero\u{200B}width"),
            Err(TextError::ForbiddenCharacter { .. })
        ));
    }

    #[test]
    fn counts_characters_not_bytes() {
        let emoji = "\u{1F600}".repeat(Label::LIMIT);
        assert!(Label::new(emoji).is_ok());
    }
}

/// Literal text a package writes into the terminal.
///
/// Printable ASCII, tab and newline only. A terminal template is terminal input, and terminal
/// input that can carry an escape sequence is a way to drive the terminal from a manifest: move
/// the cursor, rewrite what a person just read, set a title, or start a query the host would have
/// to answer. None of that is expressible inside this alphabet.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TerminalLiteral(String);

impl TerminalLiteral {
    /// The permitted character count.
    pub const LIMIT: usize = 1000;

    /// Wraps literal terminal text.
    ///
    /// # Errors
    ///
    /// Returns [`TextError`] when the text is empty, longer than [`Self::LIMIT`] characters, or
    /// carries anything but printable ASCII, tab and newline.
    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        let len = value.chars().count();
        if len == 0 {
            return Err(TextError::Empty {
                kind: "terminal literal",
            });
        }
        if len > Self::LIMIT {
            return Err(TextError::TooLong {
                kind: "terminal literal",
                len,
                limit: Self::LIMIT,
            });
        }
        if let Some(character) = value
            .chars()
            .find(|c| !matches!(c, ' '..='~' | '\t' | '\n'))
        {
            return Err(TextError::ForbiddenCharacter {
                kind: "terminal literal",
                codepoint: character as u32,
            });
        }
        Ok(Self(value))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TerminalLiteral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for TerminalLiteral {
    type Err = TextError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for TerminalLiteral {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for TerminalLiteral {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TerminalLiteral".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::TerminalLiteral".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": TerminalLiteral::LIMIT,
            "pattern": "^[ -~\\t\\n]+$",
            "description": "Literal text written into the terminal. Printable ASCII, tab and newline only, so a template cannot carry an escape sequence."
        })
    }
}

#[cfg(test)]
mod terminal_literal_tests {
    use super::*;

    #[test]
    fn accepts_a_command_line_and_rejects_an_escape() {
        assert!(TerminalLiteral::new("status --json\n").is_ok());
        assert!(TerminalLiteral::new("\t indented\n").is_ok());
        for escape in ["\u{1b}[2J", "bell\u{7}", "caf\u{e9}", "\u{200B}"] {
            assert!(
                matches!(
                    TerminalLiteral::new(escape),
                    Err(TextError::ForbiddenCharacter { .. })
                ),
                "accepted {escape:?}"
            );
        }
        assert!(TerminalLiteral::new("").is_err());
    }
}
