//! The person's keys, text and paste, as a view hands them to the client's shared encoder.
//!
//! The page names each key as its platform reported it: the key, the character it makes with
//! nothing held where the platform said, the keypad key it is, the modifiers and locks, and whether
//! it went down, repeated or came up. It never spells a byte. Here each becomes the encoder's key,
//! and the encoder spells it in the encoding the program has negotiated, which the view reads off
//! the session's screen: the Kitty flags of the buffer that is showing, else the `modifyOtherKeys`
//! level, else the ordinary encoding, with DEC mode 1 for the cursor keys and DEC mode 2004 for
//! bracketed paste.
//!
//! The view produces the ordinary encoding, `modifyOtherKeys` at either level, and the Kitty
//! protocol's disambiguation and event types, from every platform it runs on. Not every key as an
//! escape code: an input method, a dead key and a phone's software keyboard give text with no key,
//! and that flag has no spelling for such text without associated text, which kr-vt/1 does not
//! advertise. Nor alternate keys, which the encoder does not write. The host's keyboard table gives
//! the view's profile exactly this, so the view and the host agree on when it may hold the keys.

use std::collections::BTreeMap;

use kr_client::encoder::{
    Arrow, Key, KeyEvent, KeyEventKind, KeyboardEncoding, Keypad, Locks, Modifiers, Unsupported,
};
use kr_client::projection::{ProjectedModeSpelling, Screen};
use kr_protocol::limits::MAX_INPUT_FRAME_LEN;
use serde::Deserialize;

/// The Kitty flags the view produces: disambiguation and event types.
const KITTY_FLAGS: u8 = KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES;

/// The bytes bracketed paste adds around a paste: its two delimiters.
pub const PASTE_FRAMING: usize =
    kr_client::encoder::PASTE_START.len() + kr_client::encoder::PASTE_END.len();

/// Why an input cannot reach the program while the view holds no screen of the session.
pub const NO_SCREEN: &str = "the view is waiting for the session's screen";

/// What the program reads keys in, and whether it asked for bracketed paste, as a screen says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keyboard {
    /// The encoding the program negotiated.
    pub encoding: KeyboardEncoding,
    /// Whether DEC mode 2004 is set.
    pub bracketed: bool,
}

impl Keyboard {
    /// What `screen` says of the program's keyboard.
    #[must_use]
    pub fn of(screen: &Screen) -> Self {
        let dec = |mode| screen.mode(ProjectedModeSpelling::Dec, mode);
        Self {
            encoding: KeyboardEncoding::negotiated(&screen.keyboard, dec(1049), dec(1)),
            bracketed: dec(2004),
        }
    }

    /// Whether the view produces the encoding the program reads.
    #[must_use]
    pub const fn supplied(self) -> bool {
        match self.encoding {
            KeyboardEncoding::Legacy { .. } => true,
            KeyboardEncoding::ModifyOtherKeys { level, .. } => level <= 2,
            KeyboardEncoding::Kitty { flags } => flags & !KITTY_FLAGS == 0,
        }
    }
}

/// Words for an input that did not reach the program: `what` names it ("That key", "That text",
/// "That paste"), and `why` says why.
pub fn unsent(what: &str, why: impl std::fmt::Display) -> String {
    format!("{what} did not reach the program: {why}.")
}

/// A key's name as the page sends it: one character, or the name of a key that makes none.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub enum KeyName {
    /// A key that makes this character.
    Character(char),
    /// A key that makes no character, by its name.
    Named(String),
}

impl std::fmt::Debug for KeyName {
    /// A name, and for a character only that it is one: it is part of what a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Character(_) => formatter.write_str("Character(..)"),
            Self::Named(name) => formatter.debug_tuple("Named").field(name).finish(),
        }
    }
}

impl TryFrom<String> for KeyName {
    type Error = String;

    fn try_from(key: String) -> Result<Self, String> {
        let mut characters = key.chars();
        if let (Some(character), None) = (characters.next(), characters.next()) {
            return Scalar::try_from(character.to_string()).map(|scalar| Self::Character(scalar.0));
        }
        if key.is_empty() || key.len() > 32 || !key.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err("a key is one character or the name of a key".to_owned());
        }
        Ok(Self::Named(key))
    }
}

/// One Unicode scalar that is not a control character.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct Scalar(char);

impl std::fmt::Debug for Scalar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Scalar(..)")
    }
}

impl TryFrom<String> for Scalar {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let mut characters = text.chars();
        match (characters.next(), characters.next()) {
            (Some(character), None) if !character.is_control() => Ok(Self(character)),
            (Some(_), None) => Err("a key's character is never a control character".to_owned()),
            _ => Err("a key's character is one character".to_owned()),
        }
    }
}

/// A key of the numeric keypad, by the code the platform gives its place on the keyboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum KeypadCode {
    /// The digit keys.
    #[serde(rename = "Numpad0")]
    Numpad0,
    #[serde(rename = "Numpad1")]
    Numpad1,
    #[serde(rename = "Numpad2")]
    Numpad2,
    #[serde(rename = "Numpad3")]
    Numpad3,
    #[serde(rename = "Numpad4")]
    Numpad4,
    #[serde(rename = "Numpad5")]
    Numpad5,
    #[serde(rename = "Numpad6")]
    Numpad6,
    #[serde(rename = "Numpad7")]
    Numpad7,
    #[serde(rename = "Numpad8")]
    Numpad8,
    #[serde(rename = "Numpad9")]
    Numpad9,
    /// The decimal key.
    #[serde(rename = "NumpadDecimal")]
    Decimal,
    /// The separator key.
    #[serde(rename = "NumpadComma")]
    Comma,
    /// Divide.
    #[serde(rename = "NumpadDivide")]
    Divide,
    /// Multiply.
    #[serde(rename = "NumpadMultiply")]
    Multiply,
    /// Subtract.
    #[serde(rename = "NumpadSubtract")]
    Subtract,
    /// Add.
    #[serde(rename = "NumpadAdd")]
    Add,
    /// Equals.
    #[serde(rename = "NumpadEqual")]
    Equal,
    /// The keypad's Enter.
    #[serde(rename = "NumpadEnter")]
    Enter,
}

impl KeypadCode {
    /// The digit of a digit key.
    const fn digit(self) -> Option<u8> {
        Some(match self {
            Self::Numpad0 => 0,
            Self::Numpad1 => 1,
            Self::Numpad2 => 2,
            Self::Numpad3 => 3,
            Self::Numpad4 => 4,
            Self::Numpad5 => 5,
            Self::Numpad6 => 6,
            Self::Numpad7 => 7,
            Self::Numpad8 => 8,
            Self::Numpad9 => 9,
            _ => return None,
        })
    }
}

/// Whether a key went down, repeated while held, or came up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAction {
    /// It went down.
    Press,
    /// It repeated while held.
    Repeat,
    /// It came up.
    Release,
}

/// One key the page names, and what its platform said of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedKey {
    /// The key: what it made, or its name.
    pub key: KeyName,
    /// The character it makes with nothing held, where the platform said.
    pub base: Option<Scalar>,
    /// The keypad key it is, if it is one.
    pub keypad: Option<KeypadCode>,
    /// The modifiers held.
    pub modifiers: Modifiers,
    /// The locks on.
    pub locks: Locks,
}

/// Which key a press was, so its release finds it: what it made or its name, its unshifted
/// character, and its keypad key.
pub type Identity = (KeyName, Option<Scalar>, Option<KeypadCode>);

impl TypedKey {
    /// Which key this is, as a release names its press.
    #[must_use]
    pub fn identity(&self) -> Identity {
        (self.key.clone(), self.base, self.keypad)
    }

    /// The encoder's event for this key going down or repeating.
    ///
    /// # Errors
    ///
    /// Returns [`Unsupported::UnknownKey`] for a name or a keypad key this view has no key for.
    pub fn event(&self, kind: KeyEventKind) -> Result<KeyEvent, Unsupported> {
        Ok(KeyEvent {
            key: self.encoder_key()?,
            base: self.base.map(|base| base.0),
            modifiers: self.modifiers,
            locks: self.locks,
            kind,
        })
    }

    /// The encoder's key.
    fn encoder_key(&self) -> Result<Key, Unsupported> {
        match (self.keypad, &self.key) {
            (Some(code), made) => keypad_key(code, made).map(Key::Keypad),
            (None, KeyName::Character(character)) => Ok(Key::Char(*character)),
            (None, KeyName::Named(name)) => named(name).ok_or(Unsupported::UnknownKey),
        }
    }
}

/// A press the view wrote, and whether its release will be reported.
#[derive(Clone, Copy, Debug)]
pub struct Pressed {
    /// The press, as the encoder spelled it.
    pub event: KeyEvent,
    /// Whether the encoding it went in reports its release.
    pub reported: bool,
}

/// The most presses a view keeps a record of at once: far more keys than a person holds down, and
/// a bound on what a page that never sends a release can make the view keep.
const MOST_PRESSES: usize = 256;

/// The presses a view wrote under its newest take, so each release finds the press it ends.
///
/// The records of an older take go when a newer take writes, so nothing made in one period of
/// control is answered in another. Past [`MOST_PRESSES`] a press still goes and is not recorded,
/// and its release is then nothing: a release left out, never one invented.
#[derive(Debug, Default)]
pub struct Presses {
    take: u64,
    pressed: BTreeMap<Identity, Pressed>,
}

impl Presses {
    /// Records a press written under `take`.
    pub fn record(&mut self, take: u64, identity: Identity, pressed: Pressed) {
        if take != self.take {
            self.pressed.clear();
            self.take = take;
        }
        if self.pressed.len() < MOST_PRESSES || self.pressed.contains_key(&identity) {
            self.pressed.insert(identity, pressed);
        }
    }

    /// The press a release made under `take` ends, which it takes out of the record.
    pub fn released(&mut self, take: u64, identity: &Identity) -> Option<Pressed> {
        if take != self.take {
            return None;
        }
        self.pressed.remove(identity)
    }
}

/// The key a name names, for the keys that make no character.
fn named(name: &str) -> Option<Key> {
    Some(match name {
        "Enter" => Key::Enter,
        "Tab" => Key::Tab,
        "Backspace" => Key::Backspace,
        "Escape" => Key::Escape,
        "ArrowUp" => Key::Arrow(Arrow::Up),
        "ArrowDown" => Key::Arrow(Arrow::Down),
        "ArrowLeft" => Key::Arrow(Arrow::Left),
        "ArrowRight" => Key::Arrow(Arrow::Right),
        "Home" => Key::Home,
        "End" => Key::End,
        "PageUp" => Key::PageUp,
        "PageDown" => Key::PageDown,
        "Insert" => Key::Insert,
        "Delete" => Key::Delete,
        "ContextMenu" => Key::Menu,
        "PrintScreen" => Key::PrintScreen,
        "Pause" => Key::Pause,
        _ => {
            let number: u8 = name.strip_prefix('F')?.parse().ok()?;
            if !(1..=35).contains(&number) || name != format!("F{number}") {
                return None;
            }
            Key::Function(number)
        }
    })
}

/// The keypad key at `code` that made `made`: the character it makes, or, with Num Lock off, the
/// navigation key it became.
fn keypad_key(code: KeypadCode, made: &KeyName) -> Result<Keypad, Unsupported> {
    Ok(match (code, made) {
        (_, KeyName::Named(name)) => match (code, name.as_str()) {
            (KeypadCode::Enter, "Enter") => Keypad::Enter,
            (_, "Insert") => Keypad::Insert,
            (_, "Delete") => Keypad::Delete,
            (_, "End") => Keypad::End,
            (_, "Home") => Keypad::Home,
            (_, "PageDown") => Keypad::PageDown,
            (_, "PageUp") => Keypad::PageUp,
            (_, "ArrowDown") => Keypad::Arrow(Arrow::Down),
            (_, "ArrowLeft") => Keypad::Arrow(Arrow::Left),
            (_, "ArrowRight") => Keypad::Arrow(Arrow::Right),
            (_, "ArrowUp") => Keypad::Arrow(Arrow::Up),
            (_, "Clear") => Keypad::Begin,
            _ => return Err(Unsupported::UnknownKey),
        },
        (KeypadCode::Decimal, KeyName::Character(character)) => Keypad::Decimal(*character),
        (KeypadCode::Comma, KeyName::Character(character)) => Keypad::Separator(*character),
        (KeypadCode::Divide, KeyName::Character(_)) => Keypad::Divide,
        (KeypadCode::Multiply, KeyName::Character(_)) => Keypad::Multiply,
        (KeypadCode::Subtract, KeyName::Character(_)) => Keypad::Subtract,
        (KeypadCode::Add, KeyName::Character(_)) => Keypad::Add,
        (KeypadCode::Equal, KeyName::Character(_)) => Keypad::Equal,
        (KeypadCode::Enter, KeyName::Character(_)) => return Err(Unsupported::UnknownKey),
        (digit, KeyName::Character(_)) => {
            Keypad::Digit(digit.digit().ok_or(Unsupported::UnknownKey)?)
        }
    })
}

/// Text an input method, a software keyboard, dictation or a suggestion committed: never empty, no
/// control character, and no more than one input frame.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Text(String);

impl std::fmt::Debug for Text {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Text(..)")
    }
}

impl TryFrom<String> for Text {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        if text.is_empty() {
            return Err("text says something".to_owned());
        }
        if text.len() > MAX_INPUT_FRAME_LEN {
            return Err(format!(
                "text carries at most {MAX_INPUT_FRAME_LEN} bytes at once, not {}",
                text.len()
            ));
        }
        if text.chars().any(char::is_control) {
            return Err("text carries no control character: a key is sent as a key".to_owned());
        }
        Ok(Self(text))
    }
}

impl Text {
    /// The text's bytes, which is what every encoding the view produces sends for text.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

/// Text the person pasted: never empty, and small enough that framed as a bracketed paste it fits
/// one input frame.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Pasted(String);

impl std::fmt::Debug for Pasted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Pasted(..)")
    }
}

impl TryFrom<String> for Pasted {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let most = MAX_INPUT_FRAME_LEN - PASTE_FRAMING;
        if text.is_empty() {
            return Err("a paste says something".to_owned());
        }
        if text.len() > most {
            return Err(format!(
                "a paste carries at most {most} bytes at once, not {}",
                text.len()
            ));
        }
        Ok(Self(text))
    }
}

impl Pasted {
    /// The pasted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(key: &str, keypad: Option<KeypadCode>) -> TypedKey {
        TypedKey {
            key: KeyName::try_from(key.to_owned()).expect("a key"),
            base: None,
            keypad,
            modifiers: Modifiers::NONE,
            locks: Locks::NONE,
        }
    }

    #[test]
    fn a_name_is_a_key_that_makes_no_character() {
        for (name, expected) in [
            ("Enter", Key::Enter),
            ("ArrowLeft", Key::Arrow(Arrow::Left)),
            ("PageDown", Key::PageDown),
            ("ContextMenu", Key::Menu),
            ("F1", Key::Function(1)),
            ("F24", Key::Function(24)),
            ("F35", Key::Function(35)),
        ] {
            assert_eq!(
                key(name, None).encoder_key().expect("a key"),
                expected,
                "{name}"
            );
        }
        for unknown in ["F0", "F36", "F01", "Fn", "AudioVolumeUp", "Unidentified"] {
            assert_eq!(
                key(unknown, None).encoder_key(),
                Err(Unsupported::UnknownKey),
                "{unknown}"
            );
        }
        assert_eq!(key("a", None).encoder_key().expect("a key"), Key::Char('a'));
    }

    #[test]
    fn a_keypad_key_is_known_by_its_code_and_what_it_made() {
        for (made, code, expected) in [
            ("1", KeypadCode::Numpad1, Keypad::Digit(1)),
            ("End", KeypadCode::Numpad1, Keypad::End),
            ("ArrowUp", KeypadCode::Numpad8, Keypad::Arrow(Arrow::Up)),
            ("Clear", KeypadCode::Numpad5, Keypad::Begin),
            (",", KeypadCode::Decimal, Keypad::Decimal(',')),
            ("Delete", KeypadCode::Decimal, Keypad::Delete),
            (".", KeypadCode::Comma, Keypad::Separator('.')),
            ("+", KeypadCode::Add, Keypad::Add),
            ("Enter", KeypadCode::Enter, Keypad::Enter),
        ] {
            assert_eq!(
                key(made, Some(code)).encoder_key().expect("a keypad key"),
                Key::Keypad(expected),
                "{made} at {code:?}"
            );
        }
        assert_eq!(
            key("Tab", Some(KeypadCode::Numpad1)).encoder_key(),
            Err(Unsupported::UnknownKey)
        );
    }

    #[test]
    fn what_the_page_sends_is_held_to_its_shape() {
        assert!(KeyName::try_from(String::new()).is_err());
        assert!(
            KeyName::try_from("\u{1b}".to_owned()).is_err(),
            "no control character"
        );
        assert!(KeyName::try_from("\u{7f}".to_owned()).is_err());
        assert!(
            KeyName::try_from("\u{9b}".to_owned()).is_err(),
            "nor a C1 one"
        );
        assert!(KeyName::try_from("Arrow Up".to_owned()).is_err());
        assert!(KeyName::try_from("x".repeat(33)).is_err());
        assert!(KeyName::try_from("é".to_owned()).is_ok());
        assert!(Scalar::try_from("ab".to_owned()).is_err());
        assert!(
            Text::try_from("ls\r".to_owned()).is_err(),
            "a key is sent as a key"
        );
        assert!(Text::try_from("a\tb".to_owned()).is_err());
        assert!(Text::try_from("日本語".to_owned()).is_ok());
        assert!(Text::try_from("x".repeat(MAX_INPUT_FRAME_LEN + 1)).is_err());
        assert!(Pasted::try_from("x".repeat(MAX_INPUT_FRAME_LEN - PASTE_FRAMING)).is_ok());
        assert!(Pasted::try_from("x".repeat(MAX_INPUT_FRAME_LEN - PASTE_FRAMING + 1)).is_err());
        assert!(Pasted::try_from("line one\nline two\t\u{1b}".to_owned()).is_ok());
    }

    #[test]
    fn the_view_supplies_the_encodings_the_host_gives_its_profile() {
        let supplied = |encoding| {
            Keyboard {
                encoding,
                bracketed: false,
            }
            .supplied()
        };
        assert!(supplied(KeyboardEncoding::Legacy {
            application_cursor_keys: true
        }));
        for level in [1, 2] {
            assert!(supplied(KeyboardEncoding::ModifyOtherKeys {
                level,
                application_cursor_keys: false
            }));
        }
        for flags in [1, 2, 3] {
            assert!(supplied(KeyboardEncoding::Kitty { flags }), "{flags}");
        }
        for flags in [4, 5, 8, 9, 11, 16] {
            assert!(!supplied(KeyboardEncoding::Kitty { flags }), "{flags}");
        }
    }

    #[test]
    fn a_character_stays_out_of_debug() {
        assert_eq!(
            format!("{:?}", KeyName::try_from("k".to_owned()).expect("a key")),
            "Character(..)"
        );
        assert_eq!(
            format!("{:?}", Text::try_from("secret".to_owned()).expect("text")),
            "Text(..)"
        );
        assert_eq!(
            format!(
                "{:?}",
                Pasted::try_from("secret".to_owned()).expect("a paste")
            ),
            "Pasted(..)"
        );
    }
}
