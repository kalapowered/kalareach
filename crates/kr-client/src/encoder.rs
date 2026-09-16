//! The shared terminal input encoder.
//!
//! A rich client does not have a terminal underneath it. It has a logical key, a set of modifiers,
//! a pointer position and, sometimes, a block of pasted text, and it has to turn those into the
//! bytes the application is currently reading. Section 8 makes that conversion one thing shared by
//! every such client rather than a guess per platform: paste boundaries, application cursor keys,
//! modifier encodings, focus events and enabled keyboard protocols must all survive it intact.
//!
//! # What this refuses to do
//!
//! Section 8: *do not invent key-release, modifier or scan-code information absent from a legacy
//! stream.* The encoder therefore refuses rather than approximating. A key release has no legacy
//! spelling, so asking for one under the ordinary encoding is [`Unsupported`] and the caller finds
//! out; encoding it as a press would tell the application a key went down when it came up.
//!
//! The same rule runs the other way. Nothing here upgrades: a client that only knows a key went
//! down says so, and under the Kitty protocol with event types enabled it may say which kind of
//! event it was. What it may not do is fill in the kind it was never told.
//!
//! # Where the encoding comes from
//!
//! The application decides it, the host reads it off the canonical grid, and the client is told
//! what it is. A client that encodes for the wrong one produces bytes that mean other keys, which
//! is why the host refuses the input lease to a controller that cannot produce what the
//! application negotiated.

/// A modifier held while a key or pointer event happened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers {
    /// Shift.
    pub shift: bool,
    /// Alt, which xterm calls Meta.
    pub alt: bool,
    /// Control.
    pub control: bool,
    /// The platform's command or super key.
    pub superkey: bool,
}

impl Modifiers {
    /// No modifiers.
    pub const NONE: Self = Self {
        shift: false,
        alt: false,
        control: false,
        superkey: false,
    };

    /// Control alone.
    #[must_use]
    pub const fn control() -> Self {
        Self {
            control: true,
            ..Self::NONE
        }
    }

    /// Shift alone.
    #[must_use]
    pub const fn shift() -> Self {
        Self {
            shift: true,
            ..Self::NONE
        }
    }

    /// Returns true when no modifier was held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.shift && !self.alt && !self.control && !self.superkey
    }

    /// Returns the xterm modifier parameter: a bit set, plus one.
    ///
    /// This is the encoding every enhanced protocol shares, so it is computed once here rather
    /// than per sequence.
    #[must_use]
    pub const fn parameter(self) -> u8 {
        let mut bits = 0;
        if self.shift {
            bits |= 1;
        }
        if self.alt {
            bits |= 2;
        }
        if self.control {
            bits |= 4;
        }
        if self.superkey {
            bits |= 8;
        }
        bits + 1
    }
}

/// A logical key, before anything decides how to spell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A printable character, as the keyboard layout produced it.
    Char(char),
    /// Return.
    Enter,
    /// Tab.
    Tab,
    /// Backspace.
    Backspace,
    /// Escape.
    Escape,
    /// An arrow key.
    Arrow(Arrow),
    /// Home.
    Home,
    /// End.
    End,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Insert.
    Insert,
    /// Delete.
    Delete,
    /// A function key, numbered from one.
    Function(u8),
}

/// Which arrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrow {
    /// Up.
    Up,
    /// Down.
    Down,
    /// Right.
    Right,
    /// Left.
    Left,
}

impl Arrow {
    /// The final byte of the sequence this arrow produces.
    const fn final_byte(self) -> u8 {
        match self {
            Self::Up => b'A',
            Self::Down => b'B',
            Self::Right => b'C',
            Self::Left => b'D',
        }
    }
}

/// What happened to a key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyEventKind {
    /// It went down.
    #[default]
    Press,
    /// It repeated while held.
    Repeat,
    /// It came up.
    Release,
}

/// One key event a client observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    /// The logical key.
    pub key: Key,
    /// The modifiers held with it.
    pub modifiers: Modifiers,
    /// What happened to it.
    pub kind: KeyEventKind,
}

impl KeyEvent {
    /// A plain press of `key`.
    #[must_use]
    pub const fn press(key: Key) -> Self {
        Self {
            key,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Press,
        }
    }

    /// A press of `key` with `modifiers`.
    #[must_use]
    pub const fn with(key: Key, modifiers: Modifiers) -> Self {
        Self {
            key,
            modifiers,
            kind: KeyEventKind::Press,
        }
    }
}

/// The keyboard encoding the application has negotiated.
///
/// It is what the host read off the canonical grid, not what the client would prefer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyboardEncoding {
    /// The ordinary xterm encoding. `application_cursor_keys` is DEC mode 1, which changes the
    /// arrows from `CSI A` to `SS3 A` and nothing else.
    Legacy {
        /// Whether DEC mode 1 is set.
        application_cursor_keys: bool,
    },
    /// xterm's `modifyOtherKeys` at this level, over the ordinary encoding.
    ModifyOtherKeys {
        /// The level, one or two.
        level: u8,
        /// Whether DEC mode 1 is set.
        application_cursor_keys: bool,
    },
    /// The Kitty keyboard protocol with these flags.
    Kitty {
        /// The flags in force.
        flags: u8,
    },
}

impl KeyboardEncoding {
    /// Bit 1: disambiguate escape codes.
    pub const KITTY_DISAMBIGUATE: u8 = 0b0000_0001;
    /// Bit 2: report event types, which is what makes a release expressible.
    pub const KITTY_EVENT_TYPES: u8 = 0b0000_0010;
    /// Bit 4: report alternate keys.
    pub const KITTY_ALTERNATE_KEYS: u8 = 0b0000_0100;
    /// Bit 8: report all keys as escape codes.
    pub const KITTY_ALL_AS_ESCAPES: u8 = 0b0000_1000;

    const fn application_cursor_keys(self) -> bool {
        match self {
            Self::Legacy {
                application_cursor_keys,
            }
            | Self::ModifyOtherKeys {
                application_cursor_keys,
                ..
            } => application_cursor_keys,
            // The Kitty protocol spells the arrows itself.
            Self::Kitty { .. } => false,
        }
    }
}

/// Why the encoder would not produce bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// The event carries information the negotiated encoding cannot express, and inventing a
    /// spelling for it would tell the application something that did not happen.
    NotExpressible {
        /// What could not be expressed.
        what: &'static str,
    },
    /// The key is outside what this encoder knows how to spell.
    UnknownKey,
}

impl std::fmt::Display for Unsupported {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExpressible { what } => write!(
                formatter,
                "the negotiated encoding cannot express {what}, and this encoder does not invent one"
            ),
            Self::UnknownKey => formatter.write_str("this encoder has no spelling for that key"),
        }
    }
}

impl std::error::Error for Unsupported {}

/// The bracketed-paste start delimiter.
pub const PASTE_START: &[u8] = b"\x1b[200~";

/// The bracketed-paste end delimiter.
pub const PASTE_END: &[u8] = b"\x1b[201~";

/// Encodes one key event for `encoding`.
///
/// # Errors
///
/// Returns [`Unsupported`] when the event says something the encoding cannot, rather than
/// producing bytes that mean something else.
pub fn key(event: KeyEvent, encoding: KeyboardEncoding) -> Result<Vec<u8>, Unsupported> {
    match encoding {
        KeyboardEncoding::Kitty { flags } => kitty(event, flags),
        KeyboardEncoding::Legacy { .. } => legacy(event, encoding, 0),
        KeyboardEncoding::ModifyOtherKeys { level, .. } => legacy(event, encoding, level),
    }
}

fn legacy(
    event: KeyEvent,
    encoding: KeyboardEncoding,
    modify_other_keys: u8,
) -> Result<Vec<u8>, Unsupported> {
    if event.kind == KeyEventKind::Release {
        // A legacy stream has no spelling for a key coming up. Section 8 forbids inventing one.
        return Err(Unsupported::NotExpressible {
            what: "a key release",
        });
    }
    if event.modifiers.superkey {
        // xterm's modifier parameter has a bit for it, but the ordinary encoding has nowhere to put
        // one, and no application reads a command key out of a legacy stream.
        return Err(Unsupported::NotExpressible {
            what: "a command or super modifier",
        });
    }
    let application = encoding.application_cursor_keys();
    match event.key {
        Key::Char(character) => Ok(legacy_character(
            character,
            event.modifiers,
            modify_other_keys,
        )),
        Key::Enter => Ok(control_or_plain(
            b'\r',
            event.modifiers,
            modify_other_keys,
            13,
        )),
        Key::Tab => Ok(if event.modifiers.shift {
            b"\x1b[Z".to_vec()
        } else {
            control_or_plain(b'\t', event.modifiers, modify_other_keys, 9)
        }),
        Key::Backspace => Ok(control_or_plain(
            0x7f,
            event.modifiers,
            modify_other_keys,
            127,
        )),
        Key::Escape => Ok(control_or_plain(
            0x1b,
            event.modifiers,
            modify_other_keys,
            27,
        )),
        Key::Arrow(arrow) => Ok(cursor_key(arrow, event.modifiers, application)),
        Key::Home => Ok(edit_key(b'H', 1, event.modifiers, application)),
        Key::End => Ok(edit_key(b'F', 4, event.modifiers, application)),
        Key::Insert => Ok(tilde_key(2, event.modifiers)),
        Key::Delete => Ok(tilde_key(3, event.modifiers)),
        Key::PageUp => Ok(tilde_key(5, event.modifiers)),
        Key::PageDown => Ok(tilde_key(6, event.modifiers)),
        Key::Function(number) => function_key(number, event.modifiers),
    }
}

/// Spells a printable key under the ordinary encoding, with `modifyOtherKeys` where it applies.
fn legacy_character(character: char, modifiers: Modifiers, modify_other_keys: u8) -> Vec<u8> {
    // Control plus a letter has had one spelling since the teletype, and every level of
    // `modifyOtherKeys` below two leaves it alone.
    if modifiers.control
        && !modifiers.alt
        && let Some(byte) = control_byte(character)
    {
        if modify_other_keys < 2 {
            return vec![byte];
        }
        // Level two reports even the keys that already had a spelling, which is the whole point of
        // it: an application can then tell Control-I from Tab.
        return modify_other_keys_report(u32::from(character), modifiers);
    }
    if modify_other_keys > 0 && (modifiers.control || (modifiers.alt && modifiers.shift)) {
        return modify_other_keys_report(u32::from(character), modifiers);
    }
    let mut bytes = Vec::new();
    if modifiers.alt {
        // Alt is the escape prefix, which is what every terminal has always sent for it.
        bytes.push(0x1b);
    }
    let mut buffer = [0_u8; 4];
    bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
    bytes
}

/// Spells a key that already has a control byte, reporting it instead at level two.
fn control_or_plain(byte: u8, modifiers: Modifiers, modify_other_keys: u8, code: u32) -> Vec<u8> {
    if modify_other_keys >= 2 && !modifiers.is_empty() {
        return modify_other_keys_report(code, modifiers);
    }
    if modify_other_keys > 0 && (modifiers.control || modifiers.shift) {
        return modify_other_keys_report(code, modifiers);
    }
    let mut bytes = Vec::new();
    if modifiers.alt {
        bytes.push(0x1b);
    }
    bytes.push(byte);
    bytes
}

fn modify_other_keys_report(code: u32, modifiers: Modifiers) -> Vec<u8> {
    format!("\x1b[27;{};{code}~", modifiers.parameter()).into_bytes()
}

fn control_byte(character: char) -> Option<u8> {
    match character {
        'a'..='z' => Some(character as u8 - b'a' + 1),
        'A'..='Z' => Some(character as u8 - b'A' + 1),
        '@' => Some(0),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        ' ' => Some(0),
        '?' => Some(0x7f),
        _ => None,
    }
}

/// An arrow key, which is the one place DEC mode 1 changes the spelling.
fn cursor_key(arrow: Arrow, modifiers: Modifiers, application: bool) -> Vec<u8> {
    let final_byte = arrow.final_byte();
    if modifiers.is_empty() {
        // Application cursor keys are `SS3 A`; the ordinary ones are `CSI A`. An application that
        // set mode 1 and received `CSI A` reads a different key.
        return if application {
            vec![0x1b, b'O', final_byte]
        } else {
            vec![0x1b, b'[', final_byte]
        };
    }
    // A modified arrow is always the CSI form with the modifier parameter, whichever mode is set.
    format!("\x1b[1;{}{}", modifiers.parameter(), final_byte as char).into_bytes()
}

/// Home and End, which have both a letter form and a numbered form.
fn edit_key(final_byte: u8, number: u8, modifiers: Modifiers, application: bool) -> Vec<u8> {
    if modifiers.is_empty() {
        return if application {
            vec![0x1b, b'O', final_byte]
        } else {
            vec![0x1b, b'[', final_byte]
        };
    }
    let _ = number;
    format!("\x1b[1;{}{}", modifiers.parameter(), final_byte as char).into_bytes()
}

/// The numbered editing keys, which end in a tilde.
fn tilde_key(number: u8, modifiers: Modifiers) -> Vec<u8> {
    if modifiers.is_empty() {
        format!("\x1b[{number}~").into_bytes()
    } else {
        format!("\x1b[{number};{}~", modifiers.parameter()).into_bytes()
    }
}

fn function_key(number: u8, modifiers: Modifiers) -> Result<Vec<u8>, Unsupported> {
    // F1 to F4 are the SS3 letters; F5 upwards are numbered and end in a tilde. The numbers skip
    // 16, 22, 27, 30 and 35, which is the xterm table rather than an arithmetic rule.
    let letters = *b"PQRS";
    if (1..=4).contains(&number) {
        let final_byte = letters[usize::from(number) - 1];
        return Ok(if modifiers.is_empty() {
            vec![0x1b, b'O', final_byte]
        } else {
            format!("\x1b[1;{}{}", modifiers.parameter(), final_byte as char).into_bytes()
        });
    }
    let numbered = match number {
        5 => 15,
        6..=10 => u16::from(number) + 11,
        11 | 12 => u16::from(number) + 12,
        _ => return Err(Unsupported::UnknownKey),
    };
    Ok(if modifiers.is_empty() {
        format!("\x1b[{numbered}~").into_bytes()
    } else {
        format!("\x1b[{numbered};{}~", modifiers.parameter()).into_bytes()
    })
}

/// Spells a key under the Kitty keyboard protocol.
fn kitty(event: KeyEvent, flags: u8) -> Result<Vec<u8>, Unsupported> {
    let reports_events = flags & KeyboardEncoding::KITTY_EVENT_TYPES != 0;
    if event.kind != KeyEventKind::Press && !reports_events {
        // The protocol is in force but event types are not, so a release has no place in the
        // stream. Sending it as a press is the invention section 8 forbids.
        return Err(Unsupported::NotExpressible {
            what: "an event type the application did not ask for",
        });
    }
    let code = kitty_code(event.key)?;
    let modifiers = event.modifiers.parameter();
    let kind = match event.kind {
        KeyEventKind::Press => 1,
        KeyEventKind::Repeat => 2,
        KeyEventKind::Release => 3,
    };
    // A plain press of a printable key stays a plain byte unless the application asked for all keys
    // as escape codes. Sending an escape sequence for every letter to an application that did not
    // ask for one is the other half of the same mistake.
    if event.kind == KeyEventKind::Press
        && event.modifiers.is_empty()
        && flags & KeyboardEncoding::KITTY_ALL_AS_ESCAPES == 0
        && let Key::Char(character) = event.key
    {
        let mut buffer = [0_u8; 4];
        return Ok(character.encode_utf8(&mut buffer).as_bytes().to_vec());
    }
    let suffix = kitty_suffix(event.key);
    if reports_events && event.kind != KeyEventKind::Press {
        return Ok(format!("\x1b[{code};{modifiers}:{kind}{suffix}").into_bytes());
    }
    if event.modifiers.is_empty() {
        return Ok(format!("\x1b[{code}{suffix}").into_bytes());
    }
    Ok(format!("\x1b[{code};{modifiers}{suffix}").into_bytes())
}

/// The final byte the Kitty protocol uses for this key.
///
/// Most keys end in `u` with their Unicode code point; the ones the ordinary encoding already had a
/// letter for keep that letter, because the protocol is an extension of it rather than a
/// replacement.
const fn kitty_suffix(key: Key) -> char {
    match key {
        Key::Arrow(Arrow::Up) => 'A',
        Key::Arrow(Arrow::Down) => 'B',
        Key::Arrow(Arrow::Right) => 'C',
        Key::Arrow(Arrow::Left) => 'D',
        Key::Home => 'H',
        Key::End => 'F',
        Key::Function(1) => 'P',
        Key::Function(2) => 'Q',
        Key::Function(4) => 'S',
        Key::Insert | Key::Delete | Key::PageUp | Key::PageDown | Key::Function(_) => '~',
        _ => 'u',
    }
}

fn kitty_code(key: Key) -> Result<u32, Unsupported> {
    Ok(match key {
        Key::Char(character) => u32::from(character),
        Key::Enter => 13,
        Key::Tab => 9,
        Key::Backspace => 127,
        Key::Escape => 27,
        Key::Arrow(_) | Key::Home | Key::End => 1,
        Key::Insert => 2,
        Key::Delete => 3,
        Key::PageUp => 5,
        Key::PageDown => 6,
        Key::Function(number) => match number {
            1 | 2 | 4 => 1,
            3 => 13,
            5 => 15,
            6..=10 => u32::from(number) + 11,
            11 | 12 => u32::from(number) + 12,
            _ => return Err(Unsupported::UnknownKey),
        },
    })
}

/// Encodes a paste operation.
///
/// When the application has canonical bracketed-paste mode on, the text is delimited so it arrives
/// as one paste rather than as keystrokes. When it does not, the text is the bytes and nothing
/// wraps them.
///
/// The end delimiter is removed from the payload either way. Text that contained it would end its
/// own paste and hand the rest to the application as typing, which is how a pasted line becomes a
/// command; a client that passed it through would be the source of that.
#[must_use]
pub fn paste(text: &str, bracketed: bool) -> Vec<u8> {
    let filtered = strip_delimiters(text.as_bytes());
    if !bracketed {
        return filtered;
    }
    let mut bytes = Vec::with_capacity(filtered.len() + PASTE_START.len() + PASTE_END.len());
    bytes.extend_from_slice(PASTE_START);
    bytes.extend_from_slice(&filtered);
    bytes.extend_from_slice(PASTE_END);
    bytes
}

fn strip_delimiters(bytes: &[u8]) -> Vec<u8> {
    let mut kept = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(PASTE_END) {
            index += PASTE_END.len();
            continue;
        }
        if bytes[index..].starts_with(PASTE_START) {
            index += PASTE_START.len();
            continue;
        }
        kept.push(bytes[index]);
        index += 1;
    }
    kept
}

/// Which mouse reporting encoding the application turned on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseEncoding {
    /// The original report: `CSI M` and three offset bytes. It cannot express a column or row
    /// beyond 223.
    X10,
    /// DEC mode 1006, which reports decimal parameters and distinguishes a release.
    Sgr,
}

/// What the pointer did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseAction {
    /// A button went down.
    Press(MouseButton),
    /// A button came up.
    Release(MouseButton),
    /// The pointer moved with a button held.
    Drag(MouseButton),
    /// The wheel turned. It is a wheel event in the stream, never an arrow key.
    Wheel(WheelDirection),
}

/// Which button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    /// The left button.
    Left,
    /// The middle button.
    Middle,
    /// The right button.
    Right,
}

impl MouseButton {
    const fn code(self) -> u32 {
        match self {
            Self::Left => 0,
            Self::Middle => 1,
            Self::Right => 2,
        }
    }
}

/// Which way the wheel turned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WheelDirection {
    /// Away from the person.
    Up,
    /// Towards the person.
    Down,
}

/// One pointer event, at canonical cell coordinates.
///
/// The coordinates are the canonical grid's, counted from zero. Mapping a display position onto
/// them is [`crate::viewport::Viewport::map`]'s job and happens before this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MouseEvent {
    /// What the pointer did.
    pub action: MouseAction,
    /// The canonical column, counted from zero.
    pub column: u32,
    /// The canonical row, counted from zero.
    pub row: u32,
    /// The modifiers held with it.
    pub modifiers: Modifiers,
}

/// Encodes one pointer event.
///
/// # Errors
///
/// Returns [`Unsupported`] when the encoding cannot carry the event: the original report has no
/// room for a coordinate beyond 223 and no way to say which button was released, and a client that
/// rounded either would tell the application about a different cell or a different button.
pub fn mouse(event: MouseEvent, encoding: MouseEncoding) -> Result<Vec<u8>, Unsupported> {
    let mut code = match event.action {
        MouseAction::Press(button) | MouseAction::Release(button) => button.code(),
        MouseAction::Drag(button) => button.code() + 32,
        MouseAction::Wheel(WheelDirection::Up) => 64,
        MouseAction::Wheel(WheelDirection::Down) => 65,
    };
    if event.modifiers.shift {
        code += 4;
    }
    if event.modifiers.alt {
        code += 8;
    }
    if event.modifiers.control {
        code += 16;
    }
    match encoding {
        MouseEncoding::Sgr => {
            // One based on the wire, and a release is the same report with a lower-case final byte.
            let final_byte = if matches!(event.action, MouseAction::Release(_)) {
                'm'
            } else {
                'M'
            };
            Ok(format!(
                "\x1b[<{code};{};{}{final_byte}",
                event.column + 1,
                event.row + 1
            )
            .into_bytes())
        }
        MouseEncoding::X10 => {
            if matches!(event.action, MouseAction::Release(_)) {
                // The original report says a button came up and not which one. Choosing one would
                // be an invention; the caller either asks for a protocol that can say it or hears
                // that this one cannot.
                if !matches!(event.action, MouseAction::Release(MouseButton::Left)) {
                    return Err(Unsupported::NotExpressible {
                        what: "which button was released",
                    });
                }
                code = 3;
            }
            let column = event.column + 1;
            let row = event.row + 1;
            if column > 223 || row > 223 || code > 223 {
                return Err(Unsupported::NotExpressible {
                    what: "a position beyond the original report's range",
                });
            }
            let mut bytes = vec![0x1b, b'[', b'M'];
            bytes.push(u8::try_from(code + 32).unwrap_or(u8::MAX));
            bytes.push(u8::try_from(column + 32).unwrap_or(u8::MAX));
            bytes.push(u8::try_from(row + 32).unwrap_or(u8::MAX));
            Ok(bytes)
        }
    }
}

/// Encodes a focus change for DEC mode 1004.
///
/// Only the attachment holding the input lease sends these. Section 8 is explicit that other views
/// cannot change the application's focus state, so a client that is not the holder encodes nothing
/// rather than sending bytes the host would refuse.
#[must_use]
pub const fn focus(gained: bool) -> &'static [u8] {
    if gained { b"\x1b[I" } else { b"\x1b[O" }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: KeyboardEncoding = KeyboardEncoding::Legacy {
        application_cursor_keys: false,
    };
    const APPLICATION: KeyboardEncoding = KeyboardEncoding::Legacy {
        application_cursor_keys: true,
    };

    /// KR-REQ-08.59: application cursor keys survive the conversion.
    #[test]
    fn an_arrow_key_is_spelled_the_way_the_mode_in_force_spells_it() {
        let up = KeyEvent::press(Key::Arrow(Arrow::Up));
        assert_eq!(key(up, LEGACY).expect("encodes"), b"\x1b[A");
        assert_eq!(
            key(up, APPLICATION).expect("encodes"),
            b"\x1bOA",
            "mode 1 changes the arrows and nothing else"
        );
        // A modified arrow is the CSI form in both, which is what xterm does.
        let modified = KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control());
        assert_eq!(key(modified, LEGACY).expect("encodes"), b"\x1b[1;5A");
        assert_eq!(key(modified, APPLICATION).expect("encodes"), b"\x1b[1;5A");
    }

    /// KR-REQ-08.59: the modifier encodings.
    #[test]
    fn the_modifier_parameter_is_the_bit_set_plus_one() {
        assert_eq!(Modifiers::NONE.parameter(), 1);
        assert_eq!(Modifiers::shift().parameter(), 2);
        assert_eq!(Modifiers::control().parameter(), 5);
        assert_eq!(
            Modifiers {
                shift: true,
                alt: true,
                control: true,
                superkey: false
            }
            .parameter(),
            8
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Arrow(Arrow::Left), Modifiers::shift()),
                LEGACY
            )
            .expect("encodes"),
            b"\x1b[1;2D"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Delete, Modifiers::control()), LEGACY).expect("encodes"),
            b"\x1b[3;5~"
        );
    }

    /// KR-REQ-08.59: `modifyOtherKeys` reports what the ordinary encoding could not distinguish.
    #[test]
    fn modify_other_keys_reports_the_key_and_its_modifiers() {
        let level_one = KeyboardEncoding::ModifyOtherKeys {
            level: 1,
            application_cursor_keys: false,
        };
        let level_two = KeyboardEncoding::ModifyOtherKeys {
            level: 2,
            application_cursor_keys: false,
        };
        let control_i = KeyEvent::with(Key::Char('i'), Modifiers::control());
        assert_eq!(
            key(control_i, level_one).expect("encodes"),
            b"\x09",
            "level one leaves a key that already had a spelling alone"
        );
        assert_eq!(
            key(control_i, level_two).expect("encodes"),
            b"\x1b[27;5;105~",
            "level two reports it, so an application can tell it from Tab"
        );
        // A key with no legacy spelling is reported at either level.
        let control_semicolon = KeyEvent::with(Key::Char(';'), Modifiers::control());
        assert_eq!(
            key(control_semicolon, level_one).expect("encodes"),
            b"\x1b[27;5;59~"
        );
    }

    /// KR-REQ-08.59, KR-REQ-08.60: the Kitty protocol, with and without event types.
    #[test]
    fn the_kitty_protocol_spells_what_its_flags_allow_and_refuses_the_rest() {
        let disambiguate = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
        };
        let with_events = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        let all_escapes = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };

        // A plain letter stays a letter unless the application asked for every key as an escape.
        assert_eq!(
            key(KeyEvent::press(Key::Char('a')), disambiguate).expect("encodes"),
            b"a"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Char('a')), all_escapes).expect("encodes"),
            b"\x1b[97u"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Char('a'), Modifiers::control()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[97;5u"
        );
        // A release needs the flag that makes event types part of the stream.
        let release = KeyEvent {
            key: Key::Char('a'),
            modifiers: Modifiers::control(),
            kind: KeyEventKind::Release,
        };
        assert_eq!(
            key(release, disambiguate),
            Err(Unsupported::NotExpressible {
                what: "an event type the application did not ask for"
            })
        );
        assert_eq!(key(release, with_events).expect("encodes"), b"\x1b[97;5:3u");
        let repeat = KeyEvent {
            kind: KeyEventKind::Repeat,
            ..release
        };
        assert_eq!(key(repeat, with_events).expect("encodes"), b"\x1b[97;5:2u");
    }

    /// KR-REQ-08.59: a release has no legacy spelling, and none is invented for it.
    #[test]
    fn a_key_release_is_refused_rather_than_sent_as_a_press() {
        let release = KeyEvent {
            key: Key::Char('a'),
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Release,
        };
        for encoding in [
            LEGACY,
            APPLICATION,
            KeyboardEncoding::ModifyOtherKeys {
                level: 2,
                application_cursor_keys: false,
            },
        ] {
            assert_eq!(
                key(release, encoding),
                Err(Unsupported::NotExpressible {
                    what: "a key release"
                }),
                "{encoding:?}"
            );
        }
    }

    /// KR-REQ-08.59: paste boundaries survive, and a paste cannot end itself.
    #[test]
    fn a_paste_is_delimited_when_the_application_asked_for_boundaries() {
        assert_eq!(paste("hello", true), b"\x1b[200~hello\x1b[201~".to_vec());
        assert_eq!(
            paste("hello", false),
            b"hello".to_vec(),
            "with the mode off the text is the bytes and nothing wraps them"
        );
        // Text that contained the end delimiter would end its own paste and hand the rest to the
        // application as typing.
        let hostile = "rm -rf /\x1b[201~\ninnocent";
        let encoded = paste(hostile, true);
        assert_eq!(
            encoded
                .windows(PASTE_END.len())
                .filter(|window| *window == PASTE_END)
                .count(),
            1,
            "one terminator, and it is the encoder's own: {}",
            String::from_utf8_lossy(&encoded).escape_debug()
        );
        assert!(encoded.starts_with(PASTE_START));
        assert!(encoded.ends_with(PASTE_END));
        assert!(
            String::from_utf8_lossy(&encoded).contains("innocent"),
            "and the rest of the text is still there"
        );
        // A start delimiter inside the text goes the same way: one paste, one pair of boundaries.
        let nested = paste("a\x1b[200~b", true);
        assert_eq!(nested, b"\x1b[200~ab\x1b[201~".to_vec());
    }

    /// KR-REQ-08.58, KR-REQ-08.76: the wheel is a wheel event, at canonical coordinates.
    #[test]
    fn a_wheel_event_is_encoded_as_the_wheel_and_never_as_an_arrow() {
        let event = MouseEvent {
            action: MouseAction::Wheel(WheelDirection::Up),
            column: 9,
            row: 4,
            modifiers: Modifiers::NONE,
        };
        let sgr = mouse(event, MouseEncoding::Sgr).expect("encodes");
        assert_eq!(sgr, b"\x1b[<64;10;5M".to_vec());
        assert!(
            !sgr.ends_with(b"A") && !sgr.ends_with(b"B"),
            "nothing about it is an arrow key"
        );
        let down = MouseEvent {
            action: MouseAction::Wheel(WheelDirection::Down),
            ..event
        };
        assert_eq!(
            mouse(down, MouseEncoding::Sgr).expect("encodes"),
            b"\x1b[<65;10;5M".to_vec()
        );
    }

    /// KR-REQ-08.76: a press, its release and a drag, in both encodings.
    #[test]
    fn a_pointer_event_is_encoded_at_the_cell_it_was_mapped_to() {
        let press = MouseEvent {
            action: MouseAction::Press(MouseButton::Left),
            column: 2,
            row: 3,
            modifiers: Modifiers::NONE,
        };
        assert_eq!(
            mouse(press, MouseEncoding::Sgr).expect("encodes"),
            b"\x1b[<0;3;4M".to_vec()
        );
        let release = MouseEvent {
            action: MouseAction::Release(MouseButton::Left),
            ..press
        };
        assert_eq!(
            mouse(release, MouseEncoding::Sgr).expect("encodes"),
            b"\x1b[<0;3;4m".to_vec(),
            "the release is the lower-case final byte"
        );
        assert_eq!(
            mouse(press, MouseEncoding::X10).expect("encodes"),
            vec![0x1b, b'[', b'M', 32, 35, 36]
        );
        let right_release = MouseEvent {
            action: MouseAction::Release(MouseButton::Right),
            ..press
        };
        assert_eq!(
            mouse(right_release, MouseEncoding::X10),
            Err(Unsupported::NotExpressible {
                what: "which button was released"
            }),
            "the original report cannot say which button came up"
        );
        let far = MouseEvent {
            column: 500,
            ..press
        };
        assert!(
            mouse(far, MouseEncoding::X10).is_err(),
            "nor a column beyond its range"
        );
        assert!(
            mouse(far, MouseEncoding::Sgr).is_ok(),
            "which is what mode 1006 exists for"
        );
    }

    /// KR-REQ-08.58: focus events are two sequences and nothing else.
    #[test]
    fn a_focus_change_is_the_sequence_mode_one_thousand_and_four_defines() {
        assert_eq!(focus(true), b"\x1b[I");
        assert_eq!(focus(false), b"\x1b[O");
    }

    /// KR-REQ-08.59: the function keys follow xterm's table rather than an arithmetic rule.
    #[test]
    fn the_function_keys_are_spelled_from_the_table_rather_than_computed() {
        assert_eq!(
            key(KeyEvent::press(Key::Function(1)), LEGACY).expect("encodes"),
            b"\x1bOP"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(5)), LEGACY).expect("encodes"),
            b"\x1b[15~",
            "and fifteen, not sixteen"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(6)), LEGACY).expect("encodes"),
            b"\x1b[17~"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(12)), LEGACY).expect("encodes"),
            b"\x1b[24~"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(13)), LEGACY),
            Err(Unsupported::UnknownKey),
            "a key with no spelling is refused rather than guessed at"
        );
    }

    /// KR-REQ-08.59: Alt is the escape prefix, and a command key has nowhere to go.
    #[test]
    fn alt_is_the_escape_prefix_and_a_command_key_is_refused() {
        let alt_a = KeyEvent::with(
            Key::Char('a'),
            Modifiers {
                alt: true,
                ..Modifiers::NONE
            },
        );
        assert_eq!(key(alt_a, LEGACY).expect("encodes"), b"\x1ba");
        let command_a = KeyEvent::with(
            Key::Char('a'),
            Modifiers {
                superkey: true,
                ..Modifiers::NONE
            },
        );
        assert_eq!(
            key(command_a, LEGACY),
            Err(Unsupported::NotExpressible {
                what: "a command or super modifier"
            })
        );
    }

    /// KR-REQ-08.59: control and a letter keeps the spelling it has always had.
    #[test]
    fn control_and_a_letter_is_the_byte_it_has_always_been() {
        assert_eq!(
            key(KeyEvent::with(Key::Char('c'), Modifiers::control()), LEGACY).expect("encodes"),
            b"\x03"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Char('d'), Modifiers::control()), LEGACY).expect("encodes"),
            b"\x04"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Enter), LEGACY).expect("encodes"),
            b"\r"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Backspace), LEGACY).expect("encodes"),
            b"\x7f"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Tab, Modifiers::shift()),
                KeyboardEncoding::Legacy {
                    application_cursor_keys: false
                }
            )
            .expect("encodes"),
            b"\x1b[Z"
        );
    }
}
