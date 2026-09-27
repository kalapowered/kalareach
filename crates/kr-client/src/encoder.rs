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
//! stream.* The encoder therefore refuses rather than approximating. It spells a key's release only
//! from the press it ends ([`release`]), and only where the encoding reports releases at all: the
//! ordinary encoding and `modifyOtherKeys` have no spelling for one, so a release under them is
//! nothing, never a press. A client learns when a key goes down whether its release will be
//! reported ([`release_reported`]) and keeps that answer with the key.
//!
//! The same rule runs the other way. Nothing here upgrades: a client that only knows a key went
//! down says so, and under the Kitty protocol with event types enabled it may say which kind of
//! event it was. What it may not do is fill in what it was never told, the unshifted key a
//! character came from included.
//!
//! # Where the encoding comes from
//!
//! The application decides it, the host reads it off the canonical grid, and the client is told
//! what it is: [`KeyboardEncoding::negotiated`] reads it from what the host projects. A client that
//! encodes for the wrong one produces bytes that mean other keys, which is why the host refuses the
//! input lease to a controller that cannot produce what the application negotiated.
//!
//! # Whose spellings
//!
//! The ordinary encoding and `modifyOtherKeys` are xterm's, with X11's mapping of Control and a
//! character. The Kitty protocol's are its specification's, and kitty's own encoder's where the
//! specification is silent.

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

/// Which lock keys were on when a key event happened.
///
/// The Kitty keyboard protocol reports them beside the modifiers, as bits 64 and 128 of the same
/// parameter, on every key it sends as an escape code. The ordinary encoding and `modifyOtherKeys`
/// have nowhere to put them, and never do. A client reports what its platform says of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Locks {
    /// Caps Lock.
    pub caps_lock: bool,
    /// Num Lock.
    pub num_lock: bool,
}

impl Locks {
    /// No lock on.
    pub const NONE: Self = Self {
        caps_lock: false,
        num_lock: false,
    };

    /// Returns true when no lock is on.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.caps_lock && !self.num_lock
    }

    /// The bits the Kitty keyboard protocol gives the locks in its modifier parameter.
    const fn kitty_bits(self) -> u16 {
        let mut bits = 0;
        if self.caps_lock {
            bits |= 64;
        }
        if self.num_lock {
            bits |= 128;
        }
        bits
    }
}

/// A logical key, before anything decides how to spell it.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// A function key, numbered from one. The ordinary encoding spells one to twelve, and the Kitty
    /// protocol one to thirty-five.
    Function(u8),
    /// A key of the numeric keypad.
    Keypad(Keypad),
    /// The menu key.
    Menu,
    /// Print Screen.
    PrintScreen,
    /// Pause.
    Pause,
}

impl std::fmt::Debug for Key {
    /// Which key it is, and for a character only that it is one: a typed character is part of
    /// whatever a person typed, a password included.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Char(_) => formatter.write_str("Char(..)"),
            Self::Enter => formatter.write_str("Enter"),
            Self::Tab => formatter.write_str("Tab"),
            Self::Backspace => formatter.write_str("Backspace"),
            Self::Escape => formatter.write_str("Escape"),
            Self::Arrow(arrow) => formatter.debug_tuple("Arrow").field(arrow).finish(),
            Self::Home => formatter.write_str("Home"),
            Self::End => formatter.write_str("End"),
            Self::PageUp => formatter.write_str("PageUp"),
            Self::PageDown => formatter.write_str("PageDown"),
            Self::Insert => formatter.write_str("Insert"),
            Self::Delete => formatter.write_str("Delete"),
            Self::Function(number) => formatter.debug_tuple("Function").field(number).finish(),
            Self::Keypad(keypad) => formatter.debug_tuple("Keypad").field(keypad).finish(),
            Self::Menu => formatter.write_str("Menu"),
            Self::PrintScreen => formatter.write_str("PrintScreen"),
            Self::Pause => formatter.write_str("Pause"),
        }
    }
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

/// A key of the numeric keypad as it stands when pressed: a key that makes a character, or, with
/// Num Lock off, the navigation key it becomes.
///
/// The Kitty protocol can tell the keypad from the main keys once an application asks it to; the
/// ordinary encoding cannot, and there a keypad key is the main key it stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Keypad {
    /// A digit key making its digit, zero to nine.
    Digit(u8),
    /// The decimal key, making the character the layout gives it.
    Decimal(char),
    /// The separator key, making the character the layout gives it.
    Separator(char),
    /// Divide, making `/`.
    Divide,
    /// Multiply, making `*`.
    Multiply,
    /// Subtract, making `-`.
    Subtract,
    /// Add, making `+`.
    Add,
    /// Equals, making `=`.
    Equal,
    /// The keypad's Enter.
    Enter,
    /// An arrow the keypad makes with Num Lock off.
    Arrow(Arrow),
    /// Page up, from the keypad.
    PageUp,
    /// Page down, from the keypad.
    PageDown,
    /// Home, from the keypad.
    Home,
    /// End, from the keypad.
    End,
    /// Insert, from the keypad.
    Insert,
    /// Delete, from the keypad.
    Delete,
    /// The centre key with Num Lock off.
    Begin,
}

impl std::fmt::Debug for Keypad {
    /// Which key it is, and for a key that makes a character only that it does: a digit is part of
    /// whatever a person typed, a PIN included.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digit(_)
            | Self::Decimal(_)
            | Self::Separator(_)
            | Self::Divide
            | Self::Multiply
            | Self::Subtract
            | Self::Add
            | Self::Equal => formatter.write_str("Text(..)"),
            Self::Enter => formatter.write_str("Enter"),
            Self::Arrow(arrow) => formatter.debug_tuple("Arrow").field(arrow).finish(),
            Self::PageUp => formatter.write_str("PageUp"),
            Self::PageDown => formatter.write_str("PageDown"),
            Self::Home => formatter.write_str("Home"),
            Self::End => formatter.write_str("End"),
            Self::Insert => formatter.write_str("Insert"),
            Self::Delete => formatter.write_str("Delete"),
            Self::Begin => formatter.write_str("Begin"),
        }
    }
}

impl Keypad {
    /// The code the Kitty protocol gives the key, or `None` for a digit out of range.
    fn kitty_code(self) -> Option<u32> {
        Some(match self {
            Self::Digit(digit) if digit <= 9 => 57_399 + u32::from(digit),
            Self::Digit(_) => return None,
            Self::Decimal(_) => 57_409,
            Self::Divide => 57_410,
            Self::Multiply => 57_411,
            Self::Subtract => 57_412,
            Self::Add => 57_413,
            Self::Enter => 57_414,
            Self::Equal => 57_415,
            Self::Separator(_) => 57_416,
            Self::Arrow(Arrow::Left) => 57_417,
            Self::Arrow(Arrow::Right) => 57_418,
            Self::Arrow(Arrow::Up) => 57_419,
            Self::Arrow(Arrow::Down) => 57_420,
            Self::PageUp => 57_421,
            Self::PageDown => 57_422,
            Self::Home => 57_423,
            Self::End => 57_424,
            Self::Insert => 57_425,
            Self::Delete => 57_426,
            Self::Begin => 57_427,
        })
    }

    /// The character the key makes, for the keys that make one.
    fn text(self) -> Option<char> {
        match self {
            Self::Digit(digit) if digit <= 9 => char::from_digit(u32::from(digit), 10),
            Self::Decimal(character) | Self::Separator(character) => Some(character),
            Self::Divide => Some('/'),
            Self::Multiply => Some('*'),
            Self::Subtract => Some('-'),
            Self::Add => Some('+'),
            Self::Equal => Some('='),
            _ => None,
        }
    }

    /// The unshifted character of the main key the Kitty protocol converts a text key to, which
    /// names it in a report whatever the layout makes it type: the decimal key is `.` even where it
    /// types a comma (kitty's `convert_kp_key_to_normal_key`).
    fn main_character(self) -> Option<char> {
        match self {
            Self::Decimal(_) => Some('.'),
            _ => self.text(),
        }
    }

    /// The main key it stands for where the keypad is not told apart, or `None` for the centre
    /// key, which has a spelling of its own, and for a digit out of range.
    fn main_key(self) -> Option<Key> {
        match self {
            Self::Enter => Some(Key::Enter),
            Self::Arrow(arrow) => Some(Key::Arrow(arrow)),
            Self::PageUp => Some(Key::PageUp),
            Self::PageDown => Some(Key::PageDown),
            Self::Home => Some(Key::Home),
            Self::End => Some(Key::End),
            Self::Insert => Some(Key::Insert),
            Self::Delete => Some(Key::Delete),
            Self::Begin => None,
            _ => self.text().map(Key::Char),
        }
    }
}

/// What happened to a key: it went down, or it repeated while held.
///
/// A key coming up is not one of these. Its release is spelled from the press it ends, by
/// [`release`], because which key it was does not change when a modifier comes up first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyEventKind {
    /// It went down.
    #[default]
    Press,
    /// It repeated while held.
    Repeat,
}

/// One key event a client observed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// The logical key, as the keyboard layout produced it.
    pub key: Key,
    /// The character the same physical key produces with nothing held, when the client knows it.
    ///
    /// The Kitty keyboard protocol identifies a key by the code point of its **unshifted** form, so
    /// a client reporting `Char('A')` for shift and the `a` key has to say which key that was.
    /// `None` is a client that does not know, and the encoder then refuses that protocol's own form
    /// for a key Shift or Caps Lock changed rather than guessing at a layout: telling an
    /// application that the `A` key was pressed, on a keyboard that has no such key, is the
    /// invention section 8 forbids.
    pub base: Option<char>,
    /// The modifiers held with it.
    pub modifiers: Modifiers,
    /// The lock keys that were on.
    pub locks: Locks,
    /// What happened to it.
    pub kind: KeyEventKind,
}

impl std::fmt::Debug for KeyEvent {
    /// The key, the modifiers, the locks and the kind, and whether a base character was reported,
    /// never it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyEvent")
            .field("key", &self.key)
            .field("base", &self.base.map(|_| ".."))
            .field("modifiers", &self.modifiers)
            .field("locks", &self.locks)
            .field("kind", &self.kind)
            .finish()
    }
}

impl KeyEvent {
    /// A plain press of `key`.
    #[must_use]
    pub const fn press(key: Key) -> Self {
        Self {
            key,
            base: None,
            modifiers: Modifiers::NONE,
            locks: Locks::NONE,
            kind: KeyEventKind::Press,
        }
    }

    /// A press of `key` with `modifiers`.
    #[must_use]
    pub const fn with(key: Key, modifiers: Modifiers) -> Self {
        Self {
            key,
            base: None,
            modifiers,
            locks: Locks::NONE,
            kind: KeyEventKind::Press,
        }
    }

    /// A press of `produced` on the key whose unshifted form is `base`, with `modifiers`.
    ///
    /// This is the constructor a client with a layout uses. It is the only one that can serve the
    /// Kitty protocol for a shifted key.
    #[must_use]
    pub const fn from_key(base: char, produced: char, modifiers: Modifiers) -> Self {
        Self {
            key: Key::Char(produced),
            base: Some(base),
            modifiers,
            locks: Locks::NONE,
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
    /// arrows from `CSI A` to `SS3 A`, and Home, End and the keypad's centre key likewise.
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
    /// The Kitty flags this encoder produces.
    ///
    /// Alternate-key reporting is outside it: that flag asks for the shifted and base forms of a
    /// key beside the one that was pressed, and this encoder reports the key it was given. Text
    /// association is outside the kr-vt/1 profile altogether. A caller that asks for either is
    /// refused rather than served an encoding that leaves the flag's own field out.
    pub const KITTY_SUPPORTED_FLAGS: u8 = 0b0000_1011;

    /// Bit 1: disambiguate escape codes.
    pub const KITTY_DISAMBIGUATE: u8 = 0b0000_0001;
    /// Bit 2: report event types, which is what makes a release expressible.
    pub const KITTY_EVENT_TYPES: u8 = 0b0000_0010;
    /// Bit 4: report alternate keys.
    pub const KITTY_ALTERNATE_KEYS: u8 = 0b0000_0100;
    /// Bit 8: report all keys as escape codes.
    pub const KITTY_ALL_AS_ESCAPES: u8 = 0b0000_1000;

    /// The encoding a session's screen says its application negotiated.
    ///
    /// The host's own rule, read from what it projects: the Kitty flags of the buffer that is
    /// showing (`alternate`, the alternate buffer, which DEC mode 1049 selects) when the protocol
    /// is in use with any flag set; else `modifyOtherKeys` at its level; else the ordinary
    /// encoding, with `application_cursor_keys` for DEC mode 1. Each buffer keeps its own Kitty
    /// stack, so one buffer's flags say nothing about the other's. A flag value too large for the
    /// protocol is kept as flags this encoder refuses, rather than cut down to flags the
    /// application never set.
    #[must_use]
    pub fn negotiated(
        keyboard: &kr_protocol::projection::ProjectedKeyboard,
        alternate: bool,
        application_cursor_keys: bool,
    ) -> Self {
        let buffer = if alternate {
            &keyboard.alternate
        } else {
            &keyboard.primary
        };
        match buffer.flags.0.map(|flags| flags.get()) {
            Some(flags) if flags != 0 => Self::Kitty {
                flags: u8::try_from(flags).unwrap_or(u8::MAX),
            },
            _ => match keyboard.modify_other_keys.get() {
                0 => Self::Legacy {
                    application_cursor_keys,
                },
                level => Self::ModifyOtherKeys {
                    level: u8::try_from(level).map_or(2, |level| level.min(2)),
                    application_cursor_keys,
                },
            },
        }
    }

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
#[derive(Clone, Copy, PartialEq, Eq)]
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

impl crate::shown::Said for Unsupported {
    fn said(&self) -> crate::shown::Shown {
        match self {
            Self::NotExpressible { what } => crate::shown!(
                "the negotiated encoding cannot express {}, and this encoder does not invent one",
                *what
            ),
            Self::UnknownKey => {
                crate::shown::Shown::said("this encoder has no spelling for that key")
            }
        }
    }
}

crate::display_as_said!(Unsupported);
crate::debug_as_display!(Unsupported);

impl std::error::Error for Unsupported {}

/// The bracketed-paste start delimiter.
pub const PASTE_START: &[u8] = b"\x1b[200~";

/// The bracketed-paste end delimiter.
pub const PASTE_END: &[u8] = b"\x1b[201~";

/// Encodes one key going down, or repeating while it is held, for `encoding`.
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

/// Returns whether `encoding` reports the release of the key `press` put down.
///
/// Only the Kitty protocol with event types does, and not for every key. A press that went out as
/// the key's text, or as the bare byte of an unmodified Return, Tab, Backspace or Escape, has no
/// release in the stream, because that byte is the whole report; every other press does, a control
/// chord's legacy byte included, since its release has nowhere else to go. A client asks when the
/// key goes down, under the encoding it went in, and spells the release with [`release`] only when
/// the answer was yes.
#[must_use]
pub fn release_reported(press: KeyEvent, encoding: KeyboardEncoding) -> bool {
    match encoding {
        KeyboardEncoding::Kitty { flags } => {
            flags & !KeyboardEncoding::KITTY_SUPPORTED_FLAGS == 0
                && flags & KeyboardEncoding::KITTY_EVENT_TYPES != 0
                && !sent_as_a_byte(resolved(press, flags), flags)
        }
        KeyboardEncoding::Legacy { .. } | KeyboardEncoding::ModifyOtherKeys { .. } => false,
    }
}

/// Spells the release of the key `press` put down, with `modifiers` and `locks` as they are when it
/// comes up.
///
/// The key is the press's, named as the press named it: which key it is does not change because a
/// modifier came up first, or because Shift or Caps Lock came on while it was held, so a Control-I
/// whose Control is released before its I is still the I key's release. The modifiers and locks are
/// the release's own, as the protocol reports them. An encoding that reports no releases gets
/// nothing, which is the caller's instruction to send nothing.
///
/// # Errors
///
/// Returns [`Unsupported`] when the encoding asks for a Kitty flag this encoder does not produce,
/// or the key has no code under the protocol.
pub fn release(
    press: KeyEvent,
    modifiers: Modifiers,
    locks: Locks,
    encoding: KeyboardEncoding,
) -> Result<Vec<u8>, Unsupported> {
    let KeyboardEncoding::Kitty { flags } = encoding else {
        return Ok(Vec::new());
    };
    supported(flags)?;
    if flags & KeyboardEncoding::KITTY_EVENT_TYPES == 0 {
        return Ok(Vec::new());
    }
    let press = resolved(press, flags);
    let code = kitty_code(press)?;
    Ok(kitty_report(code, press.key, modifiers, locks, Some(3)))
}

/// Refuses Kitty flags this encoder does not produce.
///
/// An application that asked for a flag this encoder does not produce would read a report with the
/// flag's own field missing, which is the falsely advertised encoding section 8 forbids. The host
/// refuses such a controller the lease; a caller that reaches here directly is refused too.
const fn supported(flags: u8) -> Result<(), Unsupported> {
    if flags & !KeyboardEncoding::KITTY_SUPPORTED_FLAGS == 0 {
        Ok(())
    } else {
        Err(Unsupported::NotExpressible {
            what: "a Kitty keyboard flag this encoder does not produce",
        })
    }
}

fn legacy(
    event: KeyEvent,
    encoding: KeyboardEncoding,
    modify_other_keys: u8,
) -> Result<Vec<u8>, Unsupported> {
    // A repeat is the press again: this encoding cannot tell the two apart, and the key is still
    // down. Locks have nowhere to go in it and change nothing.
    if event.modifiers.superkey {
        // xterm's modifier parameter has a bit for it, but the ordinary encoding has nowhere to put
        // one, and no application reads a command key out of a legacy stream.
        return Err(Unsupported::NotExpressible {
            what: "a command or super modifier",
        });
    }
    let application = encoding.application_cursor_keys();
    match event.key {
        Key::Char(character) => legacy_character(character, event.modifiers, modify_other_keys),
        Key::Enter => {
            if modify_other_keys == 1 && event.modifiers.alt && event.modifiers.shift {
                // xterm reports this chord at level one with Alt left out.
                return Err(Unsupported::NotExpressible {
                    what: "Alt with Shift on Return",
                });
            }
            // Level one reports Shift and Control on Return, and leaves Alt to the escape prefix,
            // Control going with it, as xterm does.
            Ok(special_key(
                b'\r',
                13,
                event.modifiers,
                modify_other_keys,
                !event.modifiers.alt && !event.modifiers.is_empty(),
            ))
        }
        Key::Tab => {
            if modify_other_keys >= 2 && !event.modifiers.is_empty() {
                // Level two reports Shift-Tab too, which is how an application tells it from the
                // back-tab an older terminal sends for several different chords.
                return Ok(modify_other_keys_report(9, event.modifiers));
            }
            if event.modifiers.shift {
                if event.modifiers.control || event.modifiers.alt {
                    // The ordinary encoding and level one have one back-tab and no room for a
                    // second modifier on it. Sending it anyway would tell the application Shift-Tab
                    // when the person held Control as well.
                    return Err(Unsupported::NotExpressible {
                        what: "Shift together with another modifier on Tab",
                    });
                }
                return Ok(b"\x1b[Z".to_vec());
            }
            // Level one reports Control on Tab, and leaves Alt to the escape prefix, Control going
            // with it, as xterm does.
            Ok(special_key(
                b'\t',
                9,
                event.modifiers,
                modify_other_keys,
                !event.modifiers.alt && event.modifiers.control,
            ))
        }
        // Control makes the backarrow key send the other of DEL and BS, as xterm's does, and level
        // one leaves Backspace to that.
        Key::Backspace => Ok(special_key(
            if event.modifiers.control { 0x08 } else { 0x7f },
            127,
            event.modifiers,
            modify_other_keys,
            false,
        )),
        Key::Escape => {
            if modify_other_keys == 1
                && event.modifiers.alt
                && (event.modifiers.shift || event.modifiers.control)
            {
                // xterm reports these chords at level one with Alt left out.
                return Err(Unsupported::NotExpressible {
                    what: "Alt with Shift or Control on Escape",
                });
            }
            // Escape is a control character already, so level one leaves Shift and Control to its
            // byte, and Alt to the escape prefix, as xterm does.
            Ok(special_key(
                0x1b,
                27,
                event.modifiers,
                modify_other_keys,
                false,
            ))
        }
        Key::Arrow(arrow) => Ok(cursor_key(arrow, event.modifiers, application)),
        Key::Home => Ok(edit_key(b'H', event.modifiers, application)),
        Key::End => Ok(edit_key(b'F', event.modifiers, application)),
        Key::Insert => Ok(tilde_key(2, event.modifiers)),
        Key::Delete => Ok(tilde_key(3, event.modifiers)),
        Key::PageUp => Ok(tilde_key(5, event.modifiers)),
        Key::PageDown => Ok(tilde_key(6, event.modifiers)),
        Key::Function(number) => function_key(number, event.modifiers),
        // The keypad's centre key has a letter of its own, as Home and End do.
        Key::Keypad(Keypad::Begin) => Ok(edit_key(b'E', event.modifiers, application)),
        // Every other keypad key is the main key it stands for: this encoding cannot tell them
        // apart, and the application reads the key the person meant.
        Key::Keypad(keypad) => {
            let Some(main) = keypad.main_key() else {
                return Err(Unsupported::UnknownKey);
            };
            legacy(
                KeyEvent {
                    key: main,
                    base: keypad.text(),
                    ..event
                },
                encoding,
                modify_other_keys,
            )
        }
        // xterm's menu key, which its terminfo entry calls F16.
        Key::Menu => Ok(tilde_key(29, event.modifiers)),
        // Neither has a spelling in this encoding, and an invented one would be a key nobody
        // pressed.
        Key::PrintScreen | Key::Pause => Err(Unsupported::UnknownKey),
    }
}

/// Spells a printable key under the ordinary encoding, with `modifyOtherKeys` where it applies.
///
/// Level one is xterm's with Alt as the escape prefix (its `metaSendsEscape`): a chord xterm would
/// report there with Alt left out is refused rather than sent without it.
fn legacy_character(
    character: char,
    modifiers: Modifiers,
    modify_other_keys: u8,
) -> Result<Vec<u8>, Unsupported> {
    // Control and a character has the spelling X11 gives it at every level of `modifyOtherKeys`
    // below two.
    if modifiers.control
        && let Some(byte) = control_byte(character)
    {
        if modify_other_keys < 2 {
            if modify_other_keys == 1
                && modifiers.alt
                && modifiers.shift
                && !('@'..='~').contains(&character)
            {
                // Space, `2` to `8`, `/` and `?` have their control characters from X11 rather
                // than from their letter, and xterm reports this chord on them at level one as
                // Shift and Control alone.
                return Err(Unsupported::NotExpressible {
                    what: "Alt with Shift and Control on this key",
                });
            }
            // Alt is the escape prefix, and it goes in front of the control byte rather than in
            // front of the letter: Control-Alt-C is an escape and then the byte Control-C is, not
            // an escape and then a `c`.
            let mut bytes = Vec::new();
            if modifiers.alt {
                bytes.push(0x1b);
            }
            bytes.push(byte);
            return Ok(bytes);
        }
        // Level two reports even the keys that already had a spelling, which is the whole point of
        // it: an application can then tell Control-I from Tab.
        return Ok(modify_other_keys_report(u32::from(character), modifiers));
    }
    // Level two reports a shift-only chord over the range xterm reports it over: the characters
    // from `@` to `~`, which are the ones a control chord can also reach, plus Space, whose shifted
    // form is a space and says nothing. Below that range a shifted key produces a byte no unshifted
    // key produces, so it is sent as that byte, and an encoder that reported it would tell an
    // application about a chord no terminal reports. Level one reports only Control on a key X11
    // has no control character for: Shift is already in the character, and xterm leaves Alt, with
    // Shift or without, to its escape prefix at that level, and reports Control with Alt as Control
    // alone.
    let ambiguous_when_shifted = character == ' ' || ('\u{40}'..='\u{7f}').contains(&character);
    let reported = if modify_other_keys >= 2 {
        modifiers.control || modifiers.alt || (modifiers.shift && ambiguous_when_shifted)
    } else {
        modify_other_keys > 0 && modifiers.control
    };
    if reported {
        if modify_other_keys == 1 && modifiers.alt {
            return Err(Unsupported::NotExpressible {
                what: "Alt with Control on a key that has no control character",
            });
        }
        return Ok(modify_other_keys_report(u32::from(character), modifiers));
    }
    let mut bytes = Vec::new();
    if modifiers.alt {
        // Alt is the escape prefix, which is what every terminal has always sent for it.
        bytes.push(0x1b);
    }
    bytes.extend_from_slice(&utf8(character));
    Ok(bytes)
}

/// Spells Return, Tab, Backspace or Escape, whose byte is a control character, outside the Kitty
/// protocol.
///
/// Level two reports the key, as `code`, with any modifier; level one only where
/// `reported_at_level_one` says xterm does. Otherwise it is `byte`, with Alt as the escape prefix,
/// and Shift and Control have nowhere else to go.
fn special_key(
    byte: u8,
    code: u32,
    modifiers: Modifiers,
    modify_other_keys: u8,
    reported_at_level_one: bool,
) -> Vec<u8> {
    let reported = match modify_other_keys {
        0 => false,
        1 => reported_at_level_one,
        _ => !modifiers.is_empty(),
    };
    if reported {
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

/// The control character Control makes with `character`, as X11 maps it and xterm sends it.
///
/// Control keeps the low five bits of a character from `@` to `~`: the letters, `[`, `\`, `]`, `^`,
/// `_`, and the grave accent and braces beside them. The digits map as the VT220's did, Two to NUL,
/// Three to Seven to ESC through US and Eight to DEL; Slash is US and Space is NUL. A question mark
/// is DEL, as terminals send it. Any other character has none.
fn control_byte(character: char) -> Option<u8> {
    match character {
        '@'..='~' => Some(character as u8 & 0x1f),
        ' ' | '2' => Some(0),
        '3'..='7' => Some(character as u8 - b'3' + 0x1b),
        '8' | '?' => Some(0x7f),
        '/' => Some(0x1f),
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

/// Home, End and the keypad's centre key, which have a letter form.
fn edit_key(final_byte: u8, modifiers: Modifiers, application: bool) -> Vec<u8> {
    if modifiers.is_empty() {
        return if application {
            vec![0x1b, b'O', final_byte]
        } else {
            vec![0x1b, b'[', final_byte]
        };
    }
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
        // F13 upwards have no spelling in this encoding, and an invented one would be a key nobody
        // pressed.
        _ => return Err(Unsupported::UnknownKey),
    };
    Ok(if modifiers.is_empty() {
        format!("\x1b[{numbered}~").into_bytes()
    } else {
        format!("\x1b[{numbered};{}~", modifiers.parameter()).into_bytes()
    })
}

/// Spells a key going down, or repeating, under the Kitty keyboard protocol with `flags`.
fn kitty(event: KeyEvent, flags: u8) -> Result<Vec<u8>, Unsupported> {
    supported(flags)?;
    if flags == 0 {
        // No flag is set, so the protocol is not in force at all: the canonical parser reports the
        // ordinary encoding for exactly this state, and a caller that names this one anyway gets
        // the same answer rather than an enhanced report nothing asked for.
        return legacy(
            event,
            KeyboardEncoding::Legacy {
                application_cursor_keys: false,
            },
            0,
        );
    }
    let event = resolved(event, flags);
    let reports_events = flags & KeyboardEncoding::KITTY_EVENT_TYPES != 0;
    match event.kind {
        KeyEventKind::Press => kitty_press(event, flags),
        // A repeat with no event types to report is the press again: that is what this stream can
        // say, and refusing would drop a key the person is holding down. A key sent as its text or
        // as a bare byte repeats as that again, because the byte is the whole report.
        KeyEventKind::Repeat if !reports_events || sent_as_a_byte(event, flags) => {
            kitty_press(event, flags)
        }
        KeyEventKind::Repeat => kitty_sequence(event, Some(2)),
    }
}

/// The key the Kitty protocol reports for `event` under `flags`.
///
/// Once the application disambiguates, or asks for every key as an escape code, a keypad key is its
/// own key. Otherwise the protocol reports it as the main key it stands for, as its legacy encoding
/// does, except the separator and the centre key, which keep their own codes: the protocol's own
/// encoder converts neither (kitty's `convert_kp_key_to_normal_key`).
fn resolved(event: KeyEvent, flags: u8) -> KeyEvent {
    let told_apart = flags
        & (KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALL_AS_ESCAPES)
        != 0;
    match event.key {
        Key::Keypad(keypad) if !told_apart && !matches!(keypad, Keypad::Separator(_)) => {
            // The key types what it types, and is named by the main key it converts to.
            match keypad.main_key() {
                Some(main) => KeyEvent {
                    key: main,
                    base: keypad.main_character(),
                    ..event
                },
                None => event,
            }
        }
        _ => event,
    }
}

/// Whether a press under the Kitty protocol with `flags` goes out as the key's text, or as the bare
/// byte of an unmodified Return, Tab, Backspace or Escape, which leaves no room for an event type.
fn sent_as_a_byte(event: KeyEvent, flags: u8) -> bool {
    if flags & KeyboardEncoding::KITTY_ALL_AS_ESCAPES != 0 || event.modifiers.superkey {
        return false;
    }
    let held = event.modifiers;
    match event.key {
        Key::Char(_) => !(held.control || held.alt),
        Key::Keypad(keypad) => keypad.text().is_some() && !(held.control || held.alt),
        Key::Enter | Key::Tab | Key::Backspace => held.is_empty(),
        Key::Escape => {
            held.is_empty()
                && event.locks.is_empty()
                && flags & KeyboardEncoding::KITTY_DISAMBIGUATE == 0
        }
        _ => false,
    }
}

/// Spells a key going down under the Kitty protocol with `flags`, one or more of them set.
///
/// The protocol extends the ordinary encoding rather than replacing it, so a press keeps a legacy
/// spelling until the application asks for something that spelling cannot carry:
///
/// * A key that makes text, with neither Control nor Alt held, is its text until every key is
///   asked for as an escape code. Shift is already in the text, and a lock does not change which
///   key it is.
/// * Return, Tab and Backspace keep their bytes while nothing but a lock is held, so a person can
///   still type `reset` at a shell a program left in this mode.
/// * Escape keeps its byte until the application asks to disambiguate it, and only while nothing
///   at all is held: a lock has no place in a bare byte.
/// * Without disambiguation, a text key pressed with Control or Alt keeps the protocol's legacy
///   spelling where it has one ([`kitty_legacy_text`]).
///
/// Everything else is the protocol's own report, which a functional key always is.
fn kitty_press(event: KeyEvent, flags: u8) -> Result<Vec<u8>, Unsupported> {
    let held = event.modifiers;
    let disambiguates = flags & KeyboardEncoding::KITTY_DISAMBIGUATE != 0;
    if flags & KeyboardEncoding::KITTY_ALL_AS_ESCAPES == 0 && !held.superkey {
        let text = !(held.control || held.alt);
        match event.key {
            Key::Char(character) if text => return Ok(utf8(character)),
            Key::Keypad(keypad) if text => {
                if let Some(character) = keypad.text() {
                    return Ok(utf8(character));
                }
            }
            Key::Enter if held.is_empty() => return Ok(b"\r".to_vec()),
            Key::Tab if held.is_empty() => return Ok(b"\t".to_vec()),
            Key::Backspace if held.is_empty() => return Ok(vec![0x7f]),
            Key::Escape if !disambiguates && held.is_empty() && event.locks.is_empty() => {
                return Ok(vec![0x1b]);
            }
            Key::Char(_) if !disambiguates => {
                if let Some(bytes) = kitty_legacy_text(event) {
                    return Ok(bytes);
                }
            }
            _ => {}
        }
    }
    kitty_sequence(event, None)
}

/// The Kitty protocol's legacy spelling of a text key pressed with Control or Alt, or `None` where
/// the protocol gives it none and the press is a report.
///
/// The protocol names the key by its unshifted character, and spells five chords on the keys a
/// legacy terminal spelled (`a` to `z`, the digits, `` ` - = [ ] \ ; ' , . / `` and Space): Alt is
/// the escape prefix, Control maps the key through the protocol's own table, which leaves a key it
/// does not list as it is, and Shift gives the shifted character. So Shift, Alt, Control, Shift
/// with Alt and Control with Alt have legacy spellings, and so does Control with Shift on Space,
/// which is NUL. Every other chord, every other key, a chord made while a lock is on (a byte has
/// nowhere to say so) and a key whose unshifted character the client did not report are reports.
fn kitty_legacy_text(event: KeyEvent) -> Option<Vec<u8>> {
    let Key::Char(produced) = event.key else {
        return None;
    };
    let held = event.modifiers;
    if held.superkey || !event.locks.is_empty() {
        return None;
    }
    let key = match event.base {
        Some(base) => base,
        None if held.shift => return None,
        None => produced,
    };
    if !legacy_text_key(key) {
        return None;
    }
    let body = match (held.control, held.alt, held.shift) {
        (false, true, false) => utf8(key),
        (false, true, true) => utf8(produced),
        (true, _, false) => kitty_control(key),
        (true, false, true) if key == ' ' => vec![0],
        _ => return None,
    };
    let mut bytes = Vec::with_capacity(body.len() + 1);
    if held.alt {
        bytes.push(0x1b);
    }
    bytes.extend_from_slice(&body);
    Some(bytes)
}

/// Whether the Kitty protocol's legacy encoding spells chords on this unshifted key.
const fn legacy_text_key(key: char) -> bool {
    matches!(
        key,
        'a'..='z'
            | '0'..='9'
            | '`'
            | '-'
            | '='
            | '['
            | ']'
            | '\\'
            | ';'
            | '\''
            | ','
            | '.'
            | '/'
            | ' '
    )
}

/// Control on a key the Kitty protocol's legacy encoding spells, from the protocol's table: the
/// keys it lists become their control codes, and the rest stay as they are.
fn kitty_control(key: char) -> Vec<u8> {
    let byte = match key {
        'a'..='z' => key as u8 - b'a' + 1,
        ' ' | '2' => 0,
        '3'..='7' => key as u8 - b'3' + 0x1b,
        '8' => 0x7f,
        '[' => 0x1b,
        '\\' => 0x1c,
        ']' => 0x1d,
        '/' => 0x1f,
        _ => return utf8(key),
    };
    vec![byte]
}

/// Spells one key event as the Kitty protocol's own sequence.
///
/// `event_type` is the protocol's second modifier field: `Some(2)` for a repeat, `Some(3)` for a
/// release, `None` for a press, whose type is the default and is left out.
fn kitty_sequence(event: KeyEvent, event_type: Option<u8>) -> Result<Vec<u8>, Unsupported> {
    let code = kitty_code(event)?;
    Ok(kitty_report(
        code,
        event.key,
        event.modifiers,
        event.locks,
        event_type,
    ))
}

/// The protocol's report of `key`, named by `code`, with `modifiers` and `locks` held.
fn kitty_report(
    code: u32,
    key: Key,
    modifiers: Modifiers,
    locks: Locks,
    event_type: Option<u8>,
) -> Vec<u8> {
    // The modifier bits plus one, with the locks beside them.
    let parameter = u16::from(modifiers.parameter()) + locks.kitty_bits();
    let suffix = kitty_suffix(key);
    if let Some(event_type) = event_type {
        // The event type travels in the modifier field's second part, so the modifier parameter is
        // always present when one is reported, even when nothing was held.
        return format!("\x1b[{code};{parameter}:{event_type}{suffix}").into_bytes();
    }
    if parameter == 1 {
        // A key whose suffix is a letter needs no number: `CSI A` is the canonical spelling and
        // the parameter's default is the only value it could have. One that ends in a tilde does
        // need it, because the number is which key it is.
        return if suffix == '~' || suffix == 'u' {
            format!("\x1b[{code}{suffix}").into_bytes()
        } else {
            format!("\x1b[{suffix}").into_bytes()
        };
    }
    format!("\x1b[{code};{parameter}{suffix}").into_bytes()
}

/// The final byte the Kitty protocol uses for this key.
///
/// Most keys end in `u` with their code; the ones the ordinary encoding already had a letter or a
/// tilde for keep it, because the protocol is an extension of it rather than a replacement, and
/// the keypad's centre key takes the letter `E`.
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
        Key::Keypad(Keypad::Begin) => 'E',
        Key::Insert | Key::Delete | Key::PageUp | Key::PageDown | Key::Function(3 | 5..=12) => '~',
        _ => 'u',
    }
}

/// The code the Kitty protocol identifies this key by.
///
/// For a printable key that is the **unshifted** form. A client that reported a character Shift or
/// Caps Lock made, and did not say which key produced it, has not established that, and this
/// refuses rather than guessing: there is no layout-independent way back from `A` to the key it
/// came from.
fn kitty_code(event: KeyEvent) -> Result<u32, Unsupported> {
    Ok(match event.key {
        Key::Char(character) => match event.base {
            Some(base) => u32::from(base),
            None if event.modifiers.shift => {
                return Err(Unsupported::NotExpressible {
                    what: "the unshifted key a shifted character was produced from",
                });
            }
            None if event.locks.caps_lock => {
                return Err(Unsupported::NotExpressible {
                    what: "the unshifted key a character made under Caps Lock was produced from",
                });
            }
            None => u32::from(character),
        },
        Key::Enter => 13,
        Key::Tab => 9,
        Key::Backspace => 127,
        Key::Escape => 27,
        Key::Arrow(_) | Key::Home | Key::End | Key::Keypad(Keypad::Begin) => 1,
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
            // The protocol numbers F13 to F35 in the private-use area.
            13..=35 => 57_376 + u32::from(number) - 13,
            _ => return Err(Unsupported::UnknownKey),
        },
        Key::Keypad(keypad) => keypad.kitty_code().ok_or(Unsupported::UnknownKey)?,
        Key::Menu => 57_363,
        Key::PrintScreen => 57_361,
        Key::Pause => 57_362,
    })
}

/// A character's UTF-8 bytes.
fn utf8(character: char) -> Vec<u8> {
    let mut buffer = [0_u8; 4];
    character.encode_utf8(&mut buffer).as_bytes().to_vec()
}

/// Encodes a paste operation.
///
/// When the application has canonical bracketed-paste mode on, the text is delimited so it arrives
/// as one paste rather than as keystrokes. When it does not, the text is the bytes and nothing
/// wraps them.
///
/// When framing is added, the delimiters are removed from the payload first. Text that contained
/// one would end its own paste and hand the rest to the application as typing, which is how a
/// pasted line becomes a command; a client that passed it through would be the source of that.
/// Removing one can bring its neighbours together into another, so the removal runs to a fixed
/// point and the payload that gets the framing provably contains neither delimiter.
///
/// With the mode off nothing is removed. There is no framing to protect, the bytes are the bytes,
/// and quietly deleting six of them from somebody's text would be a change to their text.
#[must_use]
pub fn paste(text: &str, bracketed: bool) -> Vec<u8> {
    if !bracketed {
        return text.as_bytes().to_vec();
    }
    let filtered = strip_delimiters(text.as_bytes());
    let mut bytes = Vec::with_capacity(filtered.len() + PASTE_START.len() + PASTE_END.len());
    bytes.extend_from_slice(PASTE_START);
    bytes.extend_from_slice(&filtered);
    bytes.extend_from_slice(PASTE_END);
    bytes
}

/// Removes every paste delimiter, including one that removing another brought into existence.
///
/// Scanning the input once is not enough. `ESC[20` followed by `ESC[201~` followed by `1~` holds
/// one delimiter; taking it out joins `ESC[20` to `1~` and spells another. So the check is made on
/// the *output* instead: each byte is appended and the tail is examined, so a delimiter that has
/// just been spelled is removed at the moment it appears. The result therefore contains neither
/// delimiter, and each byte is looked at a bounded number of times whatever the payload.
fn strip_delimiters(bytes: &[u8]) -> Vec<u8> {
    let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
    for byte in bytes {
        kept.push(*byte);
        if kept.ends_with(PASTE_END) || kept.ends_with(PASTE_START) {
            kept.truncate(kept.len() - PASTE_END.len());
        }
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
    let modifiers = |code: u32| {
        let mut code = code;
        if event.modifiers.shift {
            code += 4;
        }
        if event.modifiers.alt {
            code += 8;
        }
        if event.modifiers.control {
            code += 16;
        }
        code
    };
    let button = |button: MouseButton| match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    };
    match encoding {
        MouseEncoding::Sgr => {
            // Mode 1006 keeps the button on a release and says which kind of event it was in the
            // final byte, so nothing is lost either way.
            let code = modifiers(match event.action {
                MouseAction::Press(held) | MouseAction::Release(held) => button(held),
                MouseAction::Drag(held) => button(held) + 32,
                MouseAction::Wheel(WheelDirection::Up) => 64,
                MouseAction::Wheel(WheelDirection::Down) => 65,
            });
            let final_byte = if matches!(event.action, MouseAction::Release(_)) {
                'm'
            } else {
                'M'
            };
            // One based on the wire. A coordinate at the end of its range has no one-based form, so
            // it is refused rather than wrapped to the opposite corner of the grid.
            let (column, row) = one_based(event)?;
            Ok(format!("\x1b[<{code};{column};{row}{final_byte}").into_bytes())
        }
        MouseEncoding::X10 => {
            // The original report spells every release the same way: button code three, which says
            // a button came up and not which one. That is the encoding's own limit rather than
            // something to invent around, so the release is reported in it and the detail the
            // protocol has no room for is the detail the application does not get. The modifier
            // bits it does have room for are kept.
            let code = modifiers(match event.action {
                MouseAction::Release(_) => 3,
                MouseAction::Press(held) => button(held),
                MouseAction::Drag(held) => button(held) + 32,
                MouseAction::Wheel(WheelDirection::Up) => 64,
                MouseAction::Wheel(WheelDirection::Down) => 65,
            });
            let (column, row) = one_based(event)?;
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

/// Returns the one-based coordinates a mouse report carries.
///
/// # Errors
///
/// Returns [`Unsupported`] for a coordinate at the very end of its range, which has no one-based
/// form. Wrapping it would report the opposite corner of the grid.
fn one_based(event: MouseEvent) -> Result<(u32, u32), Unsupported> {
    let column = event.column.checked_add(1);
    let row = event.row.checked_add(1);
    match (column, row) {
        (Some(column), Some(row)) => Ok((column, row)),
        _ => Err(Unsupported::NotExpressible {
            what: "a coordinate at the end of its range, which has no one-based form",
        }),
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
    const LEVEL_ONE: KeyboardEncoding = KeyboardEncoding::ModifyOtherKeys {
        level: 1,
        application_cursor_keys: false,
    };
    const LEVEL_TWO: KeyboardEncoding = KeyboardEncoding::ModifyOtherKeys {
        level: 2,
        application_cursor_keys: false,
    };
    const DISAMBIGUATE: KeyboardEncoding = KeyboardEncoding::Kitty {
        flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
    };
    const EVENTS: KeyboardEncoding = KeyboardEncoding::Kitty {
        flags: KeyboardEncoding::KITTY_EVENT_TYPES,
    };
    const BOTH: KeyboardEncoding = KeyboardEncoding::Kitty {
        flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES,
    };
    const EVERY_KEY: KeyboardEncoding = KeyboardEncoding::Kitty {
        flags: KeyboardEncoding::KITTY_DISAMBIGUATE
            | KeyboardEncoding::KITTY_EVENT_TYPES
            | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
    };

    const ALT: Modifiers = Modifiers {
        alt: true,
        ..Modifiers::NONE
    };
    const CONTROL_ALT: Modifiers = Modifiers {
        control: true,
        alt: true,
        ..Modifiers::NONE
    };
    const CONTROL_SHIFT: Modifiers = Modifiers {
        control: true,
        shift: true,
        ..Modifiers::NONE
    };
    const SHIFT_ALT: Modifiers = Modifiers {
        shift: true,
        alt: true,
        ..Modifiers::NONE
    };
    const CAPS: Locks = Locks {
        caps_lock: true,
        num_lock: false,
    };
    const NUM: Locks = Locks {
        caps_lock: false,
        num_lock: true,
    };

    /// The bytes `event` goes out as under `encoding`.
    fn spelled(event: KeyEvent, encoding: KeyboardEncoding) -> Vec<u8> {
        key(event, encoding).expect("encodes")
    }

    /// `event` with `locks` on.
    fn locked(event: KeyEvent, locks: Locks) -> KeyEvent {
        KeyEvent { locks, ..event }
    }

    /// `event` repeating.
    fn repeated(event: KeyEvent) -> KeyEvent {
        KeyEvent {
            kind: KeyEventKind::Repeat,
            ..event
        }
    }

    /// A press of the key whose unshifted character is `base`, making `produced`.
    fn on(base: char, produced: char, modifiers: Modifiers) -> KeyEvent {
        KeyEvent::from_key(base, produced, modifiers)
    }

    /// A press of a keypad key.
    fn keypad(key: Keypad, modifiers: Modifiers) -> KeyEvent {
        KeyEvent::with(Key::Keypad(key), modifiers)
    }

    /// KR-REQ-08.59: application cursor keys survive the conversion.
    #[test]
    fn an_arrow_key_is_spelled_the_way_the_mode_in_force_spells_it() {
        let up = KeyEvent::press(Key::Arrow(Arrow::Up));
        assert_eq!(spelled(up, LEGACY), b"\x1b[A");
        assert_eq!(
            spelled(up, APPLICATION),
            b"\x1bOA",
            "mode 1 changes the arrows and nothing else"
        );
        // A modified arrow is the CSI form in both, which is what xterm does.
        let modified = KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control());
        assert_eq!(spelled(modified, LEGACY), b"\x1b[1;5A");
        assert_eq!(spelled(modified, APPLICATION), b"\x1b[1;5A");
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
            spelled(
                KeyEvent::with(Key::Arrow(Arrow::Left), Modifiers::shift()),
                LEGACY
            ),
            b"\x1b[1;2D"
        );
        assert_eq!(
            spelled(KeyEvent::with(Key::Delete, Modifiers::control()), LEGACY),
            b"\x1b[3;5~"
        );
    }

    /// KR-REQ-08.59: `modifyOtherKeys` reports what the ordinary encoding could not distinguish.
    #[test]
    fn modify_other_keys_reports_the_key_and_its_modifiers() {
        let control_i = KeyEvent::with(Key::Char('i'), Modifiers::control());
        assert_eq!(
            spelled(control_i, LEVEL_ONE),
            b"\x09",
            "level one leaves a key that already had a spelling alone"
        );
        assert_eq!(
            spelled(control_i, LEVEL_TWO),
            b"\x1b[27;5;105~",
            "level two reports it, so an application can tell it from Tab"
        );
        // A key with no legacy spelling is reported at either level.
        let control_semicolon = KeyEvent::with(Key::Char(';'), Modifiers::control());
        assert_eq!(spelled(control_semicolon, LEVEL_ONE), b"\x1b[27;5;59~");
    }

    /// KR-REQ-08.59: `modifyOtherKeys` level 1 spells Escape, Backspace, Return and Tab as xterm's
    /// input path does with Alt as the escape prefix (its `metaSendsEscape`). Escape keeps its byte
    /// with Shift or Control. Backspace is never reported, and Control makes it the other of DEL and
    /// BS, as xterm's backarrow key does in the ordinary encoding too. Return is reported with Shift
    /// and Control, Tab with Control, and Shift alone on Tab is the back-tab. Alt is the escape
    /// prefix, and a chord xterm would report with Alt left out is refused. Level 2 reports all four
    /// with any modifier.
    #[test]
    fn level_one_spells_escape_backspace_return_and_tab_as_xterm_does() {
        let shift = Modifiers::shift();
        let control = Modifiers::control();
        let all = Modifiers {
            shift: true,
            alt: true,
            control: true,
            superkey: false,
        };
        let spelled_cases: [(Key, Modifiers, &[u8]); 20] = [
            (Key::Escape, Modifiers::NONE, b"\x1b"),
            (Key::Escape, shift, b"\x1b"),
            (Key::Escape, control, b"\x1b"),
            (Key::Escape, CONTROL_SHIFT, b"\x1b"),
            (Key::Escape, ALT, b"\x1b\x1b"),
            (Key::Backspace, Modifiers::NONE, b"\x7f"),
            (Key::Backspace, shift, b"\x7f"),
            (Key::Backspace, control, b"\x08"),
            (Key::Backspace, CONTROL_SHIFT, b"\x08"),
            (Key::Backspace, ALT, b"\x1b\x7f"),
            (Key::Backspace, CONTROL_ALT, b"\x1b\x08"),
            (Key::Enter, Modifiers::NONE, b"\r"),
            (Key::Enter, shift, b"\x1b[27;2;13~"),
            (Key::Enter, control, b"\x1b[27;5;13~"),
            (Key::Enter, CONTROL_SHIFT, b"\x1b[27;6;13~"),
            (Key::Enter, ALT, b"\x1b\r"),
            (Key::Tab, Modifiers::NONE, b"\t"),
            (Key::Tab, shift, b"\x1b[Z"),
            (Key::Tab, control, b"\x1b[27;5;9~"),
            (Key::Tab, ALT, b"\x1b\t"),
        ];
        for (pressed, held, expected) in spelled_cases {
            assert_eq!(
                spelled(KeyEvent::with(pressed, held), LEVEL_ONE),
                expected,
                "{pressed:?} with {held:?}"
            );
        }
        // Control goes with Alt on Return and Tab, as it does in the ordinary encoding.
        assert_eq!(
            spelled(KeyEvent::with(Key::Enter, CONTROL_ALT), LEVEL_ONE),
            b"\x1b\r"
        );
        assert_eq!(
            spelled(KeyEvent::with(Key::Tab, CONTROL_ALT), LEVEL_ONE),
            b"\x1b\t"
        );
        for (pressed, held, what) in [
            (
                Key::Escape,
                SHIFT_ALT,
                "Alt with Shift or Control on Escape",
            ),
            (
                Key::Escape,
                CONTROL_ALT,
                "Alt with Shift or Control on Escape",
            ),
            (Key::Escape, all, "Alt with Shift or Control on Escape"),
            (Key::Enter, SHIFT_ALT, "Alt with Shift on Return"),
            (Key::Enter, all, "Alt with Shift on Return"),
            (
                Key::Tab,
                CONTROL_SHIFT,
                "Shift together with another modifier on Tab",
            ),
            (
                Key::Tab,
                SHIFT_ALT,
                "Shift together with another modifier on Tab",
            ),
        ] {
            assert_eq!(
                key(KeyEvent::with(pressed, held), LEVEL_ONE),
                Err(Unsupported::NotExpressible { what }),
                "{pressed:?} with {held:?}"
            );
        }
        // The ordinary encoding's Backspace is the same, Control making the other byte.
        assert_eq!(
            spelled(KeyEvent::with(Key::Backspace, control), LEGACY),
            b"\x08"
        );
        assert_eq!(
            spelled(KeyEvent::with(Key::Backspace, CONTROL_ALT), LEGACY),
            b"\x1b\x08"
        );
        // Level 2 reports each of them with any modifier.
        for (pressed, code) in [
            (Key::Escape, 27),
            (Key::Backspace, 127),
            (Key::Enter, 13),
            (Key::Tab, 9),
        ] {
            for (held, parameter) in [(shift, 2), (ALT, 3), (control, 5), (all, 8)] {
                assert_eq!(
                    spelled(KeyEvent::with(pressed, held), LEVEL_TWO),
                    format!("\x1b[27;{parameter};{code}~").into_bytes(),
                    "{pressed:?} with {held:?}"
                );
            }
        }
    }

    /// KR-REQ-08.59: at level 1, Alt on an ordinary key is the escape prefix, with Shift or without,
    /// and goes in front of a control character; Control reports a key X11 gives no control
    /// character, and with Alt that chord is refused, because xterm reports it with Alt left out.
    /// Level 2 reports Alt.
    #[test]
    fn level_one_leaves_alt_on_an_ordinary_key_to_the_escape_prefix() {
        assert_eq!(spelled(on('c', 'c', ALT), LEVEL_ONE), b"\x1bc");
        assert_eq!(spelled(on('c', 'C', SHIFT_ALT), LEVEL_ONE), b"\x1bC");
        assert_eq!(spelled(on('1', '!', SHIFT_ALT), LEVEL_ONE), b"\x1b!");
        assert_eq!(spelled(on('c', 'c', CONTROL_ALT), LEVEL_ONE), b"\x1b\x03");
        assert_eq!(
            spelled(on('1', '1', Modifiers::control()), LEVEL_ONE),
            b"\x1b[27;5;49~"
        );
        assert_eq!(
            spelled(on('1', '!', CONTROL_SHIFT), LEVEL_ONE),
            b"\x1b[27;6;33~"
        );
        for (base, produced, held) in [('1', '1', CONTROL_ALT), (';', ';', CONTROL_ALT)] {
            assert_eq!(
                key(on(base, produced, held), LEVEL_ONE),
                Err(Unsupported::NotExpressible {
                    what: "Alt with Control on a key that has no control character"
                }),
                "{produced}"
            );
        }
        assert_eq!(
            spelled(on('c', 'C', SHIFT_ALT), LEVEL_TWO),
            b"\x1b[27;4;67~"
        );
        assert_eq!(
            spelled(on('1', '1', CONTROL_ALT), LEVEL_TWO),
            b"\x1b[27;7;49~"
        );
        // X11 gives Space, `2` to `8`, `/` and `?` their control characters, and xterm reports them
        // at level 1 with Shift, Control and Alt as Shift and Control alone, so that chord is
        // refused; a letter's control character keeps the escape prefix.
        let all = Modifiers {
            shift: true,
            alt: true,
            control: true,
            superkey: false,
        };
        for (base, produced) in [(' ', ' '), ('2', '2'), ('/', '?')] {
            assert_eq!(
                key(on(base, produced, all), LEVEL_ONE),
                Err(Unsupported::NotExpressible {
                    what: "Alt with Shift and Control on this key"
                }),
                "{produced}"
            );
        }
        assert_eq!(spelled(on('a', 'A', all), LEVEL_ONE), b"\x1b\x01");
        assert_eq!(spelled(on(' ', ' ', all), LEGACY), b"\x1b\x00");
        assert_eq!(spelled(on(' ', ' ', all), LEVEL_TWO), b"\x1b[27;8;32~");
    }

    /// KR-REQ-08.59: Control and a character is what X11 makes of it, which is what xterm sends,
    /// and `modifyOtherKeys` below level two leaves every such spelling alone.
    #[test]
    fn control_and_a_character_is_what_x11_makes_of_it() {
        let control = |produced: char| KeyEvent::with(Key::Char(produced), Modifiers::control());
        for (produced, expected) in [
            ('2', 0x00),
            ('3', 0x1b),
            ('4', 0x1c),
            ('5', 0x1d),
            ('6', 0x1e),
            ('7', 0x1f),
            ('8', 0x7f),
            ('/', 0x1f),
            ('`', 0x00),
            ('@', 0x00),
            ('{', 0x1b),
            ('|', 0x1c),
            ('}', 0x1d),
            ('~', 0x1e),
            (' ', 0x00),
        ] {
            assert_eq!(spelled(control(produced), LEGACY), [expected], "{produced}");
            assert_eq!(
                spelled(control(produced), LEVEL_ONE),
                [expected],
                "{produced}: a spelling level one keeps"
            );
        }
        // A character Control does nothing to keeps its own byte in the ordinary encoding, and
        // level one reports the chord, since the ordinary encoding cannot say it.
        assert_eq!(spelled(control(';'), LEGACY), b";");
        assert_eq!(spelled(control('1'), LEGACY), b"1");
        assert_eq!(spelled(control('1'), LEVEL_ONE), b"\x1b[27;5;49~");
        // Alt is the escape prefix in front of the control byte.
        assert_eq!(
            spelled(KeyEvent::with(Key::Char('3'), CONTROL_ALT), LEGACY),
            b"\x1b\x1b"
        );
        // Level two reports every one of them.
        assert_eq!(spelled(control('3'), LEVEL_TWO), b"\x1b[27;5;51~");
    }

    /// KR-REQ-08.59, KR-REQ-08.60: the Kitty protocol changes only what its flags ask it to.
    #[test]
    fn the_kitty_protocol_leaves_alone_what_its_flags_did_not_ask_about() {
        let all_escapes = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };

        // An application that asked only for event types still reads the legacy encoding for
        // everything else. A shell under it expects Control-C to be one byte.
        assert_eq!(
            spelled(KeyEvent::with(Key::Char('c'), Modifiers::control()), EVENTS),
            b"\x03"
        );
        assert_eq!(spelled(KeyEvent::press(Key::Escape), EVENTS), b"\x1b");
        // Under disambiguation, Escape is the one key the protocol has to spell differently.
        assert_eq!(
            spelled(KeyEvent::press(Key::Escape), DISAMBIGUATE),
            b"\x1b[27u"
        );
        assert_eq!(
            spelled(
                KeyEvent::with(Key::Char('c'), Modifiers::control()),
                DISAMBIGUATE
            ),
            b"\x1b[99;5u",
            "and a control chord, which is what it exists to disambiguate"
        );
        // The keys the ordinary encoding already spells keep that spelling until the application
        // asks for every key as an escape code.
        for encoding in [EVENTS, DISAMBIGUATE] {
            assert_eq!(
                spelled(KeyEvent::press(Key::Enter), encoding),
                b"\r",
                "{encoding:?}"
            );
            assert_eq!(spelled(KeyEvent::press(Key::Tab), encoding), b"\t");
            assert_eq!(spelled(KeyEvent::press(Key::Backspace), encoding), b"\x7f");
            assert_eq!(spelled(KeyEvent::press(Key::Char('a')), encoding), b"a");
            assert_eq!(
                spelled(KeyEvent::press(Key::Arrow(Arrow::Up)), encoding),
                b"\x1b[A",
                "and a functional key is the same sequence in both encodings"
            );
        }
        assert_eq!(
            spelled(KeyEvent::press(Key::Char('a')), all_escapes),
            b"\x1b[97u"
        );
        assert_eq!(
            spelled(KeyEvent::press(Key::Enter), all_escapes),
            b"\x1b[13u"
        );
        // A modified functional key carries the modifier parameter, in either encoding.
        assert_eq!(
            spelled(
                KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control()),
                DISAMBIGUATE
            ),
            b"\x1b[1;5A"
        );
    }

    /// KR-REQ-08.59: the protocol's own example table, "Example encodings", holds for presses
    /// while the application asks only for event types, which leaves presses legacy. The keys are
    /// named by their unshifted character; Control with Shift is outside the five legacy chords,
    /// so it is the protocol's report.
    #[test]
    fn the_kitty_protocols_example_table_holds_under_event_types_alone() {
        let rows: [(char, char, [&[u8]; 7]); 3] = [
            (
                'i',
                'I',
                [
                    b"i",
                    b"I",
                    b"\x1bi",
                    b"\x09",
                    b"\x1bI",
                    b"\x1b\x09",
                    b"\x1b[105;6u",
                ],
            ),
            (
                '3',
                '#',
                [
                    b"3",
                    b"#",
                    b"\x1b3",
                    b"\x1b",
                    b"\x1b#",
                    b"\x1b\x1b",
                    b"\x1b[51;6u",
                ],
            ),
            (
                ';',
                ':',
                [
                    b";",
                    b":",
                    b"\x1b;",
                    b";",
                    b"\x1b:",
                    b"\x1b;",
                    b"\x1b[59;6u",
                ],
            ),
        ];
        for (base, shifted, expected) in rows {
            let chords = [
                on(base, base, Modifiers::NONE),
                on(base, shifted, Modifiers::shift()),
                on(base, base, ALT),
                on(base, base, Modifiers::control()),
                on(base, shifted, SHIFT_ALT),
                on(base, base, CONTROL_ALT),
                on(base, shifted, CONTROL_SHIFT),
            ];
            for (chord, bytes) in chords.into_iter().zip(expected) {
                assert_eq!(spelled(chord, EVENTS), bytes, "{base} with {chord:?}");
            }
        }
    }

    /// KR-REQ-08.59: Space follows the protocol's table of control characters.
    #[test]
    fn space_is_spelled_from_the_protocols_control_table() {
        for (modifiers, expected) in [
            (Modifiers::NONE, &b" "[..]),
            (Modifiers::control(), &b"\x00"[..]),
            (ALT, &b"\x1b "[..]),
            (Modifiers::shift(), &b" "[..]),
            (CONTROL_SHIFT, &b"\x00"[..]),
            (SHIFT_ALT, &b"\x1b "[..]),
            (CONTROL_ALT, &b"\x1b\x00"[..]),
        ] {
            assert_eq!(
                spelled(on(' ', ' ', modifiers), EVENTS),
                expected,
                "{modifiers:?}"
            );
        }
    }

    /// KR-REQ-08.59: a key outside the protocol's legacy set is a report once Control or Alt is
    /// held, and its text otherwise.
    #[test]
    fn a_key_outside_the_legacy_set_is_a_report_with_control_or_alt() {
        assert_eq!(
            spelled(on('ä', 'ä', Modifiers::control()), EVENTS),
            b"\x1b[228;5u"
        );
        assert_eq!(spelled(on('ä', 'ä', ALT), EVENTS), b"\x1b[228;3u");
        assert_eq!(
            spelled(on('ä', 'Ä', Modifiers::shift()), EVENTS),
            "Ä".as_bytes()
        );
        // With Shift held and no unshifted character, the chord cannot be named.
        assert_eq!(
            key(KeyEvent::with(Key::Char('I'), CONTROL_SHIFT), EVENTS),
            Err(Unsupported::NotExpressible {
                what: "the unshifted key a shifted character was produced from"
            })
        );
    }

    /// KR-REQ-08.59: disambiguation reports Escape and every chord with Control or Alt as the
    /// protocol's own report; text, and Return, Tab and Backspace alone, keep their bytes.
    #[test]
    fn disambiguation_reports_every_chord_on_a_text_key() {
        for (event, expected) in [
            (KeyEvent::press(Key::Escape), &b"\x1b[27u"[..]),
            (on('i', 'i', ALT), b"\x1b[105;3u"),
            (on('i', 'i', Modifiers::control()), b"\x1b[105;5u"),
            (on('i', 'i', CONTROL_ALT), b"\x1b[105;7u"),
            (on('i', 'I', SHIFT_ALT), b"\x1b[105;4u"),
            (on('i', 'I', CONTROL_SHIFT), b"\x1b[105;6u"),
            (on('i', 'I', Modifiers::shift()), b"I"),
            (on('i', 'i', Modifiers::NONE), b"i"),
            (KeyEvent::press(Key::Enter), b"\r"),
            (
                KeyEvent::with(Key::Enter, Modifiers::shift()),
                b"\x1b[13;2u",
            ),
            (KeyEvent::press(Key::Tab), b"\t"),
            (KeyEvent::with(Key::Tab, Modifiers::shift()), b"\x1b[9;2u"),
            (KeyEvent::press(Key::Backspace), b"\x7f"),
            (
                KeyEvent::with(Key::Backspace, Modifiers::control()),
                b"\x1b[127;5u",
            ),
            (KeyEvent::press(Key::Arrow(Arrow::Up)), b"\x1b[A"),
            (KeyEvent::press(Key::Function(5)), b"\x1b[15~"),
            (KeyEvent::press(Key::Insert), b"\x1b[2~"),
        ] {
            assert_eq!(spelled(event, DISAMBIGUATE), expected, "{event:?}");
        }
    }

    /// KR-REQ-08.59: a functional key is a sequence in every mode, from the protocol's table.
    #[test]
    fn a_functional_key_is_spelled_from_the_protocols_table_in_every_mode() {
        // The table applies whichever flags are in force, because a functional key is a sequence
        // either way and it is this table that numbers them: a letter suffix needs no number, a
        // tilde suffix is the number, and F3 has one where the ordinary encoding gave it a letter
        // that is also a valid cursor-position report.
        for encoding in [EVENTS, DISAMBIGUATE] {
            assert_eq!(
                spelled(KeyEvent::press(Key::Function(1)), encoding),
                b"\x1b[P",
                "{encoding:?}"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::Function(3)), encoding),
                b"\x1b[13~"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::Arrow(Arrow::Up)), encoding),
                b"\x1b[A"
            );
            assert_eq!(
                spelled(
                    KeyEvent::with(Key::Function(3), Modifiers::shift()),
                    encoding
                ),
                b"\x1b[13;2~"
            );
        }
        // And it reports its repeats and releases the moment the application asks for them,
        // whether or not it asked to disambiguate anything.
        let up = KeyEvent::press(Key::Arrow(Arrow::Up));
        assert_eq!(spelled(repeated(up), EVENTS), b"\x1b[1;1:2A");
        assert!(release_reported(up, EVENTS));
        assert_eq!(
            release(up, Modifiers::NONE, Locks::NONE, EVENTS).expect("encodes"),
            b"\x1b[1;1:3A"
        );
        // A modified Escape has no ordinary spelling that says a modifier was held, so it is
        // reported once either flag is in force; a plain one keeps its byte until disambiguation.
        assert_eq!(
            spelled(KeyEvent::with(Key::Escape, Modifiers::shift()), EVENTS),
            b"\x1b[27;2u"
        );
        assert_eq!(spelled(KeyEvent::press(Key::Escape), EVENTS), b"\x1b");
        assert_eq!(
            spelled(KeyEvent::press(Key::Escape), DISAMBIGUATE),
            b"\x1b[27u"
        );
        // Enter, Tab and Backspace keep their bytes unmodified and are reported once anything is
        // held, whichever flag put the reports in force.
        assert_eq!(spelled(KeyEvent::press(Key::Enter), EVENTS), b"\r");
        assert_eq!(
            spelled(KeyEvent::with(Key::Enter, Modifiers::shift()), EVENTS),
            b"\x1b[13;2u"
        );
        assert_eq!(
            spelled(KeyEvent::with(Key::Tab, CONTROL_SHIFT), EVENTS),
            b"\x1b[9;6u",
            "and a chord the ordinary encoding cannot carry at all is the protocol's own report \
             rather than a refusal"
        );
        assert_eq!(spelled(KeyEvent::press(Key::Home), DISAMBIGUATE), b"\x1b[H");
        assert_eq!(
            spelled(KeyEvent::press(Key::Delete), DISAMBIGUATE),
            b"\x1b[3~"
        );
    }

    /// KR-REQ-08.59: a modified key the ordinary encoding spells ambiguously is disambiguated.
    #[test]
    fn a_modified_special_or_functional_key_takes_the_protocols_own_form() {
        // Shift-Enter has no ordinary spelling of its own: a terminal sends the same byte for it as
        // for Enter, which is what disambiguation exists to fix.
        assert_eq!(
            spelled(KeyEvent::with(Key::Enter, Modifiers::shift()), DISAMBIGUATE),
            b"\x1b[13;2u"
        );
        assert_eq!(
            spelled(KeyEvent::with(Key::Tab, Modifiers::control()), DISAMBIGUATE),
            b"\x1b[9;5u"
        );
        // F3 is numbered differently under this protocol, and its ordinary form with a modifier is
        // also a valid cursor-position report, which an application would read as one.
        assert_eq!(
            spelled(
                KeyEvent::with(Key::Function(3), Modifiers::shift()),
                DISAMBIGUATE
            ),
            b"\x1b[13;2~"
        );
        // The functional keys whose numbering the two encodings share come out the same either way.
        assert_eq!(
            spelled(
                KeyEvent::with(Key::Delete, Modifiers::shift()),
                DISAMBIGUATE
            ),
            b"\x1b[3;2~"
        );
        assert_eq!(
            spelled(
                KeyEvent::with(Key::Function(1), Modifiers::shift()),
                DISAMBIGUATE
            ),
            b"\x1b[1;2P"
        );
    }

    /// KR-REQ-08.59: the locks ride on every key the protocol sends as an escape code, as bits 64
    /// and 128, and on nothing it sends as text or as a byte that keeps its spelling; the ordinary
    /// encoding and `modifyOtherKeys` never carry them.
    #[test]
    fn the_locks_ride_on_every_report_and_on_nothing_else() {
        let control_c = on('c', 'c', Modifiers::control());
        for encoding in [DISAMBIGUATE, EVENTS, BOTH] {
            assert_eq!(
                spelled(locked(KeyEvent::press(Key::Escape), CAPS), encoding),
                b"\x1b[27;65u",
                "{encoding:?}: under event types alone too, a lock turns Escape's byte into a report"
            );
            assert_eq!(
                spelled(
                    locked(KeyEvent::press(Key::Arrow(Arrow::Up)), NUM),
                    encoding
                ),
                b"\x1b[1;129A"
            );
            assert_eq!(
                spelled(locked(control_c, CAPS), encoding),
                b"\x1b[99;69u",
                "and Control-C's legacy byte, which has nowhere to say a lock is on"
            );
            assert_eq!(
                spelled(locked(on('a', 'A', Modifiers::NONE), CAPS), encoding),
                b"A",
                "text is text"
            );
            for plain in [Key::Enter, Key::Tab, Key::Backspace] {
                assert_eq!(
                    spelled(locked(KeyEvent::press(plain), CAPS), encoding),
                    spelled(KeyEvent::press(plain), encoding),
                    "{plain:?}: a lock alone leaves the byte"
                );
            }
            assert_eq!(
                spelled(
                    locked(KeyEvent::with(Key::Enter, Modifiers::shift()), NUM),
                    encoding
                ),
                b"\x1b[13;130u"
            );
            assert_eq!(
                spelled(
                    locked(
                        KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control()),
                        Locks {
                            caps_lock: true,
                            num_lock: true
                        }
                    ),
                    encoding
                ),
                b"\x1b[1;197A"
            );
        }
        assert_eq!(
            spelled(locked(on('c', 'c', ALT), NUM), EVENTS),
            b"\x1b[99;131u"
        );
        // Nowhere to put them in the ordinary encoding or `modifyOtherKeys`, so they change nothing.
        assert_eq!(spelled(locked(control_c, CAPS), LEGACY), b"\x03");
        assert_eq!(
            spelled(locked(control_c, CAPS), LEVEL_TWO),
            b"\x1b[27;5;99~"
        );
        assert_eq!(
            spelled(locked(KeyEvent::press(Key::Arrow(Arrow::Up)), NUM), LEGACY),
            b"\x1b[A"
        );
    }

    /// KR-REQ-08.59, KR-REQ-08.60: a character Caps Lock made needs the key it came from before the
    /// protocol can report it, as a shifted one does.
    #[test]
    fn a_character_caps_lock_made_needs_the_key_it_came_from() {
        assert_eq!(
            key(
                locked(KeyEvent::with(Key::Char('C'), Modifiers::control()), CAPS),
                DISAMBIGUATE
            ),
            Err(Unsupported::NotExpressible {
                what: "the unshifted key a character made under Caps Lock was produced from"
            })
        );
        assert_eq!(
            spelled(
                locked(on('c', 'C', Modifiers::control()), CAPS),
                DISAMBIGUATE
            ),
            b"\x1b[99;69u"
        );
        assert_eq!(
            spelled(locked(KeyEvent::press(Key::Char('C')), CAPS), DISAMBIGUATE),
            b"C",
            "text needs no code"
        );
    }

    /// KR-REQ-08.59: a release is spelled from its press. The press decides whether the encoding
    /// reports it at all; the release carries its own modifiers and locks.
    #[test]
    fn a_release_is_spelled_from_its_press() {
        // Control-I with Control released first: still the I key's release.
        let control_i = on('i', 'i', Modifiers::control());
        assert!(release_reported(control_i, BOTH));
        assert_eq!(
            release(control_i, Modifiers::NONE, Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[105;1:3u"
        );
        assert_eq!(
            release(control_i, Modifiers::control(), Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[105;5:3u"
        );
        // A control chord's legacy byte has no room for an event type, so its release is reported.
        let control_c = on('c', 'c', Modifiers::control());
        assert!(release_reported(control_c, EVENTS));
        assert_eq!(
            release(control_c, Modifiers::control(), Locks::NONE, EVENTS).expect("encodes"),
            b"\x1b[99;5:3u"
        );
        assert_eq!(
            release(control_c, Modifiers::control(), CAPS, EVENTS).expect("encodes"),
            b"\x1b[99;69:3u"
        );
        // Text, and a bare byte, are the whole report: no release follows them.
        for press in [
            on('a', 'a', Modifiers::NONE),
            on('a', 'A', Modifiers::shift()),
            KeyEvent::press(Key::Enter),
            KeyEvent::press(Key::Tab),
            KeyEvent::press(Key::Backspace),
            KeyEvent::press(Key::Escape),
            locked(KeyEvent::press(Key::Enter), CAPS),
        ] {
            assert!(!release_reported(press, EVENTS), "{press:?}");
        }
        assert!(
            release_reported(locked(KeyEvent::press(Key::Escape), NUM), EVENTS),
            "a lock made Escape a report"
        );
        // Disambiguated, Escape is a report and is released like one.
        let escape = KeyEvent::press(Key::Escape);
        assert!(release_reported(escape, BOTH));
        assert_eq!(
            release(escape, Modifiers::NONE, Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[27;1:3u"
        );
        let shift_enter = KeyEvent::with(Key::Enter, Modifiers::shift());
        assert!(release_reported(shift_enter, EVENTS));
        assert_eq!(
            release(shift_enter, Modifiers::shift(), Locks::NONE, EVENTS).expect("encodes"),
            b"\x1b[13;2:3u"
        );
        // Every key is a report once the application asks for every key as one.
        let a = on('a', 'a', Modifiers::NONE);
        assert!(release_reported(a, EVERY_KEY));
        assert_eq!(
            release(a, Modifiers::NONE, Locks::NONE, EVERY_KEY).expect("encodes"),
            b"\x1b[97;1:3u"
        );
        assert_eq!(
            release(
                KeyEvent::press(Key::Enter),
                Modifiers::NONE,
                Locks::NONE,
                EVERY_KEY
            )
            .expect("encodes"),
            b"\x1b[13;1:3u"
        );
    }

    /// KR-REQ-08.59: a release keeps the key its press established. A Control-C whose platform
    /// reported no unshifted character is still the C key when Shift or Caps Lock comes on before it
    /// comes up: the release takes its modifiers and locks from the moment it happens, never its
    /// identity. A press that had no code has no release either.
    #[test]
    fn a_release_keeps_the_key_its_press_established() {
        let control_c = KeyEvent::with(Key::Char('c'), Modifiers::control());
        assert_eq!(spelled(control_c, BOTH), b"\x1b[99;5u");
        assert_eq!(
            release(control_c, Modifiers::shift(), Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[99;2:3u"
        );
        assert_eq!(
            release(control_c, CONTROL_SHIFT, Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[99;6:3u"
        );
        assert_eq!(
            release(control_c, Modifiers::control(), CAPS, BOTH).expect("encodes"),
            b"\x1b[99;69:3u"
        );
        let unknown = KeyEvent::with(Key::Char('C'), CONTROL_SHIFT);
        assert!(key(unknown, BOTH).is_err());
        assert!(release(unknown, Modifiers::NONE, Locks::NONE, BOTH).is_err());
    }

    /// KR-REQ-08.59: an encoding that reports no releases gets nothing for one, never a press.
    #[test]
    fn a_release_under_an_encoding_without_releases_is_nothing() {
        let control_i = on('i', 'i', Modifiers::control());
        for encoding in [
            LEGACY,
            APPLICATION,
            LEVEL_ONE,
            LEVEL_TWO,
            DISAMBIGUATE,
            KeyboardEncoding::Kitty { flags: 0 },
        ] {
            assert!(!release_reported(control_i, encoding), "{encoding:?}");
            assert!(
                release(control_i, Modifiers::NONE, Locks::NONE, encoding)
                    .expect("encodes")
                    .is_empty(),
                "{encoding:?}"
            );
        }
        let alternate_keys = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_EVENT_TYPES | KeyboardEncoding::KITTY_ALTERNATE_KEYS,
        };
        assert!(!release_reported(control_i, alternate_keys));
        assert_eq!(
            release(control_i, Modifiers::NONE, Locks::NONE, alternate_keys),
            Err(Unsupported::NotExpressible {
                what: "a Kitty keyboard flag this encoder does not produce"
            })
        );
    }

    /// KR-REQ-08.59: a repeat is the press again, except where event types report it.
    #[test]
    fn a_repeat_is_the_press_again_unless_event_types_report_it() {
        assert_eq!(
            spelled(repeated(on('a', 'a', Modifiers::NONE)), EVENTS),
            b"a"
        );
        assert_eq!(
            spelled(repeated(on('c', 'c', Modifiers::control())), EVENTS),
            b"\x1b[99;5:2u"
        );
        assert_eq!(
            spelled(repeated(on('a', 'a', Modifiers::control())), DISAMBIGUATE),
            b"\x1b[97;5u",
            "a repeat with no event types is the press it is, rather than a refusal that drops a \
             key the person is holding down"
        );
        assert_eq!(
            spelled(repeated(KeyEvent::press(Key::Arrow(Arrow::Up))), LEGACY),
            b"\x1b[A"
        );
        assert_eq!(spelled(repeated(KeyEvent::press(Key::Enter)), BOTH), b"\r");
    }

    /// KR-REQ-08.59: once the application tells keys apart, the keypad is its own key: a key that
    /// makes text is its text, and every other keypad event is its report.
    #[test]
    fn the_keypad_is_its_own_key_once_keys_are_told_apart() {
        for (event, expected) in [
            (keypad(Keypad::Digit(1), Modifiers::NONE), &b"1"[..]),
            (
                keypad(Keypad::Digit(1), Modifiers::control()),
                b"\x1b[57400;5u",
            ),
            (keypad(Keypad::Digit(0), ALT), b"\x1b[57399;3u"),
            (
                keypad(Keypad::Digit(9), Modifiers::control()),
                b"\x1b[57408;5u",
            ),
            (keypad(Keypad::Decimal(','), Modifiers::NONE), b","),
            (
                keypad(Keypad::Decimal(','), Modifiers::control()),
                b"\x1b[57409;5u",
            ),
            (
                keypad(Keypad::Divide, Modifiers::control()),
                b"\x1b[57410;5u",
            ),
            (
                keypad(Keypad::Multiply, Modifiers::control()),
                b"\x1b[57411;5u",
            ),
            (keypad(Keypad::Subtract, ALT), b"\x1b[57412;3u"),
            (keypad(Keypad::Add, Modifiers::shift()), b"+"),
            (keypad(Keypad::Add, Modifiers::control()), b"\x1b[57413;5u"),
            (keypad(Keypad::Enter, Modifiers::NONE), b"\x1b[57414u"),
            (
                keypad(Keypad::Equal, Modifiers::control()),
                b"\x1b[57415;5u",
            ),
            (keypad(Keypad::Separator('.'), Modifiers::NONE), b"."),
            (
                keypad(Keypad::Separator('.'), Modifiers::control()),
                b"\x1b[57416;5u",
            ),
            (
                keypad(Keypad::Arrow(Arrow::Left), Modifiers::NONE),
                b"\x1b[57417u",
            ),
            (
                keypad(Keypad::Arrow(Arrow::Right), Modifiers::NONE),
                b"\x1b[57418u",
            ),
            (
                keypad(Keypad::Arrow(Arrow::Up), Modifiers::NONE),
                b"\x1b[57419u",
            ),
            (
                keypad(Keypad::Arrow(Arrow::Down), Modifiers::NONE),
                b"\x1b[57420u",
            ),
            (keypad(Keypad::PageUp, Modifiers::NONE), b"\x1b[57421u"),
            (keypad(Keypad::PageDown, Modifiers::NONE), b"\x1b[57422u"),
            (keypad(Keypad::Home, Modifiers::NONE), b"\x1b[57423u"),
            (keypad(Keypad::End, Modifiers::NONE), b"\x1b[57424u"),
            (keypad(Keypad::Insert, Modifiers::NONE), b"\x1b[57425u"),
            (keypad(Keypad::Delete, Modifiers::NONE), b"\x1b[57426u"),
            (keypad(Keypad::Begin, Modifiers::NONE), b"\x1b[E"),
            (keypad(Keypad::Begin, Modifiers::control()), b"\x1b[1;5E"),
            (
                locked(keypad(Keypad::End, Modifiers::NONE), NUM),
                b"\x1b[57424;129u",
            ),
        ] {
            assert_eq!(spelled(event, DISAMBIGUATE), expected, "{event:?}");
            assert_eq!(spelled(event, BOTH), expected, "{event:?}");
        }
        // Released: a key that went as its text has no release; a report does.
        assert!(!release_reported(
            keypad(Keypad::Digit(1), Modifiers::NONE),
            BOTH
        ));
        let control_one = keypad(Keypad::Digit(1), Modifiers::control());
        assert!(release_reported(control_one, BOTH));
        assert_eq!(
            release(control_one, Modifiers::NONE, Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[57400;1:3u"
        );
        let enter = keypad(Keypad::Enter, Modifiers::NONE);
        assert!(release_reported(enter, BOTH));
        assert_eq!(
            release(enter, Modifiers::NONE, Locks::NONE, BOTH).expect("encodes"),
            b"\x1b[57414;1:3u"
        );
        // Every key as an escape code: the digit too.
        assert_eq!(
            spelled(keypad(Keypad::Digit(1), Modifiers::NONE), EVERY_KEY),
            b"\x1b[57400u"
        );
        assert_eq!(
            key(keypad(Keypad::Digit(10), Modifiers::NONE), DISAMBIGUATE),
            Err(Unsupported::UnknownKey)
        );
    }

    /// KR-REQ-08.59: elsewhere a keypad key is the main key it stands for, as the protocol's legacy
    /// encoding and the ordinary one both report it; under event types alone the separator keeps
    /// its own code, and the centre key its letter.
    #[test]
    fn the_keypad_is_the_main_key_it_stands_for_elsewhere() {
        for (event, legacy, application) in [
            (
                keypad(Keypad::Digit(1), Modifiers::NONE),
                &b"1"[..],
                &b"1"[..],
            ),
            (keypad(Keypad::Enter, Modifiers::NONE), b"\r", b"\r"),
            (keypad(Keypad::End, Modifiers::NONE), b"\x1b[F", b"\x1bOF"),
            (
                keypad(Keypad::Arrow(Arrow::Up), Modifiers::NONE),
                b"\x1b[A",
                b"\x1bOA",
            ),
            (keypad(Keypad::Begin, Modifiers::NONE), b"\x1b[E", b"\x1bOE"),
            (
                keypad(Keypad::Begin, Modifiers::control()),
                b"\x1b[1;5E",
                b"\x1b[1;5E",
            ),
            (keypad(Keypad::Separator(','), Modifiers::NONE), b",", b","),
            (keypad(Keypad::Decimal('.'), Modifiers::NONE), b".", b"."),
            (
                keypad(Keypad::Digit(5), Modifiers::control()),
                b"\x1d",
                b"\x1d",
            ),
            (
                keypad(Keypad::PageUp, Modifiers::NONE),
                b"\x1b[5~",
                b"\x1b[5~",
            ),
        ] {
            assert_eq!(spelled(event, LEGACY), legacy, "{event:?}");
            assert_eq!(spelled(event, APPLICATION), application, "{event:?}");
        }
        assert_eq!(
            spelled(keypad(Keypad::Digit(1), Modifiers::control()), LEVEL_TWO),
            b"\x1b[27;5;49~"
        );
        for (event, expected) in [
            (keypad(Keypad::Digit(1), Modifiers::NONE), &b"1"[..]),
            (keypad(Keypad::Digit(1), Modifiers::control()), b"1"),
            (keypad(Keypad::Digit(3), Modifiers::control()), b"\x1b"),
            (keypad(Keypad::Enter, Modifiers::NONE), b"\r"),
            (keypad(Keypad::Enter, Modifiers::shift()), b"\x1b[13;2u"),
            (keypad(Keypad::End, Modifiers::NONE), b"\x1b[F"),
            (keypad(Keypad::Begin, Modifiers::NONE), b"\x1b[E"),
            (keypad(Keypad::Separator(','), Modifiers::NONE), b","),
            (
                keypad(Keypad::Separator(','), Modifiers::control()),
                b"\x1b[57416;5u",
            ),
        ] {
            assert_eq!(spelled(event, EVENTS), expected, "{event:?}");
        }
        let control_separator = keypad(Keypad::Separator(','), Modifiers::control());
        assert_eq!(
            spelled(repeated(control_separator), EVENTS),
            b"\x1b[57416;5:2u"
        );
        assert!(release_reported(control_separator, EVENTS));
        assert_eq!(
            release(control_separator, Modifiers::NONE, Locks::NONE, EVENTS).expect("encodes"),
            b"\x1b[57416;1:3u"
        );
        assert!(!release_reported(
            keypad(Keypad::Separator(','), Modifiers::NONE),
            EVENTS
        ));
        let end = keypad(Keypad::End, Modifiers::NONE);
        assert!(release_reported(end, EVENTS));
        assert_eq!(
            release(end, Modifiers::NONE, Locks::NONE, EVENTS).expect("encodes"),
            b"\x1b[1;1:3F"
        );
    }

    /// KR-REQ-08.59: without disambiguation the Kitty protocol names a keypad key by the main key it
    /// converts it to, whatever the layout makes it type: a decimal key that makes a comma is `.` in
    /// a report, its repeat and its release, and still types its comma. Told apart, it is the keypad's
    /// own decimal key.
    #[test]
    fn a_decimal_key_that_makes_a_comma_is_the_period_key_in_a_report() {
        let comma = |held| locked(keypad(Keypad::Decimal(','), held), NUM);
        assert_eq!(spelled(comma(Modifiers::NONE), EVENTS), b",");
        let control = comma(Modifiers::control());
        assert_eq!(spelled(control, EVENTS), b"\x1b[46;133u");
        assert_eq!(spelled(repeated(control), EVENTS), b"\x1b[46;133:2u");
        assert!(release_reported(control, EVENTS));
        assert_eq!(
            release(control, Modifiers::control(), NUM, EVENTS).expect("encodes"),
            b"\x1b[46;133:3u"
        );
        assert_eq!(
            spelled(keypad(Keypad::Decimal(','), Modifiers::control()), EVENTS),
            b".",
            "the period key's legacy spelling with Control"
        );
        assert_eq!(spelled(control, BOTH), b"\x1b[57409;133u");
    }

    /// KR-REQ-08.59: F13 upwards have the Kitty protocol's codes and no ordinary spelling.
    #[test]
    fn function_keys_past_twelve_are_the_kitty_protocols_alone() {
        for encoding in [LEGACY, LEVEL_TWO] {
            assert_eq!(
                key(KeyEvent::press(Key::Function(13)), encoding),
                Err(Unsupported::UnknownKey),
                "{encoding:?}"
            );
        }
        for encoding in [DISAMBIGUATE, EVENTS, BOTH] {
            assert_eq!(
                spelled(KeyEvent::press(Key::Function(13)), encoding),
                b"\x1b[57376u"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::Function(24)), encoding),
                b"\x1b[57387u"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::Function(35)), encoding),
                b"\x1b[57398u"
            );
            assert_eq!(
                spelled(
                    KeyEvent::with(Key::Function(13), Modifiers::control()),
                    encoding
                ),
                b"\x1b[57376;5u"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Function(36)), encoding),
                Err(Unsupported::UnknownKey)
            );
        }
        assert_eq!(
            release(
                KeyEvent::press(Key::Function(13)),
                Modifiers::NONE,
                Locks::NONE,
                EVENTS
            )
            .expect("encodes"),
            b"\x1b[57376;1:3u"
        );
    }

    /// KR-REQ-08.59: the menu key is xterm's `CSI 29 ~` and the protocol's 57363; Print Screen and
    /// Pause have only the protocol's codes.
    #[test]
    fn menu_print_screen_and_pause() {
        assert_eq!(spelled(KeyEvent::press(Key::Menu), LEGACY), b"\x1b[29~");
        assert_eq!(
            spelled(KeyEvent::with(Key::Menu, Modifiers::control()), LEGACY),
            b"\x1b[29;5~"
        );
        assert_eq!(spelled(KeyEvent::press(Key::Menu), LEVEL_TWO), b"\x1b[29~");
        for encoding in [DISAMBIGUATE, EVENTS] {
            assert_eq!(
                spelled(KeyEvent::press(Key::Menu), encoding),
                b"\x1b[57363u"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::PrintScreen), encoding),
                b"\x1b[57361u"
            );
            assert_eq!(
                spelled(KeyEvent::press(Key::Pause), encoding),
                b"\x1b[57362u"
            );
        }
        for pressed in [Key::PrintScreen, Key::Pause] {
            assert_eq!(
                key(KeyEvent::press(pressed), LEGACY),
                Err(Unsupported::UnknownKey),
                "{pressed:?}"
            );
        }
    }

    /// KR-REQ-08.60, KR-REQ-08.61: the encoding is the host's own rule, read from what it projects:
    /// the showing buffer's Kitty flags, else `modifyOtherKeys`, else the ordinary encoding.
    #[test]
    fn the_negotiated_encoding_is_the_hosts_rule() {
        use kr_protocol::projection::{KittyKeyboardState, ProjectedKeyboard};
        use kr_protocol::scalars::{Nullable, U64};
        let board = |modify_other_keys: u64, primary: Option<u64>, alternate: Option<u64>| {
            ProjectedKeyboard {
                modify_other_keys: U64::new(modify_other_keys),
                primary: KittyKeyboardState {
                    flags: Nullable(primary.map(U64::new)),
                    stack: Vec::new(),
                },
                alternate: KittyKeyboardState {
                    flags: Nullable(alternate.map(U64::new)),
                    stack: Vec::new(),
                },
            }
        };
        assert_eq!(
            KeyboardEncoding::negotiated(&board(0, None, None), false, true),
            APPLICATION
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(0, Some(1), None), false, false),
            DISAMBIGUATE
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(0, Some(1), None), true, false),
            LEGACY,
            "the alternate buffer keeps its own stack, and it is empty"
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(2, Some(1), Some(3)), true, false),
            BOTH
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(2, Some(0), None), false, false),
            LEVEL_TWO,
            "flags of zero are no protocol at all"
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(1, None, None), false, true),
            KeyboardEncoding::ModifyOtherKeys {
                level: 1,
                application_cursor_keys: true
            }
        );
        assert_eq!(
            KeyboardEncoding::negotiated(&board(7, None, None), false, false),
            LEVEL_TWO
        );
        let beyond = KeyboardEncoding::negotiated(&board(0, Some(300), None), false, false);
        assert_eq!(beyond, KeyboardEncoding::Kitty { flags: u8::MAX });
        assert!(
            key(KeyEvent::press(Key::Char('a')), beyond).is_err(),
            "flags the protocol cannot have are refused rather than cut down"
        );
    }

    /// KR-REQ-08.60: no flag set is not this protocol, whatever the encoding is called.
    #[test]
    fn a_kitty_encoding_with_no_flags_is_the_ordinary_encoding() {
        let nothing = KeyboardEncoding::Kitty { flags: 0 };
        // The canonical parser reports the ordinary encoding for exactly this state, so a caller
        // that names this one gets the same answer rather than an enhanced report nothing asked
        // for.
        assert_eq!(
            spelled(KeyEvent::press(Key::Function(1)), nothing),
            b"\x1bOP"
        );
        assert_eq!(spelled(KeyEvent::press(Key::Char('a')), nothing), b"a");
        assert_eq!(spelled(KeyEvent::press(Key::Escape), nothing), b"\x1b");
        assert!(
            release(
                KeyEvent::press(Key::Char('a')),
                Modifiers::NONE,
                Locks::NONE,
                nothing
            )
            .expect("encodes")
            .is_empty(),
            "including the ordinary encoding's release, which is nothing"
        );
    }

    /// KR-REQ-08.60: a flag this encoder does not produce is refused, not half-served.
    #[test]
    fn a_kitty_flag_this_encoder_does_not_produce_is_refused() {
        for flags in [
            KeyboardEncoding::KITTY_ALTERNATE_KEYS,
            KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALTERNATE_KEYS,
            0b0001_0000,
            KeyboardEncoding::KITTY_DISAMBIGUATE | 0b0001_0000,
        ] {
            assert_eq!(
                key(
                    KeyEvent::press(Key::Char('a')),
                    KeyboardEncoding::Kitty { flags }
                ),
                Err(Unsupported::NotExpressible {
                    what: "a Kitty keyboard flag this encoder does not produce"
                }),
                "flags {flags}"
            );
        }
        assert_eq!(
            KeyboardEncoding::KITTY_SUPPORTED_FLAGS,
            KeyboardEncoding::KITTY_DISAMBIGUATE
                | KeyboardEncoding::KITTY_EVENT_TYPES
                | KeyboardEncoding::KITTY_ALL_AS_ESCAPES
        );
    }

    /// KR-REQ-08.59, KR-REQ-08.60: the Kitty code is the unshifted key, and it is not guessed at.
    #[test]
    fn a_shifted_key_needs_the_key_it_came_from_rather_than_a_guess() {
        let all_escapes = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };
        // A client with a layout says which key produced the character.
        assert_eq!(
            spelled(on('a', 'A', Modifiers::shift()), all_escapes),
            b"\x1b[97;2u",
            "the protocol identifies the key by its unshifted code point"
        );
        // A client that does not know is refused rather than reporting a key the keyboard may not
        // have.
        assert_eq!(
            key(
                KeyEvent::with(Key::Char('A'), Modifiers::shift()),
                all_escapes
            ),
            Err(Unsupported::NotExpressible {
                what: "the unshifted key a shifted character was produced from"
            })
        );
        // Without shift there is nothing to undo: the character is the key as pressed.
        assert_eq!(
            spelled(KeyEvent::press(Key::Char('a')), all_escapes),
            b"\x1b[97u"
        );
    }

    /// A keypad key that makes a character keeps it out of `Debug`, as a character does, and a key
    /// event says which locks were on.
    #[test]
    fn the_keypads_characters_stay_out_of_debug() {
        for text in [
            Keypad::Digit(4),
            Keypad::Decimal(','),
            Keypad::Separator('.'),
            Keypad::Add,
        ] {
            assert_eq!(format!("{:?}", Key::Keypad(text)), "Keypad(Text(..))");
        }
        assert_eq!(format!("{:?}", Key::Keypad(Keypad::Enter)), "Keypad(Enter)");
        assert_eq!(
            format!("{:?}", locked(on('k', 'K', Modifiers::shift()), CAPS)),
            "KeyEvent { key: Char(..), base: Some(\"..\"), modifiers: Modifiers { shift: true, \
             alt: false, control: false, superkey: false }, locks: Locks { caps_lock: true, \
             num_lock: false }, kind: Press }"
        );
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
        assert_eq!(
            paste("a\x1b[201~b", false),
            b"a\x1b[201~b".to_vec(),
            "and with no framing to protect, nothing is taken out of somebody's text"
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
        // And text built so that removing one delimiter spells another. One pass would leave
        // `ESC[20` joined to `1~`, which is a terminator the payload did not contain and the
        // encoder would have made.
        // And the same construction repeated, which a payload could hold any number of times.
        let repeated = paste(&"\x1b[20\x1b[201~1~".repeat(64), true);
        assert_eq!(
            repeated,
            b"\x1b[200~\x1b[201~".to_vec(),
            "every delimiter a removal spelled is removed as it appears: {}",
            String::from_utf8_lossy(&repeated).escape_debug()
        );
        let manufactured = paste("\x1b[20\x1b[201~1~rest", true);
        assert_eq!(
            manufactured,
            b"\x1b[200~rest\x1b[201~".to_vec(),
            "the removal runs to a fixed point: {}",
            String::from_utf8_lossy(&manufactured).escape_debug()
        );
        assert_eq!(
            manufactured
                .windows(PASTE_END.len())
                .filter(|window| *window == PASTE_END)
                .count(),
            1
        );
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
        // The original report spells every release the same way: button code three, which says a
        // button came up and not which one. That is the encoding's limit, so the release is
        // reported in it rather than refused, and the modifier bits it does carry are kept.
        for released in [MouseButton::Left, MouseButton::Middle, MouseButton::Right] {
            let event = MouseEvent {
                action: MouseAction::Release(released),
                ..press
            };
            assert_eq!(
                mouse(event, MouseEncoding::X10).expect("encodes"),
                vec![0x1b, b'[', b'M', 35, 35, 36],
                "{released:?}"
            );
        }
        let with_control = MouseEvent {
            action: MouseAction::Release(MouseButton::Right),
            modifiers: Modifiers::control(),
            ..press
        };
        assert_eq!(
            mouse(with_control, MouseEncoding::X10).expect("encodes"),
            vec![0x1b, b'[', b'M', 51, 35, 36],
            "and the modifier bits survive the release"
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
        // A coordinate at the very end of its range has no one-based form. Wrapping it would
        // report the opposite corner of the grid, so both encodings refuse it.
        let unrepresentable = MouseEvent {
            column: u32::MAX,
            row: u32::MAX,
            ..press
        };
        for encoding in [MouseEncoding::Sgr, MouseEncoding::X10] {
            assert_eq!(
                mouse(unrepresentable, encoding),
                Err(Unsupported::NotExpressible {
                    what: "a coordinate at the end of its range, which has no one-based form"
                }),
                "{encoding:?}"
            );
        }
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

    /// KR-REQ-08.59: a second modifier is carried or refused, never dropped.
    #[test]
    fn a_chord_keeps_every_modifier_it_was_given_or_says_it_cannot() {
        let level_two = KeyboardEncoding::ModifyOtherKeys {
            level: 2,
            application_cursor_keys: false,
        };
        let control_alt = Modifiers {
            control: true,
            alt: true,
            ..Modifiers::NONE
        };
        // The escape prefix goes in front of the control byte, not in front of the letter: an
        // application reading `ESC c` sees Alt and a `c`, which is a different chord.
        assert_eq!(
            key(KeyEvent::with(Key::Char('c'), control_alt), LEGACY).expect("encodes"),
            b"\x1b\x03"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Char('c'), control_alt), level_two).expect("encodes"),
            b"\x1b[27;7;99~",
            "and level two reports the chord rather than spelling it"
        );
        // Alt on its own has an ordinary spelling, and level two reports it too, which is what
        // lets an application tell Alt-C from an Escape followed by a `c`.
        let alt = Modifiers {
            alt: true,
            ..Modifiers::NONE
        };
        assert_eq!(
            key(KeyEvent::with(Key::Char('c'), alt), LEGACY).expect("encodes"),
            b"\x1bc"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Char('c'), alt), level_two).expect("encodes"),
            b"\x1b[27;3;99~"
        );
        // Shift on its own is reported at level two where the byte does not say a key was
        // shifted, which is what lets an application tell Shift-C from a capital C somebody's
        // layout or Caps Lock produced.
        assert_eq!(
            key(KeyEvent::from_key('c', 'C', Modifiers::shift()), level_two).expect("encodes"),
            b"\x1b[27;2;67~"
        );
        // And over the rest of the range a control chord can reach, which is where a byte alone
        // cannot say which chord produced it.
        for (base, produced, report) in [
            ('2', '@', &b"\x1b[27;2;64~"[..]),
            ('6', '^', &b"\x1b[27;2;94~"[..]),
            ('[', '{', &b"\x1b[27;2;123~"[..]),
        ] {
            assert_eq!(
                key(
                    KeyEvent::from_key(base, produced, Modifiers::shift()),
                    level_two
                )
                .expect("encodes"),
                report,
                "{produced}"
            );
        }
        // Below that range a shifted key produces a byte no unshifted key produces, so it is sent
        // as that byte, which is what xterm sends.
        assert_eq!(
            key(KeyEvent::from_key('1', '!', Modifiers::shift()), level_two).expect("encodes"),
            b"!"
        );
        assert_eq!(
            key(KeyEvent::from_key('/', '?', Modifiers::shift()), level_two).expect("encodes"),
            b"?"
        );
        let level_one = KeyboardEncoding::ModifyOtherKeys {
            level: 1,
            application_cursor_keys: false,
        };
        assert_eq!(
            key(KeyEvent::from_key('c', 'C', Modifiers::shift()), level_one).expect("encodes"),
            b"C"
        );
        // And Shift-Space, which the ordinary encoding cannot tell from a space at all.
        assert_eq!(
            key(
                KeyEvent::with(Key::Char(' '), Modifiers::shift()),
                level_two
            )
            .expect("encodes"),
            b"\x1b[27;2;32~"
        );
        // Back-tab has one spelling and no room for a second modifier on it.
        assert_eq!(
            key(KeyEvent::with(Key::Tab, Modifiers::shift()), LEGACY).expect("encodes"),
            b"\x1b[Z"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Tab, Modifiers::shift()), level_two).expect("encodes"),
            b"\x1b[27;2;9~",
            "which is what level two is for"
        );
        let control_shift = Modifiers {
            control: true,
            shift: true,
            ..Modifiers::NONE
        };
        assert_eq!(
            key(KeyEvent::with(Key::Tab, control_shift), LEGACY),
            Err(Unsupported::NotExpressible {
                what: "Shift together with another modifier on Tab"
            }),
            "rather than a back-tab that says the person held only Shift"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Tab, control_shift), level_two).expect("encodes"),
            b"\x1b[27;6;9~"
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
