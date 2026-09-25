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
    /// A function key, numbered from one.
    Function(u8),
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// The logical key, as the keyboard layout produced it.
    pub key: Key,
    /// The character the same physical key produces with nothing held, when the client knows it.
    ///
    /// The Kitty keyboard protocol identifies a key by the code point of its **unshifted** form, so
    /// a client reporting `Char('A')` for shift and the `a` key has to say which key that was.
    /// `None` is a client that does not know, and the encoder then refuses that protocol's own form
    /// for a shifted key rather than guessing at a layout: telling an application that the `A` key
    /// was pressed, on a keyboard that has no such key, is the invention section 8 forbids.
    pub base: Option<char>,
    /// The modifiers held with it.
    pub modifiers: Modifiers,
    /// What happened to it.
    pub kind: KeyEventKind,
}

impl std::fmt::Debug for KeyEvent {
    /// The key, the modifiers and the kind, and whether a base character was reported, never it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyEvent")
            .field("key", &self.key)
            .field("base", &self.base.map(|_| ".."))
            .field("modifiers", &self.modifiers)
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
        Key::Tab => {
            if modify_other_keys >= 2 && !event.modifiers.is_empty() {
                // Level two reports Shift-Tab too, which is how an application tells it from the
                // back-tab an older terminal sends for several different chords.
                return Ok(modify_other_keys_report(9, event.modifiers));
            }
            if event.modifiers.shift {
                if event.modifiers.control || event.modifiers.alt {
                    // The ordinary encoding has one back-tab and no room for a second modifier on
                    // it. Sending it anyway would tell the application Shift-Tab when the person
                    // held Control as well.
                    return Err(Unsupported::NotExpressible {
                        what: "Shift together with another modifier on Tab",
                    });
                }
                return Ok(b"\x1b[Z".to_vec());
            }
            Ok(control_or_plain(
                b'\t',
                event.modifiers,
                modify_other_keys,
                9,
            ))
        }
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
        && let Some(byte) = control_byte(character)
    {
        if modify_other_keys < 2 {
            // Alt is the escape prefix, and it goes in front of the control byte rather than in
            // front of the letter: Control-Alt-C is an escape and then the byte Control-C is, not
            // an escape and then a `c`.
            let mut bytes = Vec::new();
            if modifiers.alt {
                bytes.push(0x1b);
            }
            bytes.push(byte);
            return bytes;
        }
        // Level two reports even the keys that already had a spelling, which is the whole point of
        // it: an application can then tell Control-I from Tab.
        return modify_other_keys_report(u32::from(character), modifiers);
    }
    // Level two reports a shift-only chord over the range xterm reports it over: the characters
    // from `@` to `~`, which are the ones a control chord can also reach, plus Space, whose shifted
    // form is a space and says nothing. Below that range a shifted key produces a byte no unshifted
    // key produces, so it is sent as that byte, and an encoder that reported it would tell an
    // application about a chord no terminal reports. Level one reports only the chords the ordinary
    // encoding has no spelling for at all.
    let ambiguous_when_shifted = character == ' ' || ('\u{40}'..='\u{7f}').contains(&character);
    let reported = if modify_other_keys >= 2 {
        modifiers.control || modifiers.alt || (modifiers.shift && ambiguous_when_shifted)
    } else {
        modify_other_keys > 0 && (modifiers.control || (modifiers.alt && modifiers.shift))
    };
    if reported {
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
    if flags & !KeyboardEncoding::KITTY_SUPPORTED_FLAGS != 0 {
        // An application that asked for a flag this encoder does not produce would read a report
        // with the flag's own field missing, which is the falsely advertised encoding section 8
        // forbids. The host refuses such a controller the lease; a caller that reaches here
        // directly is refused too.
        return Err(Unsupported::NotExpressible {
            what: "a Kitty keyboard flag this encoder does not produce",
        });
    }
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
    let reports_events = flags & KeyboardEncoding::KITTY_EVENT_TYPES != 0;
    let disambiguates = flags & KeyboardEncoding::KITTY_DISAMBIGUATE != 0;
    let all_as_escapes = flags & KeyboardEncoding::KITTY_ALL_AS_ESCAPES != 0;

    if event.kind == KeyEventKind::Release && !reports_events {
        // The protocol is in force but event types are not, so a key coming up has no place in the
        // stream at all. Sending it as a press is the invention section 8 forbids.
        return Err(Unsupported::NotExpressible {
            what: "a key release the application did not ask to be told about",
        });
    }
    // A repeat is a press as far as a stream without event types can say, and the press did happen.
    // Saying so invents nothing; refusing would drop a key the person is holding down.
    let kind = if reports_events {
        event.kind
    } else {
        KeyEventKind::Press
    };

    // Two separate questions, and conflating them is what made the earlier rounds of this wrong.
    //
    // The first is how a *press* is spelled. The protocol is an extension of the ordinary encoding
    // rather than a replacement for it, so a press keeps the spelling it had until the application
    // asks to disambiguate it or asks for every key as an escape code. A shell under an application
    // that asked only for event types still expects Control-C to be one byte.
    //
    // The second is whether this key can carry an event type at all. Only the keys whose press went
    // out as a bare byte cannot: a release of a printable character, or of Return, has nowhere to
    // go, because the byte is the whole report. Everything whose press became a sequence has room
    // for one, so a functional key - and a control chord, whose release the ordinary encoding
    // cannot express either way - reports its repeats and releases the moment the application asks
    // for them, whether or not it asked to disambiguate anything.
    // Either flag puts the protocol's own reports in force for the keys the ordinary encoding
    // spells ambiguously. Disambiguation asks for them by name; event reporting asks for something
    // the ordinary spelling cannot carry, which comes to the same thing.
    let enhanced = disambiguates || reports_events;
    let press_keeps_its_spelling = !all_as_escapes
        && !event.modifiers.superkey
        && match event.key {
            // Disambiguation exists for exactly this: Escape on its own, so an application can
            // tell it from the start of a sequence. A modified Escape has no ordinary spelling that
            // says so at all, so it is reported the moment either flag is in force.
            Key::Escape => !disambiguates && event.modifiers.is_empty(),
            // A printable key is its own text, and shift is already in that text. What
            // disambiguation changes is the chords the ordinary encoding spells ambiguously:
            // Control-I and Tab, Alt-a and Escape then a.
            Key::Char(_) => !(disambiguates && (event.modifiers.control || event.modifiers.alt)),
            // These three keep their bytes unmodified and are reported once anything is held,
            // which is what lets an application tell Shift-Enter from Enter.
            Key::Enter | Key::Tab | Key::Backspace => !enhanced || event.modifiers.is_empty(),
            // A functional key is a sequence in every mode, and the protocol's own table is what
            // numbers them: it gives F3 a number where the ordinary encoding gave it a letter that
            // is also a valid cursor-position report.
            _ => false,
        };
    // A key can carry an event type only where its press became a *sequence*: the protocol reports
    // an event type for the keys it sends as escape codes, and for no others. A press that went out
    // as the character itself, or as one of the bare control bytes the ordinary encoding uses for
    // Return, Tab, Backspace and Escape, has nowhere to put one - the byte is the whole report -
    // so its release is nothing at all and its repeat is that byte again.
    let sent_as_a_byte = press_keeps_its_spelling
        && match event.key {
            Key::Char(_) => !(event.modifiers.control || event.modifiers.alt),
            Key::Enter | Key::Tab | Key::Backspace | Key::Escape => event.modifiers.is_empty(),
            _ => false,
        };
    let press = KeyEvent {
        kind: KeyEventKind::Press,
        ..event
    };
    let spell_press = |event: KeyEvent| {
        if press_keeps_its_spelling {
            legacy(
                event,
                KeyboardEncoding::Legacy {
                    application_cursor_keys: false,
                },
                0,
            )
        } else {
            kitty_sequence(event, None)
        }
    };
    match kind {
        KeyEventKind::Press => spell_press(press),
        // A repeat with no event types to report is the press again: that is what this stream can
        // say, and refusing would drop a key the person is holding down. A text key's repeat is
        // the text again either way, because the text is the whole report.
        KeyEventKind::Repeat if !reports_events || sent_as_a_byte => spell_press(press),
        KeyEventKind::Repeat => kitty_sequence(event, Some(2)),
        // A key the stream sends as text has no release event at all: the protocol reports those
        // only for the keys it sends as escape codes. An empty answer is the caller's instruction
        // to send nothing, which is what a terminal in this mode does.
        KeyEventKind::Release if sent_as_a_byte => Ok(Vec::new()),
        KeyEventKind::Release => kitty_sequence(event, Some(3)),
    }
}

/// Spells one key event as the Kitty protocol's own sequence.
///
/// `event_type` is the protocol's second modifier field: `Some(2)` for a repeat, `Some(3)` for a
/// release, `None` for a press, whose type is the default and is left out.
fn kitty_sequence(event: KeyEvent, event_type: Option<u8>) -> Result<Vec<u8>, Unsupported> {
    let code = kitty_code(event)?;
    let modifiers = event.modifiers.parameter();
    let suffix = kitty_suffix(event.key);
    if let Some(event_type) = event_type {
        // The event type travels in the modifier field's second part, so the modifier parameter is
        // always present when one is reported, even when nothing was held.
        return Ok(format!("\x1b[{code};{modifiers}:{event_type}{suffix}").into_bytes());
    }
    if event.modifiers.is_empty() {
        // A key whose suffix is a letter needs no number: `CSI A` is the canonical spelling and
        // the parameter's default is the only value it could have. One that ends in a tilde does
        // need it, because the number is which key it is.
        return Ok(if suffix == '~' || suffix == 'u' {
            format!("\x1b[{code}{suffix}").into_bytes()
        } else {
            format!("\x1b[{suffix}").into_bytes()
        });
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

/// The code point the Kitty protocol identifies this key by.
///
/// For a printable key that is the **unshifted** form. A client that reported a shifted character
/// and did not say which key produced it has not established that, and this refuses rather than
/// guessing: there is no layout-independent way back from `A` to the key it came from.
fn kitty_code(event: KeyEvent) -> Result<u32, Unsupported> {
    Ok(match event.key {
        Key::Char(character) => match event.base {
            Some(base) => u32::from(base),
            None if event.modifiers.shift => {
                return Err(Unsupported::NotExpressible {
                    what: "the unshifted key a shifted character was produced from",
                });
            }
            None => u32::from(character),
        },
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

    /// KR-REQ-08.59, KR-REQ-08.60: the Kitty protocol changes only what its flags ask it to.
    #[test]
    fn the_kitty_protocol_leaves_alone_what_its_flags_did_not_ask_about() {
        let events_only = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        let disambiguate = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
        };
        let all_escapes = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };

        // An application that asked only for event types still reads the ordinary encoding for
        // everything else. A shell under it expects Control-C to be one byte.
        assert_eq!(
            key(
                KeyEvent::with(Key::Char('c'), Modifiers::control()),
                events_only
            )
            .expect("encodes"),
            b"\x03"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Escape), events_only).expect("encodes"),
            b"\x1b"
        );
        // Under disambiguation, Escape is the one key the protocol has to spell differently.
        assert_eq!(
            key(KeyEvent::press(Key::Escape), disambiguate).expect("encodes"),
            b"\x1b[27u"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Char('c'), Modifiers::control()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[99;5u",
            "and a control chord, which is what it exists to disambiguate"
        );
        // The keys the ordinary encoding already spells keep that spelling until the application
        // asks for every key as an escape code.
        for encoding in [events_only, disambiguate] {
            assert_eq!(
                key(KeyEvent::press(Key::Enter), encoding).expect("encodes"),
                b"\r",
                "{encoding:?}"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Tab), encoding).expect("encodes"),
                b"\t"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Backspace), encoding).expect("encodes"),
                b"\x7f"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Char('a')), encoding).expect("encodes"),
                b"a"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Arrow(Arrow::Up)), encoding).expect("encodes"),
                b"\x1b[A",
                "and a functional key is the same sequence in both encodings"
            );
        }
        assert_eq!(
            key(KeyEvent::press(Key::Char('a')), all_escapes).expect("encodes"),
            b"\x1b[97u"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Enter), all_escapes).expect("encodes"),
            b"\x1b[13u"
        );
        // A modified functional key carries the modifier parameter, in either encoding.
        assert_eq!(
            key(
                KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[1;5A"
        );
    }

    /// KR-REQ-08.59: a functional key is a sequence in every mode, from the protocol's own table.
    #[test]
    fn a_functional_key_is_spelled_from_the_protocols_table_in_every_mode() {
        let events_only = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        let disambiguate = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
        };
        // The table applies whichever flags are in force, because a functional key is a sequence
        // either way and it is this table that numbers them: a letter suffix needs no number, a
        // tilde suffix is the number, and F3 has one where the ordinary encoding gave it a letter
        // that is also a valid cursor-position report.
        for encoding in [events_only, disambiguate] {
            assert_eq!(
                key(KeyEvent::press(Key::Function(1)), encoding).expect("encodes"),
                b"\x1b[P",
                "{encoding:?}"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Function(3)), encoding).expect("encodes"),
                b"\x1b[13~"
            );
            assert_eq!(
                key(KeyEvent::press(Key::Arrow(Arrow::Up)), encoding).expect("encodes"),
                b"\x1b[A"
            );
            assert_eq!(
                key(
                    KeyEvent::with(Key::Function(3), Modifiers::shift()),
                    encoding
                )
                .expect("encodes"),
                b"\x1b[13;2~"
            );
        }
        // And it reports its repeats and releases the moment the application asks for them,
        // whether or not it asked to disambiguate anything.
        let up = KeyEvent::press(Key::Arrow(Arrow::Up));
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Repeat,
                    ..up
                },
                events_only
            )
            .expect("encodes"),
            b"\x1b[1;1:2A"
        );
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Release,
                    ..up
                },
                events_only
            )
            .expect("encodes"),
            b"\x1b[1;1:3A"
        );
        // A modified Escape has no ordinary spelling that says a modifier was held, so it is
        // reported once either flag is in force; a plain one keeps its byte until disambiguation.
        assert_eq!(
            key(KeyEvent::with(Key::Escape, Modifiers::shift()), events_only).expect("encodes"),
            b"\x1b[27;2u"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Escape), events_only).expect("encodes"),
            b"\x1b"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Escape), disambiguate).expect("encodes"),
            b"\x1b[27u"
        );
        // Enter, Tab and Backspace keep their bytes unmodified and are reported once anything is
        // held, whichever flag put the reports in force.
        assert_eq!(
            key(KeyEvent::press(Key::Enter), events_only).expect("encodes"),
            b"\r"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Enter, Modifiers::shift()), events_only).expect("encodes"),
            b"\x1b[13;2u"
        );
        let control_shift = Modifiers {
            control: true,
            shift: true,
            ..Modifiers::NONE
        };
        assert_eq!(
            key(KeyEvent::with(Key::Tab, control_shift), events_only).expect("encodes"),
            b"\x1b[9;6u",
            "and a chord the ordinary encoding cannot carry at all is the protocol's own report \
             rather than a refusal"
        );
        // A plain Return's press is a bare byte in this mode, so its release is nothing: the byte
        // is the whole report and the protocol reports event types only for what it sends as an
        // escape code. Once the application asks for every key as one, it is reported.
        let enter = KeyEvent::press(Key::Enter);
        assert!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Release,
                    ..enter
                },
                events_only
            )
            .expect("encodes")
            .is_empty()
        );
        let all_escapes_and_events = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_EVENT_TYPES | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Release,
                    ..enter
                },
                all_escapes_and_events
            )
            .expect("encodes"),
            b"\x1b[13;1:3u"
        );
        // A key whose press became a report has somewhere to put an event type, so it reports one.
        let escape = KeyEvent::press(Key::Escape);
        let both = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Repeat,
                    ..escape
                },
                both
            )
            .expect("encodes"),
            b"\x1b[27;1:2u"
        );
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Release,
                    ..escape
                },
                both
            )
            .expect("encodes"),
            b"\x1b[27;1:3u"
        );
        // A chord the ordinary encoding does spell keeps that spelling for its press and reports
        // its release, because a release has nowhere else to go.
        let control_c = KeyEvent::with(Key::Char('c'), Modifiers::control());
        assert_eq!(key(control_c, events_only).expect("encodes"), b"\x03");
        assert_eq!(
            key(
                KeyEvent {
                    kind: KeyEventKind::Release,
                    ..control_c
                },
                events_only
            )
            .expect("encodes"),
            b"\x1b[99;5:3u"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(1)), disambiguate).expect("encodes"),
            b"\x1b[P"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Function(3)), disambiguate).expect("encodes"),
            b"\x1b[13~"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Arrow(Arrow::Up)), disambiguate).expect("encodes"),
            b"\x1b[A"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Home), disambiguate).expect("encodes"),
            b"\x1b[H"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Delete), disambiguate).expect("encodes"),
            b"\x1b[3~"
        );
    }

    /// KR-REQ-08.59: a key the stream spells the ordinary way has no release event.
    #[test]
    fn a_release_of_a_key_sent_as_text_is_nothing_rather_than_a_bare_report() {
        let with_events = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        let all_escapes = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE
                | KeyboardEncoding::KITTY_EVENT_TYPES
                | KeyboardEncoding::KITTY_ALL_AS_ESCAPES,
        };
        // The protocol reports an event type only for the keys it sends as escape codes, so a
        // release of one it sends as text is nothing at all rather than a report with no key in it.
        for key_pressed in [Key::Char('a'), Key::Enter, Key::Tab, Key::Backspace] {
            let release = KeyEvent {
                key: key_pressed,
                base: None,
                modifiers: Modifiers::NONE,
                kind: KeyEventKind::Release,
            };
            assert!(
                key(release, with_events).expect("encodes").is_empty(),
                "{key_pressed:?}"
            );
            // And a repeat of one is the press again, which is what this stream can say.
            let repeat = KeyEvent {
                kind: KeyEventKind::Repeat,
                ..release
            };
            assert_eq!(
                key(repeat, with_events).expect("encodes"),
                key(
                    KeyEvent {
                        kind: KeyEventKind::Press,
                        ..release
                    },
                    with_events
                )
                .expect("encodes"),
                "{key_pressed:?}"
            );
        }
        // Once the application asks for every key as an escape code, they are reported.
        let release = KeyEvent {
            key: Key::Enter,
            base: None,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Release,
        };
        assert_eq!(key(release, all_escapes).expect("encodes"), b"\x1b[13;1:3u");
    }

    /// KR-REQ-08.59: a modified key the ordinary encoding spells ambiguously is disambiguated.
    #[test]
    fn a_modified_special_or_functional_key_takes_the_protocols_own_form() {
        let disambiguate = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
        };
        // Shift-Enter has no ordinary spelling of its own: a terminal sends the same byte for it as
        // for Enter, which is what disambiguation exists to fix.
        assert_eq!(
            key(KeyEvent::with(Key::Enter, Modifiers::shift()), disambiguate).expect("encodes"),
            b"\x1b[13;2u"
        );
        assert_eq!(
            key(KeyEvent::with(Key::Tab, Modifiers::control()), disambiguate).expect("encodes"),
            b"\x1b[9;5u"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Backspace, Modifiers::control()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[127;5u"
        );
        // F3 is numbered differently under this protocol, and its ordinary form with a modifier is
        // also a valid cursor-position report, which an application would read as one.
        assert_eq!(
            key(
                KeyEvent::with(Key::Function(3), Modifiers::shift()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[13;2~"
        );
        // The functional keys whose numbering the two encodings share come out the same either way.
        assert_eq!(
            key(
                KeyEvent::with(Key::Arrow(Arrow::Up), Modifiers::control()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[1;5A"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Delete, Modifiers::shift()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[3;2~"
        );
        assert_eq!(
            key(
                KeyEvent::with(Key::Function(1), Modifiers::shift()),
                disambiguate
            )
            .expect("encodes"),
            b"\x1b[1;2P"
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
            key(KeyEvent::press(Key::Function(1)), nothing).expect("encodes"),
            b"\x1bOP"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Char('a')), nothing).expect("encodes"),
            b"a"
        );
        assert_eq!(
            key(KeyEvent::press(Key::Escape), nothing).expect("encodes"),
            b"\x1b"
        );
        let release = KeyEvent {
            key: Key::Char('a'),
            base: None,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Release,
        };
        assert_eq!(
            key(release, nothing),
            Err(Unsupported::NotExpressible {
                what: "a key release"
            }),
            "including the refusal the ordinary encoding gives a release"
        );
    }

    /// KR-REQ-08.60: a flag this encoder does not produce is refused, not half-served.
    #[test]
    fn a_kitty_flag_this_encoder_does_not_produce_is_refused() {
        for flags in [
            KeyboardEncoding::KITTY_ALTERNATE_KEYS,
            KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_ALTERNATE_KEYS,
            0b0001_0000,
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

    /// KR-REQ-08.59: event types, and what a stream without them can say.
    #[test]
    fn an_event_type_is_reported_only_when_the_application_asked_for_them() {
        let disambiguate = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE,
        };
        let with_events = KeyboardEncoding::Kitty {
            flags: KeyboardEncoding::KITTY_DISAMBIGUATE | KeyboardEncoding::KITTY_EVENT_TYPES,
        };
        let release = KeyEvent {
            key: Key::Char('a'),
            base: None,
            modifiers: Modifiers::control(),
            kind: KeyEventKind::Release,
        };
        assert_eq!(
            key(release, disambiguate),
            Err(Unsupported::NotExpressible {
                what: "a key release the application did not ask to be told about"
            })
        );
        assert_eq!(key(release, with_events).expect("encodes"), b"\x1b[97;5:3u");
        let repeat = KeyEvent {
            kind: KeyEventKind::Repeat,
            ..release
        };
        assert_eq!(key(repeat, with_events).expect("encodes"), b"\x1b[97;5:2u");
        assert_eq!(
            key(repeat, disambiguate).expect("encodes"),
            b"\x1b[97;5u",
            "a repeat with no event types is the press it is, rather than a refusal that drops a \
             key the person is holding down"
        );
        // An unmodified release still carries the modifier parameter, because the event type sits
        // beside it.
        let plain_release = KeyEvent {
            key: Key::Arrow(Arrow::Up),
            base: None,
            modifiers: Modifiers::NONE,
            kind: KeyEventKind::Release,
        };
        assert_eq!(
            key(plain_release, with_events).expect("encodes"),
            b"\x1b[1;1:3A"
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
            key(
                KeyEvent::from_key('a', 'A', Modifiers::shift()),
                all_escapes
            )
            .expect("encodes"),
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
            key(KeyEvent::press(Key::Char('a')), all_escapes).expect("encodes"),
            b"\x1b[97u"
        );
    }

    /// KR-REQ-08.59: a release has no legacy spelling, and none is invented for it.
    #[test]
    fn a_key_release_is_refused_rather_than_sent_as_a_press() {
        let release = KeyEvent {
            key: Key::Char('a'),
            base: None,
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
