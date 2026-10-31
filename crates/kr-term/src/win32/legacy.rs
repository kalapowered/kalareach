//! Console key records, spelled as the legacy VT input a terminal would have sent.
//!
//! A session whose backend never asked for records is sent what a terminal doing the translation
//! would have sent. No scan code is claimed, because none is sent, and nothing here invents a key:
//! a record that has no spelling produces nothing rather than something that means another key.
//!
//! The spelling of a key is [`kr_keys::key`], the one encoder every client uses, so a Windows
//! console and a Unix terminal spell a key the same way. Only text, and the control codes the
//! console itself produced, are written straight out, because that is what the encoder produces
//! for them anyway and because a character outside the basic plane is two records that `char`
//! cannot hold one of.
//!
//! The translation is a function of the records, the session's keyboard and a bound on what it may
//! produce. It keeps no state between calls, so a call sees whole characters only: a high
//! surrogate with no low one after it is replaced. A producer that reads a console in pieces keeps
//! a pair together with [`PairHold`](super::PairHold).

use kr_keys::{Arrow, Key, KeyEvent, KeyboardEncoding, Modifiers};
use thiserror::Error;

use super::{KeyRecord, TooLong, control_keys};
use crate::modes;

/// The Tab key, whose shifted form is a sequence rather than the character the console reports.
const VK_TAB: u16 = 0x09;

/// The Alt key.
const VK_MENU: u16 = 0x12;

/// What a session's keyboard asks of the legacy spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keyboard {
    /// Whether the application set DEC mode 1, which spells the arrows with `SS3` instead of
    /// `CSI`. An application that set it and received `CSI A` reads a different key.
    pub application_cursor_keys: bool,
    /// The keyboard protocol the application negotiated.
    pub negotiated: modes::KeyboardEncoding,
}

/// Why records were not spelled for a session's terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Refused {
    /// The spelling would be longer than the bound.
    #[error("the keys spell more bytes than one write may carry")]
    TooLong,
    /// The application negotiated an encoding that the legacy spelling cannot express: Ctrl and I
    /// would reach it as a tab, and a key's release would not reach it at all.
    #[error("the application has negotiated a keyboard encoding that console keys cannot spell")]
    Enhanced(modes::KeyboardEncoding),
}

impl From<TooLong> for Refused {
    fn from(_: TooLong) -> Self {
        Self::TooLong
    }
}

/// The bytes written so far, which never pass the bound.
struct Output {
    bytes: Vec<u8>,
    limit: usize,
}

impl Output {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    /// Whether `more` bytes still fit, which is decided before anything is built for them.
    fn room_for(&self, more: usize) -> Result<(), TooLong> {
        if more > self.limit - self.bytes.len() {
            return Err(TooLong);
        }
        Ok(())
    }

    fn push_slice(&mut self, bytes: &[u8]) -> Result<(), TooLong> {
        self.room_for(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn push(&mut self, byte: u8) -> Result<(), TooLong> {
        self.push_slice(&[byte])
    }
}

/// The UTF-16 code units gathered since the last key that is not text.
///
/// Every unit comes out as at least one byte, so a unit that would leave the bound behind it is
/// refused when it is gathered and the buffer never holds more units than the bound has bytes.
struct Text {
    units: Vec<u16>,
}

impl Text {
    fn push(&mut self, unit: u16, output: &Output) -> Result<(), TooLong> {
        output.room_for(self.units.len() + 1)?;
        self.units.push(unit);
        Ok(())
    }

    /// Writes the gathered units, replacing anything left unpaired.
    ///
    /// A lone surrogate is a keyboard or an application doing something odd. Replacing it is
    /// visible; dropping it would look to the person like a key that did nothing at all.
    fn write(&mut self, output: &mut Output) -> Result<(), TooLong> {
        let mut buffer = [0_u8; 4];
        for unit in char::decode_utf16(self.units.drain(..)) {
            let character = unit.unwrap_or(char::REPLACEMENT_CHARACTER);
            output.push_slice(character.encode_utf8(&mut buffer).as_bytes())?;
        }
        Ok(())
    }
}

/// Returns whether a record is an Alt coming up with the character composed on the numeric keypad.
///
/// The console reports that character on the release of the Alt, so this is the one release that
/// is text rather than the end of a press. The release of any other key carries the character the
/// key made going down, which has been spelled already.
const fn composed_with_alt(record: &KeyRecord) -> bool {
    !record.key_down && record.virtual_key == VK_MENU && record.unicode != 0
}

/// Spells a run of key records as legacy VT input, in the order they were read.
///
/// A key coming up produces nothing: legacy input has no way to say so, and the encoder refuses to
/// invent one. The one exception is an Alt coming up with the character composed on the numeric
/// keypad, which is that character. A key the encoder cannot spell produces nothing rather than
/// something else. A repeat count is applied to whatever the key produced, character or sequence. A
/// character outside the basic plane is two records, the high surrogate then the low one, and the
/// pair is repeated as one character.
///
/// The output never passes `limit` bytes, and the bound is checked before each append, the buffers
/// of text waiting to be written included, so a record with a repeat count of 65,535 is refused at
/// the bound and never built.
///
/// # Errors
///
/// Returns [`Refused::Enhanced`] when the application negotiated `modifyOtherKeys` or the Kitty
/// protocol, whatever the records are: the legacy spelling would be a different key from the one
/// that was pressed. Returns [`Refused::TooLong`] when the spelling would pass `limit`.
pub fn legacy_within(
    records: &[KeyRecord],
    keyboard: &Keyboard,
    limit: usize,
) -> Result<Vec<u8>, Refused> {
    let application_cursor_keys = match keyboard.negotiated {
        modes::KeyboardEncoding::Legacy => keyboard.application_cursor_keys,
        enhanced => return Err(Refused::Enhanced(enhanced)),
    };
    let mut output = Output::new(limit);
    let mut text = Text { units: Vec::new() };
    for key in records {
        let composed = composed_with_alt(key);
        if !key.key_down && !composed {
            continue;
        }
        // Half of a character outside the basic plane. Both halves are gathered and the pair is
        // repeated as one character: high, high, low, low would be two replacements around one
        // character.
        if key.is_high_surrogate() {
            text.push(key.unicode, &output)?;
            continue;
        }
        if key.is_low_surrogate() {
            let high = text
                .units
                .last()
                .copied()
                .filter(|unit| (0xD800..=0xDBFF).contains(unit));
            if let Some(high) = high {
                text.units.pop();
                text.write(&mut output)?;
                let pair = char::decode_utf16([high, key.unicode])
                    .next()
                    .and_then(Result::ok)
                    .unwrap_or(char::REPLACEMENT_CHARACTER);
                let mut buffer = [0_u8; 4];
                let spelled = pair.encode_utf8(&mut buffer).as_bytes();
                for _ in 0..key.repeat.max(1) {
                    output.push_slice(spelled)?;
                }
            } else {
                text.push(key.unicode, &output)?;
            }
            continue;
        }
        // A character composed with Alt on the numeric keypad. The console reports it on the Alt
        // coming up, and what the Alt carries is the Alt itself rather than a modifier of the
        // character, so it is text whatever state the record is in.
        if composed {
            for _ in 0..key.repeat.max(1) {
                text.push(key.unicode, &output)?;
            }
            continue;
        }
        // A control code the console itself produced for a key held with Control. The console has
        // already done the translation an application expects - Ctrl and Return is a line feed,
        // Ctrl and A is 0x01 - and replacing it with the key's own sequence would send a
        // different key.
        if let Some((byte, alt)) = console_control(key) {
            text.write(&mut output)?;
            for _ in 0..key.repeat.max(1) {
                // Alt in front of the control code rather than instead of it: that is how the
                // legacy encoding spells a chord with Alt in it, and dropping the prefix would
                // turn Alt, Ctrl and I into an ordinary tab.
                if alt {
                    output.push(0x1B)?;
                }
                output.push(byte)?;
            }
            continue;
        }
        // Plain text: no modifier the encoder would spell differently, and a character that is not
        // a control code. Anything else is a key rather than text.
        if let Some(character) = plain_text(key) {
            for _ in 0..key.repeat.max(1) {
                text.push(character, &output)?;
            }
            continue;
        }
        // A key interrupts the text around it, so what is pending is written before its sequence
        // rather than after. A key with no sequence interrupts nothing: the Alt and the keypad
        // digits of a character composed in two parts come between its halves, and a half written
        // at the first of them would be replaced.
        if let Some(bytes) = encoded_key(key, application_cursor_keys) {
            text.write(&mut output)?;
            for _ in 0..key.repeat.max(1) {
                output.push_slice(&bytes)?;
            }
        }
    }
    text.write(&mut output)?;
    Ok(output.bytes)
}

/// Returns whether a record produced text rather than a control code or nothing.
///
/// This is what tells AltGr from an ordinary chord. AltGr is a *layout* producing a character, so
/// its Ctrl and Alt bits are not modifiers an application should be told about. A record with the
/// same bits and a control code did not come from a layout: right Ctrl with right Alt and Escape
/// is a chord, and reading it as AltGr would take both modifiers off a key that was held with
/// them.
const fn produces_text(record: &KeyRecord) -> bool {
    record.unicode >= 0x20 && record.unicode != 0x7F
}

/// Returns the control code the console produced for a key held with Control, and whether Alt was
/// held with it.
///
/// A console translates Control and a key into the control code an application expects, and that
/// translation is the answer: Ctrl and Return is a line feed rather than the carriage return the
/// Return key alone produces, and Ctrl and A is 0x01.
///
/// Three things are deliberately *not* read this way, because the console's character does not
/// settle them:
///
/// * a record with no Control held. Shift and Tab carries a control character too, and it is the
///   key it is rather than a tab;
/// * Ctrl, Shift and Tab. The console reports a tab for it, and this encoding has no spelling for
///   the chord; sending a plain tab would be a different key. Shift alone does not disqualify a
///   record - Ctrl, Shift and Return is still a line feed, and Ctrl, Shift and Space is still the
///   code a byte cannot otherwise carry;
/// * AltGr, which is how a layout produces a character rather than a chord.
///
/// Alt held with Control **is** read this way, and reported, because the escape prefix an
/// application expects goes in front of the same control code rather than instead of it.
///
/// Ctrl and Space is the one key the console reports with no character at all, and the code it
/// stands for is the one a byte cannot otherwise carry.
fn console_control(record: &KeyRecord) -> Option<(u8, bool)> {
    let control = record.control_keys
        & (control_keys::LEFT_CTRL_PRESSED | control_keys::RIGHT_CTRL_PRESSED)
        != 0;
    let shift = record.control_keys & control_keys::SHIFT_PRESSED != 0;
    // Tab is the one key whose shifted form this encoding spells differently, and the console's
    // own character does not say so. Everything else with Shift held keeps the console's answer.
    //
    // AltGr disqualifies a record only when it produced text. A control code held with right Ctrl
    // and right Alt is a chord that happens to match AltGr's bits, and it is still the control code
    // the console produced.
    if !control
        || (record.is_alt_graph() && produces_text(record))
        || (shift && record.virtual_key == VK_TAB)
    {
        return None;
    }
    let alt = record.control_keys
        & (control_keys::LEFT_ALT_PRESSED | control_keys::RIGHT_ALT_PRESSED)
        != 0;
    if record.unicode == 0 {
        // The space bar, whose control code is zero and which the console therefore cannot report
        // as a character.
        return (record.virtual_key == 0x20).then_some((0, alt));
    }
    (record.unicode <= 0x1F || record.unicode == 0x7F)
        .then(|| (u8::try_from(record.unicode).unwrap_or(0), alt))
}

/// Returns the character a record produced when nothing about it needs the encoder.
///
/// A printable character with no Control and no Alt held. Shift is not one of them: the layout has
/// already applied it, and `A` is the character rather than a modified `a`. AltGr is not one
/// either - it is how a layout produces a character, and reading its Ctrl and Alt bits as
/// modifiers would turn the character into a different key.
fn plain_text(record: &KeyRecord) -> Option<u16> {
    if record.unicode == 0 || record.unicode < 0x20 || record.unicode == 0x7F {
        return None;
    }
    if record.is_alt_graph() {
        return Some(record.unicode);
    }
    let held = control_keys::LEFT_CTRL_PRESSED
        | control_keys::RIGHT_CTRL_PRESSED
        | control_keys::LEFT_ALT_PRESSED
        | control_keys::RIGHT_ALT_PRESSED;
    (record.control_keys & held == 0).then_some(record.unicode)
}

/// Returns the legacy sequence for one key, or `None` for a record that is not a key an
/// application receives and for one this encoding cannot spell.
///
/// A key the encoder refuses - a release, a key it has no name for, a function key beyond the
/// twelve the legacy encoding spells - produces nothing rather than something that would mean a
/// different key.
fn encoded_key(record: &KeyRecord, application_cursor_keys: bool) -> Option<Vec<u8>> {
    let named = match record.virtual_key {
        0x08 => Key::Backspace,
        0x09 => Key::Tab,
        0x0D => Key::Enter,
        0x1B => Key::Escape,
        0x21 => Key::PageUp,
        0x22 => Key::PageDown,
        0x23 => Key::End,
        0x24 => Key::Home,
        0x25 => Key::Arrow(Arrow::Left),
        0x26 => Key::Arrow(Arrow::Up),
        0x27 => Key::Arrow(Arrow::Right),
        0x28 => Key::Arrow(Arrow::Down),
        0x2D => Key::Insert,
        0x2E => Key::Delete,
        // F1 to F12 are consecutive from 0x70. F13 upwards have no spelling in this encoding, and
        // an invented one would be a key nobody pressed.
        code @ 0x70..=0x7B => Key::Function(u8::try_from(code - 0x6F).ok()?),
        // Not a named key. A character with a modifier the layout did not apply is still a key an
        // application receives, and the encoder is what spells it.
        _ => Key::Char(char::from_u32(u32::from(record.unicode)).filter(|_| record.unicode != 0)?),
    };
    // AltGr is how a layout produces a character, so its Ctrl and Alt bits are not modifiers.
    // That is true only of a record that produced *text*: one carrying a control code, or none at
    // all, had no layout involved, and its modifiers are what they say.
    let layout_produced = record.is_alt_graph() && produces_text(record);
    let modifiers = Modifiers {
        shift: record.control_keys & control_keys::SHIFT_PRESSED != 0,
        control: !layout_produced
            && record.control_keys
                & (control_keys::LEFT_CTRL_PRESSED | control_keys::RIGHT_CTRL_PRESSED)
                != 0,
        alt: !layout_produced
            && record.control_keys
                & (control_keys::LEFT_ALT_PRESSED | control_keys::RIGHT_ALT_PRESSED)
                != 0,
        superkey: false,
    };
    kr_keys::key(
        KeyEvent::with(named, modifiers),
        KeyboardEncoding::Legacy {
            application_cursor_keys,
        },
    )
    .ok()
}
