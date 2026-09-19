//! Windows console key records, and the encoding a ConPTY asks for when it wants them.
//!
//! Section 8's Windows contract, in one place. Three things live here and nothing else does.
//!
//! **The record.** [`KeyRecord`] is one `KEY_EVENT_RECORD` as `ReadConsoleInputW` produced it:
//! the virtual key, the scan code the keyboard sent, one UTF-16 code unit, whether the key went
//! down or came up, the control-key state and the repeat count. Every field is carried as it was
//! read. Nothing here decodes a record into a character and encodes it again: a scan code that was
//! not on the wire is not one this host may invent, and a re-encoded record is exactly that.
//!
//! **The encoding.** `CSI Vk ; Sc ; Uc ; Kd ; Cs ; Rc _` - a final underscore, not an APC string.
//! Omitted fields default to `0,0,0,0,0,1`, so [`KeyRecord::DEFAULT`] is what a reader fills in
//! for a field that was not sent, and [`encode`] leaves out a trailing run of fields that are
//! already their defaults.
//!
//! **The boundary.** `CSI ?9001h` requests the mode and `CSI ?9001l` disables it. Section 8 gives
//! this host one obligation about them: *KR terminates each such mode request at the corresponding
//! boundary*, and never broadcasts it to a remote client. That is what the engine's policy does -
//! neither sequence is ever forwarded - and what this host then records is the input encoding of
//! the one backend it owns, from what that backend sent it.
//!
//! The other half of the rule is not this host's to implement. A session can contain another
//! console - `wsl.exe`, an `ssh` session, a nested ConPTY - and each asks for the mode itself.
//! Keeping an inner console's disable from reaching the outer one is *ConPTY's* behaviour, on the
//! boundary between those two consoles, and this host is above both of them: what arrives here is
//! what the console it owns chose to send. So the state is what the owned backend said, and
//! nothing here infers a nesting depth from a stream that does not carry one. What this host does
//! owe is that a nested transition cannot leave a **client's** console in the wrong mode after
//! detach, which is the attach client's saved console modes rather than this state.
//!
//! What the record path is **not** is a promise about fidelity. A client that sends no records
//! sends legacy VT input, which this host accepts without claiming it carries scan codes; and the
//! records an outer ConPTY produces carry whatever that console gave them, which on a remote or
//! virtual keyboard is not a hardware scan code at all. [`Fidelity`] is how that is reported.

/// The control-key state bits a console record carries, named as the console API names them.
///
/// They are re-exported here so that a reader on Windows and a fixture on a machine that is not
/// Windows agree about one set of numbers.
pub mod control_keys {
    /// The right Alt key is down. With [`LEFT_CTRL_PRESSED`] this is AltGr.
    pub const RIGHT_ALT_PRESSED: u32 = 0x0001;
    /// The left Alt key is down.
    pub const LEFT_ALT_PRESSED: u32 = 0x0002;
    /// The right Ctrl key is down.
    pub const RIGHT_CTRL_PRESSED: u32 = 0x0004;
    /// The left Ctrl key is down. With [`RIGHT_ALT_PRESSED`] this is AltGr.
    pub const LEFT_CTRL_PRESSED: u32 = 0x0008;
    /// A Shift key is down.
    pub const SHIFT_PRESSED: u32 = 0x0010;
    /// Num Lock is on.
    pub const NUMLOCK_ON: u32 = 0x0020;
    /// Scroll Lock is on.
    pub const SCROLLLOCK_ON: u32 = 0x0040;
    /// Caps Lock is on.
    pub const CAPSLOCK_ON: u32 = 0x0080;
    /// The key is an enhanced key.
    pub const ENHANCED_KEY: u32 = 0x0100;

    /// Whether this state is AltGr: the right Alt key with a Ctrl key, which is what a keyboard
    /// layout that has an AltGr key actually sends.
    #[must_use]
    pub const fn is_alt_graph(state: u32) -> bool {
        state & RIGHT_ALT_PRESSED != 0 && state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0
    }
}

/// The sequence a ConPTY sends to ask for win32 input mode.
pub const MODE_SET: &[u8] = b"\x1b[?9001h";

/// The sequence that disables it.
pub const MODE_RESET: &[u8] = b"\x1b[?9001l";

/// One console key record, exactly as the console reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    /// The virtual-key code.
    pub virtual_key: u16,
    /// The scan code the keyboard sent, as the console reported it. Never invented.
    pub scan_code: u16,
    /// One UTF-16 code unit. A character outside the basic plane arrives as two records, a high
    /// surrogate then a low one, and both are carried through unchanged.
    pub unicode: u16,
    /// Whether the key went down. `false` is a key-up event, which the record path carries and
    /// legacy VT input has no way to express at all.
    pub key_down: bool,
    /// The control-key state, as [`control_keys`] names its bits.
    pub control_keys: u32,
    /// How many times the key repeated in this one record.
    pub repeat: u16,
}

impl KeyRecord {
    /// What every field of an omitted record means: `0,0,0,0,0,1`.
    pub const DEFAULT: Self = Self {
        virtual_key: 0,
        scan_code: 0,
        unicode: 0,
        key_down: false,
        control_keys: 0,
        repeat: 1,
    };

    /// Returns whether this record's modifier state is AltGr.
    #[must_use]
    pub const fn is_alt_graph(&self) -> bool {
        control_keys::is_alt_graph(self.control_keys)
    }

    /// Returns whether this record carries the first half of a character outside the basic plane.
    #[must_use]
    pub const fn is_high_surrogate(&self) -> bool {
        self.unicode >= 0xD800 && self.unicode <= 0xDBFF
    }

    /// Returns whether this record carries the second half of one.
    #[must_use]
    pub const fn is_low_surrogate(&self) -> bool {
        self.unicode >= 0xDC00 && self.unicode <= 0xDFFF
    }
}

impl Default for KeyRecord {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Encodes one record as `CSI Vk;Sc;Uc;Kd;Cs;Rc_`.
///
/// All six fields are written every time, even the ones already holding their default. Omitting
/// them is permitted - a reader fills in `0,0,0,0,0,1` for anything it was not sent, which
/// [`decode`] does - but an application reading this is somebody else's parser, and the form that
/// asks least of it is the one that spells every field out.
#[must_use]
pub fn encode(record: &KeyRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    encode_into(record, &mut out);
    out
}

/// Encodes a run of records, in the order they were read, into one buffer.
///
/// The order is the record path's own promise: a key-down and the key-up that follows it arrive in
/// that order, and a repeat count is one record rather than several.
#[must_use]
pub fn encode_all(records: &[KeyRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(records.len() * 24);
    for record in records {
        encode_into(record, &mut out);
    }
    out
}

fn encode_into(record: &KeyRecord, out: &mut Vec<u8>) {
    let fields = [
        u64::from(record.virtual_key),
        u64::from(record.scan_code),
        u64::from(record.unicode),
        u64::from(record.key_down),
        u64::from(record.control_keys),
        u64::from(record.repeat),
    ];
    out.extend_from_slice(b"\x1b[");
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b';');
        }
        out.extend_from_slice(field.to_string().as_bytes());
    }
    out.push(b'_');
}

/// What went wrong reading an encoded record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The bytes do not begin `CSI` and end with the final underscore.
    NotARecord,
    /// A field is not a number, or names a value the field cannot hold.
    Field(usize),
    /// More than six fields were given.
    TooManyFields,
}

/// Reads one encoded record back.
///
/// This exists so that the encoding has one definition rather than two: a fixture that spells the
/// bytes out by hand checks what [`encode`] produced, and this checks that the fields it produced
/// mean what they were given. A ConPTY sends these to an application, not to this host, so nothing
/// in the running product parses them.
///
/// # Errors
///
/// Returns [`RecordError`] when the bytes are not one record.
pub fn decode(bytes: &[u8]) -> Result<KeyRecord, RecordError> {
    let body = bytes
        .strip_prefix(b"\x1b[")
        .and_then(|rest| rest.strip_suffix(b"_"))
        .ok_or(RecordError::NotARecord)?;
    let mut record = KeyRecord::DEFAULT;
    if body.is_empty() {
        return Ok(record);
    }
    let fields: Vec<&[u8]> = body.split(|byte| *byte == b';').collect();
    if fields.len() > 6 {
        return Err(RecordError::TooManyFields);
    }
    for (index, field) in fields.iter().enumerate() {
        // An empty field is an omitted one, which means its default.
        if field.is_empty() {
            continue;
        }
        let text = std::str::from_utf8(field).map_err(|_| RecordError::Field(index))?;
        let value: u64 = text.parse().map_err(|_| RecordError::Field(index))?;
        let narrow = |value: u64| u16::try_from(value).map_err(|_| RecordError::Field(index));
        match index {
            0 => record.virtual_key = narrow(value)?,
            1 => record.scan_code = narrow(value)?,
            2 => record.unicode = narrow(value)?,
            3 => record.key_down = value != 0,
            4 => {
                record.control_keys = u32::try_from(value).map_err(|_| RecordError::Field(index))?
            }
            5 => record.repeat = narrow(value)?,
            _ => return Err(RecordError::TooManyFields),
        }
    }
    Ok(record)
}

/// What a session can honestly say about the input it is carrying.
///
/// Section 8 is explicit that fidelity is reported as it is rather than claimed. A record read
/// from a console carries whatever that console had; a client that sends no records sends legacy
/// VT input, and nothing about that input contains a scan code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fidelity {
    /// Console key records, carried through unchanged.
    ///
    /// The scan codes in them are the ones the console reported. Over a remote desktop connection,
    /// a virtual keyboard or a keyboard hook, a console reports zero or a synthesised value, and
    /// that is what is carried: this host neither replaces it nor claims it came from hardware.
    Records,
    /// Legacy VT input: logical text and the supported special keys.
    ///
    /// Accepted without pretending it carries Windows scan-code fidelity. Microsoft's own contract
    /// permits a terminal to ignore mode 9001, so a client that does is behaving correctly.
    LegacyVt,
}

impl Fidelity {
    /// Whether this input carries the scan codes a console reported.
    ///
    /// True does not mean the scan codes are a keyboard's: it means they are the console's own and
    /// were not invented here.
    #[must_use]
    pub const fn carries_console_scan_codes(&self) -> bool {
        matches!(self, Self::Records)
    }

    /// The sentence a receipt or a diagnostic prints.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::Records => {
                "console key records, carried through as the console reported them, including \
                 whatever scan code it gave each one"
            }
            Self::LegacyVt => {
                "legacy VT input: logical text and the supported special keys, with no Windows \
                 scan-code fidelity"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_encoded_with_the_final_underscore_and_not_an_apc_string() {
        // `A` pressed: virtual key 0x41, scan code 0x1E, the code unit, key down, no modifiers,
        // once. The sequence begins CSI and ends with `_`; an APC string would begin `\x1b_` and
        // end with a string terminator, and an application reading one for the other would take
        // the whole of the rest of the stream as a string.
        let record = KeyRecord {
            virtual_key: 0x41,
            scan_code: 0x1E,
            unicode: u16::from(b'a'),
            key_down: true,
            control_keys: 0,
            repeat: 1,
        };
        assert_eq!(encode(&record), b"\x1b[65;30;97;1;0;1_");
        assert_eq!(decode(&encode(&record)), Ok(record));
    }

    #[test]
    fn omitted_fields_mean_zero_zero_zero_zero_zero_one() {
        // Every field is written, and a record with none of them is the defaults themselves.
        assert_eq!(encode(&KeyRecord::DEFAULT), b"\x1b[0;0;0;0;0;1_");
        assert_eq!(decode(b"\x1b[_"), Ok(KeyRecord::DEFAULT));
        assert_eq!(decode(b"\x1b[0;0;0;0;0;1_"), Ok(KeyRecord::DEFAULT));
        // And a reader fills in the same defaults for fields that were not sent.
        assert_eq!(
            decode(b"\x1b[65_"),
            Ok(KeyRecord {
                virtual_key: 0x41,
                ..KeyRecord::DEFAULT
            })
        );
        // An empty field between two that were sent is that field's default too.
        assert_eq!(
            decode(b"\x1b[65;;97_"),
            Ok(KeyRecord {
                virtual_key: 0x41,
                scan_code: 0,
                unicode: u16::from(b'a'),
                ..KeyRecord::DEFAULT
            })
        );
        // And a record whose later fields are all default still writes them, so a parser never
        // has to decide how many were meant.
        let once = KeyRecord {
            virtual_key: 0x41,
            key_down: true,
            ..KeyRecord::DEFAULT
        };
        assert_eq!(encode(&once), b"\x1b[65;0;0;1;0;1_");
        assert_eq!(decode(b"\x1b[65;0;0;1_"), Ok(once));
    }

    #[test]
    fn a_character_outside_the_basic_plane_keeps_both_of_its_code_units() {
        // U+1F600 is 0xD83D 0xDE00 in UTF-16, and a console reports it as two records. Decoding it
        // into a character and encoding that again would produce one record the application could
        // not read, so both are carried exactly as they were.
        let high = KeyRecord {
            unicode: 0xD83D,
            key_down: true,
            ..KeyRecord::DEFAULT
        };
        let low = KeyRecord {
            unicode: 0xDE00,
            key_down: true,
            ..KeyRecord::DEFAULT
        };
        assert!(high.is_high_surrogate() && low.is_low_surrogate());
        let bytes = encode_all(&[high, low]);
        assert_eq!(bytes, b"\x1b[0;0;55357;1;0;1_\x1b[0;0;56832;1;0;1_");
        // And the pair still names the character it came from.
        let pair = [0xD83D_u16, 0xDE00];
        assert_eq!(String::from_utf16(&pair).expect("a character"), "\u{1F600}");
    }

    #[test]
    fn a_repeat_count_and_a_key_up_are_carried_rather_than_expanded() {
        // A held key is one record with a count, not five records; and the key coming up is a
        // record of its own, which legacy VT input cannot express at all.
        let held = KeyRecord {
            virtual_key: 0x41,
            scan_code: 0x1E,
            unicode: u16::from(b'a'),
            key_down: true,
            control_keys: 0,
            repeat: 5,
        };
        assert_eq!(encode(&held), b"\x1b[65;30;97;1;0;5_");
        let released = KeyRecord {
            key_down: false,
            ..held
        };
        assert_eq!(encode(&released), b"\x1b[65;30;97;0;0;5_");
        assert_eq!(decode(&encode(&released)).expect("a record"), released);
    }

    #[test]
    fn alt_graph_is_the_right_alt_key_with_a_control_key() {
        let alt_graph = KeyRecord {
            virtual_key: 0x32,
            scan_code: 0x03,
            unicode: u16::from(b'@'),
            key_down: true,
            control_keys: control_keys::RIGHT_ALT_PRESSED | control_keys::LEFT_CTRL_PRESSED,
            repeat: 1,
        };
        assert!(alt_graph.is_alt_graph());
        // The right Alt key on its own is not AltGr, and neither is a Ctrl key on its own.
        assert!(
            !KeyRecord {
                control_keys: control_keys::RIGHT_ALT_PRESSED,
                ..alt_graph
            }
            .is_alt_graph()
        );
        assert!(
            !KeyRecord {
                control_keys: control_keys::LEFT_CTRL_PRESSED,
                ..alt_graph
            }
            .is_alt_graph()
        );
        // And the state travels whole: 9 is right Alt and left Ctrl together.
        assert_eq!(encode(&alt_graph), b"\x1b[50;3;64;1;9;1_");
    }

    #[test]
    fn legacy_input_never_claims_the_fidelity_records_have() {
        assert!(Fidelity::Records.carries_console_scan_codes());
        assert!(!Fidelity::LegacyVt.carries_console_scan_codes());
        assert!(Fidelity::LegacyVt.describe().contains("no Windows"));
        assert!(
            Fidelity::Records
                .describe()
                .contains("as the console reported")
        );
    }

    #[test]
    fn bytes_that_are_not_a_record_are_refused_rather_than_read_as_one() {
        assert_eq!(decode(b"\x1b[65;30;97;1;0;1"), Err(RecordError::NotARecord));
        assert_eq!(decode(b"\x1b_65_"), Err(RecordError::NotARecord));
        assert_eq!(
            decode(b"\x1b[1;2;3;4;5;6;7_"),
            Err(RecordError::TooManyFields)
        );
        assert_eq!(decode(b"\x1b[abc_"), Err(RecordError::Field(0)));
        // A field too large for what it names is refused rather than truncated into a different
        // key: a virtual key of 70000 is not virtual key 4464.
        assert_eq!(decode(b"\x1b[70000_"), Err(RecordError::Field(0)));
    }
}
