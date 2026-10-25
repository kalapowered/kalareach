//! What a session is sent for the console's key records: the records themselves when the backend
//! asked for them, and the legacy VT input a terminal would have sent when it did not.
//!
//! `fixtures/terminal/console-legacy-input.json` holds the legacy spelling of each kind of record,
//! written by hand and not read off the translation, so a translation checked against it is not
//! compared with itself. The cases that a fixture cannot hold are here: the bound on what one write
//! may produce, the pair of surrogate halves a console reports in two reads, and the records the
//! wire carries.

use std::path::Path;

use kr_protocol::input::ConsoleKey;
use kr_term::conformance::WIN32_INPUT_CASES;
use kr_term::modes::KeyboardEncoding;
use kr_term::win32::{
    KeyRecord, Keyboard, PairHold, Refused, TooLong, encode_all, legacy_within, records_within,
};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hex"))
        .collect()
}

fn records_of(value: &Value) -> Vec<KeyRecord> {
    value
        .as_array()
        .expect("a list of records")
        .iter()
        .map(|record| {
            let key: ConsoleKey = serde_json::from_value(record.clone()).expect("six members");
            key.into()
        })
        .collect()
}

fn keyboard_of(value: &Value) -> Keyboard {
    let negotiated = match &value["negotiated"] {
        Value::String(name) if name == "legacy" => KeyboardEncoding::Legacy,
        other => match (other.get("modify_other_keys"), other.get("kitty")) {
            (Some(level), None) => {
                KeyboardEncoding::ModifyOtherKeys(level.as_u64().expect("a level") as u8)
            }
            (None, Some(flags)) => KeyboardEncoding::Kitty(flags.as_u64().expect("flags") as u8),
            _ => panic!("{other} is not a negotiated encoding"),
        },
    };
    Keyboard {
        application_cursor_keys: value["application_cursor_keys"]
            .as_bool()
            .expect("a switch"),
        negotiated,
    }
}

/// The largest write one input frame may carry.
const LIMIT: usize = kr_protocol::limits::MAX_INPUT_FRAME_LEN;

fn ordinary() -> Keyboard {
    Keyboard {
        application_cursor_keys: false,
        negotiated: KeyboardEncoding::Legacy,
    }
}

fn typed(unicode: u16, repeat: u16) -> KeyRecord {
    KeyRecord {
        virtual_key: 0x41,
        scan_code: 0x1e,
        unicode,
        key_down: true,
        control_keys: 0,
        repeat,
    }
}

fn up_arrow(repeat: u16) -> KeyRecord {
    KeyRecord {
        virtual_key: 0x26,
        scan_code: 0x48,
        unicode: 0,
        key_down: true,
        control_keys: 0,
        repeat,
    }
}

/// KR-REQ-08.53: a session whose backend did not ask for records is sent the legacy VT input a
/// terminal would have sent, with the arrows in the form DEC mode 1 asks for, and a write is
/// refused, whole, while the application has negotiated an encoding that legacy input cannot
/// express. No scan code is sent, because none is claimed.
#[test]
fn records_are_spelled_as_the_legacy_input_a_terminal_would_have_sent() {
    let document = fixture("console-legacy-input.json");
    let cases = document["cases"].as_array().expect("cases");
    assert!(cases.len() > 30, "the fixture has {} cases", cases.len());
    for case in cases {
        let id = case["id"].as_str().expect("an id");
        let records = records_of(&case["records"]);
        let keyboard = keyboard_of(&case["keyboard"]);
        let spelled = legacy_within(&records, &keyboard, LIMIT);
        match (case.get("bytes"), case.get("refused")) {
            (Some(bytes), None) => {
                let expected = unhex(bytes.as_str().expect("hex"));
                assert_eq!(spelled.as_deref(), Ok(expected.as_slice()), "{id}");
            }
            (None, Some(why)) => {
                assert_eq!(why, "enhanced", "{id}");
                assert!(
                    matches!(spelled, Err(Refused::Enhanced(_))),
                    "{id}: {spelled:?}"
                );
            }
            _ => panic!("{id} says both what it spells and that it is refused, or neither"),
        }
    }
}

/// The records the wire carries are the ones the console reported: the fixture of the win32 input
/// encoding reads as wire records, converts to the type that encodes them, and comes back as it
/// was.
#[test]
fn the_wire_record_and_the_console_record_are_the_same_six_numbers() {
    let document = fixture("input-encodings.json");
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), WIN32_INPUT_CASES.len());
    for case in cases {
        let id = case["id"].as_str().expect("an id");
        let wanted = WIN32_INPUT_CASES
            .iter()
            .find(|candidate| candidate.id == id)
            .unwrap_or_else(|| panic!("{id} is a case of the encoding"));
        let wire: Vec<ConsoleKey> = case["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|record| serde_json::from_value(record.clone()).expect("six members"))
            .collect();
        let converted: Vec<KeyRecord> = wire.iter().copied().map(KeyRecord::from).collect();
        assert_eq!(converted, wanted.records, "{id}");
        let back: Vec<ConsoleKey> = converted.iter().copied().map(ConsoleKey::from).collect();
        assert_eq!(back, wire, "{id}");
        assert_eq!(
            records_within(&converted, LIMIT).as_deref(),
            Ok(wanted.bytes),
            "{id}: and the records are spelled as the fixture says"
        );
    }
}

/// KR-REQ-08.53: records that reach a backend which asked for them are spelled in the documented
/// sequence with every field written, and a write that would pass the bound is refused at the
/// bound. The same input just inside the bound is the unbounded spelling.
#[test]
fn the_records_a_backend_asked_for_are_bounded_on_what_they_spell() {
    let record = typed(u16::from(b'a'), 1);
    let one = encode_all(&[record]);
    assert_eq!(one, b"\x1b[65;30;97;1;0;1_");
    // More than a frame carries, from records that are each far below the bound.
    let run = vec![record; LIMIT / one.len() + 1];
    assert!(encode_all(&run).len() > LIMIT);
    assert_eq!(records_within(&run, LIMIT), Err(TooLong));
    let whole = encode_all(&run);
    assert_eq!(records_within(&run, whole.len()).as_deref(), Ok(&whole[..]));
    assert_eq!(
        records_within(&run, whole.len() - 1),
        Err(TooLong),
        "one byte under the length is over"
    );
    assert_eq!(records_within(&[], 0).as_deref(), Ok(&[][..]));
}

/// A record that repeats 65,535 times is refused at the bound, for a character and for a
/// sequence, and the same input just inside the bound is the unbounded spelling. The text waiting to
/// be written counts toward the bound as it is gathered, so a long run is refused before it is
/// built.
#[test]
fn a_repeat_count_cannot_make_the_legacy_spelling_longer_than_the_bound() {
    let held_up = up_arrow(u16::MAX);
    assert_eq!(
        legacy_within(&[held_up], &ordinary(), LIMIT),
        Err(Refused::TooLong)
    );
    let held_letter = typed(u16::from(b'a'), u16::MAX);
    assert_eq!(
        legacy_within(&[held_letter], &ordinary(), 100),
        Err(Refused::TooLong)
    );
    // Inside the bound the output is what the unbounded spelling is.
    let few = [up_arrow(10)];
    let whole = legacy_within(&few, &ordinary(), usize::MAX).expect("unbounded");
    assert_eq!(whole.len(), 30);
    assert_eq!(
        legacy_within(&few, &ordinary(), 30).as_deref(),
        Ok(&whole[..])
    );
    assert_eq!(
        legacy_within(&few, &ordinary(), 29),
        Err(Refused::TooLong),
        "one byte under the length is over"
    );
    let letters = [typed(u16::from(b'a'), 40)];
    assert_eq!(
        legacy_within(&letters, &ordinary(), 40).map(|bytes| bytes.len()),
        Ok(40)
    );
    assert_eq!(
        legacy_within(&letters, &ordinary(), 39),
        Err(Refused::TooLong)
    );
    // Text and a pair together: the characters before a pair count against the bound as well.
    let pair = [typed(0xD83D, 1), typed(0xDE00, 3)];
    assert_eq!(
        legacy_within(&pair, &ordinary(), 12).map(|bytes| bytes.len()),
        Ok(12)
    );
    assert_eq!(legacy_within(&pair, &ordinary(), 11), Err(Refused::TooLong));
}

fn high() -> KeyRecord {
    typed(0xD83D, 1)
}

fn low() -> KeyRecord {
    typed(0xDE00, 1)
}

fn released(record: KeyRecord) -> KeyRecord {
    KeyRecord {
        key_down: false,
        ..record
    }
}

/// A character outside the basic plane is two records that one read of the console can end
/// between. The first half waits for the second, with the key-ups after it so that their order is
/// kept, and the records go out in the order they were read.
#[test]
fn the_halves_of_a_character_are_kept_in_one_write() {
    let mut hold = PairHold::new();
    assert!(
        hold.take(&[high()]).is_empty(),
        "the first half waits rather than going out broken"
    );
    assert_eq!(hold.take(&[low()]), [high(), low()]);

    // A key coming up between the halves, and after the first, goes with them in its place.
    assert!(hold.take(&[high(), released(high())]).is_empty());
    assert_eq!(
        hold.take(&[low(), released(low())]),
        [high(), released(high()), low(), released(low())]
    );

    // Something that is not the other half starts something else, and what waited goes out as it
    // was, to be replaced by the translation.
    assert!(hold.take(&[high()]).is_empty());
    let next = typed(u16::from(b'a'), 1);
    let sent = hold.take(&[next]);
    assert_eq!(sent, [high(), next]);
    assert_eq!(
        legacy_within(&sent, &ordinary(), LIMIT).as_deref(),
        Ok("\u{FFFD}a".as_bytes())
    );

    // A first half at the end of a read waits, and the text before it goes. Nothing is lost: it is
    // given back when the producer has something else to deliver.
    let before = typed(u16::from(b'z'), 1);
    assert_eq!(hold.take(&[before, high()]), [before]);
    assert_eq!(hold.release(), [high()]);
    assert!(hold.release().is_empty());

    // A second high half in a row: the first has nothing to pair with and goes out; the second
    // waits.
    assert_eq!(hold.take(&[high(), high()]), [high()]);
    assert_eq!(hold.take(&[low()]), [high(), low()]);
}

/// However a console's records are cut into reads, what is sent is what the whole run would have
/// been sent as.
#[test]
fn a_run_cut_anywhere_is_sent_as_the_whole_run_would_be() {
    let run = [
        typed(u16::from(b'a'), 1),
        high(),
        released(high()),
        low(),
        released(low()),
        up_arrow(2),
        typed(u16::from(b'b'), 1),
        high(),
        typed(u16::from(b'c'), 1),
    ];
    let whole = legacy_within(&run, &ordinary(), LIMIT).expect("the whole run");
    assert_eq!(
        whole,
        "a\u{1F600}\x1b[A\x1b[Ab\u{FFFD}c".as_bytes(),
        "the pair is one character and the lone half is replaced"
    );
    for cut in 0..=run.len() {
        let mut hold = PairHold::new();
        let mut sent = hold.take(&run[..cut]);
        let mut spelled = legacy_within(&sent, &ordinary(), LIMIT).expect("the first part");
        sent = hold.take(&run[cut..]);
        spelled.extend(legacy_within(&sent, &ordinary(), LIMIT).expect("the second part"));
        // The tail that still waits is given back at the end of the input.
        spelled
            .extend(legacy_within(&hold.release(), &ordinary(), LIMIT).expect("what was waiting"));
        assert_eq!(spelled, whole, "cut after {cut} records");
    }
}
