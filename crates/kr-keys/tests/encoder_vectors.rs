//! The input encoder against vectors written by hand.
//!
//! `fixtures/terminal/client-encodings.json` holds the bytes a key must be spelled as under the
//! ordinary encoding, `modifyOtherKeys` and the Kitty protocol, written from xterm's documentation
//! and the protocol's specification and not read off the encoder: a vector made from the encoder's
//! own output would compare it with itself. The capability manifest lists the file with the other
//! fixtures that fix what the terminal does, so a change to a vector moves the manifest.

use std::path::Path;

use kr_keys::{
    Arrow, Key, KeyEvent, KeyEventKind, KeyboardEncoding, Locks, Modifiers, key, release,
};
use serde_json::Value;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join("client-encodings.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hex"))
        .collect()
}

fn character(value: &Value) -> char {
    let text = value.as_str().expect("a character");
    let mut scalars = text.chars();
    let (Some(one), None) = (scalars.next(), scalars.next()) else {
        panic!("{text:?} is not one character");
    };
    one
}

fn key_of(value: &Value) -> Key {
    if let Some(name) = value.as_str() {
        return match name {
            "enter" => Key::Enter,
            "tab" => Key::Tab,
            "backspace" => Key::Backspace,
            "escape" => Key::Escape,
            "up" => Key::Arrow(Arrow::Up),
            "down" => Key::Arrow(Arrow::Down),
            "right" => Key::Arrow(Arrow::Right),
            "left" => Key::Arrow(Arrow::Left),
            "home" => Key::Home,
            "end" => Key::End,
            "page_up" => Key::PageUp,
            "page_down" => Key::PageDown,
            "insert" => Key::Insert,
            "delete" => Key::Delete,
            "menu" => Key::Menu,
            "print_screen" => Key::PrintScreen,
            "pause" => Key::Pause,
            other => panic!("no key named {other}"),
        };
    }
    if let Some(scalar) = value.get("char") {
        return Key::Char(character(scalar));
    }
    if let Some(number) = value.get("function") {
        return Key::Function(u8::try_from(number.as_u64().expect("a number")).expect("a key"));
    }
    panic!("no key in {value}");
}

fn modifiers_of(value: &Value) -> Modifiers {
    let mut held = Modifiers::NONE;
    for name in value.as_array().map_or(&[][..], Vec::as_slice) {
        match name.as_str().expect("a name") {
            "shift" => held.shift = true,
            "alt" => held.alt = true,
            "control" => held.control = true,
            "super" => held.superkey = true,
            other => panic!("no modifier named {other}"),
        }
    }
    held
}

fn locks_of(value: &Value) -> Locks {
    let mut on = Locks::NONE;
    for name in value.as_array().map_or(&[][..], Vec::as_slice) {
        match name.as_str().expect("a name") {
            "caps_lock" => on.caps_lock = true,
            "num_lock" => on.num_lock = true,
            other => panic!("no lock named {other}"),
        }
    }
    on
}

fn event_of(value: &Value) -> KeyEvent {
    KeyEvent {
        key: key_of(&value["key"]),
        base: value.get("base").map(character),
        modifiers: modifiers_of(&value["modifiers"]),
        locks: locks_of(&value["locks"]),
        kind: if value["kind"].as_str() == Some("repeat") {
            KeyEventKind::Repeat
        } else {
            KeyEventKind::Press
        },
    }
}

fn encoding_of(value: &Value) -> KeyboardEncoding {
    let application_cursor_keys = value["application_cursor_keys"].as_bool().unwrap_or(false);
    let level = |value: &Value| u8::try_from(value.as_u64().expect("a number")).expect("a u8");
    match value["kind"].as_str().expect("a kind") {
        "legacy" => KeyboardEncoding::Legacy {
            application_cursor_keys,
        },
        "modify_other_keys" => KeyboardEncoding::ModifyOtherKeys {
            level: level(&value["level"]),
            application_cursor_keys,
        },
        "kitty" => KeyboardEncoding::Kitty {
            flags: level(&value["flags"]),
        },
        other => panic!("no encoding named {other}"),
    }
}

/// KR-REQ-08.11, KR-REQ-08.59: each key is spelled as the vector says under the encoding the
/// application negotiated, a release is spelled from the press it ends where the encoding reports
/// one, and a key the encoding cannot express is refused rather than spelled as another.
#[test]
fn the_encoder_spells_every_key_as_the_hand_written_vectors_do() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let id = case["id"].as_str().expect("an id");
        let encoding = encoding_of(&case["encoding"]);
        let event = event_of(&case["event"]);
        let spelled = if let Some(after) = case.get("release") {
            release(
                event,
                modifiers_of(&after["modifiers"]),
                locks_of(&after["locks"]),
                encoding,
            )
        } else {
            key(event, encoding)
        };
        match case.get("bytes") {
            Some(bytes) => assert_eq!(
                spelled.as_deref().ok(),
                Some(unhex(bytes.as_str().expect("hex")).as_slice()),
                "case {id}"
            ),
            None => assert!(spelled.is_err(), "case {id} is refused, not spelled"),
        }
    }
}
