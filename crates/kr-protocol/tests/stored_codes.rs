//! The words of the protocol's error codes, as the stores keep them.
//!
//! A store keeps an error code as its wire word and reads the word back as the code, so a word, its
//! retry class and its meaning outlast the build that wrote them. `stored_codes.txt` lists every
//! code's word with its class. The cases hold that list against this build, and they run on every
//! platform and whatever the protocol's public freeze and retained worker level say.

use std::path::Path;

use kr_protocol::error::{ErrorCode, RetryCategory};
use serde_json::Value;

const LIST: &str = include_str!("stored_codes.txt");

/// The list's lines: a word and a class, with the header's comments left out.
fn listed() -> Vec<(&'static str, &'static str)> {
    LIST.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split(' ');
            let word = parts.next().expect("a line has a word");
            let class = parts
                .next()
                .unwrap_or_else(|| panic!("the line {line:?} has no class"));
            assert!(
                parts.next().is_none(),
                "the line {line:?} has more than a word and a class"
            );
            (word, class)
        })
        .collect()
}

/// The name of a retry class as the wire spells it.
fn class_of(category: RetryCategory) -> String {
    serde_json::to_value(category)
        .expect("a class serialises")
        .as_str()
        .expect("a class is a string")
        .to_owned()
}

/// KR-REQ-23.55, KR-REQ-26.10: a word that is listed is still a code, with the class that is
/// listed. A word is never removed or renamed, and a code is never given another class, while a
/// store that a supported release reads can hold it.
#[test]
fn every_listed_word_is_still_a_code_of_the_class_listed_for_it() {
    let mut found = Vec::new();
    for (word, class) in listed() {
        match ErrorCode::from_wire(word) {
            None => found.push(format!(
                "{word} is listed and is no longer a code: a word that stores keep is never removed or renamed"
            )),
            Some(code) if class_of(code.retry_category()) != class => found.push(format!(
                "{word} is listed as {class} and is now {}: a code's class is never changed",
                class_of(code.retry_category())
            )),
            Some(_) => {}
        }
    }
    assert!(
        found.is_empty(),
        "the stored vocabulary has changed:\n{}",
        found.join("\n")
    );
}

/// KR-REQ-23.55, KR-REQ-26.10: every code of this build is listed once, so a new code appends its
/// line in the change that adds it.
#[test]
fn every_code_of_this_build_is_listed_once() {
    let words: Vec<&str> = listed().into_iter().map(|(word, _)| word).collect();
    let mut found = Vec::new();
    for code in ErrorCode::ALL {
        let times = words.iter().filter(|word| **word == code.as_str()).count();
        if times != 1 {
            found.push(format!(
                "{} is listed {times} times: a new code appends one line to stored_codes.txt in the change that adds it",
                code.as_str()
            ));
        }
    }
    assert!(
        found.is_empty(),
        "the stored vocabulary is not the build's:\n{}",
        found.join("\n")
    );
}

/// The error code's definition in each committed retained surface: the schema that a retained
/// release generated, kept in `retained/` for the level the workspace retains and in
/// `tests/retained/` for the older levels its cases read.
fn retained_surfaces() -> Vec<(String, Value)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for folder in ["retained", "tests/retained"] {
        let mut levels: Vec<_> = std::fs::read_dir(manifest.join(folder))
            .unwrap_or_else(|error| panic!("the folder {folder} does not read: {error}"))
            .map(|entry| entry.expect("a folder entry reads").path())
            .filter(|level| level.join("surface.schema.json").is_file())
            .collect();
        levels.sort();
        assert!(
            !levels.is_empty(),
            "the folder {folder} holds no retained surface, so the list is held against nothing there"
        );
        for level in levels {
            let name = format!(
                "{folder}/{}",
                level
                    .file_name()
                    .expect("a level has a name")
                    .to_string_lossy()
            );
            let text = std::fs::read_to_string(level.join("surface.schema.json"))
                .unwrap_or_else(|error| panic!("the surface of {name} does not read: {error}"));
            let surface: Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("the surface of {name} is not JSON: {error}"));
            found.push((name, surface));
        }
    }
    found
}

/// KR-REQ-23.55, KR-REQ-26.10: every word of the code in each committed retained surface is listed.
/// A change that removes or renames a code and edits the list in the same change passes the two
/// cases above, and a store that a retained release wrote can still hold the word.
#[test]
fn every_code_word_of_each_retained_surface_is_listed() {
    let words: Vec<&str> = listed().into_iter().map(|(word, _)| word).collect();
    let mut found = Vec::new();
    for (name, surface) in retained_surfaces() {
        let variants = surface
            .pointer("/$defs/ErrorCode/oneOf")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("the surface of {name} has no list of error codes"));
        assert!(
            !variants.is_empty(),
            "the surface of {name} lists no error code"
        );
        for variant in variants {
            let word = variant
                .get("const")
                .and_then(Value::as_str)
                .unwrap_or_else(|| {
                    panic!("a code of the surface of {name} is not a string constant")
                });
            if !words.contains(&word) {
                found.push(format!(
                    "{word} is a code of the retained surface {name} and the list lacks it: a word that a retained release wrote is never removed or renamed"
                ));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the stored vocabulary lacks a word of a retained release:\n{}",
        found.join("\n")
    );
}
