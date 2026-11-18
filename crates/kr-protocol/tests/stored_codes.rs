//! The words of the protocol's error codes, as the stores keep them.
//!
//! A store keeps an error code as its wire word and reads the word back as the code, so a word, its
//! retry class and its meaning outlast the build that wrote them. `stored_codes.txt` lists every
//! code's word with its class. The cases hold that list against this build, and they run on every
//! platform and whatever the protocol's public freeze and retained worker level say.

use kr_protocol::error::{ErrorCode, RetryCategory};

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
