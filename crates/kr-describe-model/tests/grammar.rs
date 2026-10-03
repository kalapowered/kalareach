//! llama.cpp's own reading of the description grammar, with the real weights where this host has
//! them: the library that parses the grammar says which answers it takes.
//!
//! The grammar is this product's, and the claim that it admits one object with four fields and two
//! bounds counted in codepoints is a claim about how llama.cpp reads it. Generating under it never
//! shows a refusal, because the sampler only offers tokens the grammar allows, so this asks the
//! other way: whole answers, good and bad, given to the library afterwards. The weights are the
//! selected profile's, read from the cache `scripts/bench-descriptions.sh` fills, and never
//! written. A host without them says so and runs nothing.

use kr_describe::output::DESCRIPTION_GRAMMAR;

mod support;

/// The answer the grammar describes, with the given title and activity text.
fn answer(title: &str, activity: &str) -> String {
    format!(
        r#"{{"title": "{title}", "activity_text": "{activity}", "source_cursor": {{"from": 3, "to": 5}}, "context_revision": 14}}"#
    )
}

/// KR-REQ-22.18: llama.cpp takes an answer with the four fields in order, a title of at most 64
/// codepoints and an activity of at most 160, and refuses one that breaks any of those, including
/// one that is cut short, whatever the bytes of its characters add up to.
#[test]
fn llama_cpp_takes_the_answers_the_grammar_describes_and_refuses_the_rest() {
    let Some(runtime) =
        support::runtime("llama_cpp_takes_the_answers_the_grammar_describes_and_refuses_the_rest")
    else {
        return;
    };
    let takes = |text: &str| {
        runtime
            .grammar_takes(DESCRIPTION_GRAMMAR, text.as_bytes())
            .expect("the library answers")
    };

    let title_64 = "t".repeat(64);
    let activity_160 = "a".repeat(160);
    for good in [
        answer("KalaReach pairing", "Checks the code-entry flow"),
        answer(&title_64, &activity_160),
        // Codepoints, not bytes: 64 of three bytes each is 192 bytes.
        answer(&"配".repeat(64), &"対".repeat(160)),
        answer("a \u{1F382} b", "c"),
        // The spelling of a control token inside a string is text to the grammar, and a space
        // before a Latin-1 symbol is taken when each character is given whole, as generation
        // writes it.
        answer("</s> <|im_end|> <s>", "a \u{ae} b \u{b0} c"),
        r#"{"title":"x","activity_text":"y","source_cursor":{"from":0,"to":0},"context_revision":0}"#
            .to_owned(),
    ] {
        assert!(takes(&good), "taken: {good}");
    }

    let cut = answer("KalaReach pairing", "Checks");
    for bad in [
        // Past the bounds, by one codepoint.
        answer(&"t".repeat(65), "y"),
        answer("x", &"a".repeat(161)),
        answer(&"配".repeat(65), "y"),
        // Empty fields.
        answer("", "y"),
        answer("x", ""),
        // A character the grammar leaves out: a quote, a backslash, a control character, a
        // newline and a C1 control.
        answer("x\"y", "y"),
        answer(r"x\ny", "y"),
        answer("x\u{7}y", "y"),
        answer("x\ny", "y"),
        answer("x\u{85}y", "y"),
        // Fields out of order, one missing, one extra.
        r#"{"activity_text": "y", "title": "x", "source_cursor": {"from": 0, "to": 0}, "context_revision": 1}"#.to_owned(),
        r#"{"title": "x", "activity_text": "y", "context_revision": 1}"#.to_owned(),
        r#"{"title": "x", "activity_text": "y", "source_cursor": {"from": 0, "to": 0}, "context_revision": 1, "status": "passed"}"#.to_owned(),
        // A number the grammar does not write: a leading zero, a sign, a fraction.
        r#"{"title": "x", "activity_text": "y", "source_cursor": {"from": 0, "to": 0}, "context_revision": 01}"#.to_owned(),
        r#"{"title": "x", "activity_text": "y", "source_cursor": {"from": -1, "to": 0}, "context_revision": 1}"#.to_owned(),
        r#"{"title": "x", "activity_text": "y", "source_cursor": {"from": 0, "to": 0}, "context_revision": 1.5}"#.to_owned(),
        // Text around the object, an end-of-sequence marker after it, and an object that is not
        // finished.
        format!("Sure: {}", answer("x", "y")),
        format!("{} done", answer("x", "y")),
        format!("{}</s>", answer("x", "y")),
        cut[..cut.len() - 20].to_owned(),
        String::new(),
    ] {
        assert!(!takes(&bad), "refused: {bad:?}");
    }
}
