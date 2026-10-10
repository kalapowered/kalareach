//! Replacing one top-level member of a JSON object without touching the rest of its bytes.
//!
//! The gateway forwards what the terminal and the upstream write. Reading a frame into a value and
//! writing the value back changes it: members are reordered, a number is respelled (`1e9` becomes
//! `1000000000.0`), one past what a double holds loses digits, and a frame near the bound grows by
//! more than the identifier that was replaced. The only change this host means to make is the
//! request identifier, so that is the only change it makes: the member's value is found in the
//! bytes and cut out, and everything around it goes through as it was written.

use std::ops::Range;

use crate::broker::error::{BrokerError, Result};

fn unreadable() -> BrokerError {
    BrokerError::invalid("this frame is not an object this host can find a member of")
}

fn skip_whitespace(text: &[u8], mut at: usize) -> usize {
    while text
        .get(at)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        at += 1;
    }
    at
}

/// Where the string that begins at `at` ends, the closing quote included.
fn string_end(text: &[u8], at: usize) -> Option<usize> {
    let mut index = at + 1;
    while let Some(byte) = text.get(index) {
        match byte {
            b'\\' => index += 2,
            b'"' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

/// Where the value that begins at `at` ends.
fn value_end(text: &[u8], at: usize) -> Option<usize> {
    match *text.get(at)? {
        b'"' => string_end(text, at),
        b'{' | b'[' => {
            let mut depth = 0_usize;
            let mut index = at;
            while let Some(byte) = text.get(index) {
                match byte {
                    b'"' => {
                        index = string_end(text, index)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(index + 1);
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            None
        }
        _ => {
            let mut index = at;
            while text.get(index).is_some_and(|byte| {
                !matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            }) {
                index += 1;
            }
            (index > at).then_some(index)
        }
    }
}

/// Finds the value of the top-level member `name` of the JSON object `object`.
///
/// The bytes are expected to have been read as JSON already; what is not an object this can walk
/// is refused rather than guessed at.
///
/// # Errors
///
/// Returns [`BrokerError::InvalidArgument`] when `object` is not an object this can walk, and when
/// it names `name` more than once, because two readers of such a frame could disagree about which
/// is meant.
pub(crate) fn find_member(object: &[u8], name: &str) -> Result<Option<Range<usize>>> {
    let mut at = skip_whitespace(object, 0);
    if object.get(at) != Some(&b'{') {
        return Err(unreadable());
    }
    at += 1;
    let mut found: Option<Range<usize>> = None;
    loop {
        at = skip_whitespace(object, at);
        match object.get(at) {
            Some(b'}') => break,
            Some(b'"') => {}
            _ => return Err(unreadable()),
        }
        let key_end = string_end(object, at).ok_or_else(unreadable)?;
        let key: String = serde_json::from_slice(&object[at..key_end]).map_err(|_| unreadable())?;
        at = skip_whitespace(object, key_end);
        if object.get(at) != Some(&b':') {
            return Err(unreadable());
        }
        at = skip_whitespace(object, at + 1);
        let end = value_end(object, at).ok_or_else(unreadable)?;
        if key == name {
            if found.is_some() {
                return Err(BrokerError::invalid(format!(
                    "this frame names {name:?} more than once, and two readers of it could \
                     disagree"
                )));
            }
            found = Some(at..end);
        }
        at = skip_whitespace(object, end);
        match object.get(at) {
            Some(b',') => at += 1,
            Some(b'}') => break,
            _ => return Err(unreadable()),
        }
    }
    Ok(found)
}

/// Writes `object` with the value of its top-level member `name` replaced by `value`, which is the
/// text of a JSON value, and every other byte as it was.
///
/// # Errors
///
/// Returns [`BrokerError::InvalidArgument`] when `object` has no such member or is not an object
/// this can walk, and whatever [`find_member`] refuses.
pub(crate) fn replace_member(object: &[u8], name: &str, value: &str) -> Result<Vec<u8>> {
    let span = find_member(object, name)?.ok_or_else(|| {
        BrokerError::invalid(format!("this frame has no {name:?} member to replace"))
    })?;
    let mut replaced = Vec::with_capacity(object.len() + value.len());
    replaced.extend_from_slice(&object[..span.start]);
    replaced.extend_from_slice(value.as_bytes());
    replaced.extend_from_slice(&object[span.end..]);
    Ok(replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parser vectors: what is found in each object, and what replacing it leaves.
    #[test]
    fn a_member_is_replaced_and_every_other_byte_is_kept() {
        // (object, member, replacement, the object after)
        let vectors: &[(&str, &str, &str, &str)] = &[
            (
                r#"{"id":1,"method":"m"}"#,
                "id",
                r#""kr-1""#,
                r#"{"id":"kr-1","method":"m"}"#,
            ),
            (
                // Whitespace and a member of the same name below the top level stay as they are.
                r#" { "id" : 1 , "x" : [ 1, {"id":2}, "}" ] } "#,
                "id",
                "9",
                r#" { "id" : 9 , "x" : [ 1, {"id":2}, "}" ] } "#,
            ),
            (
                // A string with a brace, an escaped quote and an escaped backslash before the member.
                r#"{"p":"a}\"b\\","id":7}"#,
                "id",
                r#""x""#,
                r#"{"p":"a}\"b\\","id":"x"}"#,
            ),
            (
                // Numbers keep the spelling they were written in, and the order of the members
                // stays what it was.
                r#"{"z":1e9,"n":123456789012345678901234567890,"id":3,"a":1.50}"#,
                "id",
                r#""kr-3""#,
                r#"{"z":1e9,"n":123456789012345678901234567890,"id":"kr-3","a":1.50}"#,
            ),
            (
                // A name written with an escape is the name it decodes to.
                r#"{"\u0069d":1,"k":null}"#,
                "id",
                "2",
                r#"{"\u0069d":2,"k":null}"#,
            ),
            (
                // The value is an object, and so is what replaces it.
                r#"{"id":{"a":[1,2]},"k":1}"#,
                "id",
                r#"{"b":1}"#,
                r#"{"id":{"b":1},"k":1}"#,
            ),
            (r#"{"k":1,"id":null}"#, "id", "1", r#"{"k":1,"id":1}"#),
        ];
        for (object, member, value, after) in vectors {
            let replaced = replace_member(object.as_bytes(), member, value)
                .unwrap_or_else(|error| panic!("{object}: {error}"));
            assert_eq!(
                String::from_utf8(replaced).expect("text"),
                *after,
                "{object}"
            );
        }
    }

    #[test]
    fn a_member_that_is_absent_is_not_found_and_one_named_twice_is_refused() {
        assert_eq!(
            find_member(br#"{"a":1}"#, "id").expect("walks"),
            None,
            "an absent member is not found"
        );
        assert!(replace_member(br#"{"a":1}"#, "id", "1").is_err());
        assert!(find_member(br#"{"id":1,"id":2}"#, "id").is_err());
        // The same member written two ways is named twice.
        assert!(find_member(br#"{"id":1,"\u0069d":2}"#, "id").is_err());
        assert!(find_member(b"[1]", "id").is_err());
        assert!(find_member(br#"{"id":"#, "id").is_err());
    }
}
