//! What the journal's file may hold, by construction.
//!
//! Every kind of row has a largest encoded size, and the kinds that repeat have a largest count.
//! The writer refuses a row over either before it reaches the file ([`Row::check_caps`](super::rows::Row::check_caps)). The rows of an
//! object (its grant, the release that undoes it and what that leaves) are paid for from a budget,
//! [`WRITER_LIMIT`], in the tracker: a row that starts work is admitted only when the file still has
//! room, after it, for every row that the work already begun may still write, and a row that ends
//! work is paid from what was kept for it. The rows that are not an object's are bounded by their
//! counts and sizes, whose sum is [`CLOSING`]. So no file that a correct writer produces is longer
//! than [`MAX_FILE`], which is the sum of the two, and the reader's bound is that figure.
//!
//! The reader applies none of these caps and none of the budget: they limit what may still be
//! added, and a file already written is read by its order and its gates alone.
//!
//! # What the next row over a count does
//!
//! | Kind | Largest count | The next one over it |
//! |---|---|---|
//! | `Begin`, `GrantComplete`, `ProcessStarted`, `RootIntent`, `RootMade`, `RootRemoved`, `End` | 1 | refused as out of order: it would say the same thing twice or something that cannot be |
//! | `RepositorySnapshot` | 4 | not written; the caller records a leftover for the tree that says the journal holds no more snapshots |
//! | `JobEnded`, `EndUncertain` | 16 each | one that repeats what the journal already says is not written, and the caller is told it is already recorded; an `EndUncertain` that repeats the state with another reason is not written and the caller is told it differs (the first reason stands, and the caller gives the other to the person in its own answer; it uses none of the sixteen); one that changes the state is not written either, and the caller records a leftover of class `Uncertain` for the tree, which says the journal holds no more end checks |
//! | `ReleaseVerified` | 16 | one that repeats the standing verification is not written (already recorded); one that repeats it with another count of objects is not written and the caller is told it differs, which it treats as a fault of its own count and ends the invocation unfinished; the seventeenth, after sixteen were voided, is not written and the caller records a leftover for the tree that says the verification was made too often |
//! | `AcceptedState` | 4 | one for a state already accepted by the same person, at any time, is not written (already recorded); one for it from another person is not written and the caller is told it differs, and the caller tells that person the state was accepted already; another state's acceptance over the count is refused with words for the person, and its leftover stays |
//! | `Leftover` of class `Repository` | 4 | refused; the caller records a leftover for the tree |
//! | `Leftover` of class `Root` | 1,024 | refused with words; the removal ends with the leftovers that are there, which already say the root is not whole, and the invocation's end counts them |
//! | `Leftover` of another class that no release of the invocation reserved room for | 8 | refused; the invocation stays unfinished and its tree blocked, which is what the leftovers already say |
//!
//! A row that was refused for room is never lost silently: the caller is given the refusal with the
//! words that say why, and writes the leftover; a leftover is always admitted within its count. A
//! row that repeats a recorded one with other content is never taken for the recorded one: the
//! caller is told it differs, and nothing is written.
//!
//! A writer that takes up a file an earlier writer made counts the bytes that are in it: what is
//! left of the file's bound after those bytes and what the rows that are not an object's may still
//! add is the most the objects' rows may take, and the file itself refuses a row that would pass
//! the bound whatever the tracker holds.

use super::framing::FRAME_BYTES;

/// The most UTF-16 units of a path in a row.
pub const PATH_UNITS: usize = 1024;
/// The most bytes a path takes in a row once it is written as JSON: a unit takes at most three.
pub const PATH_JSON_BYTES: usize = 3 * PATH_UNITS;
/// The most bytes of a permission list in a row; it takes twice that in hex.
pub const LIST_BYTES: usize = 4096;
/// How much longer than at its grant a list may be when its release is written: the room kept for
/// it grows by this much, in bytes, beyond the grant's list.
pub const LIST_GROWTH: usize = 256;
/// The most bytes of an identifier's text in a row.
pub const SID_BYTES: usize = 184;
/// The most bytes of a reason, an outcome or a person's name in a row.
pub const TEXT_BYTES: usize = 256;
/// The most directories in the chain of a tree's root.
pub const CHAIN_KEYS: usize = 256;
/// The most hooks a snapshot lists.
pub const HOOKS: usize = 128;
/// The most names a snapshot lists as absent.
pub const ABSENT_NAMES: usize = 64;
/// The most bytes a name in a snapshot takes in a row.
pub const NAME_BYTES: usize = 255;

/// The most objects the grant's walk covers for one invocation: a larger tree is refused at
/// admission.
pub const OBJECTS_PER_TREE: usize = 100_000;
/// What the rows of one object are allowed on average in the journal, as a figure to multiply: its
/// grant row, the release intent and its result, and the room kept for a failure.
pub const BYTES_PER_OBJECT: usize = 4096;
/// The budget of the rows that belong to objects: a grant that would leave the file without room
/// for the rows its release may still write is refused.
pub const WRITER_LIMIT: usize = OBJECTS_PER_TREE * BYTES_PER_OBJECT;

/// One identifier of a file as a row writes it: 16 + 1 + 32 digits and the quotes.
const KEY_JSON: usize = 51;
/// What the fixed words of a row and its small numbers take, for any kind.
const OVERHEAD: usize = 512;

/// The largest `Begin` row.
pub const BEGIN_MAX: usize =
    OVERHEAD + 4 * SID_BYTES + PATH_JSON_BYTES + CHAIN_KEYS * (KEY_JSON + 1);
/// The largest `RepositorySnapshot` row.
pub const SNAPSHOT_MAX: usize = OVERHEAD
    + 64
    + (HOOKS + 1) * (NAME_BYTES + KEY_JSON + 64 + 64)
    + ABSENT_NAMES * (NAME_BYTES + 4);
/// The largest `RootIntent`, `RootMade` or `RootRemoved` row.
pub const ROOT_MAX: usize = OVERHEAD;
/// The largest `Grant` row.
pub const GRANT_MAX: usize =
    OVERHEAD + KEY_JSON + PATH_JSON_BYTES + 2 * LIST_BYTES + SID_BYTES + TEXT_BYTES;
/// The largest `GrantComplete`, `ProcessStarted`, `JobEnded`, `End` or `ReleaseVerified` row.
pub const SMALL_MAX: usize = OVERHEAD;
/// The largest `EndUncertain` row.
pub const UNCERTAIN_MAX: usize = OVERHEAD + TEXT_BYTES;
/// The largest `ReleaseIntent` row.
pub const INTENT_MAX: usize = OVERHEAD + KEY_JSON + 2 * LIST_BYTES + SID_BYTES;
/// The largest `ObjectReleased` row.
pub const RELEASED_MAX: usize = OVERHEAD + KEY_JSON + TEXT_BYTES;
/// The largest `Leftover` row.
pub const LEFTOVER_MAX: usize = OVERHEAD + PATH_JSON_BYTES + TEXT_BYTES;
/// The largest `AcceptedState` row.
pub const ACCEPTED_MAX: usize = OVERHEAD + SID_BYTES;
/// The largest `LeftoverCleared` row.
pub const CLEARED_MAX: usize = OVERHEAD + PATH_JSON_BYTES;

/// The most snapshots.
pub const SNAPSHOTS: u32 = 4;
/// The most `JobEnded` rows, and the most `EndUncertain` rows.
pub const END_CHECKS: u32 = 16;
/// The most `ReleaseVerified` rows.
pub const VERIFICATIONS: u32 = 16;
/// The most `AcceptedState` rows, and the most leftovers of class `Repository`.
pub const ACCEPTANCES: u32 = 4;
/// The most leftovers of class `Root`.
pub const ROOT_LEFTOVERS: u32 = 1024;
/// The most leftovers that no release of the invocation reserved room for.
pub const OTHER_LEFTOVERS: u32 = 8;

const fn framed(size: usize) -> usize {
    size + FRAME_BYTES
}

/// What the rows that are not an object's may take together: each kind at its largest size and its
/// largest count, with a leftover and the row that clears it for each leftover that may be open.
#[must_use]
pub const fn closing_bytes() -> usize {
    let leftover_and_clearance = framed(LEFTOVER_MAX) + framed(CLEARED_MAX);
    framed(BEGIN_MAX)
        + SNAPSHOTS as usize * framed(SNAPSHOT_MAX)
        + 3 * framed(ROOT_MAX)
        + 3 * framed(SMALL_MAX)
        + END_CHECKS as usize * (framed(SMALL_MAX) + framed(UNCERTAIN_MAX))
        + VERIFICATIONS as usize * framed(SMALL_MAX)
        + ACCEPTANCES as usize * (framed(ACCEPTED_MAX) + leftover_and_clearance)
        + ROOT_LEFTOVERS as usize * leftover_and_clearance
        + OTHER_LEFTOVERS as usize * leftover_and_clearance
        + framed(SMALL_MAX)
}

/// The most the rows that are not an object's take.
pub const CLOSING: usize = closing_bytes();

/// The most bytes a correct writer makes a journal file, and so the most the reader reads: the
/// budget of the objects' rows and the rows that are not an object's, each at its caps.
pub const MAX_FILE: usize = WRITER_LIMIT + CLOSING;

/// The fixed words of a result, leftover or clearance row, with its small fields, in bytes.
const ROOM_WORDS: usize = 128;
/// The fixed words of a release intent with an owner's identifier, in bytes.
const INTENT_WORDS: usize = 400;

/// What the row that says an object was released may take, framed.
#[must_use]
pub const fn released_room() -> usize {
    framed(ROOM_WORDS + KEY_JSON + TEXT_BYTES)
}

/// What a leftover that names an object by `object_json` bytes may take, framed, with a reason of
/// the longest length.
#[must_use]
pub const fn leftover_room(object_json: usize) -> usize {
    framed(ROOM_WORDS + object_json + TEXT_BYTES)
}

/// What the row that clears a leftover that names an object by `object_json` bytes may take,
/// framed.
#[must_use]
pub const fn cleared_room(object_json: usize) -> usize {
    framed(ROOM_WORDS + object_json)
}

/// What a release intent may take, framed, for a list of `list_bytes` (written in hex, twice as
/// long).
#[must_use]
pub const fn intent_room(list_bytes: usize) -> usize {
    framed(INTENT_WORDS + 2 * list_bytes)
}

/// The text of a key in a row, in bytes.
pub const KEY_TEXT_BYTES: usize = KEY_JSON - 2;

// The figures fit each other: the rows that are not an object's take a few megabytes at their caps,
// the largest file is the two budgets added, and the longest path fits the rows that carry one.
const _: () = assert!(CLOSING < 16 * 1024 * 1024);
const _: () = assert!(MAX_FILE == WRITER_LIMIT + CLOSING);
const _: () = assert!(PATH_JSON_BYTES < GRANT_MAX && PATH_JSON_BYTES < LEFTOVER_MAX);

/// A text cut to at most `max` bytes of its own, at a character boundary. The cut counts the text's
/// own bytes and not the bytes the text takes once written in a row, where a backslash, a quote and
/// a control character take more: a text that a row carries is cut by [`short`], which counts the
/// written bytes, so that the row is never refused for the length of a message.
#[must_use]
pub fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A reason, an outcome or a name for a row: the longest start of the text, cut at a character
/// boundary, that takes at most [`TEXT_BYTES`] once written as a row writes it. A backslash and a
/// quote take two bytes there and a control character six, so the cut counts those bytes and not
/// the text's own: the row that carries the cut text is never refused for its length.
#[must_use]
pub fn short(text: &str) -> String {
    if json_bytes(text) <= TEXT_BYTES {
        return text.to_owned();
    }
    let mut taken = 0;
    let mut end = 0;
    for (start, character) in text.char_indices() {
        taken += json_bytes(character.encode_utf8(&mut [0; 4]));
        if taken > TEXT_BYTES {
            break;
        }
        end = start + character.len_utf8();
    }
    text[..end].to_owned()
}

/// The bytes of `text` once written as a JSON string, without the quotes.
#[must_use]
pub fn json_bytes(text: &str) -> usize {
    #[expect(
        clippy::disallowed_methods,
        reason = "a text that cannot be written as JSON counts as too large and is refused; nothing was read from the machine"
    )]
    let bytes = serde_json::to_string(text).map_or(usize::MAX, |encoded| encoded.len() - 2);
    bytes
}

/// Whether a path fits a row, and the words for the person when it does not.
///
/// # Errors
///
/// Returns the reason: more than [`PATH_UNITS`] characters, or a control character.
pub fn check_path(text: &str) -> Result<(), String> {
    let units = text.encode_utf16().count();
    if units > PATH_UNITS {
        return Err(format!(
            "a path is longer than {PATH_UNITS} characters ({units}), which the journal does not record: {}",
            cut(text, 80)
        ));
    }
    if text.chars().any(char::is_control) {
        return Err("a path has a control character, which the journal does not record".to_owned());
    }
    // A unit takes at most three bytes in a row (a backslash or a quote, two; a control character,
    // the only one that takes six, was refused above), so a path of at most `PATH_UNITS` units
    // takes at most `PATH_JSON_BYTES`.
    Ok(())
}

/// Whether a text fits in `max` bytes as a row writes it.
///
/// # Errors
///
/// Returns the words for the person when it does not.
pub fn check_text(what: &str, text: &str, max: usize) -> Result<(), String> {
    if json_bytes(text) > max {
        Err(format!(
            "{what} is longer than {max} bytes, which the journal does not record"
        ))
    } else {
        Ok(())
    }
}

/// Whether a permission list fits a row, and the words for the person when it does not.
///
/// # Errors
///
/// Returns the reason when the list is longer than [`LIST_BYTES`].
pub fn check_list(what: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > LIST_BYTES {
        Err(format!(
            "{what} is {} bytes long, and the journal does not record a list over {LIST_BYTES} bytes",
            bytes.len()
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_is_cut_at_a_character_boundary() {
        let text = "é".repeat(200);
        let cut = cut(&text, 255);
        assert_eq!(cut.len(), 254);
        assert!(text.starts_with(&cut));
    }
}
