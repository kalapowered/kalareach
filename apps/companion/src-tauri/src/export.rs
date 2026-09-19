//! Two exports, both written to a file the person chose.
//!
//! Section 25 asks for a semantic JSON archive and an asciicast terminal recording, each carrying
//! timestamps, dimensions and its declared omissions, and each including safe rendering data
//! without replaying historical clipboard writes or other terminal side effects. Section 25 also
//! says what an export is not: an automatic upload. Nothing here writes a path of its own; the
//! caller passes the destination the platform's save dialog returned.
//!
//! # Declared omissions
//!
//! An export that quietly left something out would be worse than one that refused, so both formats
//! carry an `omissions` list. Every omission has a reason a reader can act on, and the two obvious
//! ones are here by construction: a sequence whose replay would touch the reader's machine, and
//! content a privacy generation never retained.

use serde::{Deserialize, Serialize};

use crate::error::{CommandError, Result};

/// One thing an export deliberately does not carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omission {
    /// A stable key, so a reader can recognise the kind without parsing prose.
    pub kind: String,
    /// What was left out, in plain words.
    pub detail: String,
    /// How many times it was left out.
    pub count: u64,
}

/// The terminal's size at the moment of the recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dimensions {
    /// Columns.
    pub columns: u32,
    /// Rows.
    pub rows: u32,
}

/// One semantic event, as the archive carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedNode {
    /// The node's stable identifier.
    pub id: String,
    /// The revision the export was taken at.
    pub revision: String,
    /// The node body, in the document union's own shape.
    pub body: serde_json::Value,
    /// When it was recorded.
    pub at_ms: u64,
}

/// The semantic JSON archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticArchive {
    /// The archive format, so a reader knows what it has.
    pub format: String,
    /// The session this is an archive of.
    pub session_id: String,
    /// When the export was taken.
    pub exported_at_ms: u64,
    /// The terminal's dimensions at that moment.
    pub dimensions: Dimensions,
    /// The nodes, in order.
    pub nodes: Vec<ArchivedNode>,
    /// What the archive does not carry.
    pub omissions: Vec<Omission>,
}

/// The archive format identifier this application writes.
pub const SEMANTIC_ARCHIVE_FORMAT: &str = "kalareach.semantic-archive/1";

/// Builds the semantic archive.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` when the dimensions are not a terminal's.
pub fn semantic_archive(
    session_id: &str,
    exported_at_ms: u64,
    dimensions: Dimensions,
    nodes: Vec<ArchivedNode>,
    omissions: Vec<Omission>,
) -> Result<SemanticArchive> {
    check_dimensions(dimensions)?;
    Ok(SemanticArchive {
        format: SEMANTIC_ARCHIVE_FORMAT.to_owned(),
        session_id: session_id.to_owned(),
        exported_at_ms,
        dimensions,
        nodes,
        omissions,
    })
}

/// One recorded slice of terminal output, with the time it arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Milliseconds since the recording began.
    pub at_ms: u64,
    /// The bytes, as text.
    pub text: String,
}

/// The result of rendering an asciicast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asciicast {
    /// The file's contents: one JSON header line, then one JSON array per frame.
    pub body: String,
    /// What the recording does not carry, also recorded in the header.
    pub omissions: Vec<Omission>,
}

/// The control sequences an export never replays.
///
/// A recording is read back by pasting it into a terminal, so a sequence that acts on the reader's
/// machine rather than on the recorded screen is a side effect the reader did not ask for. OSC 52
/// writes the system clipboard; OSC 7 and OSC 9;9 report a working directory a shell may then
/// change to; DCS and APC carry payloads a terminal or a multiplexer executes.
const SIDE_EFFECT_INTRODUCERS: &[(&str, &str, &str)] = &[
    ("clipboard_write", "\u{1b}]52;", "a clipboard write recorded from the session"),
    ("working_directory_report", "\u{1b}]7;", "a working-directory report"),
    ("working_directory_report", "\u{1b}]9;9;", "a working-directory report"),
    ("device_control_string", "\u{1b}P", "a device-control string"),
    ("application_program_command", "\u{1b}_", "an application-program command"),
];

/// Builds an asciicast recording, dropping every sequence whose replay would act on the reader's
/// machine and declaring what it dropped.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` when the dimensions are not a terminal's, or a frame's timestamp goes
/// backwards: a recording whose times are not ordered is not a recording.
pub fn asciicast(
    dimensions: Dimensions,
    started_at_unix_seconds: u64,
    title: &str,
    frames: &[Frame],
    mut omissions: Vec<Omission>,
) -> Result<Asciicast> {
    check_dimensions(dimensions)?;
    let mut last = 0_u64;
    let mut cleaned = Vec::with_capacity(frames.len());
    let mut dropped: Vec<(String, String, u64)> = Vec::new();
    for frame in frames {
        if frame.at_ms < last {
            return Err(CommandError::invalid(
                "a recording's frames are in the order they arrived",
            ));
        }
        last = frame.at_ms;
        let (text, removals) = strip_side_effects(&frame.text);
        for (kind, detail) in removals {
            match dropped
                .iter_mut()
                .find(|(seen_kind, seen_detail, _)| *seen_kind == kind && *seen_detail == detail)
            {
                Some(entry) => entry.2 += 1,
                None => dropped.push((kind, detail, 1)),
            }
        }
        cleaned.push(Frame {
            at_ms: frame.at_ms,
            text,
        });
    }
    for (kind, detail, count) in dropped {
        omissions.push(Omission {
            kind,
            detail,
            count,
        });
    }

    let header = serde_json::json!({
        "version": 2,
        "width": dimensions.columns,
        "height": dimensions.rows,
        "timestamp": started_at_unix_seconds,
        "title": title,
        "env": { "TERM": "xterm-256color" },
        "kalareach": { "omissions": omissions },
    });
    let mut body = header.to_string();
    for frame in cleaned {
        body.push('\n');
        let seconds = frame.at_ms as f64 / 1000.0;
        let event = serde_json::json!([seconds, "o", frame.text]);
        body.push_str(&event.to_string());
    }
    body.push('\n');
    Ok(Asciicast { body, omissions })
}

/// Removes every side-effecting sequence from one slice of recorded output.
///
/// The sequence and its terminator go together: leaving the terminator behind would print the rest
/// of a payload as text.
fn strip_side_effects(text: &str) -> (String, Vec<(String, String)>) {
    let mut out = String::with_capacity(text.len());
    let mut removed = Vec::new();
    let mut rest = text;
    loop {
        // The earliest introducer wins, so a clipboard write after a device-control string is not
        // matched first and the text between them is not swallowed.
        let earliest = SIDE_EFFECT_INTRODUCERS
            .iter()
            .filter_map(|(kind, introducer, detail)| {
                rest.find(introducer)
                    .map(|index| (index, *kind, *introducer, *detail))
            })
            .min_by_key(|(index, _, introducer, _)| (*index, usize::MAX - introducer.len()));
        let Some((index, kind, introducer, detail)) = earliest else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..index]);
        let after = &rest[index + introducer.len()..];
        rest = &after[terminator_end(after)..];
        removed.push((kind.to_owned(), detail.to_owned()));
    }
    (out, removed)
}

/// Where the string terminator or BEL that ends a sequence finishes.
fn terminator_end(after: &str) -> usize {
    let string_terminator = after.find("\u{1b}\\").map(|index| index + 2);
    let bell = after.find('\u{7}').map(|index| index + 1);
    match (string_terminator, bell) {
        (Some(left), Some(right)) => left.min(right),
        (Some(only), None) | (None, Some(only)) => only,
        // An unterminated sequence runs to the end of what was recorded; nothing after it is text.
        (None, None) => after.len(),
    }
}

fn check_dimensions(dimensions: Dimensions) -> Result<()> {
    if dimensions.columns == 0 || dimensions.rows == 0 {
        return Err(CommandError::invalid(
            "an export records the terminal's dimensions, which are never zero",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dimensions() -> Dimensions {
        Dimensions {
            columns: 120,
            rows: 40,
        }
    }

    #[test]
    fn a_semantic_archive_carries_its_time_its_dimensions_and_its_omissions() {
        let archive = semantic_archive(
            "s-1",
            1_700_000_000_000,
            dimensions(),
            vec![ArchivedNode {
                id: "n-1".into(),
                revision: "3".into(),
                body: serde_json::json!({ "kind": "message", "author": "agent", "text": "hello" }),
                at_ms: 1_700_000_000_000,
            }],
            vec![Omission {
                kind: "privacy_generation".into(),
                detail: "content this session never retained".into(),
                count: 4,
            }],
        )
        .expect("a valid archive");
        assert_eq!(archive.format, SEMANTIC_ARCHIVE_FORMAT);
        assert_eq!(archive.exported_at_ms, 1_700_000_000_000);
        assert_eq!(archive.dimensions.columns, 120);
        assert_eq!(archive.omissions.len(), 1);
        assert_eq!(archive.nodes[0].at_ms, 1_700_000_000_000);
    }

    #[test]
    fn an_asciicast_header_carries_the_dimensions_the_timestamp_and_the_omissions() {
        let cast = asciicast(
            dimensions(),
            1_700_000_000,
            "s-1",
            &[Frame {
                at_ms: 250,
                text: "hello\r\n".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        let mut lines = cast.body.lines();
        let header: serde_json::Value =
            serde_json::from_str(lines.next().expect("a header")).expect("valid JSON");
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);
        assert_eq!(header["height"], 40);
        assert_eq!(header["timestamp"], 1_700_000_000_u64);
        assert!(header["kalareach"]["omissions"].is_array());

        let frame: serde_json::Value =
            serde_json::from_str(lines.next().expect("a frame")).expect("valid JSON");
        assert!((frame[0].as_f64().expect("a time") - 0.25).abs() < 1e-9);
        assert_eq!(frame[1], "o");
        assert_eq!(frame[2], "hello\r\n");
    }

    #[test]
    fn a_recorded_clipboard_write_is_not_replayed_and_is_declared() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "before\u{1b}]52;c;c2VjcmV0\u{7}after".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(
            !cast.body.contains("]52;"),
            "a clipboard write never reaches the recording"
        );
        assert!(cast.body.contains("beforeafter"), "the text around it is kept");
        let omission = cast
            .omissions
            .iter()
            .find(|omission| omission.kind == "clipboard_write")
            .expect("the omission is declared");
        assert_eq!(omission.count, 1);
    }

    #[test]
    fn a_device_control_string_is_removed_with_its_terminator() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "a\u{1b}P+q544e\u{1b}\\b".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        let body = cast.body.lines().nth(1).expect("a frame");
        assert!(body.contains("ab"), "the payload and its terminator both go");
        assert!(!body.contains("544e"));
    }

    #[test]
    fn ordinary_colour_and_cursor_sequences_survive_because_they_render_the_screen() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}[31mred\u{1b}[0m\u{1b}[2J".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(cast.body.contains("[31m"), "rendering data is safe and is kept");
        assert!(cast.body.contains("[2J"));
        assert!(cast.omissions.is_empty());
    }

    #[test]
    fn a_working_directory_report_is_removed() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "x\u{1b}]7;file://host/tmp\u{7}y".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains("]7;"));
        assert_eq!(cast.omissions[0].kind, "working_directory_report");
    }

    #[test]
    fn frames_that_go_backwards_are_refused() {
        let error = asciicast(
            dimensions(),
            1,
            "s-1",
            &[
                Frame {
                    at_ms: 10,
                    text: "a".into(),
                },
                Frame {
                    at_ms: 5,
                    text: "b".into(),
                },
            ],
            Vec::new(),
        )
        .expect_err("a recording is ordered");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    #[test]
    fn zero_dimensions_are_refused_by_both_formats() {
        let zero = Dimensions {
            columns: 0,
            rows: 24,
        };
        assert!(semantic_archive("s-1", 1, zero, Vec::new(), Vec::new()).is_err());
        assert!(asciicast(zero, 1, "s-1", &[], Vec::new()).is_err());
    }
}
