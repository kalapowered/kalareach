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

/// The string sequences an export never replays.
///
/// A recording is read back by writing it to a terminal, so a sequence that acts on the reader's
/// machine rather than on the recorded screen is a side effect the reader did not ask for. OSC 52
/// writes the system clipboard; OSC 7 and OSC 9;9 report a working directory a shell may then
/// change to; DCS, APC, SOS and PM carry payloads a terminal or a multiplexer interprets.
///
/// The recogniser below is a small state machine rather than a search, because a recording is a
/// sequence of frames and a terminal does not restart at a frame boundary: `\x1b]5` at the end of
/// one frame and `2;c;…` at the start of the next is one clipboard write, and a search over each
/// frame on its own would pass both through.
const CLIPBOARD_WRITE: &str = "clipboard_write";
const WORKING_DIRECTORY: &str = "working_directory_report";
const DEVICE_CONTROL: &str = "device_control_string";
const OTHER_STRING: &str = "application_string";

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
    // One recogniser for the whole recording: a terminal does not restart at a frame boundary, and
    // a sequence split across two frames is still one sequence.
    let mut stripper = Stripper::new();
    for frame in frames {
        if frame.at_ms < last {
            return Err(CommandError::invalid(
                "a recording's frames are in the order they arrived",
            ));
        }
        last = frame.at_ms;
        cleaned.push(Frame {
            at_ms: frame.at_ms,
            text: stripper.feed(&frame.text),
        });
    }
    omissions.extend(stripper.finish());

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

/// What the recogniser is in the middle of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Ordinary text.
    Text,
    /// Inside a removed string, having just seen an escape that may terminate it.
    RemovedTerminator,
    /// An escape was seen and the next byte says what it introduces.
    Escape,
    /// Inside an OSC, collecting enough of its number to know what it is.
    OscNumber,
    /// Inside a string this export keeps, which ends at ST or BEL.
    KeptString,
    /// Inside a string this export removes.
    RemovedString,
}

/// The recogniser, kept across the whole recording.
///
/// It is deliberately narrow. It recognises the string sequences that act on the reader's machine,
/// removes them whole, and passes everything else through byte for byte: colours, cursor movement
/// and screen clears are rendering data and are what makes the recording worth keeping.
#[derive(Debug)]
struct Stripper {
    phase: Phase,
    /// The OSC number as it is being read.
    number: String,
    /// What the current removed string was, so it can be declared once it ends.
    removing: &'static str,
    /// Text held back while it is not yet known whether it belongs to a removed sequence.
    held: String,
    /// Each removed kind and how many times it was removed.
    removed: Vec<(&'static str, u64)>,
}

impl Stripper {
    fn new() -> Self {
        Self {
            phase: Phase::Text,
            number: String::new(),
            removing: OTHER_STRING,
            held: String::new(),
            removed: Vec::new(),
        }
    }

    fn note(&mut self, kind: &'static str) {
        match self.removed.iter_mut().find(|(seen, _)| *seen == kind) {
            Some(entry) => entry.1 += 1,
            None => self.removed.push((kind, 1)),
        }
    }

    /// Whether an OSC with this number is removed.
    ///
    /// 52 writes the clipboard. 7 and 9 report a working directory a shell may act on. Everything
    /// else, including the window title, only changes what the reader sees.
    fn osc_is_removed(number: &str) -> Option<&'static str> {
        match number {
            "52" => Some(CLIPBOARD_WRITE),
            "7" | "9" => Some(WORKING_DIRECTORY),
            _ => None,
        }
    }

    /// Folds one frame of recorded output in, and returns what may be replayed.
    fn feed(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for character in text.chars() {
            match self.phase {
                Phase::Text => {
                    if character == '\u{1b}' {
                        self.phase = Phase::Escape;
                        self.held.push(character);
                    } else {
                        out.push(character);
                    }
                }
                Phase::Escape => match character {
                    ']' => {
                        self.phase = Phase::OscNumber;
                        self.number.clear();
                        self.held.push(character);
                    }
                    'P' | '_' | '^' | 'X' => {
                        // A device-control string, an application-program command, a privacy
                        // message or a start-of-string: each carries a payload something
                        // interprets, and none of them draws the recorded screen.
                        self.phase = Phase::RemovedString;
                        self.removing = if character == 'P' {
                            DEVICE_CONTROL
                        } else {
                            OTHER_STRING
                        };
                        self.held.clear();
                    }
                    _ => {
                        // Any other escape sequence is rendering data. It goes through with the
                        // escape that introduced it.
                        out.push_str(&self.held);
                        self.held.clear();
                        out.push(character);
                        self.phase = Phase::Text;
                    }
                },
                Phase::OscNumber => {
                    if character.is_ascii_digit() && self.number.len() < 4 {
                        self.number.push(character);
                        self.held.push(character);
                    } else if character == ';' {
                        match Self::osc_is_removed(&self.number) {
                            Some(kind) => {
                                self.phase = Phase::RemovedString;
                                self.removing = kind;
                                self.held.clear();
                            }
                            None => {
                                self.phase = Phase::KeptString;
                                out.push_str(&self.held);
                                out.push(character);
                                self.held.clear();
                            }
                        }
                    } else if is_cancel(character) {
                        // The terminal abandons the sequence, and so does this.
                        self.held.clear();
                        self.phase = Phase::Text;
                    } else {
                        // An OSC with no number, or something that is not one: keep it as it is.
                        self.phase = Phase::KeptString;
                        out.push_str(&self.held);
                        out.push(character);
                        self.held.clear();
                    }
                }
                Phase::KeptString => {
                    out.push(character);
                    if character == '\u{7}' || is_cancel(character) {
                        self.phase = Phase::Text;
                    } else if character == '\u{1b}' {
                        // Either the string terminator or a new sequence; either way the next
                        // character decides, and both are rendering data here.
                        self.phase = Phase::Escape;
                        self.held.clear();
                        self.held.push(character);
                        out.pop();
                    }
                }
                Phase::RemovedString => {
                    if character == '\u{7}' {
                        self.note(self.removing);
                        self.phase = Phase::Text;
                    } else if is_cancel(character) {
                        // Cancelled: nothing was removed and nothing was replayed.
                        self.phase = Phase::Text;
                    } else if character == '\u{1b}' {
                        self.held.clear();
                        self.held.push(character);
                        self.phase = Phase::RemovedTerminator;
                    }
                }
                Phase::RemovedTerminator => {
                    if character == '\\' {
                        self.note(self.removing);
                        self.phase = Phase::Text;
                        self.held.clear();
                    } else {
                        // Still inside the removed payload: an escape that is not a terminator is
                        // part of it.
                        self.phase = Phase::RemovedString;
                        self.held.clear();
                    }
                }
            }
        }
        out
    }

    /// What the recording does not carry, once every frame has been folded in.
    ///
    /// A sequence still open at the end of the recording is one the terminal never completed, so
    /// what was held back is never replayed and is declared like any other removal.
    fn finish(&mut self) -> Vec<Omission> {
        if matches!(self.phase, Phase::RemovedString | Phase::RemovedTerminator) {
            self.note(self.removing);
        }
        self.removed
            .iter()
            .map(|(kind, count)| Omission {
                kind: (*kind).to_owned(),
                detail: detail_of(kind).to_owned(),
                count: *count,
            })
            .collect()
    }
}

/// Whether a character cancels a string sequence, as CAN and SUB do.
const fn is_cancel(character: char) -> bool {
    matches!(character, '\u{18}' | '\u{1a}')
}

/// What an omission is called, in words.
fn detail_of(kind: &str) -> &'static str {
    match kind {
        CLIPBOARD_WRITE => "a clipboard write recorded from the session",
        WORKING_DIRECTORY => "a working-directory report",
        DEVICE_CONTROL => "a device-control string",
        _ => "an application string a terminal would interpret",
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
        assert!(
            cast.body.contains("beforeafter"),
            "the text around it is kept"
        );
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
        assert!(
            body.contains("ab"),
            "the payload and its terminator both go"
        );
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
        assert!(
            cast.body.contains("[31m"),
            "rendering data is safe and is kept"
        );
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
    fn a_clipboard_write_split_across_two_frames_is_still_removed() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[
                Frame {
                    at_ms: 0,
                    text: "before\u{1b}]5".into(),
                },
                Frame {
                    at_ms: 10,
                    text: "2;c;c2VjcmV0\u{7}after".into(),
                },
            ],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(
            !cast.body.contains("c2VjcmV0"),
            "a sequence split across a frame boundary is still one sequence"
        );
        assert!(cast.body.contains("before"));
        assert!(cast.body.contains("after"));
        assert_eq!(cast.omissions[0].kind, "clipboard_write");
    }

    #[test]
    fn a_cancelled_sequence_removes_nothing_and_keeps_what_follows() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "a\u{1b}]52;c;partial\u{18}kept text".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(
            cast.body.contains("kept text"),
            "a terminal abandons a cancelled sequence and resumes; so does this"
        );
        assert!(!cast.body.contains("partial"));
    }

    #[test]
    fn a_window_title_survives_because_it_only_changes_what_the_reader_sees() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]0;the session\u{7}done".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(cast.body.contains("the session"));
        assert!(cast.omissions.is_empty());
    }

    #[test]
    fn a_hyperlink_survives_because_it_is_rendering_data() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]8;;https://example.org\u{1b}\\link\u{1b}]8;;\u{1b}\\".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(cast.body.contains("https://example.org"));
        assert!(cast.body.contains("link"));
        assert!(cast.omissions.is_empty());
    }

    #[test]
    fn a_sequence_left_open_at_the_end_is_declared_rather_than_replayed() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "x\u{1b}]52;c;half".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains("half"));
        assert_eq!(cast.omissions[0].kind, "clipboard_write");
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
