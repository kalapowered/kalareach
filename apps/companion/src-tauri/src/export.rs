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

/// What an export removes, and what it is called when it declares the removal.
const CLIPBOARD_WRITE: &str = "clipboard_write";
const WORKING_DIRECTORY: &str = "working_directory_report";
const NOTIFICATION: &str = "notification";
const TERMINAL_QUERY: &str = "terminal_query";
const DEVICE_CONTROL: &str = "device_control_string";
const OTHER_STRING: &str = "application_string";

/// How much of one string sequence is held while it is decided on.
///
/// An operating-system command that draws something is short. One longer than this is not display
/// data anyone is missing, and holding an unbounded one would let a recording decide how much
/// memory an export uses.
const MAX_HELD_STRING: usize = 8 * 1024;

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
    /// An escape was seen and the next character says what it introduces.
    Escape,
    /// Inside an operating-system command, holding it until its end decides what it was.
    Osc,
    /// Inside an operating-system command, having just seen an escape.
    OscEscape,
    /// Inside a string that is removed whatever it turns out to say.
    Removed,
    /// Inside a removed string, having just seen an escape.
    RemovedEscape,
}

/// The recogniser, kept across the whole recording.
///
/// A recording is read back by writing it to a terminal, so the question for every sequence is
/// what it would do to the terminal that plays it. Drawing is what the recording is for.
/// Everything else -- writing the reader's clipboard, telling a shell where to be, raising a
/// notification, asking the terminal a question it will answer into the reader's input -- is a
/// side effect the reader did not ask for, and section 25 does not permit replaying one.
///
/// So an operating-system command is held until its terminator and then decided on against a list
/// of the ones that only draw. A device-control string, an application-program command, a privacy
/// message and a start-of-string are removed outright: each carries a payload something
/// interprets. Everything that is not a string sequence -- colours, cursor movement, screen
/// clears, every ordinary escape -- passes through byte for byte.
///
/// It is one recogniser for the whole recording, because a terminal does not restart at a frame
/// boundary: `ESC ]5` at the end of one frame and `2;c;…` at the start of the next is one
/// clipboard write.
#[derive(Debug)]
struct Stripper {
    phase: Phase,
    /// The operating-system command being held, without its introducer.
    held: String,
    /// True when what is held grew past the bound and is removed whatever it says.
    overlong: bool,
    /// What the current removed string is, so it can be declared once it ends.
    removing: &'static str,
    /// Each removed kind and how many times it was removed.
    removed: Vec<(&'static str, u64)>,
}

/// The string terminator's own character, which a recording may carry instead of `ESC \\`.
const ST: char = '\u{9c}';

impl Stripper {
    fn new() -> Self {
        Self {
            phase: Phase::Text,
            held: String::new(),
            overlong: false,
            removing: OTHER_STRING,
            removed: Vec::new(),
        }
    }

    fn note(&mut self, kind: &'static str) {
        match self.removed.iter_mut().find(|(seen, _)| *seen == kind) {
            Some(entry) => entry.1 += 1,
            None => self.removed.push((kind, 1)),
        }
    }

    /// Whether an operating-system command only draws, and so may be replayed.
    ///
    /// An allowlist rather than a deny list, because "safe rendering data" is a property a
    /// sequence has to earn: an extension nobody here has heard of is not known to be safe.
    ///
    /// A colour command that carries `?` is a query, and a query makes the reader's terminal write
    /// an answer into the reader's input. That is a side effect whichever selector asks it.
    fn osc_is_kept(payload: &str) -> std::result::Result<(), &'static str> {
        let (selector, rest) = payload.split_once(';').unwrap_or((payload, ""));
        let Ok(number) = selector.trim().parse::<u32>() else {
            // An operating-system command with no numeric selector is not one this recogniser can
            // place, so it is not replayed.
            return Err(OTHER_STRING);
        };
        match number {
            52 => return Err(CLIPBOARD_WRITE),
            7 => return Err(WORKING_DIRECTORY),
            // 9 is a notification on one terminal and a working-directory report on another. Both
            // act on the machine that plays the recording back.
            9 | 99 | 777 => return Err(NOTIFICATION),
            _ => {}
        }
        let draws = matches!(number, 0 | 1 | 2 | 8 | 104 | 105)
            || matches!(number, 4 | 5 | 10..=19 | 110..=119);
        if !draws {
            return Err(OTHER_STRING);
        }
        if rest.contains('?') {
            return Err(TERMINAL_QUERY);
        }
        Ok(())
    }

    /// Ends the held operating-system command, deciding whether it may be replayed.
    fn finish_osc(&mut self, terminator: &str, out: &mut String) {
        let held = std::mem::take(&mut self.held);
        let overlong = std::mem::replace(&mut self.overlong, false);
        self.phase = Phase::Text;
        if overlong {
            self.note(OTHER_STRING);
            return;
        }
        match Self::osc_is_kept(&held) {
            Ok(()) => {
                out.push('\u{1b}');
                out.push(']');
                out.push_str(&held);
                out.push_str(terminator);
            }
            Err(kind) => self.note(kind),
        }
    }

    /// Abandons whatever is being held, as a terminal does when a string sequence is cancelled.
    fn cancel(&mut self) {
        self.held.clear();
        self.overlong = false;
        self.phase = Phase::Text;
    }

    /// Folds one frame of recorded output in, and returns what may be replayed.
    fn feed(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for character in text.chars() {
            match self.phase {
                Phase::Text => match character {
                    '\u{1b}' => self.phase = Phase::Escape,
                    // The eight-bit forms of the same introducers.
                    '\u{9d}' => {
                        self.phase = Phase::Osc;
                        self.held.clear();
                        self.overlong = false;
                    }
                    '\u{90}' => self.start_removed(DEVICE_CONTROL),
                    '\u{9f}' | '\u{98}' | '\u{9e}' => self.start_removed(OTHER_STRING),
                    _ => out.push(character),
                },
                Phase::Escape => match character {
                    ']' => {
                        self.phase = Phase::Osc;
                        self.held.clear();
                        self.overlong = false;
                    }
                    'P' => self.start_removed(DEVICE_CONTROL),
                    '_' | '^' | 'X' => self.start_removed(OTHER_STRING),
                    // A second escape abandons the first and introduces a new sequence, which is
                    // what a terminal does with it.
                    '\u{1b}' => {}
                    _ if is_cancel(character) => self.phase = Phase::Text,
                    _ => {
                        // Every other escape sequence is rendering data.
                        out.push('\u{1b}');
                        out.push(character);
                        self.phase = Phase::Text;
                    }
                },
                Phase::Osc => match character {
                    '\u{7}' => self.finish_osc("\u{7}", &mut out),
                    ST => self.finish_osc("\u{9c}", &mut out),
                    '\u{1b}' => self.phase = Phase::OscEscape,
                    _ if is_cancel(character) => self.cancel(),
                    _ => {
                        if self.held.len() >= MAX_HELD_STRING {
                            self.overlong = true;
                        } else {
                            self.held.push(character);
                        }
                    }
                },
                Phase::OscEscape => {
                    if character == '\\' {
                        self.finish_osc("\u{1b}\\", &mut out);
                    } else {
                        // An escape inside a string that is not its terminator abandons the string
                        // and starts a new sequence. What follows is text the reader should see,
                        // so the string ends here and is decided on as it stands.
                        self.finish_osc("", &mut out);
                        self.phase = Phase::Escape;
                        // The character that followed the escape is this new sequence's, so it is
                        // handled by the escape branch on the next pass.
                        match character {
                            ']' => {
                                self.phase = Phase::Osc;
                                self.held.clear();
                                self.overlong = false;
                            }
                            'P' => self.start_removed(DEVICE_CONTROL),
                            '_' | '^' | 'X' => self.start_removed(OTHER_STRING),
                            '\u{1b}' => self.phase = Phase::Escape,
                            _ if is_cancel(character) => self.phase = Phase::Text,
                            _ => {
                                out.push('\u{1b}');
                                out.push(character);
                                self.phase = Phase::Text;
                            }
                        }
                    }
                }
                Phase::Removed => match character {
                    // A device-control string and its neighbours end at the string terminator and
                    // at nothing else: a bell inside one is part of its payload.
                    ST => {
                        self.note(self.removing);
                        self.phase = Phase::Text;
                    }
                    '\u{1b}' => self.phase = Phase::RemovedEscape,
                    _ if is_cancel(character) => self.phase = Phase::Text,
                    _ => {}
                },
                Phase::RemovedEscape => {
                    if character == '\\' {
                        self.note(self.removing);
                        self.phase = Phase::Text;
                    } else if is_cancel(character) {
                        self.phase = Phase::Text;
                    } else {
                        // The string is abandoned and a new sequence begins. The removal is
                        // declared, and what follows is the reader's again.
                        self.note(self.removing);
                        match character {
                            ']' => {
                                self.phase = Phase::Osc;
                                self.held.clear();
                                self.overlong = false;
                            }
                            'P' => self.start_removed(DEVICE_CONTROL),
                            '_' | '^' | 'X' => self.start_removed(OTHER_STRING),
                            '\u{1b}' => self.phase = Phase::Escape,
                            _ => {
                                out.push('\u{1b}');
                                out.push(character);
                                self.phase = Phase::Text;
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn start_removed(&mut self, kind: &'static str) {
        self.phase = Phase::Removed;
        self.removing = kind;
        self.held.clear();
        self.overlong = false;
    }

    /// What the recording does not carry, once every frame has been folded in.
    ///
    /// A sequence still open at the end is one the terminal never completed. Nothing held back is
    /// replayed, and the removal is declared like any other.
    fn finish(&mut self) -> Vec<Omission> {
        match self.phase {
            Phase::Removed | Phase::RemovedEscape => self.note(self.removing),
            Phase::Osc | Phase::OscEscape => {
                let held = std::mem::take(&mut self.held);
                let kind = if self.overlong {
                    OTHER_STRING
                } else {
                    Self::osc_is_kept(&held).err().unwrap_or(OTHER_STRING)
                };
                self.note(kind);
            }
            Phase::Text | Phase::Escape => {}
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
        NOTIFICATION => "a notification the session raised",
        TERMINAL_QUERY => "a question the terminal would have answered",
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

    /// Drives one string through the recogniser at every split point it has.
    ///
    /// A recording is frames, and a terminal does not restart at a frame boundary. A filter that
    /// worked on whole sequences and not on split ones would pass a clipboard write through as
    /// soon as the output happened to arrive in two pieces.
    fn at_every_split(text: &str) -> Vec<(String, Vec<Omission>)> {
        let indices: Vec<usize> = (0..=text.len())
            .filter(|index| text.is_char_boundary(*index))
            .collect();
        indices
            .iter()
            .map(|split| {
                let (left, right) = text.split_at(*split);
                let cast = asciicast(
                    dimensions(),
                    1,
                    "s-1",
                    &[
                        Frame {
                            at_ms: 0,
                            text: left.to_owned(),
                        },
                        Frame {
                            at_ms: 1,
                            text: right.to_owned(),
                        },
                    ],
                    Vec::new(),
                )
                .expect("a valid recording");
                // What a terminal would receive is the frames' text in order, whatever the split
                // was, so that is what the assertions are about.
                let replayed: String = cast
                    .body
                    .lines()
                    .skip(1)
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .filter_map(|event| event[2].as_str().map(str::to_owned))
                    .collect();
                (replayed, cast.omissions)
            })
            .collect()
    }

    #[test]
    fn a_clipboard_write_is_removed_however_the_frames_fall() {
        for (body, omissions) in at_every_split("before\u{1b}]52;c;c2VjcmV0\u{7}after") {
            assert!(
                !body.contains("c2VjcmV0"),
                "a clipboard write reached the recording"
            );
            assert!(body.contains("before"), "text before it was lost");
            assert!(body.contains("after"), "text after it was lost");
            assert_eq!(omissions[0].kind, "clipboard_write");
        }
    }

    #[test]
    fn a_selector_written_with_a_leading_zero_is_the_same_selector() {
        for (body, omissions) in at_every_split("a\u{1b}]052;c;c2VjcmV0\u{1b}\\b") {
            assert!(!body.contains("c2VjcmV0"), "052 is 52");
            assert_eq!(omissions[0].kind, "clipboard_write");
            assert!(body.contains("ab"));
        }
    }

    #[test]
    fn an_abandoned_escape_does_not_smuggle_a_clipboard_write_past_the_filter() {
        // A terminal treats the second escape as the start of a new sequence, so this is one
        // clipboard write with a discarded escape in front of it.
        for (body, omissions) in at_every_split("a\u{1b}\u{1b}]52;c;c2VjcmV0\u{7}b") {
            assert!(!body.contains("c2VjcmV0"));
            assert_eq!(omissions[0].kind, "clipboard_write");
        }
    }

    #[test]
    fn a_bell_inside_a_device_control_string_is_payload_rather_than_its_end() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "x\u{1b}P+q\u{7}still inside\u{1b}\\y".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(
            !cast.body.contains("still inside"),
            "a device-control string ends at the string terminator and nothing else"
        );
        assert!(cast.body.contains("xy"));
        assert_eq!(cast.omissions[0].kind, "device_control_string");
    }

    #[test]
    fn a_colour_query_is_removed_because_the_terminal_would_answer_it() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]4;1;?\u{7}done".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains("4;1;?"));
        assert_eq!(cast.omissions[0].kind, "terminal_query");
        assert!(cast.body.contains("done"));
    }

    #[test]
    fn a_colour_that_is_set_rather_than_asked_about_survives() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]4;1;rgb:ff/00/00\u{7}done".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(cast.body.contains("rgb:ff/00/00"));
        assert!(cast.omissions.is_empty());
    }

    #[test]
    fn an_escape_inside_a_removed_string_gives_the_reader_what_follows_it() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]52;x\u{1b}[31mRED".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(
            cast.body.contains("[31m"),
            "the colour change is the reader's"
        );
        assert!(cast.body.contains("RED"));
        assert_eq!(cast.omissions[0].kind, "clipboard_write");
    }

    #[test]
    fn a_notification_is_not_raised_on_the_machine_that_plays_the_recording() {
        for selector in ["9", "99", "777"] {
            let cast = asciicast(
                dimensions(),
                1,
                "s-1",
                &[Frame {
                    at_ms: 0,
                    text: format!("\u{1b}]{selector};build finished\u{7}ok"),
                }],
                Vec::new(),
            )
            .expect("a valid recording");
            assert!(
                !cast.body.contains("build finished"),
                "{selector} was replayed"
            );
            assert!(cast.body.contains("ok"));
        }
    }

    #[test]
    fn the_eight_bit_introducer_is_the_same_introducer() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "a\u{9d}52;c;c2VjcmV0\u{9c}b".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains("c2VjcmV0"));
        assert_eq!(cast.omissions[0].kind, "clipboard_write");
    }

    #[test]
    fn an_extension_nobody_here_knows_is_not_assumed_to_be_safe() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]1337;File=inline=1:AAAA\u{7}after".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains("1337"));
        assert!(cast.body.contains("after"));
        assert_eq!(cast.omissions[0].kind, "application_string");
    }

    #[test]
    fn a_string_longer_than_the_bound_is_removed_rather_than_held() {
        let payload = "a".repeat(MAX_HELD_STRING + 64);
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: format!("\u{1b}]0;{payload}\u{7}after"),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(!cast.body.contains(&payload));
        assert!(cast.body.contains("after"));
        assert_eq!(cast.omissions[0].kind, "application_string");
    }

    #[test]
    fn a_cancel_after_an_escape_inside_a_removed_string_still_cancels() {
        let cast = asciicast(
            dimensions(),
            1,
            "s-1",
            &[Frame {
                at_ms: 0,
                text: "\u{1b}]52;c;partial\u{1b}\u{18}kept text".into(),
            }],
            Vec::new(),
        )
        .expect("a valid recording");
        assert!(cast.body.contains("kept text"));
        assert!(!cast.body.contains("partial"));
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
