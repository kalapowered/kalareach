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

/// One screen the raw terminal view drew, with the time it drew it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Milliseconds since the recording began.
    pub at_ms: u64,
    /// The screen, as the drawing a player repeats.
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
const BELL: &str = "bell";
const TERMINAL_CONTROL: &str = "terminal_control";

/// How much of one sequence is held while it is decided on.
///
/// A control sequence the view draws with is a few dozen characters, and what an operating-system
/// command was is in its first few. One longer than this is not drawing anyone is missing, and
/// holding an unbounded one would let a recording decide how much memory an export uses.
const MAX_HELD_SEQUENCE: usize = 8 * 1024;

/// Builds an asciicast recording of the view's drawing: what the view draws with is kept byte for
/// byte, and every other sequence and control is dropped and declared.
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
    /// An escape with intermediates, held until its final character.
    EscapeIntermediate,
    /// A control sequence, held until its final character says whether the view draws with it.
    ControlSequence,
    /// Inside an operating-system command, holding its start until its end.
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
/// what it would do to the terminal that plays it. Drawing is what the recording is for, and what
/// it holds is the raw terminal view's drawing: each screen written as text between a handful of
/// control sequences, for colours and attributes, the cursor's place, clears of the screen, of the
/// end of a line and of a run of cells, line wrapping off and on, and the cursor shown or hidden.
/// Those are kept byte for byte, with text and the four controls a line of text is drawn with:
/// backspace, tab, line feed and carriage return.
///
/// Nothing else is the view's drawing, and replaying it would act on the reader's machine: a
/// question the terminal answers into the reader's input, such as a cursor-position or
/// device-attributes report; a change to how the terminal reports keys or the mouse, or to its
/// modes, window, title or colours, which outlasts the recording; a bell; writing the reader's
/// clipboard, telling a shell where to be, raising a notification. Section 25 does not permit
/// replaying any of them. So every sequence is held until it is complete and then decided on
/// against the list of those the view draws with, and one that is not on it is removed and
/// declared by what it would have done. Operating-system commands, device-control strings,
/// application-program commands, privacy messages and start-of-strings are never on it: the view
/// draws with none, and each carries a payload something interprets.
///
/// Inside an escape or a control sequence, a C0 control or a delete is handled where it is met, as
/// it is anywhere, and the sequence goes on. A cancel, a new escape or an eight-bit control
/// abandons the sequence, and so does a character that cannot follow an escape; the character is
/// then read as it would be anywhere. A terminal does the same with each, so what is kept is read
/// by the terminal that plays it as exactly the sequence it was kept as.
///
/// Every character is written out, held until its sequence is decided, or left out and declared.
/// An abandoned sequence is declared too, though a terminal would do nothing with it, so nothing
/// is ever left out silently.
///
/// It is one recogniser for the whole recording, because a terminal does not restart at a frame
/// boundary: `ESC ]5` at the end of one frame and `2;c;…` at the start of the next is one
/// clipboard write.
#[derive(Debug)]
struct Stripper {
    phase: Phase,
    /// The start of the operating-system command being held, without its introducer.
    held: String,
    /// The control sequence or escape being held, from its introducer.
    sequence: String,
    /// True when the sequence grew past the bound and is removed whatever it says.
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
            sequence: String::new(),
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

    /// What an operating-system command would have done, which is how its removal is declared.
    ///
    /// A colour command whose value is `?` is a query, and a query makes the reader's terminal
    /// write an answer into the reader's input.
    fn osc_kind(payload: &str) -> &'static str {
        let (selector, rest) = payload.split_once(';').unwrap_or((payload, ""));
        match selector.trim().parse::<u32>() {
            Ok(52) => CLIPBOARD_WRITE,
            Ok(7) => WORKING_DIRECTORY,
            // 9 is a notification on one terminal and a working-directory report on another. Both
            // act on the machine that plays the recording back.
            Ok(9 | 99 | 777) => NOTIFICATION,
            Ok(4 | 5 | 10..=19) if rest.split(';').any(|value| value == "?") => TERMINAL_QUERY,
            // A title, a hyperlink, a colour set, an extension nobody here knows, or a command with
            // no numeric selector at all.
            _ => OTHER_STRING,
        }
    }

    /// Leaves out whatever is held, declares it by what it is, and goes back to text.
    ///
    /// A string ends at its terminator. Any sequence can also be abandoned, by a cancel, a new
    /// escape, an eight-bit control or a character that cannot follow an escape, or still be open
    /// when the recording ends. A terminal does nothing with an abandoned sequence, but the
    /// recording leaves it out all the same, and says so: nothing is left out silently.
    fn leave_out(&mut self) {
        let kind = match self.phase {
            Phase::Text => None,
            Phase::Escape | Phase::EscapeIntermediate | Phase::ControlSequence => {
                Some(TERMINAL_CONTROL)
            }
            Phase::Osc | Phase::OscEscape => Some(Self::osc_kind(&self.held)),
            Phase::Removed | Phase::RemovedEscape => Some(self.removing),
        };
        if let Some(kind) = kind {
            self.note(kind);
        }
        self.phase = Phase::Text;
        self.held.clear();
        self.sequence.clear();
        self.overlong = false;
    }

    /// Folds one frame of recorded output in, and returns what may be replayed.
    fn feed(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for character in text.chars() {
            match self.phase {
                Phase::Text => self.text(character, &mut out),
                Phase::Escape => self.escape(character, &mut out),
                Phase::EscapeIntermediate | Phase::ControlSequence => {
                    self.in_sequence(character, &mut out);
                }
                Phase::Osc => match character {
                    // A bell or the string terminator ends it, and a cancel abandons it.
                    '\u{7}' | ST => self.leave_out(),
                    _ if is_cancel(character) => self.leave_out(),
                    '\u{1b}' => self.phase = Phase::OscEscape,
                    _ => {
                        if self.held.len() < MAX_HELD_SEQUENCE {
                            self.held.push(character);
                        }
                    }
                },
                Phase::Removed => match character {
                    // A device-control string and its neighbours end at the string terminator and
                    // at nothing else: a bell inside one is part of its payload.
                    ST => self.leave_out(),
                    _ if is_cancel(character) => self.leave_out(),
                    '\u{1b}' => self.phase = Phase::RemovedEscape,
                    _ => {}
                },
                Phase::OscEscape | Phase::RemovedEscape => {
                    // The string ends at its terminator. Any other escape inside it abandons the
                    // string and is a new escape, and what follows it is read as it would be after
                    // any escape.
                    self.leave_out();
                    if character != '\\' {
                        self.phase = Phase::Escape;
                        self.escape(character, &mut out);
                    }
                }
            }
        }
        out
    }

    /// A character met outside any sequence.
    fn text(&mut self, character: char, out: &mut String) {
        match character {
            '\u{1b}' => self.phase = Phase::Escape,
            // The eight-bit forms of the introducers.
            '\u{9b}' => self.start_sequence(Phase::ControlSequence, "\u{9b}"),
            '\u{9d}' => self.start_osc(),
            '\u{90}' => self.start_removed(DEVICE_CONTROL),
            '\u{98}' | '\u{9e}' | '\u{9f}' => self.start_removed(OTHER_STRING),
            _ if character.is_control() => self.control(character, out),
            _ => out.push(character),
        }
    }

    /// The character after a held escape, wherever the escape was met.
    fn escape(&mut self, character: char, out: &mut String) {
        match character {
            '[' => self.start_sequence(Phase::ControlSequence, "\u{1b}["),
            ']' => self.start_osc(),
            'P' => self.start_removed(DEVICE_CONTROL),
            'X' | '^' | '_' => self.start_removed(OTHER_STRING),
            ' '..='/' => {
                self.start_sequence(Phase::EscapeIntermediate, "\u{1b}");
                self.hold(character);
            }
            // An escape and one character. The view draws with none of them, and one asks the
            // terminal to identify itself.
            '0'..='~' => {
                self.phase = Phase::Text;
                self.note(if character == 'Z' {
                    TERMINAL_QUERY
                } else {
                    TERMINAL_CONTROL
                });
            }
            _ => self.interrupt(character, out),
        }
    }

    /// One character inside a held control sequence or escape with intermediates.
    fn in_sequence(&mut self, character: char, out: &mut String) {
        if character.is_control() {
            self.interrupt(character, out);
            return;
        }
        self.hold(character);
        let finals = if self.phase == Phase::ControlSequence {
            '@'..='~'
        } else {
            '0'..='~'
        };
        if finals.contains(&character) {
            self.finish_sequence(out);
        }
    }

    /// A control, or a character that cannot follow an escape, met while an escape or a control
    /// sequence is held.
    ///
    /// A C0 control or a delete is handled where it is met, as it is anywhere, and what is held
    /// goes on: a terminal carries out the one and ignores the other. A new escape, a cancel, an
    /// eight-bit control or any other character abandons what is held, as it does in a terminal,
    /// and what was held is left out and declared; the character is then read as it would be
    /// anywhere, except a cancel, which is spent on what it cancelled.
    fn interrupt(&mut self, character: char, out: &mut String) {
        if character.is_ascii_control() && character != '\u{1b}' && !is_cancel(character) {
            self.control(character, out);
            return;
        }
        self.leave_out();
        if !is_cancel(character) {
            self.text(character, out);
        }
    }

    /// A control character met outside a string. The four a line of text is drawn with are kept,
    /// and every other is removed and declared: none of them draws, and some act on the terminal.
    fn control(&mut self, character: char, out: &mut String) {
        match character {
            '\u{8}' | '\t' | '\n' | '\r' => out.push(character),
            // Enquiry asks a terminal for its answerback message, and the eight-bit form of the
            // identification request asks it to identify itself.
            '\u{5}' | '\u{9a}' => self.note(TERMINAL_QUERY),
            '\u{7}' => self.note(BELL),
            _ => self.note(TERMINAL_CONTROL),
        }
    }

    fn start_sequence(&mut self, phase: Phase, introducer: &str) {
        self.phase = phase;
        self.sequence.clear();
        self.sequence.push_str(introducer);
        self.overlong = false;
    }

    /// Holds one more character of the control sequence or escape.
    fn hold(&mut self, character: char) {
        if self.sequence.len() >= MAX_HELD_SEQUENCE {
            self.overlong = true;
        } else {
            self.sequence.push(character);
        }
    }

    /// Ends the held control sequence or escape: kept byte for byte when the view draws with it,
    /// and removed and declared otherwise.
    fn finish_sequence(&mut self, out: &mut String) {
        let sequence = std::mem::take(&mut self.sequence);
        let overlong = std::mem::replace(&mut self.overlong, false);
        let phase = std::mem::replace(&mut self.phase, Phase::Text);
        let decided = match phase {
            Phase::ControlSequence if !overlong => control_sequence(&sequence),
            _ => Err(TERMINAL_CONTROL),
        };
        match decided {
            Ok(()) => out.push_str(&sequence),
            Err(kind) => self.note(kind),
        }
    }

    fn start_osc(&mut self) {
        self.phase = Phase::Osc;
        self.held.clear();
    }

    fn start_removed(&mut self, kind: &'static str) {
        self.phase = Phase::Removed;
        self.removing = kind;
        self.held.clear();
    }

    /// What the recording does not carry, once every frame has been folded in.
    ///
    /// A sequence still open at the end, a lone escape included, is one the terminal never
    /// completed. Nothing held back is replayed, and the removal is declared like any other.
    fn finish(&mut self) -> Vec<Omission> {
        self.leave_out();
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

/// Whether the view draws with a whole control sequence, and what it would have done if not.
///
/// The view writes each screen with these and no others: select graphic rendition, the cursor's
/// position, a clear of the screen or of part of a line, a clear of a run of cells, and line
/// wrapping or the cursor turned off or on, each without a mode it does not set beside it. A clear
/// of the lines scrolled off the screen is not one of them: those lines are the reader's own. Any
/// other sequence is declared as a question when the terminal would answer it, and as a control
/// the view does not draw with otherwise.
fn control_sequence(sequence: &str) -> std::result::Result<(), &'static str> {
    let body = sequence
        .strip_prefix("\u{1b}[")
        .or_else(|| sequence.strip_prefix('\u{9b}'))
        .unwrap_or(sequence);
    let Some(last) = body.chars().last() else {
        return Err(TERMINAL_CONTROL);
    };
    let head = &body[..body.len() - last.len_utf8()];
    // Parameters, then intermediates. A parameter after an intermediate, or a character that is
    // neither, is not a sequence a terminal reads as the one it looks like.
    let split = head
        .find(|character: char| !('0'..='?').contains(&character))
        .unwrap_or(head.len());
    let (parameters, intermediates) = head.split_at(split);
    if !intermediates
        .chars()
        .all(|character| (' '..='/').contains(&character))
    {
        return Err(TERMINAL_CONTROL);
    }
    let marker = parameters
        .chars()
        .next()
        .filter(|character| ('<'..='?').contains(character));
    let parameters = if marker.is_some() {
        &parameters[1..]
    } else {
        parameters
    };
    if parameters.contains(|character: char| ('<'..='?').contains(&character)) {
        return Err(TERMINAL_CONTROL);
    }
    let digits_and = |separators: &[char]| {
        parameters
            .chars()
            .all(|character| character.is_ascii_digit() || separators.contains(&character))
    };
    let draws = match (marker, intermediates, last) {
        (None, "", 'm') => digits_and(&[';', ':']),
        (None, "", 'H') => digits_and(&[';']),
        (None, "", 'X') => digits_and(&[]),
        (None, "", 'J' | 'K') => {
            parameters.is_empty() || matches!(parameters.parse::<u32>(), Ok(0..=2))
        }
        (Some('?'), "", 'h' | 'l') => parameters
            .split(';')
            .all(|mode| matches!(mode.parse::<u32>(), Ok(7 | 25))),
        _ => false,
    };
    if draws {
        Ok(())
    } else if asks(marker, parameters, intermediates, last) {
        Err(TERMINAL_QUERY)
    } else {
        Err(TERMINAL_CONTROL)
    }
}

/// Whether a control sequence asks the terminal to answer: for its status or the cursor's place,
/// its attributes, a mode's state, its name and version, its window's state, place, size or
/// title, its keyboard protocol or key modifiers, its parameters, a checksum of part of the
/// screen, its presentation state, its tab stops, its locator, its colours or its graphics.
fn asks(marker: Option<char>, parameters: &str, intermediates: &str, last: char) -> bool {
    match (marker, intermediates, last) {
        (None | Some('?'), "", 'n') | (_, "", 'c') | (None | Some('?'), "$", 'p') => true,
        (Some('>'), "", 'q') | (Some('?'), "", 'u' | 'm' | 'S') | (None, "", 'x') => true,
        (None, "*", 'y') | (None, "$", 'w' | 'u') | (None, "'", '|') => true,
        (None, "#", '|' | 'R') => true,
        (None, "", 't') => matches!(
            parameters.split(';').next().map(str::parse::<u32>),
            Some(Ok(11 | 13 | 14 | 15 | 16 | 18 | 19 | 20 | 21))
        ),
        _ => false,
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
        BELL => "a bell, which would ring where the recording is played",
        TERMINAL_CONTROL => {
            "a control the view does not draw with, such as one that changes how the terminal \
             reports keys or the mouse"
        }
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
        // One omission the caller supplies, and one the recording causes by holding a clipboard
        // write: the header lists both, in that order, each with its kind, words and count.
        let supplied = Omission {
            kind: "privacy_generation".into(),
            detail: "content this session never retained".into(),
            count: 4,
        };
        let cast = asciicast(
            dimensions(),
            1_700_000_000,
            "s-1",
            &[
                Frame {
                    at_ms: 250,
                    text: "hello\r\n".into(),
                },
                Frame {
                    at_ms: 300,
                    text: "\u{1b}]52;c;c2VjcmV0\u{7}".into(),
                },
            ],
            vec![supplied.clone()],
        )
        .expect("a valid recording");
        let mut lines = cast.body.lines();
        let header: serde_json::Value =
            serde_json::from_str(lines.next().expect("a header")).expect("valid JSON");
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);
        assert_eq!(header["height"], 40);
        assert_eq!(header["timestamp"], 1_700_000_000_u64);
        assert_eq!(
            header["kalareach"]["omissions"],
            serde_json::json!([
                {
                    "kind": "privacy_generation",
                    "detail": "content this session never retained",
                    "count": 4
                },
                {
                    "kind": "clipboard_write",
                    "detail": detail_of(CLIPBOARD_WRITE),
                    "count": 1
                }
            ]),
            "the header lists the omission supplied and the one caused, whole"
        );
        assert_eq!(
            cast.omissions,
            [
                supplied,
                Omission {
                    kind: CLIPBOARD_WRITE.into(),
                    detail: detail_of(CLIPBOARD_WRITE).into(),
                    count: 1,
                }
            ],
            "what the recording returns is what its header lists"
        );

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
    fn a_cancelled_sequence_is_left_out_and_declared_and_what_follows_is_kept() {
        // A terminal abandons a cancelled sequence and resumes; so does this, and says what it
        // left out.
        for (body, omissions) in at_every_split("a\u{1b}]52;c;partial\u{18}kept text") {
            assert_eq!(body, "akept text");
            assert_eq!(kinds(&omissions), [("clipboard_write", 1)]);
        }
    }

    #[test]
    fn a_window_title_is_not_replayed_because_the_view_draws_none() {
        // The recording's own header carries its title; a title written to the reader's window
        // would stay there after the recording ended.
        for (body, omissions) in at_every_split("\u{1b}]0;the session\u{7}done") {
            assert_eq!(body, "done");
            assert_eq!(kinds(&omissions), [("application_string", 1)]);
        }
    }

    #[test]
    fn a_hyperlink_is_not_replayed_and_its_text_is() {
        for (body, omissions) in
            at_every_split("\u{1b}]8;;https://example.org\u{1b}\\link\u{1b}]8;;\u{1b}\\")
        {
            assert_eq!(body, "link");
            assert_eq!(kinds(&omissions), [("application_string", 2)]);
        }
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

    /// Each declared omission's kind and how many times it was declared, in the order first met.
    fn kinds(omissions: &[Omission]) -> Vec<(&str, u64)> {
        omissions
            .iter()
            .map(|omission| (omission.kind.as_str(), omission.count))
            .collect()
    }

    /// Screens as the raw terminal view writes them, which the page's own tests check against
    /// what the view draws.
    const DRAWN_SCREENS: &str = include_str!("../../test/fixtures/drawn-screens.json");

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

    /// KR-REQ-25.25: what the view draws with is kept byte for byte, wherever a frame ends, and
    /// nothing is declared.
    #[test]
    fn the_view_s_drawing_is_kept_byte_for_byte_however_the_frames_fall() {
        let fixture: serde_json::Value =
            serde_json::from_str(DRAWN_SCREENS).expect("the drawn screens are JSON");
        let screens: Vec<&str> = fixture["screens"]
            .as_object()
            .expect("the screens by name")
            .values()
            .map(|screen| screen.as_str().expect("a screen's text"))
            .collect();
        assert_eq!(screens.len(), 2);
        for screen in &screens {
            for (body, omissions) in at_every_split(screen) {
                assert_eq!(body, *screen);
                assert!(omissions.is_empty(), "{omissions:?}");
            }
        }
        // Played one after the other, each screen is its own frame, as the view drew it.
        let frames: Vec<Frame> = screens
            .iter()
            .zip(0_u64..)
            .map(|(screen, index)| Frame {
                at_ms: index * 40,
                text: (*screen).to_owned(),
            })
            .collect();
        let cast = asciicast(dimensions(), 1, "s-1", &frames, Vec::new()).expect("a recording");
        let events: Vec<String> = cast
            .body
            .lines()
            .skip(1)
            .map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).expect("an event");
                event[2].as_str().expect("its text").to_owned()
            })
            .collect();
        assert_eq!(events, screens);
        assert!(cast.omissions.is_empty());
    }

    /// What the recogniser writes for `frames`, fed one after another, and what it declares.
    fn filtered(frames: &[&str]) -> (String, Vec<Omission>) {
        let mut stripper = Stripper::new();
        let written: String = frames.iter().map(|frame| stripper.feed(frame)).collect();
        (written, stripper.finish())
    }

    /// Whether `text` holds nothing but printable text, the four controls a line is drawn with,
    /// and whole control sequences the view draws with.
    fn drawing_only(text: &str) -> bool {
        let mut rest = text;
        while let Some(character) = rest.chars().next() {
            let length = match character {
                '\u{1b}' | '\u{9b}' => {
                    let introducer = if character == '\u{1b}' {
                        "\u{1b}["
                    } else {
                        "\u{9b}"
                    };
                    let Some(body) = rest.strip_prefix(introducer) else {
                        return false;
                    };
                    let Some(end) = body.find(|each: char| ('@'..='~').contains(&each)) else {
                        return false;
                    };
                    let length = introducer.len() + end + 1;
                    if control_sequence(&rest[..length]).is_err() {
                        return false;
                    }
                    length
                }
                '\u{8}' | '\t' | '\n' | '\r' => 1,
                _ if character.is_control() => return false,
                _ => character.len_utf8(),
            };
            rest = &rest[length..];
        }
        true
    }

    /// KR-REQ-25.25: whatever a recording is handed, it writes nothing but the view's drawing, and
    /// a recording shorter than what it was handed declares something. Every string of up to four
    /// characters drawn from those that steer the recogniser is fed whole and split in two at every
    /// point, and a split changes nothing. Between them the strings reach every phase the
    /// recogniser has, a removed string of either kind included, and meet each phase with every
    /// character in the list. How many removals each declares, and a sequence past the bound on
    /// what is held, are checked case by case below.
    #[test]
    fn every_input_writes_only_the_view_s_drawing_and_declares_whatever_it_leaves_out() {
        // Text, a parameter, a separator, a private marker, an intermediate, the introducers of a
        // control sequence, an operating-system command, a device-control string and an
        // application-program command, the string terminator's second character, a colour's final
        // and a report's, escape, bell, cancel, return, null, delete, the eight-bit control
        // sequence introducer, string terminator and next line, and a character outside ASCII.
        const STEERING: [char; 22] = [
            'x', '6', ';', '?', ' ', '[', ']', 'P', '_', '\\', 'm', 'n', '\u{1b}', '\u{7}',
            '\u{18}', '\r', '\u{0}', '\u{7f}', '\u{9b}', '\u{9c}', '\u{85}', 'é',
        ];
        let mut longest = vec![String::new()];
        let mut inputs = Vec::new();
        for _ in 0..4 {
            longest = longest
                .iter()
                .flat_map(|prefix| {
                    STEERING.iter().map(move |next| {
                        let mut input = prefix.clone();
                        input.push(*next);
                        input
                    })
                })
                .collect();
            inputs.extend(longest.iter().cloned());
        }
        for input in &inputs {
            let (written, declared) = filtered(&[input.as_str()]);
            assert!(drawing_only(&written), "{input:?} wrote {written:?}");
            // Nothing is ever added, so a shorter recording has left something out.
            if written.chars().count() < input.chars().count() {
                assert!(
                    !declared.is_empty(),
                    "{input:?} left something out silently: {written:?}"
                );
            }
            for (split, _) in input.char_indices().skip(1) {
                let (left, right) = input.split_at(split);
                assert_eq!(
                    filtered(&[left, right]),
                    (written.clone(), declared.clone()),
                    "{input:?} split at {split}"
                );
            }
        }
    }

    #[test]
    fn a_string_ended_by_an_escape_and_an_escape_then_abandoned_are_each_declared() {
        // The escape that ends a string is a new escape, and whatever abandons it (an eight-bit
        // control, a character outside ASCII, another escape, a cancel) leaves it out as well.
        fn check(input: &str, written: &str, declared: &[(&str, u64)]) {
            for (body, omissions) in at_every_split(input) {
                assert_eq!(body, written, "{input:?}");
                assert_eq!(kinds(&omissions), declared, "{input:?}");
            }
        }
        check(
            "\u{1b}P\u{1b}\u{85}",
            "",
            &[("device_control_string", 1), ("terminal_control", 2)],
        );
        check(
            "\u{1b}]0;t\u{1b}éx",
            "éx",
            &[("application_string", 1), ("terminal_control", 1)],
        );
        check(
            "\u{1b}]52;c;x\u{1b}\u{9b}6n",
            "",
            &[
                ("clipboard_write", 1),
                ("terminal_control", 1),
                ("terminal_query", 1),
            ],
        );
        check(
            "\u{1b}P+q\u{1b}\u{1b}[31mx",
            "\u{1b}[31mx",
            &[("device_control_string", 1), ("terminal_control", 1)],
        );
        check(
            "\u{1b}_a\u{1b}\u{18}x",
            "x",
            &[("application_string", 1), ("terminal_control", 1)],
        );
    }

    #[test]
    fn an_application_string_is_removed_however_it_ends() {
        // An application-program command, a privacy message and a start-of-string, each in its
        // escape form or its eight-bit form, ended by the string terminator, cancelled, abandoned
        // for a new sequence, or still open when the recording ends.
        let cases = [
            ("a\u{1b}_payload\u{1b}\\b", "ab"),
            ("a\u{9f}payload\u{9c}b", "ab"),
            ("a\u{1b}^message\u{18}b", "ab"),
            ("a\u{98}string\u{1b}[31mb", "a\u{1b}[31mb"),
            ("a\u{1b}Xopen", "a"),
            ("a\u{9e}open", "a"),
        ];
        for (input, written) in cases {
            for (body, omissions) in at_every_split(input) {
                assert_eq!(body, written, "{input:?}");
                assert_eq!(kinds(&omissions), [("application_string", 1)], "{input:?}");
            }
        }
    }

    #[test]
    fn a_sequence_past_the_bound_on_what_is_held_is_removed_however_it_ends() {
        // A colour whose parameters run past the bound would be kept whole were it shorter; cut
        // at the bound it is not the colour it says, so it is removed, whether its final
        // character comes, a cancel abandons it, or the recording ends first. An escape whose
        // intermediates run past the bound goes the same way.
        let colour = format!("\u{1b}[{}", "1;".repeat(MAX_HELD_SEQUENCE));
        let intermediates = format!("\u{1b}{}", " ".repeat(MAX_HELD_SEQUENCE + 8));
        let cases = [
            (format!("{colour}mx"), "x"),
            (format!("{colour}\u{18}x"), "x"),
            (colour.clone(), ""),
            (format!("{intermediates}0x"), "x"),
            (format!("{intermediates}\u{18}x"), "x"),
            (intermediates.clone(), ""),
        ];
        for (input, written) in &cases {
            let length = input.len();
            let whole = filtered(&[input.as_str()]);
            assert_eq!(whole.0, *written);
            assert_eq!(kinds(&whole.1), [("terminal_control", 1)]);
            // Split near the start, at the bound, and near the end, the result is the same.
            for split in [2, MAX_HELD_SEQUENCE, length - 1] {
                let (left, right) = input.split_at(split);
                assert_eq!(filtered(&[left, right]), whole);
            }
        }
    }

    /// KR-REQ-25.25: a cursor-position report and a device-attributes query each make the terminal
    /// that plays the recording answer into its input, so neither is replayed, and both are
    /// declared as the questions they are.
    #[test]
    fn a_question_the_terminal_would_answer_is_not_replayed_and_is_declared() {
        for (body, omissions) in at_every_split("a\u{1b}[6nb\u{1b}[cc\u{1b}[>0cd\u{1b}[?6ne") {
            assert_eq!(body, "abcde");
            assert_eq!(kinds(&omissions), [("terminal_query", 4)]);
        }
    }

    #[test]
    fn the_eight_bit_introducer_and_the_single_character_questions_ask_the_same() {
        // A control sequence introduced by its eight-bit form, the terminal's identification by an
        // escape and by its eight-bit form, and a request for the answerback message.
        for (body, omissions) in at_every_split("a\u{9b}6nb\u{1b}Zc\u{9a}d\u{5}e") {
            assert_eq!(body, "abcde");
            assert_eq!(kinds(&omissions), [("terminal_query", 4)]);
        }
    }

    #[test]
    fn a_change_to_how_the_terminal_reports_keys_or_the_mouse_is_not_replayed() {
        // Mouse reporting, bracketed paste, the keyboard protocol, modified keys and the
        // application keypad each change what the reader's terminal sends, after the recording
        // has ended too.
        for (body, omissions) in
            at_every_split("a\u{1b}[?1000;1006hb\u{1b}[?2004hc\u{1b}[>1ud\u{1b}[>4;1me\u{1b}=f")
        {
            assert_eq!(body, "abcdef");
            assert_eq!(kinds(&omissions), [("terminal_control", 5)]);
        }
    }

    #[test]
    fn a_sequence_the_view_does_not_draw_with_is_removed_even_where_it_would_draw() {
        // The view clears the whole screen and never the lines scrolled off it, which are the
        // reader's own; it does not step the cursor, set a scrolling region or change screens;
        // and a mode it does set is kept only in a sequence that sets nothing else.
        for (body, omissions) in
            at_every_split("\u{1b}[2J\u{1b}[3J\u{1b}[5A\u{1b}[1;10r\u{1b}[?7;1049h\u{1b}[?25lx")
        {
            assert_eq!(body, "\u{1b}[2J\u{1b}[?25lx");
            assert_eq!(kinds(&omissions), [("terminal_control", 4)]);
        }
    }

    #[test]
    fn a_control_met_inside_an_escape_is_carried_out_and_the_escape_goes_on() {
        // A terminal carries out a return or a line feed where it meets one and goes on with the
        // escape, so these are still two cursor-position reports.
        for (body, omissions) in at_every_split("a\u{1b}\r[6nb\u{1b}[\n6nc") {
            assert_eq!(body, "a\rb\nc");
            assert_eq!(kinds(&omissions), [("terminal_query", 2)]);
        }
        // And a colour with a return inside it is still a colour, drawn after the return.
        for (body, omissions) in at_every_split("\u{1b}[3\r1mx") {
            assert_eq!(body, "\r\u{1b}[31mx");
            assert!(omissions.is_empty());
        }
    }

    #[test]
    fn a_sequence_after_an_escape_inside_a_string_is_decided_like_any_other() {
        for (body, omissions) in at_every_split("a\u{1b}]0;t\u{1b}[6nb\u{1b}P+q\u{1b}[cc") {
            assert_eq!(body, "abc");
            assert_eq!(
                kinds(&omissions),
                [
                    ("application_string", 1),
                    ("terminal_query", 2),
                    ("device_control_string", 1)
                ]
            );
        }
    }

    #[test]
    fn a_bell_and_every_control_that_does_not_draw_are_removed_and_the_line_controls_kept() {
        // A null, a shift out, a delete and an eight-bit next line go with the bell; backspace,
        // tab, line feed and carriage return are how a line of text is drawn.
        for (body, omissions) in at_every_split("a\u{7}b\u{0}c\u{e}d\u{8}\t\r\n\u{7f}e\u{85}f") {
            assert_eq!(body, "abcd\u{8}\t\r\nef");
            assert_eq!(kinds(&omissions), [("bell", 1), ("terminal_control", 4)]);
        }
    }

    #[test]
    fn an_escape_the_view_does_not_draw_with_is_removed_with_its_intermediates() {
        // A character set, the screen alignment pattern, a full reset and a string terminator
        // that ends nothing.
        for (body, omissions) in at_every_split("a\u{1b}(0b\u{1b}#8c\u{1b}cd\u{1b}\\e") {
            assert_eq!(body, "abcde");
            assert_eq!(kinds(&omissions), [("terminal_control", 4)]);
        }
    }

    #[test]
    fn a_malformed_or_abandoned_control_sequence_replays_nothing_and_is_declared() {
        // A parameter after an intermediate, and a character no sequence holds, are malformed and
        // removed whole. An eight-bit introducer abandons the sequence before it, as a cancel
        // does; a terminal would have acted on neither, and both are declared all the same.
        for (body, omissions) in
            at_every_split("a\u{1b}[1$2mb\u{1b}[3é1mc\u{1b}[6\u{9b}cd\u{1b}[31\u{18}e")
        {
            assert_eq!(body, "abcde");
            assert_eq!(
                kinds(&omissions),
                [("terminal_control", 4), ("terminal_query", 1)]
            );
        }
    }

    #[test]
    fn an_escape_before_a_character_that_cannot_follow_one_is_declared() {
        // The escape is abandoned and the character is text, as a terminal reads it; the escape
        // is left out, and so declared.
        for (body, omissions) in at_every_split("x\u{1b}éy\u{1b}\u{85}z") {
            assert_eq!(body, "xéyz");
            assert_eq!(kinds(&omissions), [("terminal_control", 3)]);
        }
    }

    #[test]
    fn a_sequence_or_an_escape_left_open_at_the_end_is_declared_rather_than_replayed() {
        for open in ["x\u{1b}[?100", "x\u{1b}(", "x\u{1b}"] {
            for (body, omissions) in at_every_split(open) {
                assert_eq!(body, "x");
                assert_eq!(kinds(&omissions), [("terminal_control", 1)], "{open:?}");
            }
        }
    }

    #[test]
    fn a_delete_inside_an_escape_or_a_sequence_is_declared_and_the_sequence_goes_on() {
        // A terminal ignores a delete there, so the colour is still a colour and the report still
        // a report; the delete is removed as it is anywhere else, and said so.
        for (body, omissions) in at_every_split("\u{1b}[3\u{7f}1mx\u{1b}\u{7f}[6ny\u{1b}(\u{7f}0z")
        {
            assert_eq!(body, "\u{1b}[31mxyz");
            assert_eq!(
                kinds(&omissions),
                [("terminal_control", 4), ("terminal_query", 1)]
            );
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
            assert_eq!(body, "ab");
            assert_eq!(
                kinds(&omissions),
                [("terminal_control", 1), ("clipboard_write", 1)]
            );
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
    fn a_colour_that_is_set_is_not_replayed_because_the_view_draws_in_resolved_colours() {
        // A palette change would stay in the reader's terminal after the recording ended, and the
        // view has already drawn every cell in the colour the session's palette gave it.
        for (body, omissions) in at_every_split("\u{1b}]4;1;rgb:ff/00/00\u{7}done") {
            assert_eq!(body, "done");
            assert_eq!(kinds(&omissions), [("application_string", 1)]);
        }
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
        let payload = "a".repeat(MAX_HELD_SEQUENCE + 64);
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
        // The escape ends the string and begins an escape of its own, which the cancel abandons.
        for (body, omissions) in at_every_split("\u{1b}]52;c;partial\u{1b}\u{18}kept text") {
            assert_eq!(body, "kept text");
            assert_eq!(
                kinds(&omissions),
                [("clipboard_write", 1), ("terminal_control", 1)]
            );
        }
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
