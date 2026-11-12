//! What a person at the native terminal types, and what the terminal draws for it.
//!
//! Where standard input is a terminal, the terminal reads each key as it is typed and draws a
//! composer at the bottom of what it has written: a row with the typed text and, while a `/` and
//! the start of a command are typed, a row below it for each command of its list that begins so,
//! the command and then what it does. The clearing key empties the composer and the rows go with
//! it. While the server asks for the approval of a command, the composer gives way to the dialog
//! that shows the command and its choices. Where standard input is not a terminal nothing here
//! reads or draws, and every line is written as it was before.

use std::fmt::Display;
use std::io::Write as _;

use rustix::termios::{self, LocalModes, OptionalActions, SpecialCodeIndex, Termios};
use serde_json::Value;
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

/// What the composer's row starts with.
const PROMPT: &str = "> ";

/// What shows while a turn runs, above the composer.
const WORKING: &str = "Working (0s • esc to interrupt)";

/// What `/pwd` shows, before the directory.
pub const DIRECTORY: &str = "Current working directory:";

/// What the dialog asks.
const ASKS: &str = "Would you like to run the following command?";

/// What the dialog's command is written after.
const COMMAND: &str = "$ ";

/// The dialog's choices: the first allows the command once (`y`), the second does not run it and
/// goes on (`d`), the third stops the turn (`n` or the escape key).
const CHOICES: [&str; 3] = [
    "Yes, proceed (y)",
    "No, continue without running it (d)",
    "No, and tell Codex what to do differently (esc)",
];

/// The commands the composer lists, each with what it does.
const COMMANDS: [(&str, &str, Command); 4] = [
    (
        "/pwd",
        "show the current working directory",
        Command::Directory,
    ),
    ("/fork", "fork the current chat", Command::Fork),
    (
        "/new",
        "start a new chat during a conversation",
        Command::New,
    ),
    ("/quit", "exit Codex", Command::Quit),
];

/// A command of the composer's list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Directory,
    Fork,
    New,
    Quit,
}

/// What typing came to, for the terminal to carry out.
#[derive(Debug, PartialEq)]
pub enum Typed {
    /// A line was sent as a prompt.
    Prompt(String),
    /// A command of the list was sent.
    Command(Command),
    /// The dialog's choice, for the request it was shown for.
    Decision {
        request: Value,
        decision: &'static str,
    },
}

/// A key, as the composer takes it.
#[derive(Debug, PartialEq, Eq)]
pub enum Key {
    Character(char),
    Enter,
    Clear,
    Backspace,
    Escape,
    Other,
}

/// Turns the bytes a keyboard sends into keys, holding the end of a key that arrived in part.
#[derive(Default)]
pub struct Decoder {
    pending: Vec<u8>,
}

impl Decoder {
    pub fn keys(&mut self, bytes: &[u8]) -> Vec<Key> {
        self.pending.extend_from_slice(bytes);
        let mut keys = Vec::new();
        let mut at = 0;
        while at < self.pending.len() {
            let byte = self.pending[at];
            let (key, length) = match byte {
                b'\r' | b'\n' => (Key::Enter, 1),
                0x15 => (Key::Clear, 1),
                0x7f | 0x08 => (Key::Backspace, 1),
                0x1b => match self.pending.get(at + 1) {
                    // A sequence the keyboard sends for a key of its own, such as an arrow: taken
                    // whole, and a key to nobody here.
                    Some(b'[') => {
                        let Some(end) = self.pending[at + 2..]
                            .iter()
                            .position(|byte| (0x40..=0x7e).contains(byte))
                        else {
                            break;
                        };
                        (Key::Other, end + 3)
                    }
                    Some(b'O') if at + 2 >= self.pending.len() => break,
                    Some(b'O') => (Key::Other, 3),
                    _ => (Key::Escape, 1),
                },
                0..=0x1f => (Key::Other, 1),
                _ => {
                    let length = match byte {
                        0xf0.. => 4,
                        0xe0.. => 3,
                        0xc0.. => 2,
                        _ => 1,
                    };
                    if at + length > self.pending.len() {
                        break;
                    }
                    let key = std::str::from_utf8(&self.pending[at..at + length])
                        .ok()
                        .and_then(|text| text.chars().next())
                        .map_or(Key::Other, Key::Character);
                    (key, length)
                }
            };
            keys.push(key);
            at += length;
        }
        self.pending.drain(..at);
        keys
    }
}

/// The modes of the terminal as they were, put back when this goes.
struct Raw {
    saved: Termios,
}

impl Raw {
    /// Puts standard input into the mode keys are read in, one at a time and not shown by the
    /// terminal itself, where it is a terminal.
    fn enter() -> Option<Self> {
        let input = std::io::stdin();
        if !termios::isatty(&input) {
            return None;
        }
        let saved = termios::tcgetattr(&input).ok()?;
        let mut keys = saved.clone();
        keys.local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO);
        keys.special_codes[SpecialCodeIndex::VMIN] = 1;
        keys.special_codes[SpecialCodeIndex::VTIME] = 0;
        termios::tcsetattr(&input, OptionalActions::Now, &keys).ok()?;
        Some(Self { saved })
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(std::io::stdin(), OptionalActions::Now, &self.saved);
    }
}

/// The dialog the server's request for an approval is shown as.
struct Dialog {
    request: Value,
    command: String,
}

/// What the terminal has written, and the composer under it.
pub struct Screen {
    /// The mode of the terminal, where it is one.
    raw: Option<Raw>,
    /// How many columns a row may fill: one less than the terminal has, so that a row never ends
    /// in the last column.
    width: usize,
    text: String,
    dialog: Option<Dialog>,
    /// Whether a turn is running.
    working: bool,
    /// Whether the composer shows: the conversation has begun.
    shown: bool,
    /// The rows of the composer on the screen now.
    drawn: usize,
}

fn write(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

impl Screen {
    /// A screen that reads no keys and draws no composer: every line is written as it is.
    pub fn plain() -> Self {
        Self::with(None)
    }

    /// The screen of this terminal: with a composer where standard input is a terminal.
    pub fn open() -> Self {
        Self::with(Raw::enter())
    }

    fn with(raw: Option<Raw>) -> Self {
        let columns = raw
            .as_ref()
            .and_then(|_| termios::tcgetwinsize(std::io::stdin()).ok())
            .map_or(0, |size| usize::from(size.ws_col));
        Self {
            raw,
            width: if columns > 20 { columns - 1 } else { 79 },
            text: String::new(),
            dialog: None,
            working: false,
            shown: false,
            drawn: 0,
        }
    }

    /// Whether the keyboard is read and the composer drawn.
    pub fn is_typed_at(&self) -> bool {
        self.raw.is_some()
    }

    /// Writes `line` above the composer.
    pub fn say(&mut self, line: impl Display) {
        if self.raw.is_none() {
            println!("{line}");
            return;
        }
        let mut out = self.erase();
        out.push_str(&format!("{line}\r\n"));
        out.push_str(&self.draw());
        write(&out);
    }

    /// Draws the composer again as it is now.
    pub fn redraw(&mut self) {
        if self.raw.is_some() {
            let mut out = self.erase();
            out.push_str(&self.draw());
            write(&out);
        }
    }

    /// The conversation has begun: the composer shows.
    pub fn begins(&mut self) {
        self.shown = true;
        self.redraw();
    }

    /// A turn runs, or it does not.
    pub fn works(&mut self, working: bool) {
        self.working = working;
    }

    /// The server asks for the approval of `command` as `request`: the dialog shows in place of the
    /// composer.
    pub fn asks(&mut self, request: Value, command: String) {
        self.dialog = Some(Dialog { request, command });
    }

    /// The request `request` was answered: its dialog goes.
    pub fn resolved(&mut self, request: &Value) {
        if self
            .dialog
            .as_ref()
            .is_some_and(|dialog| dialog.request == *request)
        {
            self.dialog = None;
        }
    }

    /// What `key` does to what is typed, and what it sends where it sends something.
    pub fn key(&mut self, key: Key) -> Option<Typed> {
        if let Some(dialog) = &self.dialog {
            let decision = match key {
                Key::Character('y' | 'Y') | Key::Enter => "accept",
                Key::Character('d' | 'D') => "decline",
                Key::Character('n' | 'N') | Key::Escape => "cancel",
                _ => return None,
            };
            let request = dialog.request.clone();
            self.dialog = None;
            return Some(Typed::Decision { request, decision });
        }
        match key {
            Key::Character(character) => self.text.push(character),
            Key::Backspace => {
                self.text.pop();
            }
            Key::Clear => self.text.clear(),
            Key::Enter => {
                let line = std::mem::take(&mut self.text);
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                return Some(
                    COMMANDS
                        .iter()
                        .find(|(name, ..)| *name == line)
                        .map_or_else(
                            || Typed::Prompt(line.to_owned()),
                            |(.., command)| Typed::Command(*command),
                        ),
                );
            }
            Key::Escape | Key::Other => {}
        }
        None
    }

    /// The rows the composer, or the dialog in its place, is drawn as.
    fn rows(&self) -> Vec<String> {
        let rows = if let Some(dialog) = &self.dialog {
            let mut rows = vec![
                format!("  {ASKS}"),
                String::new(),
                format!("  {COMMAND}{}", dialog.command),
                String::new(),
            ];
            for (number, choice) in CHOICES.iter().enumerate() {
                let mark = if number == 0 { "›" } else { " " };
                rows.push(format!("{mark} {}. {choice}", number + 1));
            }
            rows
        } else {
            let mut rows = Vec::new();
            if self.working {
                rows.push(format!("• {WORKING}"));
            }
            rows.push(format!("{PROMPT}{}", self.text));
            if self.text.starts_with('/') && !self.text.contains(char::is_whitespace) {
                let typed = self.text.to_lowercase();
                for (name, does, _) in COMMANDS {
                    if name.starts_with(&typed) {
                        rows.push(format!("  {name:<8}{does}"));
                    }
                }
            }
            rows
        };
        rows.iter()
            .flat_map(|row| {
                let characters: Vec<char> = row.chars().collect();
                if characters.is_empty() {
                    vec![String::new()]
                } else {
                    characters
                        .chunks(self.width)
                        .map(|chunk| chunk.iter().collect())
                        .collect()
                }
            })
            .collect()
    }

    /// What takes the composer off the screen: the cursor goes to its first row, and everything
    /// from there on is erased.
    fn erase(&mut self) -> String {
        let rows = std::mem::take(&mut self.drawn);
        match rows {
            0 => String::new(),
            1 => "\r\x1b[J".to_owned(),
            rows => format!("\r\x1b[{}A\x1b[J", rows - 1),
        }
    }

    /// What draws the composer as it is, the cursor left at the end of its last row.
    fn draw(&mut self) -> String {
        if !self.shown {
            return String::new();
        }
        let rows = self.rows();
        self.drawn = rows.len();
        rows.join("\r\n")
    }
}

/// The bytes the keyboard sends, as they arrive.
pub fn reader() -> UnboundedReceiver<Vec<u8>> {
    let (send, receive) = unbounded_channel();
    tokio::spawn(async move {
        let mut input = tokio::io::stdin();
        let mut buffer = [0_u8; 1024];
        loop {
            match input.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if send.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    receive
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen with a composer, as a person at a terminal has one.
    fn typed_at() -> Screen {
        Screen {
            raw: None,
            width: 99,
            text: String::new(),
            dialog: None,
            working: false,
            shown: true,
            drawn: 0,
        }
    }

    fn type_text(screen: &mut Screen, text: &str) {
        for character in text.chars() {
            assert_eq!(screen.key(Key::Character(character)), None);
        }
    }

    /// Keys come out of the bytes a keyboard sends whole: a character split between two reads, an
    /// arrow as one key that is none of the composer's, and an escape that stands alone.
    #[test]
    fn a_key_split_between_reads_comes_out_whole() {
        let mut decoder = Decoder::default();
        assert_eq!(decoder.keys(&[0xe2, 0x82]), Vec::<Key>::new());
        assert_eq!(
            decoder.keys(&[0xac, b'/']),
            vec![Key::Character('€'), Key::Character('/')]
        );
        assert_eq!(decoder.keys(b"\x1b[B\x1b"), vec![Key::Other, Key::Escape]);
        assert_eq!(decoder.keys(b"\x15\r"), vec![Key::Clear, Key::Enter]);
    }

    /// A typed `/` and the start of a command lists the commands that begin so, each the command and
    /// then what it does, below the composer's row; the clearing key takes the rows away, and a
    /// line that is a command of the list is sent as that command and any other as a prompt.
    #[test]
    fn the_composer_lists_the_commands_that_begin_as_typed_and_the_clearing_key_takes_them_away() {
        let mut screen = typed_at();
        type_text(&mut screen, "/pwd");
        assert_eq!(
            screen.rows(),
            vec![
                "> /pwd".to_owned(),
                "  /pwd    show the current working directory".to_owned()
            ]
        );
        assert_eq!(screen.draw().matches("\r\n").count(), 1);
        assert_eq!(screen.erase(), "\r\x1b[1A\x1b[J");
        assert_eq!(screen.key(Key::Clear), None);
        assert_eq!(screen.rows(), vec!["> ".to_owned()]);
        type_text(&mut screen, "/");
        assert_eq!(screen.rows().len(), 1 + COMMANDS.len());
        assert_eq!(screen.key(Key::Enter), Some(Typed::Prompt("/".to_owned())));
        type_text(&mut screen, "/fork");
        assert_eq!(screen.key(Key::Enter), Some(Typed::Command(Command::Fork)));
        type_text(&mut screen, "hello there");
        assert_eq!(
            screen.key(Key::Enter),
            Some(Typed::Prompt("hello there".to_owned()))
        );
    }

    /// While the server asks for the approval of a command, the dialog shows the command on a row of
    /// its own after `$ ` and the choices after it, and only a choice's key answers it.
    #[test]
    fn the_dialog_shows_the_command_alone_and_a_choices_key_answers_the_request() {
        let mut screen = typed_at();
        screen.asks(serde_json::json!("approval-2"), "echo hi > /f".to_owned());
        let rows = screen.rows();
        assert_eq!(rows[0].trim(), ASKS);
        assert_eq!(rows[2].trim(), "$ echo hi > /f");
        assert!(rows[4].contains("Yes, proceed"));
        assert_eq!(screen.key(Key::Character('x')), None);
        assert_eq!(
            screen.key(Key::Character('y')),
            Some(Typed::Decision {
                request: serde_json::json!("approval-2"),
                decision: "accept"
            })
        );
        assert_eq!(screen.rows(), vec!["> ".to_owned()]);
    }
}
