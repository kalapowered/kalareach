//! How a run of the stand-in misbehaves, when a test asks it to.
//!
//! The variants are named in `KR_STAND_IN`, separated by commas. Without any, the stand-in behaves
//! as the pinned release was measured to: its commands lead a session and a process group of their
//! own, it ends them and exits when its input ends or when it is asked to terminate, and a
//! hang-up kills it at once and leaves its commands behind.

/// The variable that names the variants.
pub const VARIABLE: &str = "KR_STAND_IN";

/// The command the server starts when a turn begins, as a JSON array of the program and its
/// arguments. The agent's tool commands are what this stands in for.
pub const COMMAND_VARIABLE: &str = "KR_STAND_IN_COMMAND";

/// The size, in bytes, the frames a test wants large are padded to: the terminal's request to start
/// a turn and the server's notification of what the agent said.
pub const PAD_VARIABLE: &str = "KR_STAND_IN_PAD";

/// The key the terminal signs in with under the `login` variant.
pub const KEY_VARIABLE: &str = "KR_STAND_IN_API_KEY";

/// The file a terminal under `answer-when-released` waits for before it answers the approval, and
/// one under `wait-to-connect` waits for before it connects.
pub const RELEASE_VARIABLE: &str = "KR_STAND_IN_RELEASE";

/// The ways a run can differ from the default.
#[derive(Clone, Debug, Default)]
pub struct Variants {
    /// The server does not end when its input ends.
    pub ignore_eof: bool,
    /// The server does not end when it is asked to terminate.
    pub ignore_term: bool,
    /// The server starts its command in the server's own session and process group. The server
    /// then ends only the command itself when it goes: it cannot end the command's group without
    /// ending itself, so what the command started stays.
    pub command_shares_group: bool,
    /// The server exits when the approval it asked for is answered, leaving its command running.
    pub die_first: bool,
    /// The server writes a great deal to its standard error stream and goes on, in numbered lines.
    pub flood_stderr: bool,
    /// The server says its working directory and its environment on its error stream when it
    /// starts, one line each, and then goes on.
    pub report_environment: bool,
    /// The server starts a command of its own whenever it is told to end and does not: when its
    /// input ends under `ignore-eof`, and each time it is asked to terminate under `ignore-term`.
    pub spawn_late: bool,
    /// The server asks for its approval under the identifier of the terminal's request to start a
    /// turn, before it answers that request.
    pub colliding_ids: bool,
    /// The terminal reads the server's request for an approval and does not answer it.
    pub leave_unanswered: bool,
    /// The terminal declines the approval it is asked for.
    pub decline: bool,
    /// The terminal stays connected after the turn completes, until the connection ends.
    pub stay: bool,
    /// The terminal sends the key in `KR_STAND_IN_API_KEY` to sign in, before its turn.
    pub login: bool,
    /// The terminal's upgrade request carries an `Origin` header, as a browser's does.
    pub origin: bool,
    /// A terminal whose upgrade was refused tries once more, without the `Origin` header.
    pub retry_plain: bool,
    /// The terminal never connects: it runs until it is ended.
    pub idle: bool,
    /// The terminal does not answer the approval until the file `KR_STAND_IN_RELEASE` names exists.
    pub answer_when_released: bool,
    /// The terminal says it is waiting, and does not connect until the file `KR_STAND_IN_RELEASE`
    /// names exists.
    pub wait_to_connect: bool,
}

impl Variants {
    /// Reads the variants the environment names.
    ///
    /// # Panics
    ///
    /// Panics on a name it does not know, so a mistyped variant is not a test that passes by doing
    /// nothing.
    pub fn from_env() -> Self {
        let mut variants = Self::default();
        let text = std::env::var(VARIABLE).unwrap_or_default();
        for name in text
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            match name {
                "ignore-eof" => variants.ignore_eof = true,
                "ignore-term" => variants.ignore_term = true,
                "command-shares-group" => variants.command_shares_group = true,
                "die-first" => variants.die_first = true,
                "flood-stderr" => variants.flood_stderr = true,
                "report-environment" => variants.report_environment = true,
                "spawn-late" => variants.spawn_late = true,
                "colliding-ids" => variants.colliding_ids = true,
                "leave-unanswered" => variants.leave_unanswered = true,
                "decline" => variants.decline = true,
                "stay" => variants.stay = true,
                "login" => variants.login = true,
                "origin" => variants.origin = true,
                "retry-plain" => variants.retry_plain = true,
                "idle" => variants.idle = true,
                "answer-when-released" => variants.answer_when_released = true,
                "wait-to-connect" => variants.wait_to_connect = true,
                other => panic!("{VARIABLE} names a variant this program does not have: {other}"),
            }
        }
        variants
    }

    /// The command the server starts for a turn, if the environment names one.
    ///
    /// # Panics
    ///
    /// Panics when the variable is not a JSON array of text.
    pub fn command() -> Option<Vec<String>> {
        let text = std::env::var(COMMAND_VARIABLE).ok()?;
        let words: Vec<String> = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{COMMAND_VARIABLE} is a JSON array of text: {error}"));
        (!words.is_empty()).then_some(words)
    }

    /// The size frames are padded to, if the environment names one.
    ///
    /// # Panics
    ///
    /// Panics when the variable is not a number.
    pub fn pad() -> Option<usize> {
        let text = std::env::var(PAD_VARIABLE).ok()?;
        Some(
            text.parse()
                .unwrap_or_else(|error| panic!("{PAD_VARIABLE} is a number of bytes: {error}")),
        )
    }
}

/// Makes `text` as long as it takes for the whole frame `frame(text)` to be `size` bytes.
///
/// # Panics
///
/// Panics when the frame is longer than `size` with no text in it.
pub fn padded(size: usize, frame: impl Fn(&str) -> String) -> String {
    let bare = frame("").len();
    assert!(
        bare <= size,
        "a frame of {bare} bytes cannot be {size} bytes"
    );
    let text = "x".repeat(size - bare);
    let built = frame(&text);
    assert_eq!(built.len(), size);
    text
}
