//! A stand-in for a terminal coding agent, for running the qualification parts that need a
//! signed-in agent with no account and no model: it signs in nowhere, answers three kinds of
//! question from its own text, and keeps a conversation file of the shape the real agent keeps.
//!
//! It is started as the build list's command, placed under the command's name, with the arguments
//! the build list gives the real agent. Flags that take a value are skipped; the first word after
//! them is the subcommand: `resume <id>` or `fork <id>`, or none.
//!
//! - `--version` prints a version line.
//! - It answers "What is A plus B" with the sum, "What code did I ask you to remember" with the
//!   code of an earlier "Remember the code X." in the conversation, upper case, and "What colour
//!   fills this image" with `red` and the code the question gives, upper case, when the file the
//!   prompt names holds the bytes whose SHA-256 is in `STAND_IN_RED_SHA256`. Anything else it
//!   answers with a line that holds none of those.
//! - What `resume <id>` does with a conversation another process holds is set by
//!   `STAND_IN_RESUME`: `continue` (the default) writes into the same file, `locked`
//!   refuses because the first process holds the file's lock, and `fork` writes into a copy under
//!   an identifier of its own. `fork <id>` always writes into a copy.
//!
//! Without `STAND_IN_ENTRY` it is the pinned Codex terminal's stand-in:
//!
//! - `--version` prints `codex-cli` and the version of the release it stands for.
//! - Without a `config.toml` in the configuration directory (`CODEX_HOME`, else `~/.codex`) it
//!   shows the sign-in screen and moves its marker with the arrow keys, as the real agent's first
//!   screen does, and does nothing else.
//! - With one it shows the banner and the composer and reads prompts a line at a time.
//! - Each prompt and reply is a line of the conversation file
//!   `sessions/YYYY/MM/DD/rollout-<time>-<uuid>.jsonl` in the configuration directory; an image
//!   a prompt names is recorded in the prompt's line as the base64 text the real agent writes.
//!
//! With `STAND_IN_ENTRY` it stands for the build list entry whose names and texts that file holds
//! (a JSON object of the members of `Entry`, made by the driver; a member that names a program to
//! run is refused):
//!
//! - `--version` prints the entry's command and its version; the program built as the newer
//!   release prints the entry's newer version.
//! - A script or a wheel is started through its runtime, which is this program, with the script as
//!   its first argument; for those launches that argument is not taken for a command.
//! - It shows the entry's first screen text and its composer text, and no sign-in screen.
//! - On a terminal it takes each key as it is typed and echoes it itself, as a full-screen agent
//!   does: a part of a line that is typed and not sent is the agent's, and is not left in the
//!   terminal when the agent ends.
//! - The conversation file is `rollout-<time>-<uuid>.jsonl` below the entry's `conversations`
//!   (`{date}` as `YYYY/MM/DD`) in the directory the entry's configuration variable names, else
//!   in the home. A prompt is a line that holds the entry's prompt mark, after a line that holds
//!   its turn mark where the entry has one; a reply is a line that holds its reply mark; an image
//!   a prompt names is a line that holds the entry's image mark and the image as base64 text.
//! - Where `STAND_IN_LEAVE` names a program, it runs that program once, when it reads its first
//!   prompt and before it answers, and stops with an error if the program does not end well. A case
//!   uses it to have the agent change a file of the run after the host has found the agent.

/// The stand-in's own code, which uses the system's terminal and file locks.
#[cfg(unix)]
mod stand_in {
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use base64::Engine as _;
    use rustix::fs::{FlockOperation, flock};
    use serde::Deserialize;
    use serde_json::json;

    /// The version the pinned release reports.
    const VERSION: &str = "0.155.1";

    /// The version the newer release reports, where no entry is named.
    const NEWER_VERSION: &str = "0.156.1";

    /// The variable that holds the lower-case hexadecimal SHA-256 of the image the stand-in calls red.
    const RED_DIGEST: &str = "STAND_IN_RED_SHA256";

    /// The variable that says what `resume` does: `continue`, `locked` or `fork`.
    const RESUME_VARIABLE: &str = "STAND_IN_RESUME";

    /// The variable that names the file of names and texts of the entry the stand-in stands for.
    const ENTRY_VARIABLE: &str = "STAND_IN_ENTRY";

    /// The variable that names a program the stand-in runs once, when it reads its first prompt.
    const LEAVE_VARIABLE: &str = "STAND_IN_LEAVE";

    /// The text the composer shows while it waits for a prompt.
    const COMPOSER: &str = "Ask Codex to do anything";

    /// Where the Codex terminal keeps its conversations, below its configuration directory.
    const CODEX_CONVERSATIONS: &str = "sessions/{date}";

    /// What the sign-in screen offers, in order.
    const SIGN_IN: [&str; 3] = [
        "Sign in with ChatGPT",
        "Sign in with Device Code",
        "Provide your own API key",
    ];

    /// Flags the agent takes a value after.
    const WITH_VALUE: [&str; 6] = ["-c", "-a", "-s", "-m", "--disable", "--enable"];

    /// What the stand-in takes from the entry it stands for: names and texts, and no path to run.
    /// A member that is not one of these is refused.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        /// The name the agent is typed as.
        command: String,
        /// How the agent is launched: `native`, `child`, `script` or `wheel`.
        launch: String,
        /// The version the pinned build reports.
        version: String,
        /// The version the newer build reports, where the entry has one.
        newer_version: Option<String>,
        /// The text the first screen shows.
        ready: String,
        /// The text the newer build's first screen shows, where the entry has a newer build.
        newer_ready: Option<String>,
        /// The key the agent takes at its composer without sending a prompt, and the text its screen
        /// shows once it has taken it.
        harmless: Harmless,
        /// The text the composer shows while it waits for a prompt; none for an entry with no
        /// account.
        composer: Option<String>,
        /// The variable that names the configuration directory, where the agent has one.
        config_variable: Option<String>,
        /// Where the conversations are, relative to the configuration directory or the home; none
        /// for an entry with no account, which keeps no record.
        conversations: Option<String>,
        /// What marks the line of a prompt; given with the conversations.
        prompt_line: Option<String>,
        /// What marks the line of a reply; given with the conversations.
        reply_line: Option<String>,
        /// What marks the line that starts a turn, where the agent writes one.
        turn_line: Option<String>,
        /// What marks the line of an image a prompt names, where the agent records one.
        image_line: Option<String>,
    }

    /// A key, and the text the agent's screen shows once it has taken it.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Harmless {
        /// The key.
        input: String,
        /// The text.
        shows: String,
    }

    /// The marks of the lines the conversation file holds, as the entry gives them.
    #[derive(Clone)]
    struct Marks {
        prompt: String,
        reply: String,
        turn: Option<String>,
        image: Option<String>,
    }

    /// Where the conversations are, and what marks their lines: the Codex terminal's own, which
    /// has no marks, or the entry's.
    struct Layout {
        /// The directory the conversations are below.
        home: PathBuf,
        /// Where they are below it, with `{date}` for the day.
        conversations: String,
        /// The marks of an entry's lines; none for the Codex terminal's own shape.
        marks: Option<Marks>,
    }

    /// Where the conversations are and what marks their lines: the Codex terminal's own, the
    /// entry's, or none for an entry that keeps no record.
    ///
    /// # Errors
    ///
    /// Returns why the entry names some of its conversations, prompt mark and reply mark and not
    /// all three.
    fn layout_of(entry: Option<&Entry>, home: PathBuf) -> Result<Option<Layout>, String> {
        let Some(entry) = entry else {
            return Ok(Some(Layout {
                home,
                conversations: CODEX_CONVERSATIONS.to_owned(),
                marks: None,
            }));
        };
        match (&entry.conversations, &entry.prompt_line, &entry.reply_line) {
            (None, None, None) => Ok(None),
            (Some(conversations), Some(prompt), Some(reply)) => Ok(Some(Layout {
                home,
                conversations: conversations.clone(),
                marks: Some(Marks {
                    prompt: prompt.clone(),
                    reply: reply.clone(),
                    turn: entry.turn_line.clone(),
                    image: entry.image_line.clone(),
                }),
            })),
            _ => Err(
                "the entry names some of its conversations, prompt mark and reply mark, and \
                      not all three"
                    .to_owned(),
            ),
        }
    }

    /// Whether this program is the newer build of the source: the second `[[bin]]` of the package.
    fn newer() -> bool {
        option_env!("CARGO_BIN_NAME") == Some("agent-stand-in-newer")
    }

    /// The entry the environment names, where it names one.
    fn entry() -> Result<Option<Entry>, String> {
        let Some(path) = std::env::var_os(ENTRY_VARIABLE).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let text =
            std::fs::read_to_string(&path).map_err(|error| format!("{ENTRY_VARIABLE}: {error}"))?;
        serde_json::from_str(&text).map(Some).map_err(|error| {
            format!("{ENTRY_VARIABLE} names a file that is not an entry's names and texts: {error}")
        })
    }

    /// The text this build's first screen shows: the entry's, or the newer build's own.
    fn ready_of(entry: &Entry) -> Result<&str, String> {
        if newer() {
            entry
                .newer_ready
                .as_deref()
                .ok_or_else(|| "the entry names no newer first screen".to_owned())
        } else {
            Ok(&entry.ready)
        }
    }

    /// The version line this build prints.
    fn version_line(entry: Option<&Entry>) -> Result<String, String> {
        let Some(entry) = entry else {
            return Ok(format!(
                "codex-cli {}",
                if newer() { NEWER_VERSION } else { VERSION }
            ));
        };
        let version = if newer() {
            entry
                .newer_version
                .as_deref()
                .ok_or("the entry names no newer version")?
        } else {
            &entry.version
        };
        Ok(format!("{} {version}", entry.command))
    }

    pub fn run() {
        let entry = entry().unwrap_or_else(|why| {
            eprintln!("Error: {why}");
            std::process::exit(2);
        });
        let mut arguments: Vec<String> = std::env::args().skip(1).collect();
        if arguments.iter().any(|argument| argument == "--version") {
            match version_line(entry.as_ref()) {
                Ok(line) => println!("{line}"),
                Err(why) => {
                    eprintln!("Error: {why}");
                    std::process::exit(2);
                }
            }
            return;
        }
        if entry
            .as_ref()
            .is_some_and(|entry| entry.launch == "script" || entry.launch == "wheel")
            && !arguments.is_empty()
        {
            // The runtime is this program and its first argument is the script it was started for.
            arguments.remove(0);
        }
        let (subcommand, identifier) = subcommand_of(&arguments);
        let ready = entry
            .as_ref()
            .map(ready_of)
            .transpose()
            .unwrap_or_else(|why| {
                eprintln!("Error: {why}");
                std::process::exit(2);
            });
        let home = configuration_directory(entry.as_ref());
        if entry.is_none() && !home.join("config.toml").is_file() {
            sign_in_screen();
            return;
        }
        let layout = layout_of(entry.as_ref(), home).unwrap_or_else(|why| {
            eprintln!("Error: {why}");
            std::process::exit(2);
        });
        let conversation = match &layout {
            Some(layout) => {
                match open_conversation(layout, subcommand.as_deref(), identifier.as_deref()) {
                    Ok(conversation) => Some(conversation),
                    Err(why) => {
                        eprintln!("Error: {why}");
                        std::process::exit(1);
                    }
                }
            }
            None if subcommand.is_some() => {
                eprintln!("Error: the entry keeps no conversation to resume or fork");
                std::process::exit(1);
            }
            None => None,
        };
        match &entry {
            Some(entry) => composer(
                conversation,
                &[ready.expect("the first screen of an entry").to_owned()],
                entry.composer.as_deref().unwrap_or(""),
                true,
                std::env::var_os(LEAVE_VARIABLE).filter(|program| !program.is_empty()),
                Some(&entry.harmless),
            ),
            None => composer(
                conversation,
                &[
                    "╭──────────────────────────────────────╮".to_owned(),
                    format!("│ >_ OpenAI Codex (v{VERSION})          │"),
                    "╰──────────────────────────────────────╯".to_owned(),
                ],
                COMPOSER,
                false,
                None,
                None,
            ),
        }
    }

    /// The subcommand the arguments name, with its identifier: the first word that is not a flag or a
    /// flag's value.
    fn subcommand_of(arguments: &[String]) -> (Option<String>, Option<String>) {
        let mut words = arguments.iter();
        while let Some(word) = words.next() {
            if WITH_VALUE.contains(&word.as_str()) {
                let _ = words.next();
            } else if !word.starts_with('-') {
                return (Some(word.clone()), words.next().cloned());
            }
        }
        (None, None)
    }

    /// The directory the agent keeps its configuration and conversations in: for an entry, the one
    /// its configuration variable names, else the home; for the Codex terminal, `CODEX_HOME`, else
    /// `~/.codex`.
    fn configuration_directory(entry: Option<&Entry>) -> PathBuf {
        let home = || PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let named = |variable: &str| std::env::var_os(variable).filter(|value| !value.is_empty());
        match entry {
            Some(entry) => entry
                .config_variable
                .as_deref()
                .and_then(named)
                .map_or_else(home, PathBuf::from),
            None => named("CODEX_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home().join(".codex")),
        }
    }

    /// Shows the sign-in screen and moves its marker until the terminal closes or the person sends an
    /// interrupt.
    fn sign_in_screen() {
        let stdin = std::io::stdin();
        if let Ok(mut modes) = rustix::termios::tcgetattr(&stdin) {
            modes.make_raw();
            let _ =
                rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &modes);
        }
        let mut chosen = 0usize;
        draw_sign_in(chosen);
        let mut input = stdin.lock();
        let mut buffer = [0u8; 16];
        loop {
            let Ok(count) = input.read(&mut buffer) else {
                return;
            };
            if count == 0 || buffer[..count].contains(&3) {
                return;
            }
            let keys = &buffer[..count];
            if keys.windows(3).any(|keys| keys == b"\x1b[B") {
                chosen = (chosen + 1).min(SIGN_IN.len() - 1);
            } else if keys.windows(3).any(|keys| keys == b"\x1b[A") {
                chosen = chosen.saturating_sub(1);
            }
            draw_sign_in(chosen);
        }
    }

    /// Writes the sign-in screen with its marker at `chosen`.
    fn draw_sign_in(chosen: usize) {
        let mut screen = String::from("\x1b[2J\x1b[H");
        screen.push_str("  Welcome to Codex, OpenAI's command-line coding agent\r\n\r\n");
        for (index, option) in SIGN_IN.iter().enumerate() {
            let marker = if index == chosen { ">" } else { " " };
            screen.push_str(&format!("{marker} {}. {option}\r\n", index + 1));
        }
        let mut out = std::io::stdout();
        let _ = out.write_all(screen.as_bytes());
        let _ = out.flush();
    }

    /// A conversation file the agent writes its prompts and replies to.
    struct Conversation {
        /// The file, held open: its lock, where a process holds one, lasts as long as the process.
        file: File,
        /// The code an earlier "Remember the code" in the conversation gave.
        remembered: Option<String>,
        /// The marks of an entry's lines; none for the Codex terminal's own shape.
        marks: Option<Marks>,
    }

    /// The directory the conversations are searched for below: the part of `conversations` before
    /// the day.
    fn record_root(layout: &Layout) -> PathBuf {
        let base = layout.conversations.split("{date}").next().unwrap_or("");
        layout.home.join(base.trim_end_matches('/'))
    }

    /// Opens the conversation this start is for: a new one, or the one `resume` or `fork` names.
    fn open_conversation(
        layout: &Layout,
        subcommand: Option<&str>,
        identifier: Option<&str>,
    ) -> Result<Conversation, String> {
        let Some(subcommand) = subcommand else {
            return create(layout, "");
        };
        let id =
            identifier.ok_or_else(|| format!("{subcommand} needs a conversation identifier"))?;
        let saved = find(&record_root(layout), id)
            .ok_or_else(|| format!("no saved conversation with the identifier {id}"))?;
        let forks = match subcommand {
            "fork" => true,
            "resume" => std::env::var(RESUME_VARIABLE).is_ok_and(|mode| mode == "fork"),
            other => return Err(format!("unknown command {other}")),
        };
        if forks {
            let text = std::fs::read_to_string(&saved).map_err(|error| error.to_string())?;
            return create(layout, &text);
        }
        let file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&saved)
            .map_err(|error| error.to_string())?;
        if std::env::var(RESUME_VARIABLE).is_ok_and(|mode| mode == "locked")
            && flock(&file, FlockOperation::NonBlockingLockExclusive).is_err()
        {
            return Err(format!(
                "the conversation {id} is in use by another process"
            ));
        }
        let text = std::fs::read_to_string(&saved).map_err(|error| error.to_string())?;
        Ok(Conversation {
            file,
            remembered: remembered_in(&text),
            marks: layout.marks.clone(),
        })
    }

    /// Creates a conversation file with the lines `text` holds, under an identifier of its own, and
    /// takes its lock.
    fn create(layout: &Layout, text: &str) -> Result<Conversation, String> {
        let day = date(&["+%Y/%m/%d"])?;
        let time = date(&["+%Y-%m-%dT%H-%M-%S"])?;
        let directory = layout
            .home
            .join(layout.conversations.replace("{date}", &day));
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let path = directory.join(format!("rollout-{time}-{}.jsonl", uuid()?));
        let mut file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        file.write_all(text.as_bytes())
            .map_err(|error| error.to_string())?;
        // The first process on a conversation holds its lock; a second one that is not allowed to
        // share it finds it held. A copy is a conversation of its own, and takes its own lock.
        let _ = flock(&file, FlockOperation::NonBlockingLockExclusive);
        Ok(Conversation {
            file,
            remembered: remembered_in(text),
            marks: layout.marks.clone(),
        })
    }

    /// The output of the system's `date` with `arguments`, without its line end.
    fn date(arguments: &[&str]) -> Result<String, String> {
        let output = Command::new("/bin/date")
            .args(arguments)
            .output()
            .map_err(|error| format!("date: {error}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// A random identifier in the shape the agent's files carry, from the system's source.
    fn uuid() -> Result<String, String> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes))
            .map_err(|error| format!("no identifier: {error}"))?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let hex = hex_of(&bytes);
        Ok(format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        ))
    }

    /// Lower-case hexadecimal text of `bytes`.
    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The file under `directory` whose name ends in the identifier `id` and `.jsonl`.
    fn find(directory: &Path, id: &str) -> Option<PathBuf> {
        let suffix = format!("{id}.jsonl");
        let mut pending = vec![directory.to_path_buf()];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                pending.extend(std::fs::read_dir(&path).ok()?.flatten().map(|e| e.path()));
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(&suffix))
            {
                return Some(path);
            }
        }
        None
    }

    /// The code the last "Remember the code" in the conversation text gives.
    fn remembered_in(text: &str) -> Option<String> {
        text.lines()
            .filter_map(|line| {
                let after = line.split_once("Remember the code ")?.1;
                let code: String = after
                    .chars()
                    .take_while(|character| character.is_ascii_alphanumeric())
                    .collect();
                (!code.is_empty()).then_some(code)
            })
            .next_back()
    }

    /// What the terminal on the input was set to before the stand-in changed it.
    type Saved = rustix::termios::Termios;

    /// Sets the terminal on the input to deliver each key as it is typed, with no echo by the
    /// terminal, as a full-screen agent does; the stand-in echoes the keys itself. None where the
    /// input is no terminal.
    fn keys_as_typed() -> Option<Saved> {
        use rustix::termios::{
            LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr,
        };
        let stdin = std::io::stdin();
        let saved = tcgetattr(&stdin).ok()?;
        let mut modes = saved.clone();
        modes
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO);
        modes.special_codes[SpecialCodeIndex::VMIN] = 1;
        modes.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(&stdin, OptionalActions::Now, &modes).ok()?;
        Some(saved)
    }

    /// Where a read of keys is in an escape sequence.
    enum Escape {
        /// Outside one.
        None,
        /// After the escape byte.
        Opened,
        /// After `[`, until the sequence's last byte.
        Csi,
    }

    /// Reads one line of keys a terminal delivers as they are typed, and echoes each printable key
    /// as it comes; the backspace and the line-kill key take back what was echoed. Escape sequences
    /// are kept in the line and not echoed. The harmless key shows its text once it has been read.
    /// None where the terminal closes.
    fn line_of_keys(input: &mut impl Read, harmless: Option<&Harmless>) -> Option<Vec<u8>> {
        let mut out = std::io::stdout();
        let mut line: Vec<u8> = Vec::new();
        let mut escape = Escape::None;
        let mut key = [0u8; 1];
        loop {
            if input.read(&mut key).ok()? == 0 {
                return None;
            }
            let key = key[0];
            match escape {
                Escape::Opened => {
                    line.push(key);
                    escape = if key == b'[' {
                        Escape::Csi
                    } else {
                        Escape::None
                    };
                    if matches!(escape, Escape::None) {
                        shows_the_harmless_key(&mut out, &line, harmless);
                    }
                    continue;
                }
                Escape::Csi => {
                    line.push(key);
                    if (0x40..=0x7e).contains(&key) {
                        escape = Escape::None;
                        shows_the_harmless_key(&mut out, &line, harmless);
                    }
                    continue;
                }
                Escape::None => {}
            }
            match key {
                0x1b => {
                    line.push(key);
                    escape = Escape::Opened;
                }
                b'\r' | b'\n' => {
                    let _ = out.write_all(b"\r\n");
                    let _ = out.flush();
                    return Some(line);
                }
                0x04 if line.is_empty() => return None,
                0x7f | 0x08 | 0x15 => {
                    // Takes back the last character, or with the line-kill key the whole line.
                    let mut erased = 0;
                    while let Some(byte) = line.pop() {
                        if byte & 0xc0 != 0x80 {
                            erased += 1;
                            if key != 0x15 {
                                break;
                            }
                        }
                    }
                    let _ = out.write_all("\x08 \x08".repeat(erased).as_bytes());
                    let _ = out.flush();
                }
                _ => {
                    line.push(key);
                    if key >= 0x20 {
                        let _ = out.write_all(&[key]);
                        let _ = out.flush();
                    }
                    shows_the_harmless_key(&mut out, &line, harmless);
                }
            }
        }
    }

    /// Shows the text of the harmless key on a line of its own once the line ends with the key,
    /// where that text is not what the echo of the key already shows.
    fn shows_the_harmless_key(out: &mut impl Write, line: &[u8], harmless: Option<&Harmless>) {
        if let Some(harmless) = harmless
            && harmless.shows != harmless.input
            && line.ends_with(harmless.input.as_bytes())
        {
            let _ = out.write_all(format!("\r\n{}\r\n", harmless.shows).as_bytes());
            let _ = out.flush();
        }
    }

    /// Shows `banner` and the composer and answers prompts, a line at a time, until the terminal
    /// closes. With `keys_typed` on a terminal, the stand-in takes each key as it is typed and echoes
    /// it, as a full-screen agent does, so that a part of a line typed and not yet sent is the
    /// agent's and not left in the terminal when the agent ends.
    fn composer(
        mut conversation: Option<Conversation>,
        banner: &[String],
        composer: &str,
        keys_typed: bool,
        mut leave_program: Option<std::ffi::OsString>,
        harmless: Option<&Harmless>,
    ) {
        for line in banner {
            println!("{line}");
        }
        println!();
        println!("› {composer}");
        let stdin = std::io::stdin();
        let saved = keys_typed.then(keys_as_typed).flatten();
        let mut line = Vec::new();
        loop {
            line.clear();
            if saved.is_some() {
                match line_of_keys(&mut stdin.lock(), harmless) {
                    Some(keys) => line = keys,
                    None => break,
                }
            } else {
                match stdin.lock().read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let raw = String::from_utf8_lossy(&line).into_owned();
            let prompt = raw
                .replace("\x1b[200~", "")
                .replace("\x1b[201~", "")
                .trim()
                .to_owned();
            if prompt.is_empty() {
                continue;
            }
            if let Some(program) = leave_program.take()
                && let Err(why) = leave(&program)
            {
                eprintln!("Error: {why}");
                std::process::exit(2);
            }
            let reply = answer(&prompt, conversation.as_mut());
            println!("• {reply}");
            println!();
            println!("› {composer}");
        }
        if let Some(saved) = saved {
            let _ =
                rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &saved);
        }
    }

    /// Runs `program` and waits for it, as the agent's own change to the files of the run.
    ///
    /// # Errors
    ///
    /// Returns why the program did not start or did not end well.
    fn leave(program: &std::ffi::OsStr) -> Result<(), String> {
        let name = program.to_string_lossy();
        let status = Command::new(program)
            .status()
            .map_err(|error| format!("{LEAVE_VARIABLE} {name}: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{LEAVE_VARIABLE} {name} ended with {status}"))
        }
    }

    /// Records the prompt, finds the reply to it and records that.
    fn answer(prompt: &str, mut conversation: Option<&mut Conversation>) -> String {
        let image = image_named(prompt);
        if let Some(conversation) = conversation.as_deref_mut() {
            record(conversation, "user", prompt, image.as_deref());
        }
        if let Some(code) = prompt
            .split_once("Remember the code ")
            .map(|(_, after)| after)
            .map(|after| {
                after
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect()
            })
            .filter(|code: &String| !code.is_empty())
            && let Some(conversation) = conversation.as_deref_mut()
        {
            conversation.remembered = Some(code);
        }
        let remembered = conversation
            .as_deref()
            .and_then(|conversation| conversation.remembered.as_deref());
        let reply = reply_to(prompt, image.as_deref(), remembered);
        if let Some(conversation) = conversation {
            record(conversation, "assistant", &reply, None);
        }
        reply
    }

    /// What the stand-in says to `prompt`.
    fn reply_to(prompt: &str, image: Option<&[u8]>, remembered: Option<&str>) -> String {
        if prompt.contains("What colour fills this image") {
            let red = image.is_some_and(|bytes| {
                std::env::var(RED_DIGEST).is_ok_and(|digest| digest == sha256_hex(bytes))
            });
            let code = prompt
                .split_once("the code ")
                .map(|(_, after)| after)
                .map(|after| after.split_whitespace().next().unwrap_or(""))
                .unwrap_or("")
                .to_uppercase();
            return if red {
                format!("red {code}")
            } else {
                "no image".to_owned()
            };
        }
        if prompt.contains("What code did I ask you to remember") {
            return remembered.map_or_else(|| "none".to_owned(), str::to_uppercase);
        }
        if let Some(sum) = sum_in(prompt) {
            return sum.to_string();
        }
        "Understood.".to_owned()
    }

    /// The sum "What is A plus B" asks for.
    fn sum_in(prompt: &str) -> Option<u64> {
        let after = prompt.split_once("What is ")?.1;
        let (first, rest) = after.split_once(" plus ")?;
        let second: String = rest.chars().take_while(char::is_ascii_digit).collect();
        Some(first.trim().parse::<u64>().ok()? + second.parse::<u64>().ok()?)
    }

    /// The bytes of the image file the prompt names: the path between the paste marks, else the first
    /// word that is an absolute path.
    fn image_named(prompt: &str) -> Option<Vec<u8>> {
        let words: Vec<&str> = prompt.split_whitespace().collect();
        words
            .iter()
            .find(|word| word.starts_with('/'))
            .and_then(|path| std::fs::read(path).ok())
    }

    /// Lower-case hexadecimal SHA-256 of `bytes`.
    fn sha256_hex(bytes: &[u8]) -> String {
        hex_of(&kr_cbor::sha256(bytes))
    }

    /// The data address of a PNG image whose bytes are `bytes`.
    fn data_address(bytes: &[u8]) -> String {
        format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    }

    /// Appends one message to the conversation file, as the lines the agent writes: those of the
    /// Codex terminal, or those that hold the entry's marks.
    fn record(conversation: &mut Conversation, role: &str, text: &str, image: Option<&[u8]>) {
        let lines = match &conversation.marks {
            Some(marks) => entry_lines(marks, role, text, image),
            None => codex_lines(role, text, image),
        };
        for line in lines {
            let _ = writeln!(conversation.file, "{line}");
        }
        let _ = conversation.file.flush();
    }

    /// The lines the Codex terminal writes for one message.
    fn codex_lines(role: &str, text: &str, image: Option<&[u8]>) -> Vec<String> {
        let mut lines = Vec::new();
        let mut content = Vec::new();
        if role == "user" {
            lines.push(
                json!({ "type": "event_msg", "payload": { "type": "task_started" } }).to_string(),
            );
            content.push(json!({ "type": "input_text", "text": text }));
            if let Some(bytes) = image {
                content.push(json!({ "type": "input_image", "image_url": data_address(bytes) }));
            }
        } else {
            content.push(json!({ "type": "output_text", "text": text }));
        }
        lines.push(
            json!({
                "type": "response_item",
                "payload": { "type": "message", "role": role, "content": content },
            })
            .to_string(),
        );
        lines
    }

    /// The lines an entry's agent writes for one message: a prompt after the line that starts its
    /// turn, where the entry has one, and a reply; each holds its mark as the entry gives it.
    fn entry_lines(marks: &Marks, role: &str, text: &str, image: Option<&[u8]>) -> Vec<String> {
        let mut lines = Vec::new();
        if role == "user" {
            if let Some(turn) = &marks.turn {
                lines.push(format!("{{{turn}}}"));
            }
            let mut content = vec![format!("{{\"text\":{}}}", json!(text))];
            if let (Some(mark), Some(bytes)) = (&marks.image, image) {
                content.push(format!(
                    "{{{mark},\"image_url\":{}}}",
                    json!(data_address(bytes))
                ));
            }
            lines.push(format!(
                "{{{},\"content\":[{}]}}",
                marks.prompt,
                content.join(",")
            ));
        } else {
            lines.push(format!(
                "{{{},\"content\":[{{\"text\":{}}}]}}",
                marks.reply,
                json!(text)
            ));
        }
        lines
    }
}

fn main() {
    #[cfg(unix)]
    stand_in::run();
}
