//! A stand-in for the pinned Codex terminal, for running the qualification parts that need a
//! login with no account and no model: it signs in nowhere, answers three kinds of question from
//! its own text, and keeps a conversation file of the shape the real agent keeps.
//!
//! It is started as the build list's command, placed as `bin/codex` in a prefix of its own, with
//! the arguments the build list gives the real agent. Flags that take a value are skipped; the
//! first word after them is the subcommand: `resume <id>` or `fork <id>`, or none.
//!
//! - `--version` prints a version line.
//! - Without a `config.toml` in the configuration directory (`CODEX_HOME`, else `~/.codex`) it
//!   shows the sign-in screen and moves its marker with the arrow keys, as the real agent's first
//!   screen does, and does nothing else.
//! - With one it shows the banner and the composer and reads prompts a line at a time. It answers
//!   "What is A plus B" with the sum, "What code did I ask you to remember" with the code of an
//!   earlier "Remember the code X." in the conversation, upper case, and "What colour fills this
//!   image" with `red` and the code the question gives, upper case, when the file the prompt
//!   names holds the bytes whose SHA-256 is in `STAND_IN_RED_SHA256`. Anything else it
//!   answers with a line that holds none of those.
//! - Each prompt and reply is a line of the conversation file
//!   `sessions/YYYY/MM/DD/rollout-<time>-<uuid>.jsonl` in the configuration directory; an image
//!   a prompt names is recorded in the prompt's line as the base64 text the real agent writes.
//! - What `resume <id>` does with a conversation another process holds is set by
//!   `STAND_IN_RESUME`: `continue` (the default) writes into the same file, `locked`
//!   refuses because the first process holds the file's lock, and `fork` writes into a copy under
//!   an identifier of its own. `fork <id>` always writes into a copy.

/// The stand-in's own code, which uses the system's terminal and file locks.
#[cfg(unix)]
mod stand_in {
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use base64::Engine as _;
    use rustix::fs::{FlockOperation, flock};
    use serde_json::json;

    /// The version the pinned release reports.
    const VERSION: &str = "0.155.1";

    /// The variable that holds the lower-case hexadecimal SHA-256 of the image the stand-in calls red.
    const RED_DIGEST: &str = "STAND_IN_RED_SHA256";

    /// The variable that says what `resume` does: `continue`, `locked` or `fork`.
    const RESUME_VARIABLE: &str = "STAND_IN_RESUME";

    /// The text the composer shows while it waits for a prompt.
    const COMPOSER: &str = "Ask Codex to do anything";

    /// What the sign-in screen offers, in order.
    const SIGN_IN: [&str; 3] = [
        "Sign in with ChatGPT",
        "Sign in with Device Code",
        "Provide your own API key",
    ];

    /// Flags the agent takes a value after.
    const WITH_VALUE: [&str; 6] = ["-c", "-a", "-s", "-m", "--disable", "--enable"];

    pub fn run() {
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        if arguments.iter().any(|argument| argument == "--version") {
            println!("codex-cli {VERSION}");
            return;
        }
        let (subcommand, identifier) = subcommand_of(&arguments);
        let home = configuration_directory();
        if !home.join("config.toml").is_file() {
            sign_in_screen();
            return;
        }
        let conversation =
            match open_conversation(&home, subcommand.as_deref(), identifier.as_deref()) {
                Ok(conversation) => conversation,
                Err(why) => {
                    eprintln!("Error: {why}");
                    std::process::exit(1);
                }
            };
        composer(conversation);
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

    /// The directory the agent keeps its configuration and conversations in.
    fn configuration_directory() -> PathBuf {
        std::env::var_os("CODEX_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".codex")
            })
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
    }

    /// Opens the conversation this start is for: a new one, or the one `resume` or `fork` names.
    fn open_conversation(
        home: &Path,
        subcommand: Option<&str>,
        identifier: Option<&str>,
    ) -> Result<Conversation, String> {
        let Some(subcommand) = subcommand else {
            return create(home, "");
        };
        let id =
            identifier.ok_or_else(|| format!("{subcommand} needs a conversation identifier"))?;
        let saved = find(&home.join("sessions"), id)
            .ok_or_else(|| format!("no saved conversation with the identifier {id}"))?;
        let forks = match subcommand {
            "fork" => true,
            "resume" => std::env::var(RESUME_VARIABLE).is_ok_and(|mode| mode == "fork"),
            other => return Err(format!("unknown command {other}")),
        };
        if forks {
            let text = std::fs::read_to_string(&saved).map_err(|error| error.to_string())?;
            return create(home, &text);
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
        })
    }

    /// Creates a conversation file with the lines `text` holds, under an identifier of its own, and
    /// takes its lock.
    fn create(home: &Path, text: &str) -> Result<Conversation, String> {
        let day = date(&["+%Y/%m/%d"])?;
        let time = date(&["+%Y-%m-%dT%H-%M-%S"])?;
        let directory = home.join("sessions").join(day);
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

    /// Shows the banner and the composer and answers prompts, a line at a time, until the terminal
    /// closes.
    fn composer(mut conversation: Conversation) {
        println!("╭──────────────────────────────────────╮");
        println!("│ >_ OpenAI Codex (v{VERSION})          │");
        println!("╰──────────────────────────────────────╯");
        println!();
        println!("› {COMPOSER}");
        let stdin = std::io::stdin();
        let mut line = Vec::new();
        loop {
            line.clear();
            match stdin.lock().read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
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
            let reply = answer(&prompt, &mut conversation);
            println!("• {reply}");
            println!();
            println!("› {COMPOSER}");
        }
    }

    /// Records the prompt, finds the reply to it and records that.
    fn answer(prompt: &str, conversation: &mut Conversation) -> String {
        let image = image_named(prompt);
        let mut content = vec![json!({ "type": "input_text", "text": prompt })];
        if let Some(bytes) = &image {
            content.push(json!({
                "type": "input_image",
                "image_url": format!(
                    "data:image/png;base64,{}",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                ),
            }));
        }
        record(conversation, "user", &content);
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
        {
            conversation.remembered = Some(code);
        }
        let reply = reply_to(prompt, image.as_deref(), conversation.remembered.as_deref());
        record(
            conversation,
            "assistant",
            &[json!({ "type": "output_text", "text": reply })],
        );
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

    /// Appends one message to the conversation file, as a line of JSON.
    fn record(conversation: &mut Conversation, role: &str, content: &[serde_json::Value]) {
        let kind = if role == "user" {
            json!({ "type": "event_msg", "payload": { "type": "task_started" } })
        } else {
            json!(null)
        };
        let mut lines = Vec::new();
        if !kind.is_null() {
            lines.push(kind);
        }
        lines.push(json!({
            "type": "response_item",
            "payload": { "type": "message", "role": role, "content": content },
        }));
        for line in lines {
            let _ = writeln!(conversation.file, "{line}");
        }
        let _ = conversation.file.flush();
    }
}

fn main() {
    #[cfg(unix)]
    stand_in::run();
}
