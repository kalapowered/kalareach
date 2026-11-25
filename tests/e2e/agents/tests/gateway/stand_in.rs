//! The terminal stand-in for the build list's other entries.
//!
//! `agent-stand-in` takes the names and texts of the entry it stands for from a file the driver
//! makes ([`stand_in_file`]) and never a path to run. The three synthetic entries here are a script
//! launch, a wheel launch and a native entry with texts of its own. The cases in this file start the
//! program alone, with a home of its own, and read what it printed and what it recorded.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kr_e2e_agents::build::Build;
use kr_e2e_agents::held::{conversations_relative_in, turns_recorded};
use kr_e2e_m1b::run::RootPin;

/// The pinned program and the newer one: one source, two programs.
const PROGRAM: &str = env!("CARGO_BIN_EXE_agent-stand-in");
const NEWER: &str = env!("CARGO_BIN_EXE_agent-stand-in-newer");

/// How long a run of the program alone may take: it ends when its input does.
const WITHIN: Duration = Duration::from_secs(20);

/// The members of the file the stand-in takes: names and texts, and no path.
const MEMBERS: [&str; 12] = [
    "command",
    "launch",
    "version",
    "newer_version",
    "ready",
    "composer",
    "config_variable",
    "conversations",
    "prompt_line",
    "reply_line",
    "turn_line",
    "image_line",
];

/// One synthetic entry.
pub struct Synthetic {
    /// What a failure says the entry is.
    pub name: &'static str,
    /// The entry.
    pub build: Build,
}

/// An entry that is typed as `command`, launched as `launch`, shows `ready` and `composer`, and
/// whose record holds its lines under the marks `marks` (prompt, reply, turn, image).
fn entry(
    package: &str,
    (command, launch, runtime, pinned): (&str, &str, &[&str], &str),
    (ready, composer): (&str, &str),
    marks: [&str; 4],
) -> Build {
    serde_json::from_value(serde_json::json!({
        "package": package, "application": "a", "version": "1.2.3", "prefix": "/real/prefix",
        "pinned": pinned, "sha256": "00", "command": command, "launch": launch,
        "runtime": runtime, "ready": ready, "harmless": { "input": "h", "shows": "h" },
        "transcript": "t", "missing": {},
        "newer": {
            "version": "1.3.0", "prefix": "/real/newer", "pinned": pinned, "sha256": "00",
            "ready": ready
        },
        "account": {
            "login": "l", "stored": "s", "home": "run", "budget": "b", "turns": 3,
            "conversations": "sessions/{date}", "prompt_line": marks[0], "ready": ready,
            "composer": composer, "submit": "\r", "clear": "\u{15}", "reply_line": marks[1],
            "decision_line": "y", "busy": "b", "slash": { "input": "/p", "shows": "p" },
            "interrupt": { "input": "\u{1b}", "shows": "i" },
            "approval": { "shows": "a", "allow": "y", "deny": "n" },
            "resume": ["resume", "{conversation}"], "image": "paste",
            "turn_line": marks[2], "image_line": marks[3]
        }
    }))
    .expect("an entry")
}

/// The three synthetic entries: a script launch, a wheel launch and a native entry whose texts and
/// marks are not Codex's.
pub fn synthetic() -> [Synthetic; 3] {
    [
        Synthetic {
            name: "the script launch",
            build: entry(
                "kalareach/gemini-cli",
                (
                    "gemini",
                    "script",
                    &["/real/node/bin/node"],
                    "lib/gemini.js",
                ),
                ("Script agent ready", "script> type here"),
                [
                    "\"type\":\"user\"",
                    "\"type\":\"reply\"",
                    "\"type\":\"turn_started\"",
                    "\"type\":\"inline_image\"",
                ],
            ),
        },
        Synthetic {
            name: "the wheel launch",
            build: entry(
                "kalareach/kimi-cli",
                (
                    "kimi",
                    "wheel",
                    &["/real/python/bin/python3"],
                    "wheel/kimi-1.2.3-py3-none-any.whl",
                ),
                ("Wheel agent ready", "wheel> type here"),
                [
                    "\"speaker\":\"you\"",
                    "\"speaker\":\"agent\"",
                    "\"event\":\"turn\"",
                    "\"attachment\":\"image\"",
                ],
            ),
        },
        Synthetic {
            name: "the native entry with texts of its own",
            build: entry(
                "kalareach/claude-code",
                ("claude", "native", &[], "bin/claude"),
                ("Native agent ready", "native> type here"),
                [
                    "\"role\":\"user\"",
                    "\"role\":\"assistant\"",
                    "\"kind\":\"turn_started\"",
                    "\"kind\":\"image\"",
                ],
            ),
        },
    ]
}

/// The file the stand-in takes for `build`: the names and texts of the entry, and no path to run.
///
/// # Panics
///
/// Panics where the entry has no account to take the record's marks from.
pub fn stand_in_file(build: &Build) -> serde_json::Value {
    let account = build
        .account
        .as_ref()
        .expect("an entry with an account, for the record's marks");
    serde_json::json!({
        "command": build.command,
        "launch": serde_json::to_value(build.launch).expect("a launch kind"),
        "version": build.version,
        "newer_version": build.newer.as_ref().map(|newer| newer.version.clone()),
        "ready": build.ready,
        "composer": account.composer,
        "config_variable": account
            .config_directory
            .as_ref()
            .map(|directory| directory.variable.clone()),
        "conversations": account.conversations,
        "prompt_line": account.prompt_line,
        "reply_line": account.reply_line,
        "turn_line": account.turn_line,
        "image_line": account.image_line,
    })
}

/// A directory of this case's own below the system's temporary one, empty.
fn scratch(case: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-stand-in-{case}-{}", super::mark()));
    std::fs::create_dir_all(&directory).expect("a directory for the case");
    directory
}

/// What one run of the program alone printed and left.
struct Ran {
    /// What it printed on its output.
    out: String,
    /// What it printed on its error output.
    err: String,
    /// Whether it ended well.
    success: bool,
    /// The home it ran in.
    home: PathBuf,
}

/// Runs `program` with `arguments`, the file `file` as the entry it stands for, the lines `input`
/// on its input and the variables `variables`, in a home of its own below `base`, and waits for it
/// to end.
///
/// # Panics
///
/// Panics where the program cannot be started or does not end within [`WITHIN`].
fn ran(
    base: &Path,
    program: &str,
    file: &serde_json::Value,
    arguments: &[&str],
    input: &[String],
    variables: &[(&str, String)],
) -> Ran {
    let home = base.join("home");
    std::fs::create_dir_all(&home).expect("a home for the program");
    let entry_file = base.join("entry.json");
    std::fs::write(&entry_file, file.to_string()).expect("the file of the entry");
    let typed = base.join("input");
    std::fs::write(
        &typed,
        input
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )
    .expect("the program's input");
    let (out_file, err_file) = (base.join("out"), base.join("err"));
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("HOME", &home)
        .env("STAND_IN_ENTRY", &entry_file)
        .envs(variables.iter().map(|(name, value)| (*name, value)))
        .stdin(Stdio::from(std::fs::File::open(&typed).expect("the input")))
        .stdout(Stdio::from(
            std::fs::File::create(&out_file).expect("the output"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&err_file).expect("the error output"),
        ));
    let mut child = command.spawn().expect("the stand-in starts");
    let started = Instant::now();
    let status = loop {
        match child.try_wait().expect("the stand-in is waited for") {
            Some(status) => break status,
            None if started.elapsed() < WITHIN => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the stand-in did not end within {WITHIN:?} of the end of its input");
            }
        }
    };
    Ran {
        out: String::from_utf8_lossy(&std::fs::read(&out_file).expect("the output")).into_owned(),
        err: String::from_utf8_lossy(&std::fs::read(&err_file).expect("the error output"))
            .into_owned(),
        success: status.success(),
        home,
    }
}

/// The lines the program printed as replies.
fn replies(out: &str) -> Vec<&str> {
    out.lines()
        .filter_map(|line| line.strip_prefix("• "))
        .collect()
}

/// The prompts of the answering case, with what each is answered, and the image file it names.
fn questions(image: &Path) -> Vec<(String, &'static str)> {
    vec![
        ("What is 12 plus 30".to_owned(), "42"),
        ("Remember the code zq81.".to_owned(), "Understood."),
        ("What code did I ask you to remember".to_owned(), "ZQ81"),
        (
            format!(
                "What colour fills this image {} and say the code k7",
                image.display()
            ),
            "red K7",
        ),
    ]
}

/// The bytes of the image the answering case's stand-in calls red.
const RED_IMAGE: &[u8] = b"a red image, as bytes";

/// The variable the stand-in reads the digest of the image it calls red from.
fn red_variable() -> (&'static str, String) {
    (
        "STAND_IN_RED_SHA256",
        kr_cbor::sha256(RED_IMAGE)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// The stand-in shows the first screen and the composer text of the entry it stands for, and no
/// sign-in screen.
#[test]
fn the_stand_in_shows_the_texts_of_the_entry_it_stands_for_and_no_sign_in_screen() {
    for synthetic in synthetic() {
        let base = scratch("shows");
        let ran = ran(
            &base,
            PROGRAM,
            &stand_in_file(&synthetic.build),
            &[],
            &[],
            &[],
        );
        let (name, ready) = (synthetic.name, &synthetic.build.ready);
        let composer = &synthetic
            .build
            .account
            .as_ref()
            .expect("an account")
            .composer;
        assert!(
            ran.out.contains(ready.as_str()),
            "{name}: the first screen shows the entry's ready text {ready:?}, and the stand-in \
             printed:\n{}",
            ran.out
        );
        assert!(
            ran.out.contains(composer.as_str()),
            "{name}: the composer shows the entry's text {composer:?}, and the stand-in \
             printed:\n{}",
            ran.out
        );
        assert!(
            !ran.out.contains("Sign in") && ran.success,
            "{name}: the stand-in shows no sign-in screen and ends well: {}{}",
            ran.out,
            ran.err
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The stand-in answers a sum, a remembered code and an image colour, whatever the entry.
#[test]
fn the_stand_in_answers_a_sum_a_remembered_code_and_an_image_colour_for_every_entry() {
    for synthetic in synthetic() {
        let base = scratch("answers");
        let image = base.join("image.png");
        std::fs::write(&image, RED_IMAGE).expect("the image");
        let questions = questions(&image);
        let input: Vec<String> = questions.iter().map(|(prompt, _)| prompt.clone()).collect();
        let ran = ran(
            &base,
            PROGRAM,
            &stand_in_file(&synthetic.build),
            &[],
            &input,
            &[red_variable()],
        );
        let said: Vec<&str> = questions.iter().map(|(_, reply)| *reply).collect();
        assert_eq!(
            replies(&ran.out),
            said,
            "{}: the stand-in's replies, in order; it printed:\n{}{}",
            synthetic.name,
            ran.out,
            ran.err
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The files below `directory`, with their text.
fn files_below(directory: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("a directory")
                    .flatten()
                    .map(|entry| entry.path()),
            );
        } else if let Ok(text) = std::fs::read_to_string(&path) {
            found.push((path, text));
        }
    }
    found
}

/// The stand-in writes the record below the entry's `conversations`: a turn line before each prompt
/// line, a reply line after it and, for an image, the entry's image line holding the image as
/// base64 text, each under the mark the entry gives. The audit's own reader counts the turns.
#[test]
fn the_stand_in_writes_the_entrys_record_lines_below_its_conversations() {
    for synthetic in synthetic() {
        let base = scratch("records");
        let image = base.join("image.png");
        std::fs::write(&image, RED_IMAGE).expect("the image");
        let questions = questions(&image);
        let input: Vec<String> = questions.iter().map(|(prompt, _)| prompt.clone()).collect();
        let ran = ran(
            &base,
            PROGRAM,
            &stand_in_file(&synthetic.build),
            &[],
            &input,
            &[red_variable()],
        );
        let name = synthetic.name;
        let account = synthetic.build.account.as_ref().expect("an account");
        let record = ran.home.join("sessions");
        let files = files_below(&record);
        assert_eq!(
            files.len(),
            1,
            "{name}: one conversation file below the entry's conversations: {:?}",
            files.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );
        let text = &files[0].1;
        let count = |mark: &str| text.lines().filter(|line| line.contains(mark)).count();
        assert_eq!(
            count(&account.prompt_line),
            questions.len(),
            "{name}: a line holding the prompt mark {:?} for each prompt, in:\n{text}",
            account.prompt_line
        );
        assert_eq!(
            count(&account.reply_line),
            questions.len(),
            "{name}: a line holding the reply mark {:?} for each reply, in:\n{text}",
            account.reply_line
        );
        let image_mark = account.image_line.as_deref().expect("an image mark");
        let image_lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains(image_mark))
            .collect();
        assert_eq!(
            image_lines.len(),
            1,
            "{name}: one line holding the image mark {image_mark:?}, in:\n{text}"
        );
        assert!(
            image_lines[0].contains("base64,YSByZWQgaW1hZ2UsIGFzIGJ5dGVz"),
            "{name}: the image line holds the image as base64 text: {}",
            image_lines[0]
        );
        // The turn lines are the audit's: its reader counts one turn for each prompt.
        let root = std::fs::canonicalize(&ran.home).expect("the home");
        let pin = RootPin::of(&root).expect("a directory to pin");
        let recorded = turns_recorded(
            account,
            &root,
            &pin,
            &conversations_relative_in(account, ""),
        )
        .unwrap_or_else(|why| panic!("{name}: the record is read: {why}"));
        assert_eq!(
            recorded.turns,
            questions.len() as u64,
            "{name}: the audit counts a turn for each prompt, in:\n{text}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The stand-in reports the entry's version, and the newer program the entry's newer version.
#[test]
fn the_stand_in_reports_the_entrys_version_and_the_newer_one_the_entrys_newer_version() {
    for synthetic in synthetic() {
        let base = scratch("version");
        let file = stand_in_file(&synthetic.build);
        let command = &synthetic.build.command;
        let pinned = ran(&base, PROGRAM, &file, &["--version"], &[], &[]);
        assert_eq!(
            pinned.out.trim(),
            format!("{command} {}", synthetic.build.version),
            "{}: the pinned program's version line",
            synthetic.name
        );
        let newer = ran(&base, NEWER, &file, &["--version"], &[], &[]);
        assert_eq!(
            newer.out.trim(),
            format!(
                "{command} {}",
                synthetic
                    .build
                    .newer
                    .as_ref()
                    .expect("a newer build")
                    .version
            ),
            "{}: the newer program's version line",
            synthetic.name
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// A script or a wheel is started with its script as the first argument, and the stand-in does not
/// take that for a command; a native entry has no script, and the same first word is refused.
#[test]
fn a_stand_in_started_by_a_script_does_not_take_the_script_for_a_command() {
    for synthetic in synthetic() {
        let base = scratch("script");
        let started = ran(
            &base,
            PROGRAM,
            &stand_in_file(&synthetic.build),
            &["/run/t/launcher"],
            &[],
            &[],
        );
        let scripted = synthetic.build.launch != kr_e2e_agents::build::Launch::Native;
        if scripted {
            assert!(
                started.success && started.out.contains(synthetic.build.ready.as_str()),
                "{}: started with its script, the stand-in shows the first screen and ends \
                 well: {}{}",
                synthetic.name,
                started.out,
                started.err
            );
        } else {
            assert!(
                !started.success && started.err.contains("/run/t/launcher"),
                "{}: a native entry has no script, and its first word is taken as a command and \
                 refused: {}{}",
                synthetic.name,
                started.out,
                started.err
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The file made for an entry that names real executables holds none of them, and the stand-in
/// refuses a file that names a program to run.
#[test]
fn the_file_made_for_the_stand_in_names_no_program_to_run_and_one_that_does_is_refused() {
    for synthetic in synthetic() {
        let file = stand_in_file(&synthetic.build);
        let object = file.as_object().expect("an object");
        for name in object.keys() {
            assert!(
                MEMBERS.contains(&name.as_str()),
                "{}: the file made for the stand-in holds the member {name}, which is not a \
                 name or a text",
                synthetic.name
            );
        }
        let base = scratch("refuses");
        for member in ["prefix", "pinned", "runtime"] {
            let mut naming = file.clone();
            naming[member] = serde_json::json!("/usr/bin/real-program");
            let refused = ran(&base, PROGRAM, &naming, &[], &[], &[]);
            assert!(
                !refused.success && refused.err.contains(member),
                "{}: a file that names {member} is refused, naming it: {}{}",
                synthetic.name,
                refused.out,
                refused.err
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
