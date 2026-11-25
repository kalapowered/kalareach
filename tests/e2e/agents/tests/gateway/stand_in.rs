//! The terminal stand-in for the build list's other entries.
//!
//! `agent-stand-in` takes the names and texts of the entry it stands for from a file the driver
//! makes ([`stand_in_file`]) and never a path to run. The synthetic entries here are a script
//! launch, a wheel launch, a native entry with texts of its own and a native entry whose harmless
//! key is a key sequence, each with an account, and a wheel launch and a native entry with none.
//! Some cases in this file start the program alone, with a home of its own, and read what it
//! printed and what it recorded. The others choose the entry that the stand-in route stands in for
//! ([`stand_in_chosen`]) and run the staged
//! parts that start no model turn for the stand-in made from it. The route places the stand-in as
//! the entry is launched ([`placing_of`]): a script or a wheel as the program under the runtime's
//! name and a script that names it, which a person types as the command. The parts run with a
//! marker at every place the entry names a program to run ([`marked`]), because the route places
//! only the program the harness built: a part fails if a marker ran.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kr_e2e_agents::build::{Account, Build, Launch, read_build};
use kr_e2e_agents::held::{conversations_relative_in, turns_recorded};
use kr_e2e_agents::subject::Subject;
use kr_e2e_m1b::run::{RootPin, Run};
use kr_e2e_m1b::shells;
use kr_plugin_sdk::package::MANIFEST_FILE;

use super::package::{Shape, release, write};
use super::staged_a::{part_2b, part_2c, part_5a, part_6a, part_8a, part_14_03a};
use super::{
    BUILD_VARIABLE, Chosen, Context, Route, STAND_IN_ENTRY_VARIABLE, STAND_IN_MANIFEST_VARIABLE,
    inode_of,
};

/// The pinned program and the newer one: one source, two programs.
const PROGRAM: &str = env!("CARGO_BIN_EXE_agent-stand-in");
const NEWER: &str = env!("CARGO_BIN_EXE_agent-stand-in-newer");

/// How long a run of the program alone may take: it ends when its input does.
const WITHIN: Duration = Duration::from_secs(20);

/// The members of the file the stand-in takes: names and texts, and no path.
const MEMBERS: [&str; 14] = [
    "command",
    "launch",
    "version",
    "newer_version",
    "ready",
    "newer_ready",
    "harmless",
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
    /// The entry as the file the build list holds it in.
    pub file: serde_json::Value,
    /// The entry.
    pub build: Build,
}

impl Synthetic {
    /// The entry [`entry_json`] makes from the rest.
    fn of(
        name: &'static str,
        package: &str,
        shape: (&str, &str, &[&str], &str),
        texts: (&str, &str),
        marks: [&str; 4],
    ) -> Self {
        let file = entry_json(package, shape, texts, marks);
        let build = serde_json::from_value(file.clone()).expect("an entry");
        Self { name, file, build }
    }

    /// The entry with `input` as its harmless key and `shows` as the text its screen shows once it
    /// has taken that key.
    fn harmless_key(mut self, input: &str, shows: &str) -> Self {
        self.file["harmless"] = serde_json::json!({ "input": input, "shows": shows });
        self.build = serde_json::from_value(self.file.clone()).expect("an entry");
        self
    }

    /// The entry of an agent that has no account, named `name`.
    fn without_account(mut self, name: &'static str) -> Self {
        self.file
            .as_object_mut()
            .expect("an entry")
            .remove("account");
        self.name = name;
        self.build = serde_json::from_value(self.file.clone()).expect("an entry");
        self
    }
}

/// The text a harmless keystroke types at the composer of every synthetic entry, which the
/// composer shows once the terminal has echoed it.
const HARMLESS: &str = "kr-harmless";

/// An entry that is typed as `command`, launched as `launch`, shows `ready` and `composer`, and
/// whose record holds its lines under the marks `marks` (prompt, reply, turn, image), as the file
/// the build list holds it in.
fn entry_json(
    package: &str,
    (command, launch, runtime, pinned): (&str, &str, &[&str], &str),
    (ready, composer): (&str, &str),
    marks: [&str; 4],
) -> serde_json::Value {
    let newer_ready = format!("{command} 1.3.0 is up");
    serde_json::json!({
        "package": package, "application": "a", "version": "1.2.3", "prefix": "/real/prefix",
        "pinned": pinned, "sha256": "00", "command": command, "launch": launch,
        "runtime": runtime, "ready": ready,
        "harmless": { "input": HARMLESS, "shows": HARMLESS },
        "transcript": "sessions/{cwd_slug}/{session}.jsonl", "missing": {},
        "newer": {
            "version": "1.3.0", "prefix": "/real/newer", "pinned": pinned, "sha256": "00",
            "ready": newer_ready
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
    })
}

/// The marks the record of a native entry's lines holds.
const NATIVE_MARKS: [&str; 4] = [
    "\"role\":\"user\"",
    "\"role\":\"assistant\"",
    "\"kind\":\"turn_started\"",
    "\"kind\":\"image\"",
];

/// A native entry for `plugin` typed as `command`, whose first screen and composer show the
/// command's name.
fn native_synthetic(plugin: &str, command: &str) -> Synthetic {
    Synthetic::of(
        "a native entry",
        plugin,
        (command, "native", &[], &format!("bin/{command}")),
        (
            &format!("{command} ready"),
            &format!("{command}> type here"),
        ),
        NATIVE_MARKS,
    )
}

/// A native entry for `plugin` typed as `command`, whose first screen and composer show the
/// command's name.
pub fn native_entry(plugin: &str, command: &str) -> Build {
    native_synthetic(plugin, command).build
}

/// The entry [`native_entry`] makes, with no account.
pub fn native_entry_without_account(plugin: &str, command: &str) -> Build {
    native_synthetic(plugin, command)
        .without_account("a native entry with no account")
        .build
}

/// The four synthetic entries of an agent that has an account: a script launch, a wheel launch, a
/// native entry whose texts and marks are not Codex's, and a native entry whose harmless key is a
/// key sequence, as kimi-code-cli's Down key is.
pub fn synthetic() -> [Synthetic; 4] {
    [
        Synthetic::of(
            "the script launch",
            "kalareach/synthetic-script",
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
        Synthetic::of(
            "the wheel launch",
            "kalareach/synthetic-wheel",
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
        Synthetic::of(
            "the native entry with texts of its own",
            "kalareach/synthetic-native",
            ("claude", "native", &[], "bin/claude"),
            ("Native agent ready", "native> type here"),
            NATIVE_MARKS,
        ),
        Synthetic::of(
            "the native entry whose harmless key is a key sequence",
            "kalareach/synthetic-keys",
            ("kimi-code", "native", &[], "bin/kimi-code"),
            ("Keys agent ready", "keys> type here"),
            NATIVE_MARKS,
        )
        .harmless_key("\u{1b}[B", "❯ Don't trust"),
    ]
}

/// The two synthetic entries of an agent that has no account, as kimi-cli and opencode-attach have
/// none: the wheel launch and the native entry of [`synthetic`] with their accounts removed.
pub fn without_account() -> [Synthetic; 2] {
    let [_, wheel, native, ..] = synthetic();
    [
        wheel.without_account("the wheel launch with no account"),
        native.without_account("the native entry with no account"),
    ]
}

/// The file the stand-in takes for `build`: the names and texts of the entry, and no path to run. An
/// entry with no account has no composer text and no record, so the file names none.
pub fn stand_in_file(build: &Build) -> serde_json::Value {
    let account = build.account.as_ref();
    serde_json::json!({
        "command": build.command,
        "launch": serde_json::to_value(build.launch).expect("a launch kind"),
        "version": build.version,
        "newer_version": build.newer.as_ref().map(|newer| newer.version.clone()),
        "ready": build.ready,
        "newer_ready": build.newer.as_ref().map(|newer| newer.ready.clone()),
        "harmless": { "input": build.harmless.input, "shows": build.harmless.shows },
        "composer": account.map(|account| account.composer.clone()),
        "config_variable": account
            .and_then(|account| account.config_directory.as_ref())
            .map(|directory| directory.variable.clone()),
        "conversations": account.map(|account| account.conversations.clone()),
        "prompt_line": account.map(|account| account.prompt_line.clone()),
        "reply_line": account.map(|account| account.reply_line.clone()),
        "turn_line": account.and_then(|account| account.turn_line.clone()),
        "image_line": account.and_then(|account| account.image_line.clone()),
    })
}

/// The account of `build`, which a part that reads the composer's text or the record's marks needs.
///
/// # Errors
///
/// Returns the refusal of an entry with no account.
pub fn account_for(build: &Build) -> Result<&Account, String> {
    build.account.as_ref().ok_or_else(|| {
        format!(
            "{STAND_IN_ENTRY_VARIABLE} names an entry with no account, which gives the terminal \
             stand-in no composer text and no record marks"
        )
    })
}

/// The agent the stand-in route stands in for that the environment names: the build list entry the
/// file `entry` holds, with the package whose release has the manifest `manifest`. None where it
/// names neither. `real` says that [`BUILD_VARIABLE`] names an entry too.
///
/// # Errors
///
/// Returns why the two are refused: one is named without the other, a real build is named beside
/// them, the manifest is not a file named `plugin.json`, the entry's
/// command, runtime file or wheel file is not one plain file name ([`placing_of`]), or the entry and
/// the release are not one agent's.
///
/// # Panics
///
/// Panics where the file of the entry cannot be read or is not an entry ([`read_build`]).
pub fn stand_in_chosen(
    entry: Option<&Path>,
    manifest: Option<&Path>,
    real: bool,
) -> Result<Option<Chosen>, String> {
    if real && (entry.is_some() || manifest.is_some()) {
        let named = if entry.is_some() {
            STAND_IN_ENTRY_VARIABLE
        } else {
            STAND_IN_MANIFEST_VARIABLE
        };
        return Err(format!(
            "{named} and {BUILD_VARIABLE} both name an agent: a run stands in for an entry or \
             starts a real one, not both"
        ));
    }
    let (entry, manifest) = match (entry, manifest) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(format!(
                "{STAND_IN_ENTRY_VARIABLE} names the build list entry the terminal stand-in \
                 stands for, and {STAND_IN_MANIFEST_VARIABLE} names no manifest of its package: \
                 set both or neither"
            ));
        }
        (None, Some(_)) => {
            return Err(format!(
                "{STAND_IN_MANIFEST_VARIABLE} names the manifest of the package the terminal \
                 stand-in is installed from, and {STAND_IN_ENTRY_VARIABLE} names no entry: set \
                 both or neither"
            ));
        }
        (Some(entry), Some(manifest)) => (entry, manifest),
    };
    if manifest.file_name() != Some(OsStr::new(MANIFEST_FILE)) {
        return Err(format!(
            "{STAND_IN_MANIFEST_VARIABLE} names {}, which is not a file named {MANIFEST_FILE}",
            manifest.display()
        ));
    }
    let build = read_build(entry);
    placing_of(Some(&build), &build.command).map_err(|why| {
        format!(
            "{STAND_IN_ENTRY_VARIABLE} names an entry the terminal stand-in cannot be placed \
             for: {why}"
        )
    })?;
    let release = manifest.parent().unwrap_or_else(|| Path::new(""));
    let subject = Subject::from_release(&build, release).map_err(|why| {
        format!("{STAND_IN_ENTRY_VARIABLE} and {STAND_IN_MANIFEST_VARIABLE} do not name one agent: {why}")
    })?;
    Ok(Some(Chosen {
        subject,
        generation: None,
    }))
}

/// A directory of this case's own below the system's temporary one, empty.
pub fn scratch(case: &str) -> PathBuf {
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
        let composer = &account_for(&synthetic.build)
            .unwrap_or_else(|why| panic!("{name}: {why}"))
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
        let account =
            account_for(&synthetic.build).unwrap_or_else(|why| panic!("{}: {why}", synthetic.name));
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

/// The pinned program shows the entry's first screen, and the newer program the entry's newer first
/// screen, which is another text.
#[test]
fn the_pinned_stand_in_shows_the_entrys_first_screen_and_the_newer_one_the_entrys_newer_first_screen()
 {
    for synthetic in synthetic() {
        let base = scratch("newer-shows");
        let file = stand_in_file(&synthetic.build);
        let name = synthetic.name;
        let ready = &synthetic.build.ready;
        let newer_ready = &synthetic.build.newer.as_ref().expect("a newer build").ready;
        assert!(
            !ready.contains(newer_ready.as_str()) && !newer_ready.contains(ready.as_str()),
            "{name}: neither of the entry's two first screens holds the other: {ready:?}, {newer_ready:?}"
        );
        let pinned = ran(&base, PROGRAM, &file, &[], &[], &[]);
        assert!(
            pinned.out.contains(ready.as_str()) && !pinned.out.contains(newer_ready.as_str()),
            "{name}: the pinned program shows {ready:?} and not {newer_ready:?}, and printed:\n{}",
            pinned.out
        );
        let newer = ran(&base, NEWER, &file, &[], &[], &[]);
        assert!(
            newer.out.contains(newer_ready.as_str()) && !newer.out.contains(ready.as_str()),
            "{name}: the newer program shows {newer_ready:?} and not {ready:?}, and printed:\n{}",
            newer.out
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

/// The stand-in for an entry with no account shows the entry's first screen, answers a prompt, and
/// keeps no record.
#[test]
fn the_stand_in_for_an_entry_with_no_account_shows_its_first_screen_answers_and_keeps_no_record() {
    for synthetic in without_account() {
        let base = scratch("no-account-shows");
        let ran = ran(
            &base,
            PROGRAM,
            &stand_in_file(&synthetic.build),
            &[],
            &["What is 12 plus 30".to_owned()],
            &[],
        );
        let (name, ready) = (synthetic.name, &synthetic.build.ready);
        assert!(
            ran.success && ran.out.contains(ready.as_str()),
            "{name}: the first screen shows the entry's ready text {ready:?}, and the stand-in \
             printed:\n{}{}",
            ran.out,
            ran.err
        );
        assert_eq!(
            replies(&ran.out),
            ["42"],
            "{name}: the stand-in answers the prompt, and printed:\n{}",
            ran.out
        );
        let left = files_below(&ran.home);
        assert!(
            left.is_empty(),
            "{name}: the stand-in keeps no record, and left: {left:?}"
        );
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

/// The file of the entry of `synthetic` and the manifest of a release of its package, written below
/// `base`.
fn named(base: &Path, synthetic: &Synthetic) -> (PathBuf, PathBuf) {
    let entry = base.join("entry.json");
    std::fs::write(&entry, synthetic.file.to_string()).expect("the entry's file");
    let directory = base.join("release");
    release(
        &directory,
        &synthetic.build.package,
        &synthetic.build.command,
        Shape::Backend,
    );
    (entry, directory.join(MANIFEST_FILE))
}

/// The reason a choice was refused; fails where it was not.
fn refused(choice: Result<Option<Chosen>, String>, what: &str) -> String {
    match choice {
        Err(why) => why,
        Ok(_) => panic!("{what} is refused"),
    }
}

/// With neither variable the stand-in route is Codex's, and with both it is the entry, as a
/// subject whose package is the release the manifest belongs to.
#[test]
fn the_stand_in_route_is_codex_with_no_entry_named_and_the_entry_named_with_its_manifest() {
    assert!(
        stand_in_chosen(None, None, false)
            .expect("neither is named")
            .is_none(),
        "no entry named leaves the stand-in route Codex's"
    );
    assert!(
        stand_in_chosen(None, None, true)
            .expect("neither is named")
            .is_none(),
        "a real build named alone is not the stand-in route's to choose"
    );
    for synthetic in synthetic() {
        let base = scratch("chosen");
        let (entry, manifest) = named(&base, &synthetic);
        let chosen = stand_in_chosen(Some(&entry), Some(&manifest), false)
            .unwrap_or_else(|why| panic!("{}: {why}", synthetic.name))
            .unwrap_or_else(|| {
                panic!(
                    "{}: an entry and its manifest name an agent",
                    synthetic.name
                )
            });
        let name = synthetic.name;
        assert_eq!(
            chosen.subject.entry().map(|build| build.command.as_str()),
            Some(synthetic.build.command.as_str()),
            "{name}: the agent is the entry's"
        );
        assert_eq!(
            chosen.subject.selected_release(),
            manifest.parent(),
            "{name}: the package is the release the manifest belongs to"
        );
        assert!(
            chosen.generation.is_none(),
            "{name}: the stand-in route names no generation of a real agent"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// One of the two variables named alone, and either beside a real build, is refused with the
/// sentence that says so.
#[test]
fn an_entry_or_a_manifest_named_alone_for_the_stand_in_route_is_refused_and_so_is_one_beside_a_real_build()
 {
    let base = scratch("alone");
    let [synthetic, ..] = synthetic();
    let (entry, manifest) = named(&base, &synthetic);
    assert_eq!(
        refused(
            stand_in_chosen(Some(&entry), None, false),
            "an entry with no manifest"
        ),
        "KR_AGENTS_STAND_IN_ENTRY names the build list entry the terminal stand-in stands for, \
         and KR_AGENTS_STAND_IN_MANIFEST names no manifest of its package: set both or neither"
    );
    assert_eq!(
        refused(
            stand_in_chosen(None, Some(&manifest), false),
            "a manifest with no entry"
        ),
        "KR_AGENTS_STAND_IN_MANIFEST names the manifest of the package the terminal stand-in is \
         installed from, and KR_AGENTS_STAND_IN_ENTRY names no entry: set both or neither"
    );
    let with_entry = "KR_AGENTS_STAND_IN_ENTRY and KR_AGENTS_GATEWAY_BUILD both name an agent: a \
                      run stands in for an entry or starts a real one, not both";
    let with_manifest = "KR_AGENTS_STAND_IN_MANIFEST and KR_AGENTS_GATEWAY_BUILD both name an \
                         agent: a run stands in for an entry or starts a real one, not both";
    assert_eq!(
        refused(
            stand_in_chosen(Some(&entry), Some(&manifest), true),
            "an entry and its manifest beside a real build"
        ),
        with_entry
    );
    assert_eq!(
        refused(
            stand_in_chosen(Some(&entry), None, true),
            "an entry beside a real build"
        ),
        with_entry
    );
    assert_eq!(
        refused(
            stand_in_chosen(None, Some(&manifest), true),
            "a manifest beside a real build"
        ),
        with_manifest
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// A manifest that is not a file named `plugin.json` is refused, naming it.
#[test]
fn a_manifest_for_the_stand_in_route_that_is_not_named_plugin_json_is_refused() {
    let base = scratch("manifest-name");
    let [synthetic, ..] = synthetic();
    let (entry, manifest) = named(&base, &synthetic);
    let renamed = manifest.with_file_name("manifest.json");
    std::fs::copy(&manifest, &renamed).expect("the manifest under another name");
    assert_eq!(
        refused(
            stand_in_chosen(Some(&entry), Some(&renamed), false),
            "a manifest not named plugin.json"
        ),
        format!(
            "KR_AGENTS_STAND_IN_MANIFEST names {}, which is not a file named plugin.json",
            renamed.display()
        )
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// An entry with no account is accepted for the stand-in route, which gives its stand-in no
/// composer text and no record; a part that reads the account of the entry is refused it, with the
/// reason.
#[test]
fn an_entry_with_no_account_is_accepted_for_the_stand_in_route_and_refused_where_a_part_reads_its_account()
 {
    let base = scratch("no-account");
    for synthetic in without_account() {
        let name = synthetic.name;
        let (entry, manifest) = named(&base, &synthetic);
        let chosen = stand_in_chosen(Some(&entry), Some(&manifest), false)
            .unwrap_or_else(|why| panic!("{name}: an entry with no account is accepted: {why}"))
            .unwrap_or_else(|| panic!("{name}: the entry is the agent the stand-in stands for"));
        assert_eq!(
            chosen.subject.command(),
            synthetic.build.command,
            "{name}: the stand-in route stands for the entry"
        );
        assert_eq!(
            account_for(&synthetic.build).err().as_deref(),
            Some(
                "KR_AGENTS_STAND_IN_ENTRY names an entry with no account, which gives the \
                 terminal stand-in no composer text and no record marks"
            ),
            "{name}: a part that reads the entry's account is refused"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// An entry with the release of another package is refused.
#[test]
fn a_manifest_of_another_package_is_refused_for_the_stand_in_route() {
    let base = scratch("not-one-agent");
    let [first, second, ..] = synthetic();
    let (entry, _) = named(&base, &first);
    let other = base.join("other");
    release(
        &other,
        &second.build.package,
        &second.build.command,
        Shape::Backend,
    );
    let why = refused(
        stand_in_chosen(Some(&entry), Some(&other.join(MANIFEST_FILE)), false),
        "an entry with the release of another package",
    );
    assert!(
        why.starts_with(
            "KR_AGENTS_STAND_IN_ENTRY and KR_AGENTS_STAND_IN_MANIFEST do not name one agent: "
        ) && why.contains(&first.build.package)
            && why.contains(&second.build.package),
        "the refusal names the two packages: {why}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// The names of the files the stand-in route places for an entry, below one directory.
#[derive(Clone)]
pub struct Placing {
    /// The file the host sees as the agent: the entry's command, or for a script or a wheel the
    /// file name of the entry's runtime.
    pub program: String,
    /// The script a person types as the command, for a script or a wheel.
    pub script: Option<String>,
    /// The wheel's file, for a wheel.
    pub wheel: Option<String>,
}

/// Whether `name` is one plain file name: not empty, with no separator, and not `.` or `..`.
fn is_one_file_name(name: &str) -> bool {
    Path::new(name).file_name() == Some(OsStr::new(name))
}

/// The names of the files the stand-in route places for `build`, typed as `command`. A name is the
/// last part of a path and never a path: the entry's runtime and pinned file name real places, and
/// nothing placed is a copy of either. Each name is one plain file name ([`is_one_file_name`]), so
/// no file is placed outside the directory the route places them in.
///
/// # Errors
///
/// Returns why the command, the runtime's file name or the wheel's file name is not one plain file
/// name, or why an entry that launches as a script or a wheel names no runtime.
pub fn placing_of(build: Option<&Build>, command: &str) -> Result<Placing, String> {
    if !is_one_file_name(command) {
        return Err(format!(
            "the command {command:?} is not one file name: the stand-in route places a file under \
             it, and a name with a separator, an empty name, \".\" and \"..\" name another place"
        ));
    }
    let Some(build) = build.filter(|build| matches!(build.launch, Launch::Script | Launch::Wheel))
    else {
        return Ok(Placing {
            program: command.to_owned(),
            script: None,
            wheel: None,
        });
    };
    let last = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| is_one_file_name(name))
    };
    let runtime = build.runtime.first().ok_or_else(|| {
        "the entry launches as a script or a wheel and names no runtime, so there is no program \
         for the stand-in to stand for"
            .to_owned()
    })?;
    let program = last(runtime).ok_or_else(|| {
        format!(
            "the runtime {} has no file name: the stand-in route places the program under the \
             file name of the entry's runtime",
            runtime.display()
        )
    })?;
    let wheel = if build.launch == Launch::Wheel {
        Some(last(Path::new(&build.pinned)).ok_or_else(|| {
            format!(
                "the pinned file {:?} has no file name: the stand-in route places the wheel's \
                 file under the file name of the entry's pinned file",
                build.pinned
            )
        })?)
    } else {
        None
    };
    Ok(Placing {
        program,
        script: Some(command.to_owned()),
        wheel,
    })
}

/// One thing the placing of the stand-in is held to, as [`what_is_placed`] found it. A case
/// asserts that `found` is `entry_says` in its own body, and fails with `says`.
pub struct Placed {
    /// What was found, as `{:?}` prints it.
    pub found: String,
    /// What the entry says it is, as `{:?}` prints it.
    pub entry_says: String,
    /// What the case says where the two differ.
    pub says: String,
}

impl Placed {
    fn new(found: impl std::fmt::Debug, entry_says: impl std::fmt::Debug, says: String) -> Self {
        Self {
            found: format!("{found:?}"),
            entry_says: format!("{entry_says:?}"),
            says,
        }
    }
}

/// What is placed for the stand-in made from the entry of the case's subject: one [`Placed`] for
/// each thing the placing is held to, in the order they are held to it, for the case to assert in
/// its own body. For a script or a wheel the file the host sees as the agent is the entry's
/// runtime, under the runtime's file name, and the file typed as the command is another file: an
/// executable script whose first line is `#!` and the placed runtime's absolute path; a wheel's
/// file is placed too. For every entry the program placed as the agent is the terminal stand-in the
/// harness built. Where the route is not the stand-in's there is nothing to hold, and the list is
/// empty.
///
/// # Panics
///
/// Panics where a program the harness built cannot be read.
pub fn what_is_placed(ctx: &Context) -> Vec<Placed> {
    let (Route::StandIn, Some(build)) = (&ctx.route, ctx.subject.entry()) else {
        return Vec::new();
    };
    let command = ctx.subject.command();
    // What is placed is read from the entry again, and not from `placing_of`, which places it: the
    // check holds the placing to what the entry says.
    let last = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    };
    let scripted = matches!(build.launch, Launch::Script | Launch::Wheel);
    let program = if scripted {
        build.runtime.first().and_then(|runtime| last(runtime))
    } else {
        Some(command.to_owned())
    };
    let wheel = (build.launch == Launch::Wheel)
        .then(|| last(Path::new(&build.pinned)))
        .flatten();
    let placed = ctx
        .executable
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let stand_in = std::fs::read(PROGRAM).expect("the terminal stand-in the harness built");
    let mut held = vec![
        Placed::new(
            placed.as_deref(),
            program.as_deref(),
            format!(
                "{command}: the file the host sees as the agent is placed under the file name \
                 {program:?}, which the entry's runtime has, or the command's own name for a \
                 native entry"
            ),
        ),
        Placed::new(
            std::fs::read(&ctx.executable).is_ok_and(|file| file == stand_in),
            true,
            format!(
                "{command}: the program placed as the agent is the terminal stand-in the harness \
                 built"
            ),
        ),
        Placed::new(
            ctx.qualified_as().1,
            &build.version,
            format!("{command}: the generation lists the entry's build under the entry's version"),
        ),
    ];
    if let (Some((_, version)), Some(newer)) = (&ctx.newer, &build.newer) {
        held.push(Placed::new(
            version,
            &newer.version,
            format!("{command}: the newer build is listed under the entry's newer version"),
        ));
    }
    if let Some((newer, _)) = &ctx.newer {
        let newer_stand_in =
            std::fs::read(NEWER).expect("the newer terminal stand-in the harness built");
        held.push(Placed::new(
            std::fs::read(newer).is_ok_and(|file| file == newer_stand_in),
            true,
            format!(
                "{command}: the program placed as the newer build is the newer terminal stand-in \
                 the harness built"
            ),
        ));
    }
    if scripted {
        let typed = ctx.bin.join(command);
        let text = std::fs::read_to_string(&typed).unwrap_or_default();
        held.push(Placed::new(
            text.lines().next(),
            Some(format!("#!{}", ctx.executable.display())),
            format!(
                "{command}: the file typed as the command is a script whose first line is #! and \
                 the placed runtime's absolute path"
            ),
        ));
        let executable = std::fs::metadata(&typed).is_ok_and(|file| {
            std::os::unix::fs::PermissionsExt::mode(&file.permissions()) & 0o111 != 0
        });
        held.push(Placed::new(
            executable && inode_of(&typed) != inode_of(&ctx.executable),
            true,
            format!("{command}: the script a person types is executable and is not the runtime"),
        ));
    }
    if let Some(wheel) = &wheel {
        held.push(Placed::new(
            ctx.bin.join(wheel).is_file(),
            true,
            format!("{command}: the wheel's file {wheel} is placed beside the script"),
        ));
    }
    held
}

/// The package written for a script or a wheel recognises the command a person types, as its
/// integration names it, and the name of the runtime, which the host sees as the agent.
#[test]
fn the_package_written_for_a_script_or_a_wheel_recognises_the_command_and_the_runtimes_name() {
    for synthetic in synthetic()
        .into_iter()
        .filter(|synthetic| synthetic.build.launch != Launch::Native)
    {
        let (name, command) = (synthetic.name, &synthetic.build.command);
        let base = scratch("rule");
        let directory = base.join("release");
        release(
            &directory,
            &synthetic.build.package,
            command,
            Shape::Backend,
        );
        let subject = Subject::from_release(&synthetic.build, &directory)
            .unwrap_or_else(|why| panic!("{name}: {why}"));
        let written = write(&subject, &directory, &base.join("package"))
            .unwrap_or_else(|why| panic!("{name}: {why}"));
        let runtime = placing_of(Some(&synthetic.build), command)
            .unwrap_or_else(|why| panic!("{name}: {why}"))
            .program;
        assert_eq!(
            written.match_rules.len(),
            2,
            "{name}: a rule for the command and a rule for the runtime"
        );
        let recognises = |program: &str| {
            written
                .match_rules
                .iter()
                .any(|rule| rule.executable.matches_path(&format!("/run/t/{program}")))
        };
        assert!(
            recognises(command),
            "{name}: the package recognises the command {command}, which its integration names"
        );
        assert!(
            recognises(&runtime),
            "{name}: the package recognises the runtime {runtime}, which the host sees as the agent"
        );
        assert!(
            !recognises("another-name"),
            "{name}: the package recognises no other name"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// What a person's file holds before a run, which a refused entry leaves as it is.
const PERSONS_FILE: &[u8] = b"a file of the person, outside the run";

/// An entry whose command, runtime file or wheel file is not one plain file name.
struct NotAName {
    /// What is not a file name.
    what: String,
    /// The synthetic entry it is made from: the script launch (0) or the wheel launch (1).
    index: usize,
    /// The members of that entry that are changed.
    members: Vec<(&'static str, serde_json::Value)>,
    /// What the refusal says.
    reason: &'static str,
}

/// The entries that name a command, a runtime file or a wheel file that is not one plain file name.
/// The absolute command names `outside`.
fn not_one_file_name(outside: &Path) -> Vec<NotAName> {
    let mut entries: Vec<NotAName> = [&outside.display().to_string(), "", ".", "..", "a/b", "x/"]
        .into_iter()
        .map(|command| NotAName {
            what: format!("the command {command:?}"),
            index: 0,
            members: vec![("command", serde_json::json!(command))],
            reason: "is not one file name",
        })
        .collect();
    let others = [
        (
            "a script's runtime",
            0,
            "runtime",
            serde_json::json!(["/real/node/bin/.."]),
            "has no file name",
        ),
        (
            "a script with no runtime",
            0,
            "runtime",
            serde_json::json!([]),
            "names no runtime",
        ),
        (
            "a wheel's runtime",
            1,
            "runtime",
            serde_json::json!(["/real/python/bin/.."]),
            "has no file name",
        ),
        (
            "a wheel's file",
            1,
            "pinned",
            serde_json::json!("wheel/.."),
            "has no file name",
        ),
    ];
    for (what, index, member, value, reason) in others {
        entries.push(NotAName {
            what: what.to_owned(),
            index,
            members: vec![(member, value)],
            reason,
        });
    }
    entries
}

/// The entry of `synthetic` with the members `members` set.
fn with_members(
    synthetic: &Synthetic,
    members: &[(&'static str, serde_json::Value)],
) -> serde_json::Value {
    let mut file = synthetic.file.clone();
    for (member, value) in members {
        file[*member] = value.clone();
    }
    file
}

/// An entry whose command, runtime file or wheel file is not one plain file name is refused for the
/// stand-in route, with the reason.
#[test]
fn an_entry_whose_command_runtime_or_wheel_is_not_one_file_name_is_refused_for_the_stand_in_route()
{
    let base = scratch("not-a-name");
    let synthetics = synthetic();
    for entry_of in not_one_file_name(&base.join("outside")) {
        let NotAName {
            what,
            index,
            members,
            reason,
        } = entry_of;
        let (entry, manifest) = named(&base, &synthetics[index]);
        std::fs::write(
            &entry,
            with_members(&synthetics[index], &members).to_string(),
        )
        .expect("the entry whose names are not file names");
        let why = refused(stand_in_chosen(Some(&entry), Some(&manifest), false), &what);
        assert!(
            why.starts_with(
                "KR_AGENTS_STAND_IN_ENTRY names an entry the terminal stand-in cannot be placed for: "
            ) && why.contains(reason),
            "{what}: the refusal says why the entry cannot be placed ({reason}): {why}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The stand-in route places nothing for such an entry and changes no file outside the run: an
/// absolute command that names a file of the person leaves the file as it was.
#[test]
fn an_entry_whose_command_runtime_or_wheel_is_not_one_file_name_places_nothing_and_changes_no_file_outside_the_run()
 {
    let base = scratch("not-a-name-placed");
    let outside = base.join("a-file-of-the-person");
    let synthetics = synthetic();
    for entry_of in not_one_file_name(&outside) {
        let NotAName {
            what,
            index,
            members,
            reason,
        } = entry_of;
        let shell = match shells::managed_zsh() {
            Ok(shell) => shell,
            Err(why) if shells::required() => panic!("the managed shell: {why}"),
            Err(why) => {
                eprintln!("skipping: {why}");
                return;
            }
        };
        std::fs::write(&outside, PERSONS_FILE).expect("the person's file");
        let build: Build = serde_json::from_value(with_members(&synthetics[index], &members))
            .expect("the entry whose names are not file names");
        let directory = base.join("release");
        release(
            &directory,
            &build.package,
            &synthetics[index].build.command,
            Shape::Backend,
        );
        let subject =
            Subject::from_release(&build, &directory).unwrap_or_else(|why| panic!("{what}: {why}"));
        let mut ctx = Context::new(
            shell,
            Route::StandIn,
            Run::start("gateway-not-a-name"),
            super::runtime(),
        );
        ctx.subject = subject;
        ctx.manual = true;
        let placed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.place()));
        assert_eq!(
            std::fs::read(&outside).expect("the person's file"),
            PERSONS_FILE,
            "{what}: the person's file outside the run is as it was"
        );
        let said = match placed {
            Ok(()) => String::new(),
            Err(panic) => kr_e2e_agents::held::panic_text(&*panic),
        };
        assert!(
            said.starts_with("the stand-in route cannot place the agent: ")
                && said.contains(reason),
            "{what}: the route refuses the agent before it places anything ({reason}): {said:?}"
        );
        assert!(
            !ctx.run.root().join("t").exists(),
            "{what}: nothing is placed in the run"
        );
        ctx.run
            .closing_check()
            .unwrap_or_else(|why| panic!("{what}: {why}"));
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// The entry of `synthetic` with a marker at every place it names a program to run: its pinned file
/// and the command's file in the `bin` directory below its prefix, its newer build's pinned file and
/// the command's file in the `bin` directory below the newer prefix, and each file of its runtime,
/// all in folders of `base`. A marker is a script that appends its own path to the mark file, the
/// second value returned, which exists only once a marker has run. The stand-in route places the
/// stand-in program the harness built and runs nothing the entry names.
///
/// # Panics
///
/// Panics where the entry names no newer build, where a runtime file has no name, or where a
/// marker cannot be written.
fn marked(base: &Path, synthetic: &Synthetic) -> (Synthetic, PathBuf) {
    let mark = base.join("mark");
    let (prefix, newer) = (base.join("prefix"), base.join("newer"));
    let runtime: Vec<PathBuf> = synthetic
        .build
        .runtime
        .iter()
        .map(|file| {
            base.join("runtime")
                .join(file.file_name().expect("the file name of a runtime file"))
        })
        .collect();
    let newer_pinned = &synthetic
        .build
        .newer
        .as_ref()
        .expect("the entry's newer build")
        .pinned;
    let command = &synthetic.build.command;
    let markers = runtime.iter().cloned().chain([
        prefix.join(&synthetic.build.pinned),
        prefix.join("bin").join(command),
        newer.join(newer_pinned),
        newer.join("bin").join(command),
    ]);
    for marker in markers {
        std::fs::create_dir_all(marker.parent().expect("the folder of a marker"))
            .expect("a folder for a marker");
        std::fs::write(
            &marker,
            format!("#!/bin/sh\necho \"$0\" >> '{}'\n", mark.display()),
        )
        .expect("a marker");
        std::fs::set_permissions(&marker, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("an executable marker");
    }
    let mut file = synthetic.file.clone();
    file["prefix"] = serde_json::json!(prefix);
    file["newer"]["prefix"] = serde_json::json!(newer);
    file["runtime"] = serde_json::json!(runtime);
    let build = serde_json::from_value(file.clone()).expect("an entry");
    (
        Synthetic {
            name: synthetic.name,
            file,
            build,
        },
        mark,
    )
}

/// The subject the terminal stand-in stands for, made from `synthetic` and a release of the entry's
/// package written below `base`.
///
/// # Panics
///
/// Panics where the subject cannot be made from the release.
pub fn subject_for(synthetic: &Synthetic, base: &Path) -> Subject {
    let directory = base.join("release");
    release(
        &directory,
        &synthetic.build.package,
        &synthetic.build.command,
        Shape::Backend,
    );
    Subject::from_release(&synthetic.build, &directory)
        .unwrap_or_else(|why| panic!("{}: {why}", synthetic.name))
}

/// A staged part that starts no model turn, which takes the subject, the case's name and the check
/// of the stand-in's placing that the case binds ([`what_is_placed`]).
type Part = fn(Option<Subject>, &str, Option<&dyn Fn(&Context)>);

/// The paths of the markers ([`marked`]) that ran, which `mark`, the mark file, holds: none where
/// no marker ran, since the file exists only once one has.
fn markers_that_ran(mark: &Path) -> Option<String> {
    mark.exists()
        .then(|| std::fs::read_to_string(mark).unwrap_or_default())
}

/// Runs `part`, one of the staged parts that start no model turn, as `test`, for the stand-in made
/// from each synthetic entry, installed from a release of the entry's package. Every program the
/// entry names is a marker ([`marked`]) in a folder of the case, outside the run's directory. The
/// case holds the part to two things in its own body: `placed` is called at the start of the part
/// with the run's context ([`what_is_placed`]), and `no_marker_ran` is called once the part has
/// ended with the entry's name and the markers that ran ([`markers_that_ran`]).
fn for_each_entry(
    test: &str,
    part: Part,
    placed: &dyn Fn(&Context),
    no_marker_ran: &dyn Fn(&str, Option<String>),
) {
    for synthetic in synthetic().into_iter().chain(without_account()) {
        let base = scratch("part");
        let (synthetic, mark) = marked(&base, &synthetic);
        let subject = subject_for(&synthetic, &base);
        part(Some(subject), test, Some(placed));
        no_marker_ran(synthetic.name, markers_that_ran(&mark));
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// Part 2b for the stand-in made from each entry: the host detects it as the entry's agent, offers
/// it only observation and the terminal, and refuses every typed action.
#[test]
fn a_stand_in_for_an_entry_on_its_terminal_route_is_advertised_no_typed_capability_and_every_typed_action_is_refused()
 {
    const TEST: &str = "a_stand_in_for_an_entry_on_its_terminal_route_is_advertised_no_typed_capability_and_every_typed_action_is_refused";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_2b, &placed, &no_marker_ran);
}

/// Part 2c for the stand-in made from each entry: under a binding the host permits a supported
/// action and refuses an unsupported one.
#[test]
fn under_a_binding_a_stand_in_for_an_entry_is_permitted_a_supported_action_and_refused_an_unsupported_one()
 {
    const TEST: &str = "under_a_binding_a_stand_in_for_an_entry_is_permitted_a_supported_action_and_refused_an_unsupported_one";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_2c, &placed, &no_marker_ran);
}

/// Part 5a for the stand-in made from each entry: a crash of the control daemon leaves the stand-in
/// and its local terminal running.
#[test]
fn a_control_daemon_crash_leaves_a_stand_in_for_an_entry_and_its_local_terminal_running() {
    const TEST: &str =
        "a_control_daemon_crash_leaves_a_stand_in_for_an_entry_and_its_local_terminal_running";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_5a, &placed, &no_marker_ran);
}

/// Part 6a for the stand-in made from each entry: a running stand-in keeps its build through an
/// upgrade, and the newer build gets the terminal route.
#[test]
fn a_running_stand_in_for_an_entry_keeps_its_build_through_an_upgrade_and_the_newer_build_gets_the_terminal_route()
 {
    const TEST: &str = "a_running_stand_in_for_an_entry_keeps_its_build_through_an_upgrade_and_the_newer_build_gets_the_terminal_route";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_6a, &placed, &no_marker_ran);
}

/// Part 8a for the stand-in made from each entry: forged titles, transcripts, identifiers and hook
/// input leave the host unchanged.
#[test]
fn forged_titles_transcripts_identifiers_and_hook_input_leave_the_host_unchanged_for_a_stand_in_for_an_entry()
 {
    const TEST: &str = "forged_titles_transcripts_identifiers_and_hook_input_leave_the_host_unchanged_for_a_stand_in_for_an_entry";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_8a, &placed, &no_marker_ran);
}

/// Part 14.03a for the stand-in made from each entry: a path typed at the stand-in is terminal
/// input that reaches its composer.
#[test]
fn a_path_typed_at_a_stand_in_for_an_entry_is_terminal_input_that_reaches_its_composer() {
    const TEST: &str =
        "a_path_typed_at_a_stand_in_for_an_entry_is_terminal_input_that_reaches_its_composer";
    let placed = |ctx: &Context| {
        for what in what_is_placed(ctx) {
            assert_eq!(what.found, what.entry_says, "{}", what.says);
        }
    };
    let no_marker_ran = |name: &str, ran: Option<String>| {
        assert!(
            ran.is_none(),
            "{name}: the part ran a program that the entry names and the harness did not build; \
             each such program wrote its path to the mark file:\n{}",
            ran.unwrap_or_default()
        );
    };
    for_each_entry(TEST, part_14_03a, &placed, &no_marker_ran);
}
