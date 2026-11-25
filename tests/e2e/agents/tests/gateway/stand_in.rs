//! The terminal stand-in for the build list's other entries.
//!
//! `agent-stand-in` takes the names and texts of the entry it stands for from a file the driver
//! makes ([`stand_in_file`]) and never a path to run. The three synthetic entries here are a script
//! launch, a wheel launch and a native entry with texts of its own. Some cases in this file start the
//! program alone, with a home of its own, and read what it printed and what it recorded. The others
//! choose the entry that the stand-in route stands in for ([`stand_in_chosen`]) and run the staged
//! parts that start no model turn for the stand-in made from it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kr_e2e_agents::build::{Build, Launch, read_build};
use kr_e2e_agents::held::{conversations_relative_in, turns_recorded};
use kr_e2e_agents::subject::Subject;
use kr_e2e_m1b::run::RootPin;
use kr_plugin_sdk::package::MANIFEST_FILE;

use super::package::{Shape, release};
use super::staged_a::{part_2b, part_2c, part_5a, part_6a, part_8a, part_14_03a};
use super::{BUILD_VARIABLE, Chosen, STAND_IN_ENTRY_VARIABLE, STAND_IN_MANIFEST_VARIABLE};

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
    serde_json::json!({
        "package": package, "application": "a", "version": "1.2.3", "prefix": "/real/prefix",
        "pinned": pinned, "sha256": "00", "command": command, "launch": launch,
        "runtime": runtime, "ready": ready,
        "harmless": { "input": HARMLESS, "shows": HARMLESS },
        "transcript": "sessions/{cwd_slug}/{session}.jsonl", "missing": {},
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
pub fn native_entry(plugin: &str, command: &str) -> Build {
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
    .build
}

/// The three synthetic entries: a script launch, a wheel launch and a native entry whose texts and
/// marks are not Codex's.
pub fn synthetic() -> [Synthetic; 3] {
    [
        Synthetic::of(
            "the script launch",
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
        Synthetic::of(
            "the wheel launch",
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
        Synthetic::of(
            "the native entry with texts of its own",
            "kalareach/claude-code",
            ("claude", "native", &[], "bin/claude"),
            ("Native agent ready", "native> type here"),
            NATIVE_MARKS,
        ),
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

/// The agent the stand-in route stands in for that the environment names: the build list entry the
/// file `entry` holds, with the package whose release has the manifest `manifest`. None where it
/// names neither. `real` says that [`BUILD_VARIABLE`] names an entry too.
///
/// # Errors
///
/// Returns why the two are refused: one is named without the other, a real build is named beside
/// them, the manifest is not a file named `plugin.json`, the entry has no account, or the entry and
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
    if build.account.is_none() {
        return Err(format!(
            "{STAND_IN_ENTRY_VARIABLE} names an entry with no account, which gives the terminal \
             stand-in no composer text and no record marks"
        ));
    }
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

/// An entry with no account, and an entry with the release of another package, are refused.
#[test]
fn an_entry_with_no_account_or_a_manifest_of_another_package_is_refused_for_the_stand_in_route() {
    let base = scratch("not-one-agent");
    let [first, second, ..] = synthetic();
    let (entry, manifest) = named(&base, &first);
    let mut bare = first.file.clone();
    bare.as_object_mut()
        .expect("an entry")
        .remove("account")
        .expect("the entry's account");
    std::fs::write(&entry, bare.to_string()).expect("the entry without an account");
    assert_eq!(
        refused(
            stand_in_chosen(Some(&entry), Some(&manifest), false),
            "an entry with no account"
        ),
        "KR_AGENTS_STAND_IN_ENTRY names an entry with no account, which gives the terminal \
         stand-in no composer text and no record marks"
    );
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

/// The entries the stand-in is placed for in the parts below: the native ones.
fn placed_for() -> Vec<Synthetic> {
    synthetic()
        .into_iter()
        .filter(|synthetic| synthetic.build.launch == Launch::Native)
        .collect()
}

/// Runs `part`, one of the staged parts that start no model turn, as `test`, for the stand-in made
/// from each of the entries it is placed for, installed from a release of the entry's package.
fn for_each_entry(test: &str, part: fn(Option<Subject>, &str)) {
    for synthetic in placed_for() {
        let base = scratch("part");
        let directory = base.join("release");
        release(
            &directory,
            &synthetic.build.package,
            &synthetic.build.command,
            Shape::Backend,
        );
        let subject = Subject::from_release(&synthetic.build, &directory)
            .unwrap_or_else(|why| panic!("{}: {why}", synthetic.name));
        part(Some(subject), test);
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// Part 2b for the stand-in made from each entry: the host detects it as the entry's agent, offers
/// it only observation and the terminal, and refuses every typed action.
#[test]
fn a_stand_in_for_an_entry_on_its_terminal_route_is_advertised_no_typed_capability_and_every_typed_action_is_refused()
 {
    const TEST: &str = "a_stand_in_for_an_entry_on_its_terminal_route_is_advertised_no_typed_capability_and_every_typed_action_is_refused";
    for_each_entry(TEST, part_2b);
}

/// Part 2c for the stand-in made from each entry: under a binding the host permits a supported
/// action and refuses an unsupported one.
#[test]
fn under_a_binding_a_stand_in_for_an_entry_is_permitted_a_supported_action_and_refused_an_unsupported_one()
 {
    const TEST: &str = "under_a_binding_a_stand_in_for_an_entry_is_permitted_a_supported_action_and_refused_an_unsupported_one";
    for_each_entry(TEST, part_2c);
}

/// Part 5a for the stand-in made from each entry: a crash of the control daemon leaves the stand-in
/// and its local terminal running.
#[test]
fn a_control_daemon_crash_leaves_a_stand_in_for_an_entry_and_its_local_terminal_running() {
    const TEST: &str =
        "a_control_daemon_crash_leaves_a_stand_in_for_an_entry_and_its_local_terminal_running";
    for_each_entry(TEST, part_5a);
}

/// Part 6a for the stand-in made from each entry: a running stand-in keeps its build through an
/// upgrade, and the newer build gets the terminal route.
#[test]
fn a_running_stand_in_for_an_entry_keeps_its_build_through_an_upgrade_and_the_newer_build_gets_the_terminal_route()
 {
    const TEST: &str = "a_running_stand_in_for_an_entry_keeps_its_build_through_an_upgrade_and_the_newer_build_gets_the_terminal_route";
    for_each_entry(TEST, part_6a);
}

/// Part 8a for the stand-in made from each entry: forged titles, transcripts, identifiers and hook
/// input leave the host unchanged.
#[test]
fn forged_titles_transcripts_identifiers_and_hook_input_leave_the_host_unchanged_for_a_stand_in_for_an_entry()
 {
    const TEST: &str = "forged_titles_transcripts_identifiers_and_hook_input_leave_the_host_unchanged_for_a_stand_in_for_an_entry";
    for_each_entry(TEST, part_8a);
}

/// Part 14.03a for the stand-in made from each entry: a path typed at the stand-in is terminal
/// input that reaches its composer.
#[test]
fn a_path_typed_at_a_stand_in_for_an_entry_is_terminal_input_that_reaches_its_composer() {
    const TEST: &str =
        "a_path_typed_at_a_stand_in_for_an_entry_is_terminal_input_that_reaches_its_composer";
    for_each_entry(TEST, part_14_03a);
}
