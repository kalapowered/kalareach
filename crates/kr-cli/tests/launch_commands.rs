//! `kr launch`, run the way a person runs it, against a real control daemon.
//!
//! The daemon is this test's own: the real `kr-controller` service, started in this process on a
//! host tree of the test's own, with its real endpoint, handshake, admission and store of saved
//! launch commands, and a supervisor that starts no worker, because none of these commands needs a
//! session. `kr` is the real binary, copied to the internal disk and run with that tree's
//! directories on plain pipes. The host decides every rule of a command; `kr` holds none, so each
//! refusal here is the host's own sentence.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use serde_json::Value;

mod support;

/// The rows the host's check is held to, which the page's own feedback reads as well.
const ROWS: &str = include_str!("../../../tests/fixtures/launch-command-rows.json");

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A supervisor that starts nothing. None of these commands needs a worker.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// A host tree and its running daemon.
struct Host {
    controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Host {
    async fn start() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store in the test tree");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        Self {
            temp,
            controller,
            clients,
        }
    }

    /// The file the daemon keeps the saved commands in.
    fn file(&self) -> PathBuf {
        self.temp
            .environment()
            .state_dir()
            .join(kr_controller::launch_commands::FILE_NAME)
    }

    /// `kr` prepared on plain pipes with this tree's directories, from the root directory.
    fn command(&self, extra: &[(&str, &str)], line: &[&str]) -> Command {
        let mut command = Command::new(support::kr());
        command
            .args(line)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.root())
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .envs(extra.iter().copied())
            .current_dir("/")
            .stdin(Stdio::null());
        command
    }

    /// Runs `kr`.
    fn kr(&self, line: &[&str]) -> Output {
        self.command(&[], line).output().expect("kr runs")
    }

    /// Runs `kr` and says what it exited with, what it wrote on standard output and on standard
    /// error.
    fn said(&self, line: &[&str]) -> (Option<i32>, String, String) {
        said(&self.kr(line))
    }

    /// Runs `kr` with `--json` and reads the one document it printed, and how it exited.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = vec!["--json"];
        asked.extend_from_slice(line);
        let output = self.kr(&asked);
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed no JSON ({error}): {}{}",
                asked.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }

    /// The commands the list holds, as `kr launch list --json` says them.
    fn listed(&self) -> Value {
        let (status, document) = self.json(&["launch", "list"]);
        assert_eq!(status, Some(0), "{document}");
        document
    }
}

fn said(output: &Output) -> (Option<i32>, String, String) {
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The labels of a listed document, in order.
fn labels(document: &Value) -> Vec<String> {
    document["commands"]
        .as_array()
        .expect("a list of commands")
        .iter()
        .map(|command| command["label"].as_str().expect("a label").to_owned())
        .collect()
}

/// KR-REQ-13.11: the owner saves a command with `kr launch add`, sees it in `kr launch list`,
/// replaces it by saving another under the same label, and removes it with `kr launch remove`; each
/// is the daemon's own method, with text for a person and a document for a script, and each exit is
/// 0. A command is saved as written: spaces, an empty argument and a Windows path arrive exactly.
/// The control for the first half is the list before there is a command.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_launch_adds_lists_replaces_and_removes_a_command() {
    let host = Host::start().await;

    let (status, text, _) = host.said(&["launch", "list"]);
    assert_eq!(status, Some(0));
    assert_eq!(
        text.trim_end(),
        "No launch commands are saved. Add one with: kr launch add <label> -- <program> \
         [arguments...]"
    );
    let empty = host.listed();
    assert_eq!(empty["revision"], 0, "{empty}");
    assert_eq!(empty["commands"], Value::Array(Vec::new()), "{empty}");

    let (status, text, _) = host.said(&[
        "launch",
        "add",
        "Claude",
        "--",
        "claude",
        "--resume",
        "two words",
        "",
        "C:\\tools\\agent.exe",
        "say \"hi\"",
    ]);
    assert_eq!(status, Some(0));
    assert_eq!(text.trim_end(), "Saved the launch command \"Claude\".");
    let saved = host.listed();
    assert_eq!(
        saved["commands"][0],
        serde_json::json!({
            "label": "Claude",
            "program": "claude",
            "arguments": ["--resume", "two words", "", "C:\\tools\\agent.exe", "say \"hi\""],
        }),
        "the command is kept as written: {saved}"
    );
    let (_, text, _) = host.said(&["launch", "list"]);
    assert_eq!(
        text.trim_end(),
        "Claude: \"claude\" \"--resume\" \"two words\" \"\" \"C:\\\\tools\\\\agent.exe\" \
         \"say \\\"hi\\\"\""
    );

    // The same command again changes nothing and says so.
    let (status, text, _) = host.said(&[
        "launch",
        "add",
        "Claude",
        "--",
        "claude",
        "--resume",
        "two words",
        "",
        "C:\\tools\\agent.exe",
        "say \"hi\"",
    ]);
    assert_eq!(status, Some(0));
    assert_eq!(
        text.trim_end(),
        "The launch command \"Claude\" is already saved as written."
    );
    assert_eq!(host.listed()["revision"], saved["revision"]);

    // A second label goes last; a label that differs by case replaces the first in its place and
    // takes the new spelling.
    host.said(&["launch", "add", "Second", "--", "second"]);
    let (status, text, _) = host.said(&["launch", "add", "claude", "--", "claude", "--new"]);
    assert_eq!(status, Some(0));
    assert_eq!(text.trim_end(), "Replaced the launch command \"claude\".");
    let replaced = host.listed();
    assert_eq!(labels(&replaced), ["claude", "Second"], "{replaced}");
    assert_eq!(
        replaced["commands"][0]["arguments"],
        serde_json::json!(["--new"])
    );

    let (status, text, _) = host.said(&["launch", "remove", "CLAUDE"]);
    assert_eq!(status, Some(0));
    assert_eq!(text.trim_end(), "Removed the launch command \"CLAUDE\".");
    assert_eq!(labels(&host.listed()), ["Second"]);
    let (status, text, _) = host.said(&["launch", "remove", "Claude"]);
    assert_eq!(status, Some(0), "an absent label is not a failure");
    assert_eq!(text.trim_end(), "No launch command is named \"Claude\".");
    let (status, document) = host.json(&["launch", "remove", "Claude"]);
    assert_eq!(status, Some(0));
    assert_eq!(document["removed"], false, "{document}");
    assert_eq!(document["applied"], true, "{document}");
}

/// KR-REQ-13.11: a command that breaks a rule is refused by the host, `kr` prints the host's words
/// as the host wrote them and exits 8, and the host holds nothing of it. `kr` has no check of its
/// own: each refused row of the shared fixture is sent as it is, and the refusal names the first
/// refused character by its position and code point, or the size that was broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_command_that_breaks_a_rule_is_refused_by_the_host_and_kr_prints_its_words_and_exits_8()
 {
    let host = Host::start().await;
    let rows: Value = serde_json::from_str(ROWS).expect("the fixture is JSON");
    let mut tried = 0;
    for row in rows["rows"].as_array().expect("rows") {
        let Some(refused) = row.get("refused") else {
            continue;
        };
        let label = row["label"].as_str().expect("a label");
        let program = row["program"].as_str().expect("a program");
        let arguments: Vec<&str> = row["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .map(|argument| argument.as_str().expect("an argument"))
            .collect();
        // A process argument cannot hold a NUL; the host's own case holds that row.
        if std::iter::once(label)
            .chain(std::iter::once(program))
            .chain(arguments.iter().copied())
            .any(|word| word.contains('\0'))
        {
            continue;
        }
        let mut line = vec!["launch", "add", label, "--", program];
        line.extend(arguments.iter().copied());
        let (status, text, said) = host.said(&line);
        let name = row["name"].as_str().expect("a name");
        assert_eq!(status, Some(8), "{name}: {said}");
        assert_eq!(text, "", "{name}: nothing is said as done");
        let field = refused["field"].as_str().expect("a field");
        if let Some(position) = refused.get("position") {
            let whose = match field {
                "label" => "the label".to_owned(),
                "program" => "the program".to_owned(),
                _ => format!("argument {}", refused["argument"]),
            };
            let expected = format!(
                "Character {position} of {whose} is {}, which is not allowed.",
                refused["code_point"].as_str().expect("a code point")
            );
            assert!(said.contains(&expected), "{name}: {said}");
        } else {
            let rule = match field {
                "label" => "A label has 1 to 48 characters",
                "program" => "A program has 1 to 512 bytes",
                "command" => "A command may use at most 3,072 bytes in all, label included.",
                _ => "A command has at most 16 arguments of at most 512 bytes each",
            };
            assert!(said.contains(rule), "{name}: {said}");
        }
        tried += 1;
    }
    assert!(tried > 60, "the fixture's refused rows were sent: {tried}");
    assert_eq!(
        host.listed()["commands"],
        Value::Array(Vec::new()),
        "the host holds nothing of them"
    );
    assert!(!host.file().exists(), "and no file was written");

    // The refusal in a document says the host's words and the exit code beside it.
    let (status, document) = host.json(&["launch", "add", "\u{202e}ab", "--", "claude"]);
    assert_eq!(status, Some(8));
    assert_eq!(document["ok"], false, "{document}");
    assert_eq!(document["exit_code"], 8, "{document}");
    assert!(
        document["message"]
            .as_str()
            .is_some_and(|message| message
                .contains("Character 1 of the label is U+202E, which is not allowed.")),
        "{document}"
    );
}

/// KR-REQ-13.11: two `kr launch add` runs that read the list at the same revision land one and
/// report one conflict: the one that did not land prints that the list changed and the list as it
/// now stands, applies nothing, and exits 8. A second run of it applies the change. The first
/// write is held inside the daemon, with the store's lock, until the second run has read the
/// list, so the second one's revision is stale whatever the order of the writes that follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_kr_launch_adds_of_two_labels_at_once_land_one_and_report_one_conflict_with_the_current_list_and_exit_8()
 {
    let host = Arc::new(Host::start().await);
    let (arrived, release) = host.controller.pause_after_the_launch_commands_are_locked();
    let run = |line: &'static [&'static str]| {
        let host = Arc::clone(&host);
        tokio::task::spawn_blocking(move || said(&host.kr(line)))
    };

    let first = run(&["launch", "add", "First", "--", "one"]);
    tokio::task::spawn_blocking(move || arrived.recv())
        .await
        .expect("joins")
        .expect("the first write is inside the daemon, holding the store's lock");
    let reads = host.controller.launch_commands_listed();
    assert_eq!(reads, 1, "only the first run has read the list");
    let second = run(&["launch", "add", "Second", "--", "two"]);
    while host.controller.launch_commands_listed() < 2 {
        tokio::task::yield_now().await;
    }
    release.send(()).expect("the first write goes on");

    let (status, text, said) = first.await.expect("joins");
    assert_eq!(status, Some(0), "{said}");
    assert_eq!(text.trim_end(), "Saved the launch command \"First\".");
    let (status, text, said) = second.await.expect("joins");
    assert_eq!(status, Some(8), "{text}{said}");
    assert!(
        said.contains(
            "The saved launch commands changed before this request could apply. Run the command \
             again."
        ),
        "{said}"
    );
    assert_eq!(
        text.trim_end(),
        "First: \"one\"",
        "the list as it now stands is printed"
    );
    assert_eq!(
        labels(&host.listed()),
        ["First"],
        "the conflicted change applied nothing"
    );

    // A second run applies it.
    let (status, text, _) = host.said(&["launch", "add", "Second", "--", "two"]);
    assert_eq!(status, Some(0));
    assert_eq!(text.trim_end(), "Saved the launch command \"Second\".");
    assert_eq!(labels(&host.listed()), ["First", "Second"]);
}

/// KR-REQ-13.11: a conflict in a document is the answer as written with the failure beside it, the
/// code `RESYNC_REQUIRED` and exit 8; where the answer's list already holds the command as written
/// the run says it is already saved and exits 0, claiming no credit for a change another run made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conflict_in_a_document_carries_the_failure_and_a_stale_answer_that_holds_the_command_is_not_one()
 {
    let host = Arc::new(Host::start().await);
    let (arrived, release) = host.controller.pause_after_the_launch_commands_are_locked();
    let run = |line: &'static [&'static str]| {
        let host = Arc::clone(&host);
        tokio::task::spawn_blocking(move || said(&host.kr(line)))
    };

    let first = run(&["launch", "add", "First", "--", "one"]);
    tokio::task::spawn_blocking(move || arrived.recv())
        .await
        .expect("joins")
        .expect("the first write is inside the daemon");
    // Another run that asks for what the first one is writing, and one that asks for something
    // else, both read the list before the first write lands.
    let same = run(&["--json", "launch", "add", "First", "--", "one"]);
    let other = run(&["--json", "launch", "add", "Other", "--", "other"]);
    while host.controller.launch_commands_listed() < 3 {
        tokio::task::yield_now().await;
    }
    release.send(()).expect("the first write goes on");

    let (status, _, said) = first.await.expect("joins");
    assert_eq!(status, Some(0), "{said}");
    let (status, text, said) = same.await.expect("joins");
    assert_eq!(
        status,
        Some(0),
        "the list already holds it as written: {said}"
    );
    let document: Value = serde_json::from_str(&text).expect("a document");
    assert_eq!(document["ok"], true, "{document}");
    let (status, text, said) = other.await.expect("joins");
    assert_eq!(status, Some(8), "{text}{said}");
    let document: Value = serde_json::from_str(&text).expect("a document");
    assert_eq!(document["ok"], false, "{document}");
    assert_eq!(document["code"], "RESYNC_REQUIRED", "{document}");
    assert_eq!(document["exit_code"], 8, "{document}");
    assert_eq!(
        document["applied"], false,
        "the answer as written: {document}"
    );
    assert_eq!(labels(&document), ["First"], "{document}");
    assert_eq!(labels(&host.listed()), ["First"]);
}

/// KR-REQ-13.11: a file the host cannot read is named, with the way through, by `list`, `add` and
/// `remove` alike, each exits 8, and nothing replaces the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_file_names_itself_and_the_way_through_and_exits_8() {
    let host = Host::start().await;
    host.said(&["launch", "add", "Claude", "--", "claude"]);
    std::fs::write(host.file(), b"{ not a record").expect("a damaged file");

    for line in [
        vec!["launch", "list"],
        vec!["launch", "add", "Other", "--", "other"],
        vec!["launch", "remove", "Claude"],
    ] {
        let (status, text, said) = host.said(&line);
        assert_eq!(status, Some(8), "{line:?}: {text}{said}");
        assert!(
            said.contains("The saved launch commands could not be read: ")
                && said.contains("Move that file away, then add the commands again."),
            "{line:?}: {said}"
        );
    }
    assert_eq!(
        std::fs::read(host.file()).expect("the file"),
        b"{ not a record",
        "nothing replaced a file the host could not read"
    );
}

/// KR-REQ-13.11: inside a session `kr launch list`, `add` and `remove` are refused, exit 8, and
/// change nothing: the file's bytes are as they were. The guard's own cases cover a cleaned
/// environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_launch_add_remove_and_list_are_refused_inside_a_session_and_change_nothing() {
    let host = Host::start().await;
    host.said(&["launch", "add", "Claude", "--", "claude", "--resume"]);
    let kept = std::fs::read(host.file()).expect("the file");

    let session = "9f8e7d6c-5b4a-4938-8271-605f4e3d2c1b";
    for line in [
        vec!["launch", "list"],
        vec!["launch", "add", "Other", "--", "other"],
        vec!["launch", "remove", "Claude"],
    ] {
        let output = host
            .command(&[("KR_SESSION", session)], &line)
            .output()
            .expect("kr runs");
        let (status, text, said) = self::said(&output);
        assert_eq!(status, Some(8), "{line:?}: {text}{said}");
        assert_eq!(text, "", "{line:?}: nothing is listed or said as done");
        assert!(
            said.contains("KR_SESSION is set, so this is inside a KalaReach session; a saved"),
            "{line:?}: {said}"
        );
        let mut as_a_document = vec!["--json"];
        as_a_document.extend(line.iter().copied());
        let output = host
            .command(&[("KR_SESSION", session)], &as_a_document)
            .output()
            .expect("kr runs");
        let document: Value = serde_json::from_slice(&output.stdout).expect("a document");
        assert_eq!(
            document["code"], "PERMISSION_DENIED",
            "{line:?}: {document}"
        );
    }
    assert_eq!(std::fs::read(host.file()).expect("the file"), kept);
    assert_eq!(labels(&host.listed()), ["Claude"]);
}
