//! `kr host machine`, run the way a person runs it, against real control daemons.
//!
//! Each environment here is a real `kr-controller` started in this process on a host tree of its
//! own, with its real endpoint, handshake and admission, and a supervisor that starts no worker.
//! `kr` is the real binary, copied to the internal disk and run with that tree's directories on
//! plain pipes. An environment enrolled for a process bridge is reached through a stand-in for
//! `wsl.exe`: a script that runs the real `kr bridge --stdio` against the other tree's directories,
//! and that can be told to refuse to run the helper, as a distribution that cannot be reached does,
//! or to say that the distribution is stopped.

#![cfg(unix)]

use std::path::{Path, PathBuf};
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
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
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

    fn environment_id(&self) -> String {
        self.temp.environment_id().to_string()
    }

    /// Runs `kr` against this host with `--json`, with `bridges` first on its path.
    fn kr_json(&self, bridges: Option<&Path>, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = run_kr(&self.temp, bridges, &asked);
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

    /// Runs `kr` with `--json` and reads a success.
    fn ok(&self, bridges: Option<&Path>, line: &[&str]) -> Value {
        let (status, document) = self.kr_json(bridges, line);
        assert_eq!(status, Some(0), "kr {}: {document}", line.join(" "));
        assert_eq!(document["ok"], Value::Bool(true), "{document}");
        document
    }

    /// Runs `kr` with `--json` and reads the failure it printed.
    fn failed(&self, bridges: Option<&Path>, line: &[&str]) -> Value {
        let (status, document) = self.kr_json(bridges, line);
        assert_eq!(
            document["ok"],
            Value::Bool(false),
            "kr {}: {document}",
            line.join(" ")
        );
        assert_ne!(status, Some(0), "kr {} fails", line.join(" "));
        document
    }

    /// The group this host's own environment reports, as `kr host machine` shows it.
    fn group(&self) -> Group {
        let document = self.ok(None, &["host", "machine"]);
        Group::of(&document["machine"])
    }

    /// Where the plan this host's client keeps would be.
    fn plan_file(&self) -> PathBuf {
        self.temp.paths().state_root().join("machine-merge-plan")
    }
}

/// Runs `kr` on plain pipes with `temp`'s directories, from the root directory.
fn run_kr(temp: &kr_ipc::testing::TempHost, bridges: Option<&Path>, line: &[&str]) -> Output {
    let path = bridges.map_or_else(
        || "/usr/bin:/bin".to_owned(),
        |directory| format!("{}:/usr/bin:/bin", directory.display()),
    );
    Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", path)
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null())
        .output()
        .expect("kr runs")
}

/// The action identities this host's own environment holds a receipt for, as it keeps them.
fn receipts_of(host: &Host) -> Vec<String> {
    let connection = rusqlite::Connection::open_with_flags(
        host.temp.environment().registry_database(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("opens the registry");
    let mut statement = connection
        .prepare("SELECT action_id FROM authority_receipts")
        .expect("reads the receipts");
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("reads the rows")
        .map(|bytes| {
            let bytes: [u8; 16] = bytes
                .expect("a row")
                .try_into()
                .expect("an action identity is sixteen bytes");
            kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
                .to_string()
        })
        .collect()
}

/// A group, as `kr host machine --json` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Group {
    machine_id: String,
    revision: u64,
    change: String,
    previous: Option<String>,
}

impl Group {
    fn of(value: &Value) -> Self {
        Self {
            machine_id: text(&value["machine_id"]),
            revision: text(&value["revision"]).parse().expect("a revision"),
            change: text(&value["change"]),
            previous: value["previous"].as_str().map(str::to_owned),
        }
    }

    fn expect(&self) -> String {
        format!("{}@{}", self.machine_id, self.revision)
    }
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn a_group() -> String {
    kr_ipc::new_uuid().to_string()
}

/// KR-REQ-03.07: the owner shows the group an environment records, and takes a join, a merge and a
/// split at their own command line, each against the record they saw, as text and as a document. A
/// step against another record is refused and changes nothing, and so is an expectation that is
/// not written as a group and a revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_shows_the_group_and_takes_each_step_against_the_record_they_saw() {
    let host = Host::start().await;
    let minted = host.group();
    assert_eq!(minted.revision, 1);
    assert_eq!(minted.change, "created");
    assert_eq!(minted.previous, None);

    // The words a person reads say the group, its revision and how to name the record.
    let shown = run_kr(&host.temp, None, &["host", "machine"]);
    let said = String::from_utf8_lossy(&shown.stdout);
    assert!(said.contains(&minted.machine_id), "{said}");
    assert!(
        said.contains(&format!("--expect {}", minted.expect())),
        "{said}"
    );

    let into = a_group();
    let joined = host.ok(
        None,
        &[
            "host",
            "machine",
            "join",
            &into,
            "--expect",
            &minted.expect(),
        ],
    );
    let joined_group = Group::of(&joined["machine"]);
    assert_eq!(joined_group.machine_id, into);
    assert_eq!(joined_group.revision, 2);
    assert_eq!(joined_group.change, "joined");
    assert_eq!(joined_group.previous, Some(minted.machine_id.clone()));
    assert!(
        joined["action_id"].as_str().is_some(),
        "the step names the action it was taken under: {joined}"
    );
    assert_eq!(host.group(), joined_group);

    // A step against the record from before is refused, and writes nothing.
    let (stale_status, stale) = host.kr_json(
        None,
        &[
            "host",
            "machine",
            "join",
            &a_group(),
            "--expect",
            &minted.expect(),
        ],
    );
    assert_eq!(stale["code"], "DRAFT_CONFLICT", "{stale}");
    assert_eq!(stale_status, Some(8), "a refusal exits with status 8");
    assert_eq!(stale["exit_code"], 8, "{stale}");
    assert_eq!(host.group(), joined_group);

    // Expectations that are not a group and a revision are a usage failure, before anything is sent.
    for expect in [
        "nonsense",
        "nonsense@1",
        &format!("{}@x", joined_group.machine_id),
    ] {
        let malformed = host.failed(None, &["host", "machine", "split", "--expect", expect]);
        assert_eq!(malformed["code"], "INVALID_ARGUMENT", "{malformed}");
    }
    assert_eq!(host.group(), joined_group);

    // This environment's part in a merge, then a split into a fresh group.
    let merged_into = a_group();
    let merged = Group::of(
        &host.ok(
            None,
            &[
                "host",
                "machine",
                "merge",
                &merged_into,
                "--expect",
                &joined_group.expect(),
            ],
        )["machine"],
    );
    assert_eq!(merged.machine_id, merged_into);
    assert_eq!(merged.change, "merged");
    assert_eq!(merged.previous, Some(joined_group.machine_id.clone()));
    let split = Group::of(
        &host.ok(
            None,
            &["host", "machine", "split", "--expect", &merged.expect()],
        )["machine"],
    );
    assert_ne!(split.machine_id, merged_into);
    assert_eq!(split.change, "split");
    assert_eq!(split.previous, Some(merged_into));

    // An environment this host does not have is refused, not answered by the default one.
    let elsewhere = host.failed(None, &["host", "machine", "--environment", &a_group()]);
    assert_eq!(elsewhere["code"], "HOST_NOT_CONFIGURED", "{elsewhere}");
}

/// The distribution the stand-in for `wsl.exe` answers for.
const DISTRIBUTION: &str = "ubuntu-b";

/// The stand-in for `wsl.exe`: it runs the real helper against `tree` while its fixture says it may
/// start one, and refuses to when it may not.
///
/// Asked what is registered and what is running, it answers from the fixture's `stopped` file as the
/// real command does, in UTF-16LE, and runs nothing. Anything else runs in the distribution, which
/// starts a stopped one: the stand-in records that in the fixture's `started` file and goes on.
fn stand_in(fixture: &Path, tree: &kr_ipc::testing::TempHost) -> String {
    let fixture = fixture.to_str().expect("a temporary path is text");
    let runtime = tree.paths().runtime_root().display().to_string();
    let state = tree.paths().state_root().display().to_string();
    let home = tree.root().display().to_string();
    for text in [fixture, &runtime, &state, &home] {
        assert!(
            !text.contains('\''),
            "the stand-in quotes its paths with single quotes: {text}"
        );
    }
    format!(
        r##"#!/bin/sh
fixture='{fixture}'
if [ "$1" = "--list" ]; then
  case "$*" in
    "--list --all --quiet")
      printf '{DISTRIBUTION}\r\n' | iconv -f UTF-8 -t UTF-16LE
      ;;
    "--list --running --quiet")
      if [ ! -e "$fixture/stopped" ]; then
        printf '{DISTRIBUTION}\r\n' | iconv -f UTF-8 -t UTF-16LE
      fi
      ;;
    *)
      echo "the stand-in for wsl.exe has no answer for: $*" >&2
      exit 2
      ;;
  esac
  exit 0
fi
if [ -e "$fixture/stopped" ]; then
  echo "$*" >>"$fixture/started"
  rm -f "$fixture/stopped"
fi
allowed="$(cat "$fixture/allowed" 2>/dev/null || echo 0)"
if [ "$allowed" -le 0 ]; then
  echo "the helper did not start" >&2
  exit 1
fi
echo $((allowed - 1)) >"$fixture/allowed"
# wsl.exe --distribution NAME --user USER --exec HELPER bridge --stdio
KR_RUNTIME_DIR='{runtime}' KR_STATE_DIR='{state}' HOME='{home}' exec "$6" "$7" "$8"
"##
    )
}

/// What a test sets up: environment A, the host `kr` runs against, and environment B, which A has
/// enrolled for a process bridge as `bravo`.
struct Pair {
    a: Host,
    b: Host,
    bridges: tempfile::TempDir,
}

impl Pair {
    async fn start() -> Self {
        let a = Host::start().await;
        let b = Host::start().await;
        let bridges = tempfile::TempDir::new().expect("a directory for the stand-in");
        let fixture = bridges.path().join("fixture");
        std::fs::create_dir(&fixture).expect("the stand-in's fixture");
        let text = bridges.path().join("wsl.exe.text");
        std::fs::write(&text, stand_in(&fixture, &b.temp)).expect("writes the stand-in");
        kr_ipc::testing::place_program(&text, &bridges.path().join("wsl.exe"));
        let pair = Self { a, b, bridges };
        pair.allow(100);
        let helper = support::kr().display().to_string();
        let (status, enrolled) = pair.a.kr_json(
            Some(pair.bridges.path()),
            &[
                "bridge",
                "enrol",
                "--access",
                "wsl",
                "--label",
                "bravo",
                "--target",
                DISTRIBUTION,
                "--user",
                "kala",
                "--helper",
                &helper,
                "--environment-id",
                &pair.b.environment_id(),
            ],
        );
        assert_eq!(status, Some(0), "the enrolment: {enrolled}");
        pair
    }

    /// How many more times the stand-in will start a helper: it drops by one for each helper a
    /// command started, so a test can tell by condition that B was reached.
    fn starts_left(&self) -> u32 {
        std::fs::read_to_string(self.bridges.path().join("fixture/allowed"))
            .expect("the stand-in's allowance")
            .trim()
            .parse()
            .expect("a number")
    }

    /// Stops the distribution: the platform says so, and running anything in it starts it.
    fn stop(&self) {
        std::fs::write(self.bridges.path().join("fixture/stopped"), "")
            .expect("writes the stand-in's state");
    }

    /// The command lines that ran in the distribution while it was stopped, each of which started
    /// it.
    fn starts_of_a_stopped_distribution(&self) -> Vec<String> {
        std::fs::read_to_string(self.bridges.path().join("fixture/started"))
            .map(|lines| lines.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// How many more times the stand-in starts a helper.
    fn allow(&self, starts: u32) {
        std::fs::write(
            self.bridges.path().join("fixture/allowed"),
            starts.to_string(),
        )
        .expect("writes the stand-in's allowance");
    }

    /// Runs `kr` against A, which reaches B through the stand-in.
    fn at_a(&self, line: &[&str]) -> Value {
        self.a.ok(Some(self.bridges.path()), line)
    }

    fn at_a_failing(&self, line: &[&str]) -> Value {
        self.a.failed(Some(self.bridges.path()), line)
    }

    /// Puts both environments in one group, which a merge then takes them out of.
    fn together(&self) -> Group {
        let shared = self.a.group();
        let own = self.b.group();
        self.b.ok(
            None,
            &[
                "host",
                "machine",
                "join",
                &shared.machine_id,
                "--expect",
                &own.expect(),
            ],
        );
        shared
    }
}

/// KR-REQ-03.07: an enrolled environment's group is what that environment reports of itself
/// through its process bridge, read each time it is asked, and never what the enrolment holds,
/// which names no group.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolled_environments_group_is_read_from_itself_through_its_bridge() {
    let pair = Pair::start().await;
    let before = Group::of(&pair.at_a(&["host", "machine", "--environment", "bravo"])["machine"]);
    assert_eq!(before, pair.b.group(), "the group B itself reports");
    assert_ne!(before.machine_id, pair.a.group().machine_id);

    // B takes a step of its own at its own socket; what A reads through the bridge follows it.
    let into = a_group();
    pair.b.ok(
        None,
        &[
            "host",
            "machine",
            "join",
            &into,
            "--expect",
            &before.expect(),
        ],
    );
    let after = Group::of(&pair.at_a(&["host", "machine", "--environment", "bravo"])["machine"]);
    assert_eq!(after.machine_id, into);
    assert_eq!(after, pair.b.group());

    // The enrolment records the environment and says nothing of a group.
    let (status, listed) = pair
        .a
        .kr_json(Some(pair.bridges.path()), &["bridge", "list"]);
    assert_eq!(status, Some(0), "{listed}");
    assert!(
        !listed.to_string().contains(&into),
        "the cached inventory holds no group: {listed}"
    );

    // A step over the bridge changes B's record and nothing of A's.
    let a_before = pair.a.group();
    let stepped = Group::of(
        &pair.at_a(&[
            "host",
            "machine",
            "split",
            "--environment",
            "bravo",
            "--expect",
            &after.expect(),
        ])["machine"],
    );
    assert_eq!(stepped.change, "split");
    assert_eq!(stepped, pair.b.group());
    assert_eq!(
        pair.a.group(),
        a_before,
        "no environment takes a step for another"
    );
}

/// KR-REQ-03.14: showing the group of an enrolled environment whose distribution is stopped, taking
/// a step in it, and making a merge plan over it are each refused with `ENVIRONMENT_UNAVAILABLE`,
/// and none of them starts the distribution, which running the helper in it would. The same
/// commands are answered once the distribution runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_distribution_is_refused_and_not_started_by_a_machine_command() {
    let pair = Pair::start().await;
    let own = pair.b.group();
    pair.stop();

    let shown = pair.at_a_failing(&["host", "machine", "--environment", "bravo"]);
    assert_eq!(shown["code"], "ENVIRONMENT_UNAVAILABLE", "{shown}");
    let stepped = pair.at_a_failing(&[
        "host",
        "machine",
        "split",
        "--environment",
        "bravo",
        "--expect",
        &own.expect(),
    ]);
    assert_eq!(stepped["code"], "ENVIRONMENT_UNAVAILABLE", "{stepped}");
    let planned = pair.at_a_failing(&[
        "host",
        "machine",
        "merge",
        &a_group(),
        "--from",
        &own.machine_id,
        "--environment",
        "bravo",
    ]);
    assert_eq!(planned["code"], "ENVIRONMENT_UNAVAILABLE", "{planned}");

    assert_eq!(
        pair.starts_of_a_stopped_distribution(),
        Vec::<String>::new(),
        "nothing was run in the distribution, so nothing started it"
    );
    assert_eq!(pair.b.group(), own, "no step was taken");
    assert!(!pair.a.plan_file().exists(), "no plan was kept");

    // Once the distribution runs, the same command is answered.
    std::fs::remove_file(pair.bridges.path().join("fixture/stopped"))
        .expect("the distribution runs");
    let running = pair.at_a(&["host", "machine", "--environment", "bravo"]);
    assert_eq!(Group::of(&running["machine"]), own);
}

/// KR-REQ-03.07: a merge over independent environments is a plan the client keeps, owner-only
/// under its own state directory and never an environment's, until each step has its result. One
/// environment cannot be reached when its step comes, so its step stays pending and the plan is
/// kept; once it can be reached, `finish` sends the step and the plan is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_merge_over_independent_environments_is_a_plan_kept_until_each_step_has_its_result() {
    use std::os::unix::fs::PermissionsExt as _;

    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();

    // Nothing is kept to begin with, and nothing can be finished.
    let none = pair.at_a(&["host", "machine", "plan"]);
    assert_eq!(none["plan"], Value::Null, "{none}");
    let no_plan = pair.at_a_failing(&["host", "machine", "finish"]);
    assert_eq!(no_plan["code"], "INVALID_ARGUMENT", "{no_plan}");

    // A group the environments are not in is refused before anything is kept or sent.
    let wrong = pair.at_a_failing(&[
        "host",
        "machine",
        "merge",
        &into,
        "--from",
        &a_group(),
        "--environment",
        &a_id,
        "--environment",
        "bravo",
    ]);
    assert_eq!(wrong["code"], "INVALID_ARGUMENT", "{wrong}");
    assert!(!pair.a.plan_file().exists(), "no plan was kept");
    assert_eq!(pair.a.group().machine_id, shared.machine_id);

    // The bridge starts once, to read B's group, and then B cannot be reached when its step comes.
    pair.allow(1);
    let started = pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    assert_eq!(started["code"], "ENVIRONMENT_UNAVAILABLE", "{started}");
    let steps = started["steps"].as_array().expect("the steps");
    assert_eq!(steps.len(), 2, "{started}");
    assert_eq!(steps[0]["environment_id"], a_id.as_str());
    assert_eq!(steps[0]["state"], "done", "{started}");
    assert_eq!(steps[1]["state"], "unsent", "{started}");
    assert_eq!(started["kept"], Value::Bool(true));

    // A took its step; B did not.
    let a_group = pair.a.group();
    assert_eq!(a_group.machine_id, into);
    assert_eq!(a_group.change, "merged");
    assert_eq!(pair.b.group().machine_id, shared.machine_id);

    // The plan is a file only the owner reads, in this user's state directory, and no environment's
    // own directory holds one.
    let plan = pair.a.plan_file();
    assert!(plan.exists(), "the plan is kept");
    for host in [&pair.a, &pair.b] {
        assert!(
            !host
                .temp
                .environment()
                .state_dir()
                .join("machine-merge-plan")
                .exists(),
            "never in an environment's own directory"
        );
    }
    assert!(
        !pair
            .b
            .temp
            .paths()
            .state_root()
            .join("machine-merge-plan")
            .exists(),
        "nor in the other host's"
    );
    let mode = std::fs::metadata(&plan)
        .expect("the plan is kept")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "owner-only: {mode:o}");

    // `plan` says the same, and a second plan is refused while one is kept.
    let shown = pair.at_a(&["host", "machine", "plan"]);
    assert_eq!(shown["steps"][1]["state"], "unsent", "{shown}");
    let second = pair.at_a_failing(&[
        "host",
        "machine",
        "merge",
        &a_group_id(),
        "--from",
        &shared.machine_id,
        "--environment",
        "bravo",
    ]);
    assert_eq!(second["code"], "INVALID_ARGUMENT", "{second}");

    // `finish` while B still cannot be reached leaves the step pending, and the plan.
    pair.allow(0);
    let (still_status, still) = pair
        .a
        .kr_json(Some(pair.bridges.path()), &["host", "machine", "finish"]);
    assert_eq!(still_status, Some(1), "a pending step exits with status 1");
    assert_eq!(still["code"], "ENVIRONMENT_UNAVAILABLE", "{still}");
    assert_eq!(still["steps"][1]["state"], "unsent", "{still}");
    assert!(plan.exists());

    // Once B can be reached, `finish` takes its step, and the plan goes with the last result.
    pair.allow(10);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert!(!plan.exists(), "every step has a result");
    let b_group = pair.b.group();
    assert_eq!(b_group.machine_id, into);
    assert_eq!(b_group.change, "merged");
    assert_eq!(b_group.previous, Some(shared.machine_id));
}

fn a_group_id() -> String {
    a_group()
}

/// KR-REQ-03.07: a merge left half done is undone step by step. The environment that moved is put
/// back into the group it left, against the record its step left; the step that was never sent is
/// given up and never taken; and the plan goes once every step has its result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_merge_left_half_done_is_undone_by_putting_back_each_environment_that_moved() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();

    pair.allow(1);
    let started = pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    assert_eq!(started["steps"][0]["state"], "done", "{started}");
    assert_eq!(pair.a.group().machine_id, into);

    // B still cannot be reached. Undoing needs no bridge: A put itself back, and B's step was never
    // sent.
    pair.allow(0);
    let undone = pair.at_a(&["host", "machine", "undo"]);
    assert_eq!(undone["kept"], Value::Bool(false), "{undone}");
    assert_eq!(undone["steps"][1]["state"], "refused", "{undone}");
    assert_eq!(undone["steps"][1]["reason"], "given_up", "{undone}");
    assert_eq!(undone["undo"][0]["state"], "done", "{undone}");
    assert!(!pair.a.plan_file().exists(), "every step has a result");

    let back = pair.a.group();
    assert_eq!(back.machine_id, shared.machine_id);
    assert_eq!(back.change, "joined");
    assert_eq!(back.previous, Some(into));
    // B never moved, and now never will by this plan.
    assert_eq!(pair.b.group().machine_id, shared.machine_id);
}

/// KR-REQ-03.07: the environments of a merge each take their own step over their own connection,
/// and a step changes the environment it names and no other: A's step and B's step each leave the
/// other's group as the owner left it, and each is a step of its own, taken under an action of its
/// own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_environment_of_a_merge_takes_its_own_step_and_changes_no_other() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();

    let finished = pair.at_a(&[
        "host",
        "machine",
        "merge",
        &into,
        "--from",
        &shared.machine_id,
        "--environment",
        &a_id,
        "--environment",
        "bravo",
    ]);
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    let (a_action, b_action) = (
        text(&finished["steps"][0]["action_id"]),
        text(&finished["steps"][1]["action_id"]),
    );
    assert_ne!(
        a_action, b_action,
        "each step has an action identity of its own"
    );
    assert_eq!(pair.a.group().machine_id, into);
    assert_eq!(pair.b.group().machine_id, into);
    assert!(!pair.a.plan_file().exists());
}

/// KR-REQ-03.07: a step the environment was never sent is composed on the connection that sends it,
/// and the environment is read against what the step was approved against when it refuses it. Where
/// the owner took the same step another way meanwhile, the record shows it was taken, and the step
/// is taken as done without being taken twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_the_owner_took_another_way_meanwhile_is_taken_as_done_and_not_taken_twice() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();

    pair.allow(1);
    pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    // B still has the record the plan was made against. The owner takes B's part at B's own socket.
    let own = pair.b.group();
    assert_eq!(own.machine_id, shared.machine_id);
    let by_hand = Group::of(
        &pair.b.ok(
            None,
            &["host", "machine", "merge", &into, "--expect", &own.expect()],
        )["machine"],
    );
    assert_eq!(by_hand.revision, own.revision + 1);

    pair.allow(10);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert!(!pair.a.plan_file().exists());
    assert_eq!(
        pair.b.group(),
        by_hand,
        "the plan took no second step: the record is as the owner's own left it"
    );
}

/// KR-REQ-03.07: a record that shows a step taken is not called taken while its environment cannot
/// confirm that the record survives a crash. The owner took B's part by hand and B could not confirm
/// the write; every step the plan sends B meanwhile is refused before B can confirm its record,
/// whether it is composed for the first time or sent again, so none of them says the record is
/// confirmed. The step stays `sent` and the plan is kept until B can confirm its record, and then a
/// step that finds the record moved on is what takes it as done. The plan has seen B's record show
/// the step, so when B's record then cannot be read, an answer to a step sent before, whatever it
/// refuses it for, does not make the step refused: it stays `sent`, and is `done` once B can read
/// and confirm its record again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_the_owner_took_another_way_is_not_called_taken_while_its_record_is_unconfirmed() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();
    pair.allow(1);
    pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    let own = pair.b.group();
    pair.b
        .controller
        .report_the_next_machine_write_as_unconfirmed();
    let by_hand = pair.b.failed(
        None,
        &["host", "machine", "merge", &into, "--expect", &own.expect()],
    );
    assert_eq!(by_hand["code"], "OUTCOME_UNKNOWN", "{by_hand}");
    pair.b.controller.fail_the_machine_recovery_flush(true);
    let written = pair.b.group();
    assert_eq!(written.machine_id, into, "the record shows B's step");
    assert_eq!(written.revision, own.revision + 1);

    pair.allow(10);
    let mut identity = text(&pair.at_a(&["host", "machine", "plan"])["steps"][1]["action_id"]);
    // The first `finish` composes B's step under the identity the plan holds, and B refuses it
    // before it can confirm its record. Each later one sends the step again, which B refuses for
    // its window, and then composes it again under a new action, which B refuses before it can
    // confirm its record: the identity changes every time B is reached.
    for round in 1..=3 {
        let (status, still) = pair
            .a
            .kr_json(Some(pair.bridges.path()), &["host", "machine", "finish"]);
        assert_eq!(status, Some(1), "round {round}: {still}");
        assert_eq!(
            still["code"], "ENVIRONMENT_UNAVAILABLE",
            "round {round}: {still}"
        );
        assert_eq!(still["steps"][1]["state"], "sent", "round {round}: {still}");
        assert_eq!(still["kept"], Value::Bool(true), "round {round}: {still}");
        assert!(pair.a.plan_file().exists(), "round {round}");
        let now = text(&still["steps"][1]["action_id"]);
        if round == 1 {
            assert_eq!(now, identity, "the first send is under the plan's identity");
        } else {
            assert_ne!(
                now, identity,
                "round {round}: the step was sent again and composed again under a new action"
            );
        }
        identity = now;
    }
    assert_eq!(pair.b.group(), written, "B took no second step");

    // B's record then cannot be read. B refuses the step sent again for its window, which says
    // nothing of an earlier action, and it reports no group to read the step against.
    let record = pair.b.temp.environment().state_dir().join("machine-group");
    let whole = std::fs::read(&record).expect("B's record");
    kr_ipc::paths::write_owner_only_file(&record, b"damaged while the daemon ran")
        .expect("damages the record");
    let (status, unread) = pair
        .a
        .kr_json(Some(pair.bridges.path()), &["host", "machine", "finish"]);
    assert_eq!(status, Some(1), "{unread}");
    assert_eq!(unread["steps"][1]["state"], "sent", "{unread}");
    assert_eq!(unread["kept"], Value::Bool(true), "{unread}");
    assert!(pair.a.plan_file().exists());
    kr_ipc::paths::write_owner_only_file(&record, &whole).expect("restores the record");

    pair.b.controller.fail_the_machine_recovery_flush(false);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    assert!(!pair.a.plan_file().exists());
    assert_eq!(
        pair.b.group(),
        written,
        "the plan took no second step: the record is as the owner's own left it"
    );
}

/// Takes the plan to the point where A has taken its step and B, which cannot be reached, has not,
/// and then has B's owner move B on to another group. Returns the group both were in, the group A
/// was merged into, and the group B's owner moved it to.
fn merge_with_b_moved_on(pair: &Pair) -> (Group, String, String) {
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();
    pair.allow(1);
    pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    // B's record moves on before its step is taken.
    let own = pair.b.group();
    let elsewhere = a_group();
    pair.b.ok(
        None,
        &[
            "host",
            "machine",
            "join",
            &elsewhere,
            "--expect",
            &own.expect(),
        ],
    );
    pair.allow(10);
    (shared, into, elsewhere)
}

/// KR-REQ-03.07: a step whose environment has moved on from the record it was approved against can
/// never apply, and is given its refusal. Every step then has a result, so the plan goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_record_moved_on_is_refused_and_the_plan_goes() {
    let pair = Pair::start().await;
    let (_shared, into, elsewhere) = merge_with_b_moved_on(&pair);

    let finished = pair
        .a
        .failed(Some(pair.bridges.path()), &["host", "machine", "finish"]);
    assert_eq!(finished["code"], "DRAFT_CONFLICT", "{finished}");
    assert_eq!(finished["steps"][0]["state"], "done", "{finished}");
    assert_eq!(finished["steps"][1]["state"], "refused", "{finished}");
    assert_eq!(finished["steps"][1]["reason"], "moved", "{finished}");
    assert_eq!(finished["kept"], Value::Bool(false));
    assert!(!pair.a.plan_file().exists(), "every step has a result");
    assert_eq!(
        pair.b.group().machine_id,
        elsewhere,
        "B is as its owner left it"
    );
    assert_eq!(pair.a.group().machine_id, into);
}

/// KR-REQ-03.07: where a step was refused and the plan is gone, the text names each environment the
/// merge moved with the command that puts it back, against the record its step left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_environment_a_half_finished_merge_moved_is_named_with_the_command_that_puts_it_back()
{
    let pair = Pair::start().await;
    let (shared, _into, _elsewhere) = merge_with_b_moved_on(&pair);
    let a_id = pair.a.environment_id();

    let finished = run_kr(
        &pair.a.temp,
        Some(pair.bridges.path()),
        &["host", "machine", "finish"],
    );
    assert_ne!(
        finished.status.code(),
        Some(0),
        "a refused step is a failure"
    );
    let said = String::from_utf8_lossy(&finished.stdout);
    let complained = String::from_utf8_lossy(&finished.stderr);
    assert!(said.contains("not taken"), "{said}");
    assert!(said.contains("no longer kept"), "{said}");
    assert!(complained.contains("kr: "), "{complained}");
    let moved = pair.a.group();
    assert!(
        said.contains(&format!(
            "kr host machine join {} --expect {} --environment {a_id}",
            shared.machine_id,
            moved.expect()
        )),
        "{said}"
    );
}

/// The merge started with both environments reachable and B's answer lost, and the plan that is
/// kept: A took its step, and B's step is `sent`.
fn merge_with_b_answer_lost(pair: &Pair, fault: impl FnOnce(&Host)) -> (Group, String, Value) {
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();
    fault(&pair.b);
    let started = pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    (shared, into, started)
}

/// KR-REQ-03.07: a step is first sent on the connection that composes it, under the identity the
/// plan has held since it was made. B cannot be reached when its step comes, so the plan keeps B's
/// step unsent with its identity, and `finish` takes it under that identity and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_is_first_sent_under_the_identity_the_plan_holds_for_it() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();

    pair.allow(1);
    pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    let kept = pair.at_a(&["host", "machine", "plan"]);
    assert_eq!(kept["steps"][1]["state"], "unsent", "{kept}");
    let identity = text(&kept["steps"][1]["action_id"]);

    pair.allow(10);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_eq!(
        text(&finished["steps"][1]["action_id"]),
        identity,
        "the plan names the identity the step was sent under"
    );
    assert!(
        receipts_of(&pair.b).contains(&identity),
        "the environment holds its receipt under the identity the plan held, which is the one it \
         was sent under: {:?}",
        receipts_of(&pair.b)
    );
    assert_eq!(pair.b.group().machine_id, into);
}

/// KR-REQ-03.07: a step whose answer was lost after the environment wrote its record is not given a
/// result it was not given. B's record shows the step and B cannot say it took it, so the step
/// stays `sent`, the plan is kept, and no second identity is made for it; `undo` refuses while it is
/// `sent`; and `finish` sends it again under its identity and is answered with its result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_answer_was_lost_stays_pending_and_is_answered_by_the_next_finish() {
    let pair = Pair::start().await;
    let (shared, into, started) = merge_with_b_answer_lost(&pair, |b| {
        b.controller.lose_the_next_machine_receipt();
    });
    assert_eq!(started["steps"][0]["state"], "done", "{started}");
    assert_eq!(started["steps"][1]["state"], "sent", "{started}");
    assert_eq!(started["kept"], Value::Bool(true), "{started}");
    let identity = text(&started["steps"][1]["action_id"]);
    assert!(pair.a.plan_file().exists());
    assert_eq!(
        pair.b.group().machine_id,
        into,
        "B's record shows the step it could not answer"
    );

    // Undoing while a step may or may not have been taken is refused, and changes nothing.
    let refused = pair.at_a_failing(&["host", "machine", "undo"]);
    assert_eq!(refused["code"], "INVALID_ARGUMENT", "{refused}");
    assert!(pair.a.plan_file().exists());
    assert_eq!(pair.a.group().machine_id, into);

    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_eq!(
        text(&finished["steps"][1]["action_id"]),
        identity,
        "the step was asked again under its own identity"
    );
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    assert!(!pair.a.plan_file().exists());
    assert_eq!(pair.b.group().previous, Some(shared.machine_id));
}

/// KR-REQ-03.07: an environment that cannot read its own record says nothing of a step it took before
/// the record was lost. B took its step and lost its answer; its record is then damaged. `finish`
/// reads no group from B and keeps the step `sent` and the plan, and once the record is whole it is
/// answered with the step's result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_environment_that_cannot_read_its_record_is_not_taken_to_have_refused_its_step() {
    let pair = Pair::start().await;
    let (_shared, into, started) = merge_with_b_answer_lost(&pair, |b| {
        b.controller.lose_the_next_machine_receipt();
    });
    assert_eq!(started["steps"][1]["state"], "sent", "{started}");
    assert_eq!(
        pair.b.group().machine_id,
        into,
        "B took the step under the identity the plan holds, before its record is damaged"
    );
    let identity = text(&started["steps"][1]["action_id"]);
    let record = pair.b.temp.environment().state_dir().join("machine-group");
    let whole = std::fs::read(&record).expect("B's record");
    kr_ipc::paths::write_owner_only_file(&record, b"damaged while the daemon ran")
        .expect("damages the record");

    // B's daemon is told to stop the retry once it has found the step's claim unfinished, which it
    // does only when B has received the retry: a task notes that and lets it go, and B cannot
    // answer before then.
    let (arrived, go) = pair.b.controller.hold_the_next_machine_retry();
    let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let releasing = tokio::spawn({
        let received = Arc::clone(&received);
        async move {
            arrived.await.expect("B received the retry");
            received.store(true, std::sync::atomic::Ordering::SeqCst);
            go.send(()).expect("lets the retry go");
        }
    });
    let (status, still) = pair
        .a
        .kr_json(Some(pair.bridges.path()), &["host", "machine", "finish"]);
    assert!(
        received.load(std::sync::atomic::Ordering::SeqCst),
        "B received the retry, so its answer is what kept the step sent: {still}"
    );
    releasing.await.expect("the retry was let go");
    assert_eq!(status, Some(1), "{still}");
    assert_eq!(still["code"], "ENVIRONMENT_UNAVAILABLE", "{still}");
    assert_eq!(still["steps"][1]["state"], "sent", "{still}");
    assert_eq!(still["kept"], Value::Bool(true), "{still}");
    assert!(pair.a.plan_file().exists());

    kr_ipc::paths::write_owner_only_file(&record, &whole).expect("restores the record");
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_eq!(
        text(&finished["steps"][1]["action_id"]),
        identity,
        "the step is answered under the identity it was sent under, and no other"
    );
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    assert_eq!(pair.b.group().machine_id, into);
}

/// KR-REQ-03.07: an environment that can read neither its receipts nor its record is not taken to
/// have refused a step it took. B took its step and lost its answer, and both are then unreadable:
/// `finish` reaches B, keeps the step `sent` and the plan, and once B can read both again the step
/// is answered. B's own answer, an outcome nobody knows, is the daemon test's
/// `a_retry_whose_receipt_cannot_be_looked_up_is_an_outcome_nobody_knows`; this test shows the plan
/// keeps the step through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_environment_that_cannot_read_its_receipts_or_its_record_has_not_refused_its_step() {
    let pair = Pair::start().await;
    let (_shared, into, started) = merge_with_b_answer_lost(&pair, |b| {
        b.controller.lose_the_next_machine_receipt();
    });
    assert_eq!(started["steps"][1]["state"], "sent", "{started}");
    let record = pair.b.temp.environment().state_dir().join("machine-group");
    let whole = std::fs::read(&record).expect("B's record");
    kr_ipc::paths::write_owner_only_file(&record, b"damaged while the daemon ran")
        .expect("damages the record");
    let database = pair.b.temp.environment().registry_database();
    let renamed = |from: &str, to: &str| {
        let connection = rusqlite::Connection::open(&database).expect("opens B's registry");
        connection
            .busy_timeout(std::time::Duration::from_secs(10))
            .expect("waits");
        connection
            .execute_batch(&format!("ALTER TABLE {from} RENAME TO {to};"))
            .expect("renames the table");
    };
    renamed("authority_receipts", "authority_receipts_aside");

    let before = pair.starts_left();
    let (status, still) = pair
        .a
        .kr_json(Some(pair.bridges.path()), &["host", "machine", "finish"]);
    assert!(pair.starts_left() < before, "B was reached");
    assert_eq!(status, Some(1), "{still}");
    assert_eq!(still["code"], "ENVIRONMENT_UNAVAILABLE", "{still}");
    assert_eq!(still["steps"][1]["state"], "sent", "{still}");
    assert_eq!(still["kept"], Value::Bool(true), "{still}");
    assert!(pair.a.plan_file().exists(), "the plan was not given up");

    renamed("authority_receipts_aside", "authority_receipts");
    kr_ipc::paths::write_owner_only_file(&record, &whole).expect("restores the record");
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_eq!(finished["kept"], Value::Bool(false), "{finished}");
    assert_eq!(pair.b.group().machine_id, into);
}

/// KR-REQ-03.07: the same for a step whose write the environment could not confirm to survive a
/// crash: it is an outcome nobody knows, and the plan keeps it `sent` until the environment can say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_whose_write_could_not_be_confirmed_is_not_called_taken_until_it_is_answered() {
    let pair = Pair::start().await;
    let (_shared, into, started) = merge_with_b_answer_lost(&pair, |b| {
        b.controller.report_the_next_machine_write_as_unconfirmed();
    });
    assert_eq!(started["steps"][1]["state"], "sent", "{started}");
    assert_eq!(started["kept"], Value::Bool(true), "{started}");
    assert_eq!(pair.b.group().machine_id, into);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert!(!pair.a.plan_file().exists());
}

/// KR-REQ-03.07: a step the environment could not write is not given up. B's record is as it was,
/// the step stays `sent` and the plan is kept, and the next `finish` takes it under a new action.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_step_that_could_not_be_written_is_taken_by_the_next_finish() {
    let pair = Pair::start().await;
    let (shared, into, started) = merge_with_b_answer_lost(&pair, |b| {
        b.controller.fail_the_next_machine_write();
    });
    assert_eq!(started["steps"][1]["state"], "sent", "{started}");
    assert_eq!(started["kept"], Value::Bool(true), "{started}");
    assert_eq!(
        pair.b.group().machine_id,
        shared.machine_id,
        "nothing was written"
    );
    let first = text(&started["steps"][1]["action_id"]);

    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
    assert_ne!(
        text(&finished["steps"][1]["action_id"]),
        first,
        "the refusal the first action was given is final for it, so the step is taken under a new one"
    );
    assert_eq!(pair.b.group().machine_id, into);
}

/// KR-REQ-03.07: one command at a time works on the plan. While another holds it, `merge --from`,
/// `finish` and `undo` each refuse and send nothing, and `plan`, which reads a file that is always
/// whole, is answered; once it is let go the same command goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_command_at_a_time_works_on_the_plan() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();
    pair.allow(1);
    let started = pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    assert_eq!(started["steps"][1]["state"], "unsent", "{started}");
    assert!(pair.a.plan_file().exists(), "the merge kept its plan");
    pair.allow(10);

    let lock_path = pair.a.plan_file().with_file_name("machine-merge-plan.lock");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("opens the lock file");
    held.try_lock().expect("another command holds the plan");

    for line in [
        &["host", "machine", "finish"][..],
        &["host", "machine", "undo"][..],
        &[
            "host",
            "machine",
            "merge",
            &a_group(),
            "--from",
            &shared.machine_id,
            "--environment",
            "bravo",
        ][..],
    ] {
        let (status, refused) = pair.a.kr_json(Some(pair.bridges.path()), line);
        assert_eq!(status, Some(1), "{line:?}: {refused}");
        assert_eq!(refused["ok"], Value::Bool(false), "{refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|said| said.contains("another kr host machine command")),
            "{line:?}: {refused}"
        );
    }
    assert_eq!(
        pair.b.group().machine_id,
        shared.machine_id,
        "nothing was sent to B"
    );
    let shown = pair.at_a(&["host", "machine", "plan"]);
    assert_eq!(shown["steps"][1]["state"], "unsent", "{shown}");

    held.unlock().expect("lets the plan go");
    drop(held);
    let finished = pair.at_a(&["host", "machine", "finish"]);
    assert_eq!(finished["steps"][1]["state"], "done", "{finished}");
}

/// KR-REQ-03.07: a lost plan is not rebuilt from what the environments report. With A's step taken
/// and B's pending, the plan file goes: `plan` says none is kept, `finish` and `undo` refuse, B is
/// not sent anything, and nothing is written in its place. A plan file that cannot be read is left
/// as it is, and a new merge is refused until the owner moves it aside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_plan_is_not_rebuilt_and_an_unreadable_one_is_left_as_it_is() {
    let pair = Pair::start().await;
    let shared = pair.together();
    let a_id = pair.a.environment_id();
    let into = a_group();
    pair.allow(1);
    pair.a.failed(
        Some(pair.bridges.path()),
        &[
            "host",
            "machine",
            "merge",
            &into,
            "--from",
            &shared.machine_id,
            "--environment",
            &a_id,
            "--environment",
            "bravo",
        ],
    );
    pair.allow(10);
    let plan = pair.a.plan_file();
    assert!(plan.exists());

    std::fs::remove_file(&plan).expect("loses the plan");
    let none = pair.at_a(&["host", "machine", "plan"]);
    assert_eq!(none["plan"], Value::Null, "{none}");
    for step in ["finish", "undo"] {
        let refused = pair.at_a_failing(&["host", "machine", step]);
        assert_eq!(refused["code"], "INVALID_ARGUMENT", "{step}: {refused}");
    }
    assert!(!plan.exists(), "nothing was written in the plan's place");
    assert_eq!(
        pair.b.group().machine_id,
        shared.machine_id,
        "B was sent nothing"
    );
    assert_eq!(pair.a.group().machine_id, into, "A was not put back");

    // A file that is not a plan: refused, and left exactly as it is.
    kr_ipc::paths::write_owner_only_file(&plan, b"this is not a plan").expect("damages the plan");
    let refused = pair.at_a_failing(&[
        "host",
        "machine",
        "merge",
        &a_group(),
        "--from",
        &into,
        "--environment",
        "bravo",
    ]);
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|said| said.contains("moved aside")),
        "{refused}"
    );
    assert_eq!(
        std::fs::read(&plan).expect("the file"),
        b"this is not a plan",
        "the file was left as it was"
    );
    assert_eq!(pair.b.group().machine_id, shared.machine_id);
}

/// KR-REQ-03.07: `--environment` names the environment of one step or the environments of a merge
/// plan. `plan`, `finish` and `undo` act on the plan and take none, and a merge of a group into
/// itself is refused, each before anything is read or kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_options_that_name_nothing_the_command_acts_on_are_refused() {
    let pair = Pair::start().await;
    let shared = pair.together();
    for step in ["plan", "finish", "undo"] {
        let (status, refused) = pair.a.kr_json(
            Some(pair.bridges.path()),
            &["host", "machine", step, "--environment", "bravo"],
        );
        assert_eq!(status, Some(2), "{step}: {refused}");
        assert_eq!(refused["code"], "INVALID_ARGUMENT", "{step}: {refused}");
    }
    let itself = pair.at_a_failing(&[
        "host",
        "machine",
        "merge",
        &shared.machine_id,
        "--from",
        &shared.machine_id,
        "--environment",
        "bravo",
    ]);
    assert_eq!(itself["code"], "INVALID_ARGUMENT", "{itself}");
    assert!(!pair.a.plan_file().exists(), "nothing was kept");
    assert_eq!(pair.b.group().machine_id, shared.machine_id);
}
