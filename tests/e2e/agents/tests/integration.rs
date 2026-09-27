//! The command integration, end to end, with the released packages installed and stand-in agents.
//!
//! Everything a person runs is real, on the stage the qualification cases use: the `kr-controller`
//! daemon, the `kr-worker` it launches for each session, `kr` on terminals of its own and the
//! `kr-hook` launcher, all copied from this build to the internal disk, and an owner device paired
//! over loopback. The Claude Code, Gemini CLI and Qoder CLI packages are installed from a signed
//! catalogue generation on that device's confirmation, each with its `command_integration.launch`
//! grant. The agents are stand-ins that sign in nowhere: `claude`, `gemini` and `qodercli` are
//! links to bash on the session's search path, each typed at a managed prompt as
//! `<command> -c '<script>' kr-sentinel`, so the script writes down every argument after its own,
//! the registration's variable and Gemini CLI's variable.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a session created with the integrations on launches each stand-in through its backend; one created before they were on runs each command exactly as typed |
//! | KR-REQ-12.18 | `claude` gets Claude Code's released channel flag and its plugin |
//! | KR-REQ-12.20 | `gemini` gets `GEMINI_CLI_NO_RELAUNCH=true` and no flag |
//! | KR-REQ-12.22 | `qodercli` gets Qoder CLI's two released elements |
//! | KR-REQ-07.45 | the doctor names the three integrations, on, in the mode an integrated launch runs in |
//!
//! It shows what the host adds and exports through the committed route, not what a vendor agent
//! does with it: no hook, channel or thread selection runs in a stand-in.
//!
//! # Inputs
//!
//! [`GENERATION_VARIABLE`] names the signed catalogue generation the packages are installed from:
//! the development generation of the plugins repository, which publishes them. Without it the test
//! says `skipping:` and returns; [`REQUIRE_VARIABLE`] set to `1` turns that into a failure. The
//! managed shell is the package `KR_SHELL_PACKAGES` names, as for the cases.
//!
//! ```text
//! KR_AGENTS_GENERATION=<generation> KR_SHELL_PACKAGES=<prefix> \
//!     cargo test -p kr-e2e-agents --test integration -- --test-threads=1
//! ```

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_e2e_agents::keychain::RunKeychain;
use kr_e2e_agents::stage::{
    Context, Installation, Owner, PROMPT, Session, closed_port, enrol_generation, install_package,
    open_session, place_forwarder, prepare_home, runtime, session_variables,
};
use kr_e2e_agents::{GENERATION_VARIABLE, REQUIRE_VARIABLE};
use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::host::{Host, HostOptions};
use kr_e2e_m1b::run::Run;
use kr_e2e_m1b::shells;

/// The three packages, each with the command its integration resolves.
const PACKAGES: [(&str, &str); 3] = [
    ("kalareach/claude-code", "claude"),
    ("kalareach/gemini-cli", "gemini"),
    ("kalareach/qoder-cli", "qodercli"),
];

/// The argument a stand-in is given after its script, which bash makes its `$0`: everything after
/// it is what the integration added.
const SENTINEL: &str = "kr-sentinel";

/// The generation this run was given, or nothing when it was given none.
fn generation() -> Option<PathBuf> {
    let named = std::env::var_os(GENERATION_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if named.is_none() {
        let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
        assert!(
            !required,
            "{REQUIRE_VARIABLE}=1 and {GENERATION_VARIABLE} names no generation"
        );
        eprintln!("skipping: the command integration: {GENERATION_VARIABLE} names no generation");
    }
    named
}

/// The stand-ins: `bin/<command>` under `prefix`, each a link to bash, which is a native
/// executable a launch can hash and admit.
fn stand_ins(prefix: &Path) {
    let bin = prefix.join("bin");
    std::fs::create_dir_all(&bin).expect("the stand-ins' directory");
    for (_, command) in PACKAGES {
        std::os::unix::fs::symlink("/bin/bash", bin.join(command)).expect("a stand-in");
    }
}

/// What one stand-in wrote down: the arguments after its sentinel, and the two variables.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    added: Vec<String>,
    registration: bool,
    relaunch: Option<String>,
}

/// Types `<command> -c '<script>' kr-sentinel` at the session's prompt, waits for the stand-in's
/// report and for the prompt after it, and returns the report.
fn run_stand_in(session: &Session, command: &str, reports: &Path, name: &str) -> Report {
    let report = reports.join(name);
    let script = format!(
        r#"{{ printf 'sentinel=%s\n' "$0"; for argument in "$@"; do printf 'added=%s\n' "$argument"; done; printf 'registration=%s\n' "${{KR_REGISTRATION:+set}}"; printf 'relaunch=%s\n' "${{GEMINI_CLI_NO_RELAUNCH-unset}}"; }} > {part} && mv {part} {report}"#,
        part = kr_e2e_agents::build::quote(&format!("{}.part", report.display())),
        report = kr_e2e_agents::build::quote(&report.display().to_string()),
    );
    let line = format!(
        "{command} -c {} {SENTINEL}",
        kr_e2e_agents::build::quote(&script)
    );
    session.window.type_text(format!("{line}\r").as_bytes());
    let started = Instant::now();
    let text = loop {
        if let Ok(text) = std::fs::read_to_string(&report) {
            break text;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "{name}: the stand-in wrote no report; the screen is:\n{}",
            session.window.screen().join("\n")
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = session
        .window
        .wait_for_screen(PROMPT.trim_end(), "the prompt after the stand-in");
    let mut sentinel = None;
    let mut added = Vec::new();
    let mut registration = false;
    let mut relaunch = None;
    for row in text.lines() {
        match row.split_once('=') {
            Some(("sentinel", value)) => sentinel = Some(value.to_owned()),
            Some(("added", value)) => added.push(value.to_owned()),
            Some(("registration", value)) => registration = value == "set",
            Some(("relaunch", value)) => {
                relaunch = (value != "unset").then(|| value.to_owned());
            }
            _ => {}
        }
    }
    assert_eq!(
        sentinel.as_deref(),
        Some(SENTINEL),
        "{name}: the stand-in ran the typed script: {text}"
    );
    Report {
        added,
        registration,
        relaunch,
    }
}

/// What one released integration adds: its flags, and its variables as names and values.
struct Declared {
    flags: Vec<String>,
    variables: Vec<(String, String)>,
}

/// What each released integration adds, by its command, from the packages' own manifests in the
/// generation.
fn declared(copy: &Path) -> BTreeMap<String, Declared> {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(copy.join("targets/index.json")).expect("the generation's index"),
    )
    .expect("the index is JSON");
    let mut declared = BTreeMap::new();
    for (package, command) in PACKAGES {
        let entry = index["entries"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["plugin_id"] == package))
            .unwrap_or_else(|| panic!("the generation's index names {package}"));
        let (_, name) = package.split_once('/').expect("publisher and name");
        let manifest_path = copy
            .join("targets/packages/kalareach")
            .join(name)
            .join(entry["version"].as_str().expect("a version"))
            .join("plugin.json");
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&manifest_path)
                .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display())),
        )
        .expect("the manifest is JSON");
        let integration = &manifest["command_integration"];
        assert_eq!(integration["command"], command, "{package}");
        let flags = integration["flags"]
            .as_array()
            .expect("the flags")
            .iter()
            .map(|flag| flag.as_str().expect("a flag").to_owned())
            .collect();
        let variables = integration["variables"]
            .as_array()
            .expect("the variables")
            .iter()
            .map(|variable| {
                (
                    variable["name"].as_str().expect("a name").to_owned(),
                    variable["value"].as_str().expect("a value").to_owned(),
                )
            })
            .collect();
        declared.insert(command.to_owned(), Declared { flags, variables });
    }
    declared
}

/// KR-REQ-12.07, KR-REQ-12.18, KR-REQ-12.20, KR-REQ-12.22, KR-REQ-07.45: a session created with
/// the three integrations on launches each stand-in through the command, flags and variables its
/// package declares, with the registration there when it runs; a session created before they were
/// on runs each command exactly as it was typed, with neither; and the doctor names the three.
#[test]
fn a_session_created_with_the_integrations_on_launches_through_them_and_one_created_before_does_not()
 {
    let Some(generation) = generation() else {
        return;
    };
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: the command integration: {why}");
            return;
        }
    };
    let runtime = runtime();
    let run = Run::start("command integration");
    // Before anything starts in the run's home: a keychain of its own, its default there.
    let keychain = RunKeychain::create(&run.home());
    place_forwarder(&run);
    let host = Host::start(
        &run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );
    let owner = Owner::pair(&host, &runtime);
    let copy = enrol_generation(&host, &owner, &runtime, &generation);
    for (package, _) in PACKAGES {
        let installed = install_package(&host, &owner, &runtime, &copy, package);
        assert!(
            installed
                .grant
                .iter()
                .any(|capability| capability == "command_integration.launch"),
            "{package} is installed with its integration's grant: {:?}",
            installed.grant
        );
    }
    let declared = declared(&copy);

    let prefix = run.root().join("stand-ins");
    stand_ins(&prefix);
    let _installation = Installation::link(&run, &prefix, &[]);
    let variables = session_variables(&host, &shell, &BTreeMap::new(), closed_port());
    prepare_home(&host, &variables);
    let reports = run.root().join("reports");
    std::fs::create_dir_all(&reports).expect("a directory for the reports");

    let before = open_session(
        &host,
        &owner,
        &runtime,
        &shell,
        &variables,
        "a session created before the integrations are on",
        Context::Headless,
    );
    for (package, _) in PACKAGES {
        let _ = host.kr_json(&["plugin", "integration", "enable", package]);
    }
    let after = open_session(
        &host,
        &owner,
        &runtime,
        &shell,
        &variables,
        "a session created with the integrations on",
        Context::Headless,
    );

    for (_, command) in PACKAGES {
        let Declared { flags, variables } = &declared[command];
        let integrated = run_stand_in(&after, command, &reports, &format!("{command}-on"));
        assert_eq!(
            integrated.added, *flags,
            "{command} runs with the flags its package declares, after the typed words"
        );
        assert!(
            integrated.registration,
            "{command} runs under its launch's registration"
        );
        assert_eq!(
            integrated.relaunch,
            variables
                .iter()
                .find(|(name, _)| name == "GEMINI_CLI_NO_RELAUNCH")
                .map(|(_, value)| value.clone()),
            "{command} runs with the variables its package declares"
        );

        let typed = run_stand_in(&before, command, &reports, &format!("{command}-before"));
        assert_eq!(
            typed,
            Report {
                added: Vec::new(),
                registration: false,
                relaunch: None,
            },
            "{command} in a session created before the integration was on runs as typed"
        );
    }

    // The doctor names the three, on, and in the mode an integrated launch runs in.
    let diagnosed = host.kr(&["doctor", "--json"]);
    let document: serde_json::Value =
        serde_json::from_slice(&diagnosed.stdout).expect("the doctor prints one document");
    let integrations = document["doctor"]["command_integrations"]
        .as_array()
        .unwrap_or_else(|| panic!("the doctor names the integrations: {document}"));
    for (package, command) in PACKAGES {
        let reported = integrations
            .iter()
            .find(|report| report["plugin_id"] == package)
            .unwrap_or_else(|| panic!("the doctor names {package}: {document}"));
        assert_eq!(reported["command"], command, "{package}");
        assert_eq!(reported["state"], "on", "{package}: {reported}");
        assert_eq!(reported["mode"], "native_bridge", "{package}: {reported}");
    }

    for session in [&before, &after] {
        session.remote.close();
    }
    owner.close(&runtime);
    host.stop()
        .unwrap_or_else(|why| panic!("the host did not stop cleanly: {why}"));
    for mut session in [before, after] {
        let _ = session.window.exit_code(LIVENESS);
    }
    let checked = run
        .closing_check()
        .unwrap_or_else(|left| panic!("still running after the command integration: {left}"));
    println!("{checked}");
    drop(keychain);
}
