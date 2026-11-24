//! The stand-in service manager, as the service-start suite holds it: the program that stands in
//! the place of `launchctl` for a host that must reach no launchd of the account, the calls it
//! recorded, and the job it keeps.
//!
//! A host on the stand-in installs and starts the daemon through it, and every command the host
//! itself puts to the manager (what it asks of the job, how its teardown ends the daemon) is the
//! stand-in's too. The one function that builds a command here is [`StandIn::command`].

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_ipc::testing::manager_stand_in::VARIABLE;
use serde_json::Value;

/// One call the stand-in answered, as it recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The program that made it, by its file name.
    pub caller: String,
    /// The arguments exactly as given.
    pub arguments: Vec<String>,
    /// What it exited with.
    pub status: i64,
}

impl Call {
    /// The arguments as one line, which is how a failed case shows a call.
    pub fn line(&self) -> String {
        format!(
            "{} {} -> {}",
            self.caller,
            self.arguments.join(" "),
            self.status
        )
    }

    /// Whether the call changes what the manager holds: any verb other than `print`.
    pub fn changes_the_manager(&self) -> bool {
        self.arguments.first().is_some_and(|verb| verb != "print")
    }
}

/// The stand-in program of one installation, and the folders of the tree it serves.
pub struct StandIn {
    program: PathBuf,
    installation: PathBuf,
    state_root: PathBuf,
    home: PathBuf,
    uid: u32,
}

impl StandIn {
    /// The stand-in at the top of `installation`, serving the tree whose state root is
    /// `state_root` and whose home is `home`.
    pub fn new(installation: &Path, state_root: &Path, home: &Path) -> Self {
        Self {
            program: installation.join(kr_ipc::testing::manager_stand_in::PROGRAM_NAME),
            installation: installation.to_path_buf(),
            state_root: state_root.to_path_buf(),
            home: home.to_path_buf(),
            uid: kr_ipc::paths::current_uid(),
        }
    }

    /// The user the stand-in's domains are the domains of.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Gives `command`, which is a `kr` of this host, what makes it reach the stand-in and nothing
    /// else: the variable that names it, no ask for the account's own launchd, and the stand-in's
    /// installation as its working directory.
    pub fn give_to(&self, command: &mut Command) {
        kr_ipc::testing::account_launchd::pass_the_ask_from(command, None);
        command.env(VARIABLE, &self.program);
        command.current_dir(&self.installation);
    }

    /// The stand-in run with `arguments`, as a program of this host runs it: a cleared
    /// environment, the tree's home and state directory.
    pub fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", &self.home)
            .env(kr_ipc::paths::STATE_DIR_VARIABLE, &self.state_root)
            .stdin(std::process::Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        command
    }

    fn store(&self) -> PathBuf {
        self.state_root.join("manager-stand-in")
    }

    /// Every call recorded so far, in the order the stand-in answered them.
    pub fn calls(&self) -> Vec<Call> {
        let text = std::fs::read_to_string(self.store().join("calls.jsonl")).unwrap_or_default();
        text.lines()
            .map(|line| {
                let call: Value = serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("a call log line is JSON: {line}: {error}"));
                Call {
                    caller: Path::new(call["caller"]["program"].as_str().unwrap_or_default())
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    arguments: call["arguments"]
                        .as_array()
                        .map(|words| {
                            words
                                .iter()
                                .map(|word| word.as_str().unwrap_or_default().to_owned())
                                .collect()
                        })
                        .unwrap_or_default(),
                    status: call["status"].as_i64().unwrap_or(-1),
                }
            })
            .collect()
    }

    /// The calls as lines, for what a failed case says.
    pub fn log(&self) -> String {
        self.calls()
            .iter()
            .map(Call::line)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// What the stand-in keeps of the job `label`, while it is loaded.
    pub fn job(&self, label: &str) -> Option<Value> {
        let text = std::fs::read_to_string(self.store().join("jobs").join(format!("{label}.json")))
            .ok()?;
        Some(serde_json::from_str(&text).expect("a job record is JSON"))
    }
}
