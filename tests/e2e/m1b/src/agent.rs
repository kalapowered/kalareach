//! The agent a session runs: the scripted agent the local path's demonstration uses, unchanged.
//!
//! It is a small shell program standing in for a coding agent. It starts `kr agent-tools --stdio`
//! as its own child, asks its person one question with `ask_user`, waits on it with
//! `wait_for_answer`, and then acts only when one of its two gates opens, so nothing it does runs
//! on a clock of its own. Here each gate is the agent's own terminal: `go-on` and `finish` beside
//! it name `/dev/tty`, so a gate opens when a line is typed into the session while the agent holds
//! the foreground, which is what typing into an agent is. The device types those lines, holding the
//! input lease.

use std::path::{Path, PathBuf};

use crate::host::{Host, quoted};
use crate::run::Run;

/// The scripted agent, as the local path's demonstration ships it.
pub const SCRIPTED_AGENT: &str =
    include_str!("../../../../crates/kr-cli/tests/support/scripted_agent.sh");

/// What the agent prints once it has asked.
pub const ASKED: &str = "the agent asked question";

/// What the agent prints once it has been answered, before the answer.
pub const ANSWERED: &str = "the agent was answered: ";

/// What the agent prints after its first gate opened.
pub const WENT_ON: &str = "the screen as it is now";

/// The line the agent erases again before it goes on.
pub const ERASED: &str = "a line the screen no longer shows";

/// What the agent prints as it ends, with its tool server's status after it.
pub const ENDED: &str = "the tool server exited with status ";

/// One placed agent.
#[derive(Clone, Debug)]
pub struct Agent {
    directory: PathBuf,
    program: String,
}

impl Agent {
    /// Places an agent in a directory of its own under the run's working directory, with its tool
    /// configuration naming `kr` and the host, and its two gates naming its own terminal.
    ///
    /// # Panics
    ///
    /// Panics when a file cannot be written.
    #[must_use]
    pub fn place(run: &Run, host: &Host<'_>, name: &str) -> Self {
        Self::place_as(run, host, name, "agent")
    }

    /// Places an agent the same way under the program name `program`, which is what an
    /// application's match rules see.
    ///
    /// # Panics
    ///
    /// Panics when a file cannot be written.
    #[must_use]
    pub fn place_as(run: &Run, host: &Host<'_>, name: &str, program: &str) -> Self {
        let directory = run.work().join(name);
        kr_ipc::paths::create_private_tree(run.root(), &directory).expect("the agent's directory");
        // Written aside as text and placed by a process of its own, so that no child this process
        // starts meanwhile holds the agent open for writing when the session's shell starts it.
        let text = directory.join(format!("{program}.text"));
        std::fs::write(&text, SCRIPTED_AGENT).expect("writes the agent");
        kr_ipc::testing::place_program(&text, &directory.join(program));
        std::fs::write(
            directory.join("agent.conf"),
            format!(
                "kr={}\nkr_runtime_dir={}\nkr_state_dir={}\n",
                quoted(&run.binary("kr")),
                quoted(host.roots().runtime_root()),
                quoted(host.roots().state_root()),
            ),
        )
        .expect("writes the agent's tool configuration");
        for gate in ["go-on", "finish"] {
            std::os::unix::fs::symlink("/dev/tty", directory.join(gate))
                .expect("points the gate at the agent's own terminal");
        }
        Self {
            directory,
            program: program.to_owned(),
        }
    }

    /// The agent's program.
    #[must_use]
    pub fn program(&self) -> PathBuf {
        self.directory.join(&self.program)
    }

    /// The command line that starts it at a prompt and says how it ended, marked with `name`.
    #[must_use]
    pub fn command_line(&self, name: &str) -> String {
        format!(
            "{} ; printf '{name}-%s-%s\\n' ended \"$?\"\r",
            quoted(&self.program())
        )
    }

    /// The process identifier the agent recorded for itself, once it has.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        read_number(&self.directory.join("agent.pid"))
    }

    /// The process identifier of the agent's tool server, once the agent has recorded it.
    #[must_use]
    pub fn tools_pid(&self) -> Option<u32> {
        read_number(&self.directory.join("tools.pid"))
    }

    /// The tool server's answer to `ask_user`, once the agent has kept it.
    #[must_use]
    pub fn asked(&self) -> Option<serde_json::Value> {
        read_document(&self.directory.join("asked.json"))
    }

    /// The tool server's answer to the wait that returned the person's answer, once kept.
    #[must_use]
    pub fn answered(&self) -> Option<serde_json::Value> {
        read_document(&self.directory.join("answered.json"))
    }
}

fn read_number(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_document(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}
