//! The shell a Windows session starts when it names none, against a real daemon and a real worker.
//!
//! `kr new` with no `--shell` and the native-compatible mode starts the host's default shell: the
//! worker resolves it, launches it in a pseudo-console, and the test types into the session and
//! reads which shell answered.

#![cfg(windows)]

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use windows_session::{WorkerHost, WorkerTerminal};

/// KR-REQ-03.03: a session that names no shell runs PowerShell 7, the Core edition at major
/// version 7, and not the command interpreter the system names or Windows PowerShell 5.1.
///
/// The typed line holds the pieces of what it prints apart, so the pattern waited for is in the
/// shell's output and not in the echo of what was typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_names_no_shell_runs_powershell_seven() {
    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat"])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    typist
        .type_line(
            "Write-Host (\"kr-edition=\" + $PSVersionTable.PSEdition + \" kr-major=\" + \
             $PSVersionTable.PSVersion.Major + \".\")",
        )
        .await;
    typist
        .shown(
            "kr-edition=Core kr-major=7.",
            "the session's shell is PowerShell Core at major version 7",
        )
        .await;
}
