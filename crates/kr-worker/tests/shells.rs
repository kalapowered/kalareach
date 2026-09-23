//! The native worker's Unix pseudo-terminal, with each shell section 3 names as the root shell.
//!
//! Linux and macOS both run Bash, Zsh and Fish on this worker's Unix pseudo-terminal. Each test
//! here starts one of them, as this machine has it installed, as a session's root shell with no
//! startup files of the user's, and uses it the way a person at a terminal does: the shell knows it
//! is interactive and on a terminal, a command typed at it runs and its output comes back through
//! the session, and the shell's own `exit` ends the session with the shell's own status.
//!
//! A shell is the first of its name on this test's own `PATH`, and otherwise in the standard
//! install directories, and the test prints which one it ran. A shell this machine does not have
//! is reported in the test's output rather than tested. A machine that must have a shell says so
//! in `KR_REQUIRE_SHELLS` (for example `bash,zsh,fish`), and a missing shell it names is a
//! failure.
//!
//! Everything the shells touch is on the internal disk: each one's home directory is inside the
//! test's own temporary host, which is where any history a shell writes goes.

#![cfg(unix)]

mod common;

use std::path::PathBuf;

use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, ConnectionId, SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::session::{Session, SessionConfig};

/// Where a shell may be installed, after this test's own `PATH`.
const LOCATIONS: &[&str] = &["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"];

/// Returns the installed shell of this name, if the machine has one.
fn installed(name: &str) -> Option<PathBuf> {
    let searched = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    searched
        .into_iter()
        .chain(LOCATIONS.iter().map(PathBuf::from))
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

/// Returns true when this machine must have the named shell.
fn required(name: &str) -> bool {
    std::env::var("KR_REQUIRE_SHELLS")
        .is_ok_and(|names| names.split(',').any(|required| required.trim() == name))
}

/// Runs one shell as a session's root and drives it.
///
/// `arguments` start it interactively with none of the user's startup files. `probe` is a command
/// in that shell's own syntax which prints `kr-interactive` when the shell knows it is interactive
/// and `kr-terminal` when its standard input is a terminal.
async fn drive(name: &str, arguments: &[&str], probe: &str) {
    let Some(program) = installed(name) else {
        assert!(
            !required(name),
            "{name} is required on this machine and is on neither this test's PATH nor any of \
             {LOCATIONS:?}"
        );
        eprintln!("skipped: {name} is on neither this test's PATH nor any of {LOCATIONS:?}");
        return;
    };
    eprintln!("{name}: {}", program.display());
    let host = kr_ipc::testing::TempHost::create();
    let home = host.root().join("home");
    std::fs::create_dir_all(&home).expect("a home directory on the internal disk");
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: program.display().to_string(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            cwd: home.display().to_string(),
            environment: vec![
                ("TERM".to_owned(), "xterm-256color".to_owned()),
                ("HOME".to_owned(), home.display().to_string()),
                ("PATH".to_owned(), LOCATIONS.join(":")),
                (
                    "XDG_CONFIG_HOME".to_owned(),
                    home.join(".config").display().to_string(),
                ),
                (
                    "XDG_DATA_HOME".to_owned(),
                    home.join(".local/share").display().to_string(),
                ),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the root shell");
    assert_eq!(session.state(), SessionState::Live);

    // A terminal attachment, as a person's terminal attaches, which takes the keys. It declares a
    // terminal that produces both enhanced keyboard encodings, because a shell that turns one on
    // (Fish turns on the Kitty protocol) takes the keys from a terminal that cannot produce it.
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: true,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("ghostty".to_owned()),
                requested: requested.clone(),
            },
            requested,
            attachment_id,
        )
        .expect("attaches");
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the session"),
    );
    let epoch = {
        let mut session = runtime.session();
        session
            .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the input lease");
        session.lease().epoch.get()
    };
    let mut sequence = 0;
    let mut type_line = |line: &str| {
        let mut session = runtime.session();
        session
            .write_input(
                attachment_id,
                epoch,
                sequence,
                format!("{line}\r").as_bytes(),
                None,
                std::time::Instant::now(),
            )
            .expect("the keys reach the shell");
        sequence += 1;
        drop(session);
        runtime.flush_input();
    };

    // The shell knows it is interactive and on a terminal.
    type_line(probe);
    common::produced(&runtime, b"kr-interactive\r\n").await;
    common::produced(&runtime, b"kr-terminal\r\n").await;

    // A command typed at it runs, and what it prints comes back through the session.
    type_line("printf 'kr-%s-%s\\n' typed command");
    common::produced(&runtime, b"kr-typed-command\r\n").await;

    // Its own exit ends the session, with its own status.
    type_line("exit 3");
    let record = tokio::time::timeout(common::LIVENESS_DEADLINE, runtime.wait_closed())
        .await
        .unwrap_or_else(|_| panic!("{name} did not end the session when it exited"));
    assert_eq!(record.reason, ClosureReason::RootExit, "{name}");
    assert_eq!(
        record.root_exit_code.as_ref().map(|code| code.get()),
        Some(3),
        "{name} ended the session with its own status"
    );
    assert_eq!(runtime.state(), SessionState::Closed);
}

/// KR-REQ-03.01, KR-REQ-04.01: Bash runs interactively as the root shell of the Tokio worker's
/// `portable-pty` Unix pseudo-terminal, runs what is typed at it, and ends the session with its
/// own exit status.
#[tokio::test(flavor = "multi_thread")]
async fn bash_runs_interactively_on_the_unix_pseudo_terminal() {
    drive(
        "bash",
        &["--noprofile", "--norc", "-i"],
        "case $- in *i*) printf 'kr-%s\\n' interactive;; esac; [ -t 0 ] && printf 'kr-%s\\n' terminal",
    )
    .await;
}

/// KR-REQ-03.01, KR-REQ-04.01: Zsh runs interactively as the root shell of the Tokio worker's
/// `portable-pty` Unix pseudo-terminal, runs what is typed at it, and ends the session with its
/// own exit status.
#[tokio::test(flavor = "multi_thread")]
async fn zsh_runs_interactively_on_the_unix_pseudo_terminal() {
    drive(
        "zsh",
        &["-f", "-i"],
        "[[ -o interactive ]] && printf 'kr-%s\\n' interactive; [[ -t 0 ]] && printf 'kr-%s\\n' terminal",
    )
    .await;
}

/// KR-REQ-03.01, KR-REQ-04.01: Fish runs interactively as the root shell of the Tokio worker's
/// `portable-pty` Unix pseudo-terminal, runs what is typed at it, and ends the session with its
/// own exit status.
#[tokio::test(flavor = "multi_thread")]
async fn fish_runs_interactively_on_the_unix_pseudo_terminal() {
    drive(
        "fish",
        &["--no-config", "--interactive"],
        "status is-interactive; and printf 'kr-%s\\n' interactive; test -t 0; and printf 'kr-%s\\n' terminal",
    )
    .await;
}
