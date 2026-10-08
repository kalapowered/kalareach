//! Running a package's launch probe, and what a launch does with the mode it reads.
//!
//! A package can declare how to read the mode its application will run in: the application's own
//! diagnostic, run before a launch with the options of the launch that decide which configuration
//! it reads. The probe is a program the package chose, run on this host, so what it may cost is
//! bounded: no input, no shell, a deadline, a cap on what it prints, and a job (a process group)
//! that ends with it, so nothing it started outlives the answer. The stand-in for the application
//! is a real program the platform has: `sh` on Unix and Windows PowerShell on Windows, each given
//! the script a test needs.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.64 | The mode is read from what the program prints, and a nonzero exit status does not change that; the program runs in the launch's directory with no input; one that prints too much or never finishes records no mode and is ended with everything it started; one that cannot start says so; a launch records the mode its package's probe read in its profile, and a probe the installation did not grant is not run; in a Windows service session a launch whose mode is refused there, or unknown because its probe did not finish in time for a package that refuses a mode there, is a named failure and starts nothing, and a probe that finished with no mode in it is not stopped |

use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_plugin_sdk::launch_probe::LaunchProbe;
use kr_worker::broker::probe::{self, Probed};

mod common;

use common::LIVENESS_DEADLINE;

/// How long a probe is given in the tests that do not test the deadline.
const GENEROUS: Duration = Duration::from_secs(60);

/// How long a launch waits for its probe in the cases that decide by the mode the stand-in prints.
///
/// The stand-in is a program the machine may be slow to start, so these cases wait for it as long
/// as the others here do, and a probe that is late is not one they would take for a probe that
/// printed nothing.
const WAITING: Duration = GENEROUS;

/// One platform's stand-in for the application: the program and the arguments that run `script`.
struct Standin {
    program: PathBuf,
    arguments: Vec<String>,
    /// The modes its package says it cannot run with in a Windows service session.
    refused: Vec<String>,
}

/// Windows PowerShell reads a script it is given encoded as base64 of its UTF-16 text, which
/// carries no quotation or escaping for the command line to disturb.
#[cfg(windows)]
fn encoded(script: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let word = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                text.push(char::from(
                    ALPHABET[(word >> (18 - 6 * index) & 63) as usize],
                ));
            } else {
                text.push('=');
            }
        }
    }
    text
}

impl Standin {
    /// A program that runs the script written for this platform.
    #[cfg(unix)]
    fn running(unix: &str, _windows: &str) -> Self {
        Self {
            program: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_owned(), unix.to_owned()],
            refused: vec!["elevated".to_owned()],
        }
    }

    #[cfg(windows)]
    fn running(_unix: &str, windows: &str) -> Self {
        Self {
            program: Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
                .join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
            arguments: [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
            ]
            .iter()
            .map(|argument| (*argument).to_owned())
            .chain(std::iter::once(encoded(windows)))
            .collect(),
            refused: vec!["elevated".to_owned()],
        }
    }

    /// The same program, for a package that refuses no mode in a service session.
    fn refusing_nothing(mut self) -> Self {
        self.refused.clear();
        self
    }

    /// The probe a package declares for it: its own arguments, and the mode at `/mode`.
    fn probe(&self, carried: &[&str]) -> LaunchProbe {
        LaunchProbe {
            arguments: self.arguments.clone(),
            carried_options: carried.iter().map(|option| (*option).to_owned()).collect(),
            mode: "/mode".to_owned(),
            refused_in_service_session: self.refused.clone(),
            grant_statement: kr_plugin_sdk::text::Summary::new("Reads the mode for a launch")
                .expect("a literal summary"),
        }
    }

    fn run(&self, directory: &Path) -> Probed {
        probe::run_within(
            &self.program,
            &self.probe(&[]),
            &[],
            directory,
            GENEROUS,
            probe::MAX_OUTPUT_BYTES,
        )
    }
}

fn directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("a directory")
}

/// KR-REQ-07.64: the mode is what the program prints at the declared pointer, and an application's
/// diagnostic exits nonzero for a problem it reports in that output, so the exit status is not the
/// answer.
#[test]
fn kr_req_07_64_the_mode_is_read_from_what_the_program_prints_whatever_it_exits_with() {
    let standin = Standin::running(
        r#"printf '{"mode":"elevated"}'; exit 1"#,
        r#"[Console]::Out.Write('{"mode":"elevated"}'); exit 1"#,
    );
    let probed = standin.run(directory().path());
    assert_eq!(probed.mode.as_deref(), Some("elevated"), "{probed:?}");
    assert_eq!(probed.unread, None);
}

/// KR-REQ-07.64: the program runs in the directory the launch runs in and is given no input, so a
/// diagnostic that reads its input is at the end of it and never waits for one.
#[test]
fn kr_req_07_64_the_program_runs_in_the_launch_directory_and_is_given_no_input() {
    let here = directory();
    let name = here
        .path()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("a name")
        .to_owned();
    let standin = Standin::running(
        r#"read line; printf '{"mode":"%s|%s"}' "$(basename "$PWD")" "${line:-end}""#,
        r#"$line = [Console]::In.ReadLine(); if ($null -eq $line) { $line = 'end' }; [Console]::Out.Write('{"mode":"' + (Split-Path -Leaf $PWD) + '|' + $line + '"}')"#,
    );
    let probed = standin.run(here.path());
    assert_eq!(probed.mode, Some(format!("{name}|end")), "{probed:?}");
}

/// KR-REQ-07.64: what the program prints that the declaration cannot read records no mode and says
/// why: not JSON, and a string that is not a mode.
#[test]
fn kr_req_07_64_output_the_declaration_cannot_read_records_no_mode() {
    let not_json = Standin::running("printf 'not json'", "[Console]::Out.Write('not json')");
    let probed = not_json.run(directory().path());
    assert_eq!(probed.mode, None);
    assert!(probed.unread.is_some(), "{probed:?}");
    assert!(
        !probed.late,
        "it answered, with nothing a mode can be read from"
    );
    let not_a_string = Standin::running(
        r#"printf '{"mode":7}'"#,
        r#"[Console]::Out.Write('{"mode":7}')"#,
    );
    assert_eq!(not_a_string.run(directory().path()).mode, None);
}

/// KR-REQ-07.64: a program that prints more than the cap records no mode and is not read further.
#[test]
fn kr_req_07_64_a_program_that_prints_more_than_the_cap_records_no_mode() {
    let standin = Standin::running(
        r"head -c 20000 /dev/zero | tr '\0' x",
        "[Console]::Out.Write('x' * 20000)",
    );
    let probed = probe::run_within(
        &standin.program,
        &standin.probe(&[]),
        &[],
        directory().path(),
        GENEROUS,
        1000,
    );
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("more than 1000 bytes")),
        "{probed:?}"
    );
    assert!(!probed.late, "it printed, and printed too much");
}

/// The process identifier a stand-in wrote to `file` in `directory`, once it has written all of it.
fn written_pid(directory: &Path, file: &str) -> Option<u32> {
    std::fs::read_to_string(directory.join(file))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// KR-REQ-07.64: a program that never finishes is ended when its deadline passes, with what it
/// started, and records no mode. Neither the program nor its child is left running.
///
/// The deadline has to pass after the program has started what it starts, and how soon it does that
/// is the machine's to say. So the probe is given a longer deadline, up to `GENEROUS`, each time
/// the program is found not to have started it yet, and what is decided is the state of the
/// processes once a probe that the program was running in has been ended.
#[test]
fn kr_req_07_64_a_program_that_never_finishes_is_ended_with_everything_it_started() {
    let mut deadline = if cfg!(windows) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(3)
    };
    let (here, probed) = loop {
        let here = directory();
        let standin = Standin::running(
            r#"echo $$ > main.pid; sleep 600 & echo $! > child.pid; wait"#,
            r#"$PID | Out-File -Encoding ascii main.pid; $child = Start-Process "$env:SystemRoot\System32\ping.exe" -ArgumentList '-n','600','127.0.0.1' -PassThru -WindowStyle Hidden; $child.Id | Out-File -Encoding ascii child.pid; Start-Sleep 600"#,
        );
        let probed = probe::run_within(
            &standin.program,
            &standin.probe(&[]),
            &[],
            here.path(),
            deadline,
            probe::MAX_OUTPUT_BYTES,
        );
        if ["main.pid", "child.pid"]
            .iter()
            .all(|file| written_pid(here.path(), file).is_some())
        {
            break (here, probed);
        }
        assert!(
            deadline < GENEROUS,
            "the program had not started what it starts within {deadline:?}: {probed:?}"
        );
        deadline = (deadline * 2).min(GENEROUS);
    };
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("did not finish")),
        "{probed:?}"
    );
    assert!(probed.late, "a probe that never finishes is late");
    for file in ["main.pid", "child.pid"] {
        let pid = written_pid(here.path(), file).expect("a process identifier");
        let started = std::time::Instant::now();
        while kr_ipc::identity::process_start_identity(pid).is_ok() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "process {pid} ({file}) outlived the probe"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// KR-REQ-07.64: a program that cannot be started says so, by what it was.
#[test]
fn kr_req_07_64_a_program_that_cannot_start_records_no_mode_and_says_so() {
    let standin = Standin::running("true", "exit 0");
    let missing = directory().path().join("no-such-application");
    let probed = probe::run_within(
        &missing,
        &standin.probe(&[]),
        &[],
        directory().path(),
        GENEROUS,
        probe::MAX_OUTPUT_BYTES,
    );
    assert_eq!(probed.mode, None);
    assert!(
        probed
            .unread
            .as_deref()
            .is_some_and(|why| why.contains("could not be started")),
        "{probed:?}"
    );
    assert!(!probed.late, "it never ran, so it was not late");
}

// ---------------------------------------------------------------------------------------------
// A launch and the mode its package's probe reads.

mod launch {
    use std::sync::Arc;

    use kr_protocol::broker::{
        AgentOwnership, AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile,
    };
    use kr_protocol::gateway::NativeFraming;
    use kr_protocol::ids::{
        ApplicationInstanceId, EnvironmentId, LaunchProfileId, PluginId, SessionId,
    };
    use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
    use kr_worker::broker::{Broker, BrokerError, Framing, NativeGateway, NativeLaunch};
    use kr_worker::persistence::JournalHealth;

    use super::Standin;

    fn profile(program: &std::path::Path, arguments: &[String]) -> LaunchProfile {
        LaunchProfile {
            profile_id: LaunchProfileId::new("lp-1").expect("valid"),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            binary: BinaryIdentity {
                resolved_path: program.to_string_lossy().into_owned(),
                digest: Digest256::from_bytes([3; 32]),
                version: "1".to_owned(),
                distribution: "build".to_owned(),
            },
            arguments: arguments.to_vec(),
            authentication: AuthenticationState::Authenticated,
            mode: IntegrationMode::Gateway,
            ownership: AgentOwnership::Full,
            vendor_mode: Nullable::null(),
            resolved_at: TimestampMs::new(1),
        }
    }

    /// What a launch of one stand-in came to.
    pub struct Attempt {
        /// The profile the launch recorded, or what it refused.
        pub outcome: Result<LaunchProfile, BrokerError>,
        /// Whether the launch started the agent's process.
        pub started: bool,
    }

    /// What a launch of `standin` as the agent, with its package's probe given `probe_deadline`
    /// where there is one, records and refuses. The launch is in whichever kind of session this
    /// machine is in, unless `service_session` says it is in a service session or not.
    pub fn launch(
        standin: &Standin,
        probe_deadline: Option<std::time::Duration>,
        service_session: Option<bool>,
    ) -> Attempt {
        let directory = tempfile::tempdir().expect("a directory");
        let private = directory.path().join("private");
        kr_ipc::paths::create_private_directory(&private).expect("a private directory");
        let broker = Arc::new(
            Broker::open(
                None,
                SessionId::new(Uuid::from_bytes([1; 16])),
                JournalHealth::shared(),
            )
            .expect("the broker opens"),
        );
        let mut gateway = NativeGateway::bind(
            Arc::clone(&broker),
            &private,
            NativeLaunch {
                profile_id: LaunchProfileId::new("lp-1").expect("valid"),
                expected_process: None,
                native_terminal: None,
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([1; 16])),
                plugin_id: PluginId::new("kalareach/codex").expect("valid"),
                installed_protocol_version: "1".to_owned(),
                framing: Framing::new(NativeFraming::JsonLines),
                site: EnvironmentId::new(Uuid::from_bytes([4; 16])),
                os_user: "agent-user".to_owned(),
                working_directory: directory.path().to_path_buf(),
            },
        )
        .expect("the endpoint binds");
        #[cfg(windows)]
        let session = Arc::new(kr_worker::windows::job::SessionJob::create().expect("a job"));
        #[cfg(windows)]
        {
            gateway = gateway.in_session(Arc::clone(&session));
        }
        if let Some(in_service_session) = service_session {
            gateway = gateway.with_service_session(in_service_session);
        }
        if let Some(deadline) = probe_deadline {
            gateway = gateway
                .with_launch_probe(standin.probe(&[]))
                .with_probe_deadline(deadline);
        }
        let intent = broker
            .prepare_launch(
                profile(&standin.program, &standin.arguments),
                kr_worker::broker::ForegroundMark::idle(4),
                None,
            )
            .expect("the launch is prepared");
        let launched = gateway.launch(
            &intent,
            &kr_worker::broker::ForegroundMark::idle(4),
            IntegrationMode::Gateway,
            TimestampMs::new(1),
        );
        let started = gateway.last_started().is_some();
        let outcome = match launched {
            Ok(mut launched) => {
                // The agent is a program that has printed what the probe reads and will go on to
                // end by itself; what matters here is the profile its launch recorded.
                let _ = launched.child.kill();
                let _ = launched.child.wait();
                #[cfg(windows)]
                let _ = session.terminate(1);
                let recorded = broker
                    .profile_of(ApplicationInstanceId::new(Uuid::from_bytes([1; 16])))
                    .expect("the launch's profile is recorded");
                assert_eq!(recorded, launched.profile, "what is recorded is what ran");
                Ok(launched.profile)
            }
            Err(error) => Err(error),
        };
        Attempt { outcome, started }
    }
}

/// KR-REQ-07.64: a launch whose package declares a probe records the mode the probe read in its
/// profile, and one whose installation did not grant the probe runs none and records none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_launch_records_the_mode_its_probe_read_and_a_probe_not_granted_is_not_run()
{
    let standin = Standin::running(
        r#"printf '{"mode":"disabled"}'"#,
        r#"[Console]::Out.Write('{"mode":"disabled"}')"#,
    );
    let probing = launch::launch(&standin, Some(WAITING), None)
        .outcome
        .expect("the launch goes ahead");
    assert_eq!(probing.vendor_mode.0.as_deref(), Some("disabled"));
    let without = launch::launch(&standin, None, None)
        .outcome
        .expect("the launch goes ahead");
    assert_eq!(
        without.vendor_mode.0, None,
        "a probe nobody gave the gateway is not run"
    );
}

/// Whether this worker runs in a Windows service session, as the launch itself reads it.
fn in_service_session() -> bool {
    #[cfg(windows)]
    {
        kr_ipc::starter::current_session().is_ok_and(|session| session == 0)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// KR-REQ-07.64: a mode the package refuses in a service session is a named launch failure where
/// this worker runs in one and starts nothing, and a launch otherwise: the same program and the
/// same probe, with the session this test runs in deciding which.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_refused_mode_is_a_named_failure_in_a_service_session_and_a_launch_elsewhere()
 {
    let standin = Standin::running(
        r#"printf '{"mode":"elevated"}'"#,
        r#"[Console]::Out.Write('{"mode":"elevated"}')"#,
    );
    let attempt = launch::launch(&standin, Some(WAITING), None);
    if in_service_session() {
        let error = attempt
            .outcome
            .expect_err("a refused mode is a named failure here");
        assert!(
            matches!(&error, kr_worker::broker::BrokerError::PreconditionFailed { detail }
                if detail.contains("elevated") && detail.contains("service session")),
            "{error:?}"
        );
        assert!(!attempt.started, "nothing was started");
    } else {
        let profile = attempt
            .outcome
            .expect("the mode is not refused in this session");
        assert_eq!(profile.vendor_mode.0.as_deref(), Some("elevated"));
    }
}

/// KR-REQ-07.64: a launch whose probe does not finish records no mode, and its mode is unknown. In
/// a service session, for a package that refuses some mode there, it may be that mode, so the
/// launch is a named failure and starts nothing, whatever the application had printed before it
/// stopped finishing; elsewhere, or for a package that refuses none, the launch goes ahead, and
/// the application's own sandbox is left as it is: nothing is disabled and nothing is let out of
/// the job. A probe that finished and printed nothing a mode can be read from is an answer, and
/// the launch goes ahead in a service session too. The stand-ins that never finish never print
/// either, so these cases decide by that and not by how soon the deadline passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_launch_whose_probe_does_not_finish_is_a_named_failure_in_a_service_session()
{
    let silent = || Standin::running("exec sleep 600", "Start-Sleep -Seconds 600");
    let deadline = Some(Duration::from_secs(1));

    let attempt = launch::launch(&silent(), deadline, Some(true));
    let error = attempt
        .outcome
        .expect_err("a mode that is unknown may be a refused one in a service session");
    assert!(
        matches!(&error, kr_worker::broker::BrokerError::PreconditionFailed { detail }
            if detail.contains("service session")),
        "{error:?}"
    );
    assert!(!attempt.started, "nothing was started");

    // An answer that was printed but not finished is not used.
    let printed_and_stalled = Standin::running(
        r#"printf '{"mode":"disabled"}'; exec sleep 600"#,
        r#"[Console]::Out.Write('{"mode":"disabled"}'); Start-Sleep -Seconds 600"#,
    );
    let attempt = launch::launch(&printed_and_stalled, deadline, Some(true));
    assert!(
        attempt.outcome.is_err(),
        "an unfinished answer is no answer"
    );
    assert!(!attempt.started, "nothing was started");

    // Elsewhere the same probe records no mode and the launch goes ahead.
    let profile = launch::launch(&silent(), deadline, Some(false))
        .outcome
        .expect("a probe that does not finish does not stop the launch outside a service session");
    assert_eq!(profile.vendor_mode.0, None);

    // A package that refuses no mode has nothing an unknown mode could be, in any session.
    let profile = launch::launch(&silent().refusing_nothing(), deadline, Some(true))
        .outcome
        .expect("a package that refuses no mode is not stopped by a probe that does not finish");
    assert_eq!(profile.vendor_mode.0, None);

    // A probe that finished is an answer, whether or not a mode can be read from it.
    let unreadable = Standin::running("printf 'not json'", "[Console]::Out.Write('not json')");
    let profile = launch::launch(&unreadable, Some(WAITING), Some(true))
        .outcome
        .expect("an application that answered with no mode does not stop the launch");
    assert_eq!(profile.vendor_mode.0, None);
}
