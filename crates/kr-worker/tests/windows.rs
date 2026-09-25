//! The Windows terminal, run on Windows.
//!
//! Everything here needs a real pseudo-console, a real PowerShell and a real job object, so it
//! exists only on that platform. What it covers, row by row:
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-03.03 | PowerShell 7 is the root shell, inside a pseudo-console this worker owns |
//! | KR-REQ-07.62 | The per-session job object: kill-on-close, breakaway disabled, joined before execution |
//! | KR-REQ-07.63 | A process started outside the job is not held by it and survives its closure; the broker that records it as an external resource is not in this build |
//! | KR-ACC-010 | Resize, draining, the text the console carries, the interrupt, the process tree, and PowerShell itself |
//! | KR-REQ-02.04, KR-REQ-05.02 | Each worker keeps a write-ahead-logged SQLite journal of its own and is reached on a named pipe of its own, whose list is protected and its owner's |
//! | KR-REQ-02.07 | A local caller on a worker's pipe is served as the owner the pipe admits, and the worker still holds it to its own session |
//!
//! Most of these drive the terminal directly rather than through a session, because what is under
//! test is the platform half: the console, the job and the interrupt. The session's own behaviour on
//! top of them is the same code on every platform and is covered by the suites beside this one. The
//! last two host a worker, because what they are about is the worker's own endpoint and journal.

#![cfg(windows)]

use std::io::Read;
use std::time::{Duration, Instant};

use kr_protocol::session::Dimensions;
use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary, boundary_for};
use kr_worker::pty::{Pty, Room, RootShell};
use kr_worker::testing::{powershell, powershell_command};

/// How long a test waits for a shell to say something before it calls that a failure.
///
/// PowerShell 7 is not quick to start, and a build machine under load is slower still, so this is
/// generous. It bounds a wait; it is not a measurement of anything.
const PATIENCE: Duration = Duration::from_secs(60);

/// Reads the terminal until `marker` appears, or until the patience runs out.
///
/// The terminal answers a read with nothing to read rather than waiting inside it, so this waits
/// on the read the reader started, exactly as the worker's own loop does.
fn read_until(pty: &Pty, reader: &mut Box<dyn Read + Send>, marker: &str) -> String {
    let waiter = pty.output_waiter();
    let deadline = Instant::now() + PATIENCE;
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                seen.extend_from_slice(&buffer[..read]);
                if String::from_utf8_lossy(&seen).contains(marker) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                match waiter
                    .as_ref()
                    .map(|waiter| waiter.wait(Duration::from_millis(50)))
                {
                    Some(Room::Gone) => break,
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// Reads everything the terminal has, without looking for anything in particular.
///
/// The bytes are kept as bytes. A read ends where the console's pipe ends it, which is not where a
/// scalar ends, so decoding each read on its own would turn a scalar that straddled a boundary
/// into replacement characters and blame the terminal for the reader's own seam.
fn drain_bytes(pty: &Pty, reader: &mut Box<dyn Read + Send>, patience: Duration) -> Vec<u8> {
    let waiter = pty.output_waiter();
    let deadline = Instant::now() + patience;
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => seen.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(Room::Gone) = waiter
                    .as_ref()
                    .map(|waiter| waiter.wait(Duration::from_millis(50)))
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    seen
}

/// Waits for the shell to end, draining the console while it does.
///
/// A console's output pipe holds what the application has written and this host has not read. An
/// application that writes more than fits, while this host waits for it to exit before reading, is
/// an application blocked in a write and a host blocked in a wait: neither moves again. So the
/// wait reads.
fn drain_until_it_ends(
    pty: &Pty,
    reader: &mut Box<dyn Read + Send>,
    shell: &mut RootShell,
) -> (kr_worker::pty::ShellExit, String) {
    let waiter = pty.output_waiter();
    let deadline = Instant::now() + PATIENCE;
    let mut seen = Vec::new();
    let mut buffer = [0_u8; 4096];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => {}
            Ok(read) => {
                seen.extend_from_slice(&buffer[..read]);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        if let Some(exit) = shell.try_wait().expect("the shell's status") {
            // Whatever it wrote last is still in the console, so the pipe is emptied before the
            // exit is returned.
            seen.extend_from_slice(&drain_bytes(pty, reader, Duration::from_secs(5)));
            return (exit, String::from_utf8_lossy(&seen).into_owned());
        }
        if waiter
            .as_ref()
            .map(|waiter| waiter.wait(Duration::from_millis(50)))
            .is_none()
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    panic!(
        "the shell was still running after {PATIENCE:?}; it had written {} bytes",
        seen.len()
    );
}

/// Reads the identifier the shell printed as `kr-child=<pid>.`
fn named_child(seen: &str) -> u32 {
    seen.split("kr-child=")
        .nth(1)
        .and_then(|rest| rest.split('.').next())
        .and_then(|digits| digits.trim().parse().ok())
        .unwrap_or_else(|| panic!("the shell named the process it started: {seen:?}"))
}

/// Opens a terminal and starts PowerShell 7 running `command` in it.
fn powershell_in_a_console(command: &str) -> (Pty, Box<dyn Read + Send>, RootShell) {
    let mut pty = Pty::open(Dimensions::new(80, 24)).expect("the console opens");
    let reader = pty.reader().expect("a reader");
    let shell = pty
        .launch(&powershell_command(command))
        .expect("PowerShell starts inside the console");
    (pty, reader, shell)
}

#[test]
fn powershell_seven_is_the_shell_that_runs_inside_the_console(/* KR-REQ-03.03 */) {
    // KR-REQ-04.01: the worker's terminal is `portable-pty`'s native backend, which on Windows is
    // a pseudo-console, and a shell runs inside it.
    // The program is asked for by name, so what answers has to be PowerShell 7 rather than the
    // Windows PowerShell 5.1 that `powershell` resolves to.
    let program = powershell();
    assert!(
        program.to_ascii_lowercase().ends_with("pwsh.exe"),
        "{program} is PowerShell 7"
    );

    let (pty, mut reader, mut shell) = powershell_in_a_console(
        "Write-Host -NoNewline \"kr-edition=$($PSVersionTable.PSEdition) \
         kr-major=$($PSVersionTable.PSVersion.Major).\"",
    );
    let seen = read_until(&pty, &mut reader, "kr-major=");
    assert!(
        seen.contains("kr-edition=Core"),
        "the shell in the console is PowerShell Core: {seen:?}"
    );
    assert!(
        seen.contains("kr-major=7"),
        "and its major version is 7: {seen:?}"
    );
    let (exit, _) = drain_until_it_ends(&pty, &mut reader, &mut shell);
    assert_eq!(exit.code, 0, "and it ended of its own accord");
}

#[test]
fn the_console_resizes_and_the_application_reads_the_new_geometry(/* KR-ACC-010 */) {
    // The shell prints its width, waits, and prints it again. Between the two the console is
    // resized, so what the second line says is what the resize actually did to the application's
    // view rather than to this host's record of it.
    let (mut pty, mut reader, mut shell) = powershell_in_a_console(
        "Write-Host \"kr-first=$($Host.UI.RawUI.WindowSize.Width)\"; \
         Start-Sleep -Milliseconds 2500; \
         Write-Host \"kr-second=$($Host.UI.RawUI.WindowSize.Width).\"",
    );
    let first = read_until(&pty, &mut reader, "kr-first=");
    assert!(first.contains("kr-first=80"), "it started at 80: {first:?}");

    pty.resize(Dimensions::new(120, 40)).expect("the resize");
    assert_eq!(pty.dimensions(), Dimensions::new(120, 40));

    let second = read_until(&pty, &mut reader, "kr-second=");
    assert!(
        second.contains("kr-second=120"),
        "the application reads the new width: {second:?}"
    );
    drain_until_it_ends(&pty, &mut reader, &mut shell);
}

#[test]
fn everything_the_application_wrote_is_still_there_to_read_after_it_has_gone(/* KR-ACC-010 */) {
    // The shell writes a lot and exits at once. Draining after its exit has to produce every line:
    // a console whose output was lost with the process would lose a command's last screen every
    // time, which is exactly the failure a person notices.
    let (pty, mut reader, mut shell) =
        powershell_in_a_console("1..200 | ForEach-Object { Write-Host \"kr-line-$_\" }");
    // Drained while it is waited for. A console holds what has been written and not read, and a
    // host that waited for the exit first would be waiting for an application blocked in a write.
    let (exit, seen) = drain_until_it_ends(&pty, &mut reader, &mut shell);
    assert_eq!(exit.code, 0);

    assert!(
        seen.contains("kr-line-1\r\n") || seen.contains("kr-line-1\n"),
        "the first line survived the exit"
    );
    assert!(
        seen.contains("kr-line-200"),
        "and so did the last: the drain produced {} bytes",
        seen.len()
    );
}

/// One of every encoded length UTF-8 has beyond the single byte: three, two, two and four.
const SCALARS: &str = "中éλ🙂";

#[test]
fn text_that_needs_more_than_one_byte_a_character_survives_the_console(/* KR-ACC-010 */) {
    // A console read ends where the pipe ends it, which is nowhere near where a scalar ends, and
    // the run written here is long enough to be read in several pieces. What a person would see if
    // any part of that path decoded a piece on its own is a line of replacement characters, so the
    // check is the whole stream: all eighty lines the shell wrote are present with their scalars
    // intact and nothing anywhere decoded as a replacement. Where a boundary falls is the pipe's
    // choice rather than this test's, which is why the run is long rather than placed.
    let repeated = SCALARS.repeat(8);
    let (pty, mut reader, mut shell) = powershell_in_a_console(&format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); \
         1..80 | ForEach-Object {{ Write-Host \"kr-utf8-$_={repeated}\" }}"
    ));
    let (exit, seen) = drain_until_it_ends(&pty, &mut reader, &mut shell);
    assert_eq!(exit.code, 0);

    assert!(
        !seen.contains(char::REPLACEMENT_CHARACTER),
        "the console's output is valid UTF-8 throughout: {} bytes",
        seen.len()
    );
    for line in 1..=80 {
        assert!(
            seen.contains(&format!("kr-utf8-{line}={repeated}")),
            "line {line} arrived whole: the drain produced {} bytes",
            seen.len()
        );
    }
}

#[test]
fn an_interrupt_reaches_the_application_in_the_console(/* KR-ACC-010 */) {
    // A console has no foreground process group and no signal. What it has is the byte the console
    // turns into a control event, and this checks that the worker's interrupt reaches an
    // application that is asked to report it.
    let (pty, mut reader, mut shell) = powershell_in_a_console(
        "[Console]::TreatControlCAsInput = $false; \
         $null = [Console]::CancelKeyPress.GetType(); \
         Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress \
             -Action { Write-Host -NoNewline 'kr-interrupted.'; $global:kr = $true } | Out-Null; \
         Write-Host -NoNewline 'kr-waiting.'; \
         $deadline = (Get-Date).AddSeconds(30); \
         while (-not $global:kr -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }; \
         if ($global:kr) { exit 0 } else { exit 9 }",
    );
    let waiting = read_until(&pty, &mut reader, "kr-waiting.");
    assert!(
        waiting.contains("kr-waiting."),
        "the application is waiting for the interrupt: {waiting:?}"
    );

    pty.interrupt_foreground()
        .expect("the console takes the interrupt");

    let seen = read_until(&pty, &mut reader, "kr-interrupted.");
    assert!(
        seen.contains("kr-interrupted."),
        "the application was told about the interrupt: {seen:?}"
    );

    // And it ends. What code it ends with is not this test's to assert: the interrupt cancels the
    // shell's own pipeline before the script's last line runs, which is what an interrupt is for
    // and which leaves the shell reporting that it was interrupted rather than that it finished.
    drain_until_it_ends(&pty, &mut reader, &mut shell);
}

#[test]
fn the_session_job_kills_on_close_and_refuses_breakaway(/* KR-REQ-07.62 */) {
    let (_pty, _reader, mut shell) = powershell_in_a_console("Start-Sleep -Seconds 120");
    let root = u32::try_from(shell.identity().pid.get()).expect("an identifier");
    let job = kr_worker::windows::job::holding(root).expect("the session's job");

    assert!(
        job.kills_on_close().expect("the limits"),
        "closing the last handle ends what the job holds"
    );
    assert!(
        !job.breakaway_permitted().expect("the limits"),
        "a child cannot leave the job by asking"
    );

    // And the boundary the ownership record rests on says so, read back from the job rather than
    // from what this host asked for.
    let boundary = boundary_for(shell.foreground_group(), shell.identity());
    assert_eq!(
        boundary,
        OwnershipBoundary::JobObject { root },
        "the session's boundary is its job"
    );
    assert!(boundary.is_complete_boundary());

    shell.force_stop().expect("the shell is ended");
    shell.wait().expect("the shell ends");
}

/// KR-REQ-07.56: a process that detaches itself from its parent as far as Windows allows is still
/// held by the session's job, so it cannot outlive the session by leaving its parent chain.
#[test]
fn the_job_holds_the_shell_and_every_process_it_starts(/* KR-ACC-010, KR-REQ-07.62 */) {
    // The shell starts a grandchild that detaches itself from its parent as far as this platform
    // allows, then reports both identifiers. Neither may be outside the job: that is what makes
    // the boundary a boundary rather than a parent chain.
    let (pty, mut reader, mut shell) = powershell_in_a_console(
        "$child = Start-Process -PassThru -WindowStyle Hidden -FilePath \
             $PSHOME/pwsh.exe -ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep -Seconds 120'; \
         Write-Host -NoNewline \"kr-child=$($child.Id).\"; \
         Start-Sleep -Seconds 60",
    );
    let seen = read_until(&pty, &mut reader, "kr-child=");
    let child = named_child(&seen);

    let root = u32::try_from(shell.identity().pid.get()).expect("an identifier");
    let job = kr_worker::windows::job::holding(root).expect("the session's job");
    let held = job.process_ids().expect("the job's process list");
    assert!(held.contains(&root), "the job holds the root shell");
    assert!(
        held.contains(&child),
        "and the process the shell started: the job holds {held:?}"
    );

    // What the session records is that tree, by identity rather than by identifier alone.
    let mut owned = OwnedProcesses::establish(
        boundary_for(shell.foreground_group(), shell.identity()),
        shell.identity().clone(),
    );
    owned.observe();
    let surviving: Vec<u64> = owned
        .surviving()
        .into_iter()
        .map(|identity| identity.pid.get())
        .collect();
    assert!(surviving.contains(&u64::from(child)), "{surviving:?}");

    // And closing the boundary ends the whole tree, not only the shell.
    kr_worker::ownership::force_stop(&owned);
    shell.wait().expect("the shell ends");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if job.process_ids().is_ok_and(|held| held.is_empty()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "the job still holds {:?} after it was terminated",
        job.process_ids()
    );
}

#[test]
fn closing_the_last_handle_ends_what_the_job_holds(/* KR-REQ-07.62 */) {
    // Kill-on-close is the promise that a worker which crashes, is killed, or exits without
    // closing its session still takes the session's processes with it. Reading the limit back
    // says it was asked for; this is the behaviour. The console is dropped, which drops the only
    // handle to the job, and the tree the job held has to go.
    let (pty, mut reader, shell) = powershell_in_a_console(
        "$child = Start-Process -PassThru -WindowStyle Hidden -FilePath \
             $PSHOME/pwsh.exe -ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep -Seconds 300'; \
         Write-Host -NoNewline \"kr-child=$($child.Id).\"; \
         Start-Sleep -Seconds 300",
    );
    let seen = read_until(&pty, &mut reader, "kr-child=");
    let child = named_child(&seen);
    let root = u32::try_from(shell.identity().pid.get()).expect("an identifier");
    let child_identity =
        kr_ipc::identity::process_start_identity(child).expect("the operating system describes it");

    // Everything that holds the job: the terminal that created it, the shell's own handles, and
    // this test's reference for the check above. Nothing keeps a handle back.
    drop(reader);
    drop(pty);
    drop(shell);

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if matches!(
            kr_ipc::identity::process_state(&child_identity),
            kr_ipc::identity::ProcessState::Ended
        ) {
            assert!(
                kr_worker::windows::job::holding(root).is_none(),
                "and nothing is left holding the job"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("process {child} is still running after the last handle to its job was closed");
}

#[test]
fn a_resource_started_outside_the_job_is_not_held_by_it(/* KR-REQ-07.63 */) {
    // A GUI resource with a lifetime of its own is created through the desktop broker, outside the
    // session's job. This starts one the same way the broker does - as a plain child of this test
    // process, which is not in the job - and checks the two halves of the promise the *job* makes:
    // it does not hold such a resource, and ending it does not end one.
    //
    // What this does not establish is the other half of the row: that the broker records what it
    // started as an external resource in the closure receipt. Nothing in this build creates a
    // resource through a broker, so there is nothing to record; the row stays open for the task
    // that builds one.
    let (_pty, _reader, mut shell) = powershell_in_a_console("Start-Sleep -Seconds 120");
    let root = u32::try_from(shell.identity().pid.get()).expect("an identifier");
    let job = kr_worker::windows::job::holding(root).expect("the session's job");

    let mut outside = std::process::Command::new(powershell())
        .args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a resource outside the session");
    let external = outside.id();

    let held = job.process_ids().expect("the job's process list");
    assert!(
        !held.contains(&external),
        "the job holds {held:?}, which must not include the external resource {external}"
    );

    job.terminate(1).expect("the job ends");
    shell.wait().expect("the shell ends");

    // Still there: closing a session never ends a browser, a simulator or anything else the broker
    // started for somebody else's lifetime.
    assert!(
        outside.try_wait().expect("the external process").is_none(),
        "the external resource survived the session's closure"
    );
    let _ = outside.kill();
    let _ = outside.wait();
}

/// A worker this test hosts: a session whose root shell is PowerShell, served on the environment's
/// endpoint for its display number, and the descriptor a local caller finds it by.
struct Worker {
    service: std::sync::Arc<kr_worker::service::WorkerService>,
    session_id: kr_protocol::ids::SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    descriptor: kr_protocol::worker::WorkerDescriptor,
    journal: std::path::PathBuf,
}

fn build() -> kr_protocol::ids::BuildId {
    kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier")
}

/// Starts a worker for a new session in `temp`'s environment, under `display`.
async fn worker(temp: &kr_ipc::testing::TempHost, display: u64) -> Worker {
    use kr_protocol::ids::{ControllerGeneration, SessionEpoch, SessionId};

    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = kr_protocol::session::DisplayNumber::new(display);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = std::sync::Arc::new(
        kr_ipc::verify::WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            kr_protocol::hello::PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    // An in-memory store rather than the platform's credential store: all this needs is a
    // controller key the worker checks a generation token against.
    let store = kr_crypto::store::MemoryStore::new();
    let controller = kr_ipc::verify::ControllerIdentity::initialise(&store, environment_id)
        .expect("a controller identity");
    let journal = environment.journal_database(session_id);
    let config = kr_worker::session::SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: powershell_command("Start-Sleep -Seconds 300"),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = kr_worker::session::Session::open(config).expect("opens the session");
    session.launch().expect("launches the root shell");
    let runtime = std::sync::Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );
    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    let service = std::sync::Arc::new(
        kr_worker::service::WorkerService::new(
            std::sync::Arc::clone(&runtime),
            std::sync::Arc::clone(&identity),
            endpoint.clone(),
            kr_worker::service::ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: Some(journal.clone()),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(std::sync::Arc::clone(&service).serve(listener));
    let descriptor = kr_protocol::worker::WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        boot_identity: boot,
        process_start_identity: process,
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        endpoint: endpoint.as_text(),
        worker_public_key: *identity.public_key(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        published_at_ms: kr_protocol::scalars::TimestampMs::new(0),
    };
    Worker {
        service,
        session_id,
        environment_id,
        endpoint,
        descriptor,
        journal,
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // The root shell waits for minutes; the session's job ends it, and with it everything the
        // test left running in the console.
        let root = self.service.runtime().session().root_identity();
        if let Some(job) = root
            .and_then(|root| u32::try_from(root.pid.get()).ok())
            .and_then(kr_worker::windows::job::holding)
        {
            let _ = job.terminate(1);
        }
    }
}

/// Opens a worker's pipe as a client, waiting while every instance of it is taken.
fn open_pipe(endpoint: &kr_ipc::paths::Endpoint) -> std::fs::File {
    /// The operating system's answer when every instance of a pipe is connected.
    const ERROR_PIPE_BUSY: i32 = 231;

    let name = format!(r"\\.\pipe\{}", endpoint.as_text());
    let deadline = Instant::now() + PATIENCE;
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(pipe) => return pipe,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("the owner opens {name}: {error}"),
        }
    }
}

/// KR-REQ-02.04: each worker keeps its receipts in a SQLite journal of its own, written ahead, and
/// is reached on an endpoint of its own; no two sessions share either.
/// KR-REQ-05.02: a worker's endpoint carries the operating system's access control. On this
/// platform it is a named pipe, which carries its own list: read back from a handle to the pipe the
/// worker serves, the list is protected, owned by this account and grants nobody the machine does
/// not already trust, and the worker behind it answers the challenge of the descriptor it is
/// published under.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_worker_keeps_a_journal_of_its_own_and_is_reached_on_a_pipe_of_its_own() {
    use std::os::windows::io::AsHandle as _;

    let temp = kr_ipc::testing::TempHost::create();
    let workers = [worker(&temp, 1).await, worker(&temp, 2).await];
    assert_ne!(
        workers[0].journal, workers[1].journal,
        "one journal per worker"
    );
    assert_ne!(
        workers[0].endpoint, workers[1].endpoint,
        "one endpoint per worker"
    );

    for hosted in &workers {
        let header = std::fs::read(&hosted.journal)
            .unwrap_or_else(|error| panic!("reads {}: {error}", hosted.journal.display()));
        assert!(
            header.starts_with(b"SQLite format 3\0"),
            "{} is a SQLite database",
            hosted.journal.display()
        );
        let journal = kr_worker::journal::Journal::open_read_only(&hosted.journal)
            .expect("a second connection to the journal");
        assert_eq!(
            journal
                .pragma_string("journal_mode")
                .expect("the mode")
                .to_lowercase(),
            "wal",
            "the journal is written ahead"
        );

        let pipe = open_pipe(&hosted.endpoint);
        kr_ipc::paths::check_access_list(pipe.as_handle(), "the worker's pipe", true)
            .expect("the pipe's list is protected and its owner's");
        drop(pipe);

        let mut client = kr_ipc::client::LocalClient::connect(
            &hosted.endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("the owner reaches the worker on its pipe");
        client
            .verify_worker(&hosted.descriptor)
            .await
            .expect("the worker answers the challenge of the descriptor it is published under");
    }
}

/// KR-REQ-02.07: a command line on this machine is authenticated by the operating system: the
/// worker's pipe admits its owner and nobody else, and the process on the other end is named by
/// the pipe rather than by anything it sends. What it does is recorded under the local owner, and
/// nothing it sends names anyone else. The worker still checks the scope of every request itself,
/// so a mutation aimed at another session is refused rather than served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_on_a_workers_pipe_is_served_as_its_owner_and_held_to_its_session() {
    use kr_protocol::scalars::Nullable;

    let temp = kr_ipc::testing::TempHost::create();
    let hosted = worker(&temp, 1).await;
    let mut client = kr_ipc::client::LocalClient::connect(
        &hosted.endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        build(),
    )
    .await
    .expect("the owner reaches the worker on its pipe");
    let target = |session_id| kr_protocol::envelope::ActionTarget {
        environment_id: hosted.environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    client
        .mutate(
            kr_protocol::method::Method::SessionAttach,
            action_id,
            target(hosted.session_id),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: hosted.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds");
    let owner = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    assert!(
        hosted
            .service
            .runtime()
            .session()
            .journal()
            .expect("a journal")
            .read(owner, action_id)
            .expect("reads the journal")
            .is_some(),
        "the attach is recorded under the local owner the pipe admitted"
    );

    let elsewhere = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate(
            kr_protocol::method::Method::SessionClose,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            target(elsewhere),
            &kr_protocol::session::SessionCloseParams {
                session_id: elsewhere,
            },
        )
        .await
        .expect("the call reaches the worker");
    assert_eq!(
        outcome.err().map(|error| error.code),
        Some(kr_protocol::error::ErrorCode::StaleSession),
        "an authenticated local caller is still held to the scope of this session"
    );
    assert_eq!(hosted.service.runtime().state().as_str(), "live");
}
