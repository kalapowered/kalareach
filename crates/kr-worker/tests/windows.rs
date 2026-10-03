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

/// A program in the system directory, which every Windows machine has.
fn system_program(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join(name)
}

/// Starts a system program in `job` the way a launch does, with no streams of its own.
fn start_in(
    job: &kr_worker::windows::job::AgentJob,
    name: &str,
    arguments: &[&str],
) -> kr_worker::windows::launch::Child {
    let arguments: Vec<String> = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
    kr_worker::windows::launch::start(&kr_worker::windows::launch::Spec {
        program: &system_program(name),
        arguments: &arguments,
        directory: &std::env::temp_dir(),
        environment: &[],
        session: None,
        agent: job,
        pipe_input: false,
        pipe_output: false,
    })
    .expect("the program starts in its job")
}

/// A process that waits far longer than any test takes, ended when the test ends however it ends:
/// `ping` is on every Windows machine.
struct Waiting(std::process::Child);

impl Waiting {
    fn start() -> Self {
        Self(
            std::process::Command::new("ping.exe")
                .args(["-n", "600", "127.0.0.1"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("a process that waits starts"),
        )
    }

    fn identity(&self) -> kr_protocol::identity::ProcessStartIdentity {
        kr_ipc::identity::process_start_identity(self.0.id())
            .expect("the operating system describes it")
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// KR-REQ-07.61 and KR-REQ-12.02: the kernel's record of when a process started is believed on this
/// machine, and a process created between two readings of the clock it is recorded on started
/// between them. This is the check the worker makes before it orders anything by that clock, run
/// again here so that a Windows build that changes the class fails in the job that runs it.
#[test]
fn the_kernels_record_of_a_start_lies_between_the_readings_around_the_creation() {
    kr_worker::windows::lineage::start_clock().expect("the kernel's record of a start is believed");
    for _ in 0..20 {
        let before = kr_worker::windows::lineage::interrupt_now().expect("the clock reads");
        let child = Waiting::start();
        let after = kr_worker::windows::lineage::interrupt_now().expect("the clock reads");
        let started = kr_worker::windows::lineage::monotonic_start(&child.identity())
            .expect("the start of a running process is read");
        assert!(
            before <= started && started <= after,
            "a process created between {before} and {after} started at {started}"
        );
    }
}

/// KR-REQ-07.61 and KR-REQ-12.02: processes created one after another start in that order on the
/// clock every launch is placed by, and the start of a process that has ended is not a start at all.
#[test]
fn processes_created_in_turn_start_in_turn_and_an_ended_one_has_no_start() {
    let children: Vec<Waiting> = (0..10).map(|_| Waiting::start()).collect();
    let starts: Vec<u64> = children
        .iter()
        .map(|child| {
            kr_worker::windows::lineage::monotonic_start(&child.identity()).expect("a start")
        })
        .collect();
    assert!(
        starts.windows(2).all(|pair| pair[0] <= pair[1]),
        "created in turn, started in turn: {starts:?}"
    );
    let mut ended = Waiting::start();
    let identity = ended.identity();
    ended.0.kill().expect("it ends");
    ended.0.wait().expect("and is collected");
    let refused = kr_worker::windows::lineage::monotonic_start(&identity)
        .expect_err("a process that has ended has no start to place");
    assert!(
        refused.contains("ended") || refused.contains("not the process"),
        "{refused}"
    );
}

/// KR-REQ-12.02: a process is started by the process the kernel's record names when that process
/// was running first, and by nobody else. A parent that has ended is still named by Windows and is
/// refused here.
#[test]
fn a_child_is_started_by_its_running_parent_and_by_no_other_process() {
    let me = kr_ipc::identity::current_process_start_identity().expect("this process's identity");
    let child = Waiting::start();
    let child_identity = child.identity();
    assert_eq!(
        kr_worker::windows::lineage::parent_of(&child_identity),
        Ok(me.clone()),
        "the kernel names this process, which was running before its child"
    );
    assert_eq!(
        kr_worker::windows::lineage::started_by(&child_identity, &me),
        Ok(())
    );
    // Control: another running process did not start it.
    let other = Waiting::start();
    let refused = kr_worker::windows::lineage::started_by(&child_identity, &other.identity())
        .expect_err("another process did not start it");
    assert!(refused.contains("not by process"), "{refused}");
    // The same identifier with another start is another process.
    let mut replaced = me.clone();
    replaced.start_value = kr_protocol::scalars::U64::new(replaced.start_value.get() + 1);
    assert!(kr_worker::windows::lineage::started_by(&child_identity, &replaced).is_err());
}

/// KR-REQ-12.02 and KR-REQ-07.61: a process whose parent has ended names that parent still, and is
/// not started by anything this host can show.
#[test]
fn a_process_whose_parent_has_ended_is_started_by_nobody_the_host_can_show() {
    let job = kr_worker::windows::job::AgentJob::create().expect("a job");
    // `start /b` runs `ping` as a child of `cmd` and `cmd` ends without waiting for it.
    let mut shell = start_in(
        &job,
        "cmd.exe",
        &[
            "/d",
            "/c",
            "start",
            "/b",
            "ping.exe",
            "-n",
            "600",
            "127.0.0.1",
        ],
    );
    let shell_identity = kr_ipc::identity::started_process_identity(shell.id()).expect("identity");
    shell
        .wait()
        .expect("the shell ends once it has started its child");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ping = loop {
        let held = job.process_ids().expect("the job's list");
        if let Some(pid) = held
            .into_iter()
            .find(|pid| *pid != u32::try_from(shell_identity.pid.get()).unwrap_or(0))
            && let Ok(identity) = kr_ipc::identity::process_start_identity(pid)
        {
            break identity;
        }
        assert!(
            Instant::now() < deadline,
            "the shell's child never appeared"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let refused = kr_worker::windows::lineage::started_by(&ping, &shell_identity)
        .expect_err("its parent has ended");
    assert!(refused.contains("has ended"), "{refused}");
    job.terminate(1).expect("the job ends");
}

/// A backend this test launched as a launch does: held by a session's job and by a job of its own,
/// which the broker keeps with the end of the backend's input it writes, so stopping it is stopping
/// that job.
struct Backend {
    _session: kr_worker::windows::job::SessionJob,
    job: std::sync::Arc<kr_worker::windows::job::AgentJob>,
    child: kr_worker::windows::launch::Child,
    identity: kr_protocol::identity::ProcessStartIdentity,
}

impl Backend {
    fn launch(program: &str, arguments: &[&str]) -> Self {
        let session = kr_worker::windows::job::SessionJob::create().expect("a session job");
        let job = std::sync::Arc::new(kr_worker::windows::job::AgentJob::create().expect("a job"));
        let arguments: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        let child = kr_worker::windows::launch::start(&kr_worker::windows::launch::Spec {
            program: &system_program(program),
            arguments: &arguments,
            directory: &std::env::temp_dir(),
            environment: &[],
            session: Some(&session),
            agent: &job,
            pipe_input: true,
            pipe_output: true,
        })
        .expect("the backend starts");
        let identity =
            kr_ipc::identity::started_process_identity(child.id()).expect("its identity");
        kr_worker::windows::job::keep_agent(
            identity.clone(),
            std::sync::Arc::clone(&job),
            child.stdin.clone(),
        );
        Self {
            _session: session,
            job,
            child,
            identity,
        }
    }

    /// Waits until the job holds at least `count` processes.
    fn wait_for(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.job.process_ids().expect("the job lists").len() < count {
            assert!(
                Instant::now() < deadline,
                "the backend started its processes"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.job.terminate(1);
        let _ = self.child.wait();
        kr_worker::windows::job::release_agent(&self.identity);
    }
}

/// KR-REQ-07.67: a dedicated backend that ends when its input closes is stopped by closing it, and
/// is not forced; the stop is complete only when its job lists nothing.
#[tokio::test]
async fn kr_req_07_67_a_backend_that_ends_when_its_input_closes_is_stopped_without_force() {
    // `findstr` reads its input until the end and then ends.
    let backend = Backend::launch("findstr.exe", &["kr-never-matches"]);
    let stopped = kr_worker::broker::stop_backend(&backend.identity, Duration::from_secs(20)).await;
    assert!(stopped.asked, "the backend was asked to stop");
    assert!(stopped.ended, "and its job holds nothing");
    assert!(
        !stopped.forced,
        "a backend that ends on its own is not forced"
    );
    assert!(!stopped.unresolved);
    assert!(backend.job.process_ids().expect("the job lists").is_empty());
}

/// KR-REQ-07.67: a backend that ignores its input is ended with its whole job once the grace period
/// has passed, and so is what it started. Control: the case above is not forced.
#[tokio::test]
async fn kr_req_07_67_a_backend_that_ignores_its_input_is_forced_with_what_it_started() {
    let backend = Backend::launch("cmd.exe", &["/d", "/c", "ping -n 600 127.0.0.1 > NUL"]);
    backend.wait_for(2);
    let stopped = kr_worker::broker::stop_backend(&backend.identity, Duration::from_secs(1)).await;
    assert!(stopped.asked && stopped.ended && !stopped.unresolved);
    assert!(stopped.forced, "the grace period passed and the force ran");
    assert!(
        backend.job.process_ids().expect("the job lists").is_empty(),
        "nothing of it is left"
    );
}

/// KR-REQ-07.67: a backend whose root has gone while what it started has not is not stopped until
/// the job is empty: completion is the job's, never the root's.
#[tokio::test]
async fn kr_req_07_67_a_root_that_is_gone_with_helpers_alive_is_not_a_complete_stop() {
    // `start /b` runs `ping` as a child of `cmd`, and `cmd` ends without waiting for it.
    let mut backend = Backend::launch(
        "cmd.exe",
        &[
            "/d",
            "/c",
            "start",
            "/b",
            "ping.exe",
            "-n",
            "600",
            "127.0.0.1",
        ],
    );
    let _ = backend.child.wait();
    assert!(
        matches!(
            kr_ipc::identity::process_state(&backend.identity),
            kr_ipc::identity::ProcessState::Ended
        ),
        "the root has ended"
    );
    backend.wait_for(1);
    let stopped = kr_worker::broker::stop_backend(&backend.identity, Duration::from_secs(1)).await;
    assert!(stopped.asked, "its helper was still there to stop");
    assert!(stopped.forced && stopped.ended);
    assert!(backend.job.process_ids().expect("the job lists").is_empty());
}

/// KR-REQ-07.67: a stop cancels a write to the backend's input that is blocked, so the stop is not
/// held by a backend that never reads: the write fails and the backend is ended.
#[tokio::test]
async fn kr_req_07_67_a_stop_cancels_a_write_that_is_blocked() {
    let mut backend = Backend::launch("ping.exe", &["-n", "600", "127.0.0.1"]);
    let mut input = backend.child.stdin.take().expect("the backend's input");
    let written = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counting = std::sync::Arc::clone(&written);
    let writing = std::thread::spawn(move || {
        use std::io::Write as _;
        // `ping` never reads, so the pipe fills and a write waits for room that never comes.
        loop {
            if let Err(error) = input.write_all(&[0_u8; 4096]) {
                return error;
            }
            counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while written.load(std::sync::atomic::Ordering::SeqCst) < 32 {
        assert!(Instant::now() < deadline, "the pipe fills");
        std::thread::sleep(Duration::from_millis(10));
    }
    let stopped = kr_worker::broker::stop_backend(&backend.identity, Duration::from_secs(1)).await;
    assert!(stopped.asked && stopped.ended && !stopped.unresolved);
    let error = writing.join().expect("the writer returns");
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::Other
        ),
        "the blocked write failed: {error}"
    );
}

/// KR-REQ-07.67: two callers that stop one backend at once do one stop and get one answer.
#[tokio::test]
async fn kr_req_07_67_two_stops_at_once_are_one_stop() {
    let backend = Backend::launch("cmd.exe", &["/d", "/c", "ping -n 600 127.0.0.1 > NUL"]);
    backend.wait_for(2);
    let identity = backend.identity.clone();
    let (first, second) = tokio::join!(
        kr_worker::broker::stop_backend(&identity, Duration::from_secs(1)),
        kr_worker::broker::stop_backend(&identity, Duration::from_secs(1)),
    );
    assert_eq!(first, second, "one answer for one stop");
    assert!(first.asked && first.forced && first.ended);
}

/// A scratch tree under the temporary directory, removed with the test: junctions in it are removed
/// as links and never followed.
struct Tree(std::path::PathBuf);

impl Tree {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("kr-pin-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a scratch tree");
        Self(root)
    }

    /// A directory beneath the tree, made with its parents.
    fn dir(&self, relative: &str) -> std::path::PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(path: &std::path::Path) -> &str {
    path.to_str().expect("a text path")
}

/// Whether a failed operation was refused for a sharing violation, which is what a held path says.
fn held(result: std::io::Result<()>) -> bool {
    result.is_err_and(|error| error.raw_os_error() == Some(32))
}

/// Makes a junction from `link` to `target`, as `mklink /J` does.
fn junction(link: &std::path::Path, target: &std::path::Path) {
    let made = std::process::Command::new(system_program("cmd.exe"))
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("cmd.exe runs");
    assert!(
        made.status.success(),
        "the junction is made: {}",
        String::from_utf8_lossy(&made.stdout)
    );
}

/// Turns an empty directory into a junction to `target` in place, as a principal that may write to
/// the directory can whatever is held on it: the conversion changes what the path reaches and not
/// the object a handle holds.
#[expect(
    unsafe_code,
    reason = "setting a reparse point is a device control with a buffer only the caller can lay out"
)]
fn convert_to_a_junction(directory: &std::path::Path, target: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    let opened = std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)
        .expect("the directory opens for its attributes");
    let substitute: Vec<u16> = std::ffi::OsString::from(format!(r"\??\{}", target.display()))
        .encode_wide()
        .collect();
    let printed: Vec<u16> = target.as_os_str().encode_wide().collect();
    let substitute_bytes = u16::try_from(substitute.len() * 2).expect("short");
    let printed_bytes = u16::try_from(printed.len() * 2).expect("short");
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    let data_length = 8 + usize::from(substitute_bytes) + 2 + usize::from(printed_bytes) + 2;
    buffer.extend(u16::try_from(data_length).expect("short").to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(0_u16.to_le_bytes());
    buffer.extend(substitute_bytes.to_le_bytes());
    buffer.extend((substitute_bytes + 2).to_le_bytes());
    buffer.extend(printed_bytes.to_le_bytes());
    for unit in &substitute {
        buffer.extend(unit.to_le_bytes());
    }
    buffer.extend(0_u16.to_le_bytes());
    for unit in &printed {
        buffer.extend(unit.to_le_bytes());
    }
    buffer.extend(0_u16.to_le_bytes());
    let mut returned = 0_u32;
    // SAFETY: the handle is open for the call, the buffer is a local laid out as the control
    // documents, and the count is another local.
    let set = unsafe {
        DeviceIoControl(
            opened.as_raw_handle().cast(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).expect("short"),
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(
        set,
        0,
        "the directory becomes a junction: {}",
        std::io::Error::last_os_error()
    );
}

/// KR-REQ-12.16: a path held from its drive's root to its directory cannot be renamed or deleted at
/// any component while it is held, and is let go of with the pin. Control: the same operations land
/// once the pin is dropped.
#[test]
fn kr_req_12_16_a_held_path_cannot_be_renamed_or_deleted_and_is_let_go_of_with_the_pin() {
    let tree = Tree::new();
    let leaf = tree.dir(r"a\b\work");
    let pin = kr_worker::windows::pin::pin(text(&leaf)).expect("the path is held");
    assert!(held(std::fs::rename(
        &leaf,
        tree.0.join("a").join("b").join("moved")
    )));
    assert!(held(std::fs::rename(
        tree.0.join("a").join("b"),
        tree.0.join("a").join("c")
    )));
    assert!(held(std::fs::rename(tree.0.join("a"), tree.0.join("z"))));
    assert!(held(std::fs::remove_dir(&leaf)));
    assert_eq!(
        pin.recheck(),
        Ok(()),
        "and it is still the directory it was"
    );
    drop(pin);
    std::fs::rename(&leaf, tree.0.join("a").join("b").join("moved"))
        .expect("a directory nothing holds renames");
}

/// KR-REQ-12.16: every spelling of one directory is held as the same object, and it is the object
/// the directory grant names: the case of a name, forward slashes, a trailing separator and dot
/// segments walk to one directory.
#[test]
fn kr_req_12_16_every_spelling_of_a_directory_is_held_as_the_object_a_grant_names() {
    let tree = Tree::new();
    let leaf = tree.dir(r"Case\Sensitive\Work");
    let granted = kr_transfer::authority::AuthorisedDirectory::open_root(
        kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16])),
        &leaf,
    )
    .expect("the directory is opened");
    let plain = text(&leaf).to_owned();
    for spelling in [
        plain.clone(),
        plain.to_lowercase(),
        plain.to_uppercase(),
        plain.replace('\\', "/"),
        format!("{plain}\\"),
        format!("{plain}\\.\\..\\Work"),
        format!("{plain}\\."),
    ] {
        let pin = kr_worker::windows::pin::pin(&spelling)
            .unwrap_or_else(|why| panic!("{spelling} is held: {why}"));
        assert_eq!(
            pin.identity(),
            granted.identity(),
            "{spelling} is the object the grant names"
        );
    }
}

/// KR-REQ-12.16: a path through a link, a file, a directory that is not there, and any path that is
/// not an absolute path on a drive are not held, each by name. Control: the real directory is.
#[test]
fn kr_req_12_16_a_link_a_file_or_a_missing_directory_is_not_held() {
    let tree = Tree::new();
    let real = tree.dir(r"real\work");
    assert!(kr_worker::windows::pin::pin(text(&real)).is_ok());
    junction(&tree.0.join("link"), &tree.0.join("real"));
    let through = tree.0.join("link").join("work");
    let why = kr_worker::windows::pin::pin(text(&through)).expect_err("a junction is not walked");
    assert!(why.contains("is a link"), "{why}");
    std::os::windows::fs::symlink_dir(&real, tree.0.join("symbolic")).expect("a symbolic link");
    let why = kr_worker::windows::pin::pin(text(&tree.0.join("symbolic")))
        .expect_err("a symbolic link is not walked");
    assert!(why.contains("is a link"), "{why}");
    std::fs::write(tree.0.join("file.txt"), b"x").expect("a file");
    let why = kr_worker::windows::pin::pin(text(&tree.0.join("file.txt")))
        .expect_err("a file is not a directory");
    assert!(why.contains("is not a directory"), "{why}");
    assert!(kr_worker::windows::pin::pin(text(&tree.0.join("missing"))).is_err());
    for refused in [r"\\localhost\C$\Windows", r"\\?\C:\Windows", r"..\x", "x"] {
        assert!(kr_worker::windows::pin::pin(refused).is_err(), "{refused}");
    }
}

/// What a drive says, for a case no machine here has.
struct Facts(DriveFactsOf);

type DriveFactsOf = kr_worker::windows::pin::DriveFacts;

impl kr_worker::windows::pin::Drives for Facts {
    fn facts(&self, _letter: char) -> Result<kr_worker::windows::pin::DriveFacts, String> {
        Ok(self.0.clone())
    }
}

/// KR-REQ-12.16: a drive whose letter names a path and not a volume (a `subst` drive), and a volume
/// that is not NTFS, are not held. Control: this machine's own drive is.
#[test]
fn kr_req_12_16_a_drive_that_is_not_a_local_ntfs_volume_is_not_held() {
    let tree = Tree::new();
    let leaf = tree.dir("work");
    let fat = Facts(DriveFactsOf {
        device: r"\Device\HarddiskVolume9".to_owned(),
        file_system: "FAT32".to_owned(),
    });
    let why = kr_worker::windows::pin::pin_with(&fat, text(&leaf)).expect_err("FAT");
    assert!(why.contains("FAT32"), "{why}");
    let remapped = Facts(DriveFactsOf {
        device: r"\??\C:\work".to_owned(),
        file_system: "NTFS".to_owned(),
    });
    let why = kr_worker::windows::pin::pin_with(&remapped, text(&leaf)).expect_err("subst");
    assert!(why.contains("not a local volume"), "{why}");
    // The system's own answer for a drive that names a path: a letter this machine does not use.
    let letter = ('H'..='Y')
        .find(|letter| !std::path::Path::new(&format!("{letter}:\\")).exists())
        .expect("a free drive letter");
    let drive = format!("{letter}:");
    let made = std::process::Command::new(system_program("subst.exe"))
        .arg(&drive)
        .arg(&leaf)
        .output()
        .expect("subst runs");
    assert!(made.status.success(), "a substituted drive is made");
    struct Removed(String);
    impl Drop for Removed {
        fn drop(&mut self) {
            let _ = std::process::Command::new(system_program("subst.exe"))
                .args([self.0.as_str(), "/d"])
                .output();
        }
    }
    let _removed = Removed(drive.clone());
    let why = kr_worker::windows::pin::pin(&format!("{drive}\\")).expect_err("a substituted drive");
    assert!(why.contains("not a local volume"), "{why}");
    assert!(
        kr_worker::windows::pin::pin(text(&leaf)).is_ok(),
        "the same directory by its real path is held"
    );
}

/// KR-REQ-12.16: a directory converted to a junction in place, whatever is held on it, is seen by the
/// pin's next read of its attributes; the grant opened before keeps naming the held object and a
/// read through it afterwards is refused, never served from the junction's target.
#[test]
fn kr_req_12_16_a_directory_converted_to_a_link_is_seen_and_its_grant_reads_nothing() {
    let tree = Tree::new();
    let leaf = tree.dir("work");
    let target = tree.dir("target");
    std::fs::write(target.join("secret.txt"), b"secret").expect("a file in the target");
    let pin = kr_worker::windows::pin::pin(text(&leaf)).expect("the path is held");
    let granted = kr_transfer::authority::AuthorisedDirectory::open_root(
        kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16])),
        &leaf,
    )
    .expect("the directory is opened after it is held");
    assert_eq!(granted.identity(), pin.identity());
    assert_eq!(pin.recheck(), Ok(()));
    convert_to_a_junction(&leaf, &target);
    assert_eq!(
        std::fs::read(leaf.join("secret.txt")).expect("by its path it reaches the target"),
        b"secret"
    );
    let why = pin.recheck().expect_err("the directory is a link now");
    assert!(why.contains("is a link"), "{why}");
    let refused = granted.open_read(
        &kr_transfer::authority::RelativeName::parse("secret.txt").expect("a name"),
        kr_transfer::authority::ObjectPolicy::ReadableFile,
    );
    assert!(
        refused.is_err(),
        "a read through the grant is refused and never served from the target"
    );
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
