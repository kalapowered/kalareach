//! The recorder of what a pseudo-console's output pipe produces while the sources of mode 9001 run
//! in it: a program of no interest (the control), a pseudo-console nested in it, `wsl.exe`, and
//! `ssh.exe`.
//!
//! The terminal engine's cases feed it sequences written by hand. What a nested pseudo-console, a
//! Windows Subsystem for Linux session or an `ssh` client really send to the console they run in
//! is a fact about the system they run on, so it is recorded here, once, on a machine that has
//! them, and replayed as fixtures by `crates/kr-term/tests/conpty_sources.rs` on every platform.
//!
//! Nothing here runs unless it is asked for (`--ignored`), and `KR_RECORD_DIR` names the directory
//! the recordings go to. A recording is a text file: comment lines that say what was run and on
//! which build of Windows, and one `chunk` line for each read of the pipe, in the order the reads
//! returned, with the bytes spelled so that a person can read them: printable ASCII as itself, a
//! backslash doubled, and every other byte as `\xNN`.
//!
//! The pseudo-console is the terminal library's (portable-pty 0.9.0), opened with the three flags
//! that library sets: inherit the cursor, the resize quirk and win32 input mode. It inherits the
//! cursor, so it asks where the cursor is when it starts, and a thread answers that one question
//! and nothing else. The worker opens the console of a session with no flags, so its console asks
//! no such question and is not asked for win32 input mode by a flag; what the program inside sends
//! into either console is the program's own.

#![cfg(windows)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

/// Where the recordings go.
const DIRECTORY_VARIABLE: &str = "KR_RECORD_DIR";

/// The variable that makes this test binary, started in a pseudo-console of its own, be the program
/// that runs a pseudo-console inside it.
const INNER_VARIABLE: &str = "KR_CONPTY_INNER";

/// The variable that says a case may write the account's `.ssh` directory and may sign in to this
/// machine's own `sshd` as the account, which is for an account that is disposable.
const SSH_SWITCH: &str = "KR_ALLOW_SSH_CAPTURE";

/// The variable that says a case may start the Windows Subsystem for Linux distribution and end it
/// again.
const WSL_SWITCH: &str = "KR_ALLOW_WSL_CAPTURE";

/// How long a recorded program is given to end before the recording fails.
const PROGRAM_DEADLINE: Duration = Duration::from_secs(120);

/// Why the recordings are ignored in an ordinary run.
macro_rules! records {
    () => {
        "records what a source of mode 9001 sends into a directory KR_RECORD_DIR names; it runs \
         with --ignored by hand, on a machine that has the source"
    };
}

/// A program of the system directory.
fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join(program)
}

/// A read of the pipe, spelled for a recording.
fn spelled(bytes: &[u8]) -> String {
    let mut spelled = String::new();
    for byte in bytes {
        match byte {
            b'\\' => spelled.push_str("\\\\"),
            0x20..=0x7e => spelled.push(char::from(*byte)),
            other => spelled.push_str(&format!("\\x{other:02x}")),
        }
    }
    spelled
}

/// The build of Windows the recording was made on, as `ver` says it.
fn windows_build() -> String {
    let output = Command::new(system32("cmd.exe"))
        .args(["/c", "ver"])
        .output()
        .expect("cmd runs");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// What a pseudo-console produced while a command ran in it.
struct Recorded {
    /// Each read of the output pipe, in order.
    chunks: Vec<Vec<u8>>,
    /// The command's exit code, when it ended in time.
    exit: Option<u32>,
}

/// Runs `command` in a pseudo-console of `rows` by `columns` and records every read of its output
/// pipe until the pipe ends.
///
/// The pseudo-console asks this terminal where its cursor is when it starts, and serves nothing to
/// the command until it is answered, so a thread answers while it reads.
fn record_in_a_pseudo_console(command: CommandBuilder, rows: u16, columns: u16) -> Recorded {
    let pty = native_pty_system()
        .openpty(PtySize {
            rows,
            cols: columns,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a pseudo-console");
    let writer: Arc<Mutex<Box<dyn Write + Send>>> =
        Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
    let chunks = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let mut reader = pty.master.try_clone_reader().expect("a reader");
    let (running, started) = std::sync::mpsc::channel::<()>();
    let reading = {
        let writer = Arc::clone(&writer);
        let chunks = Arc::clone(&chunks);
        std::thread::spawn(move || {
            const QUERY: &[u8] = b"\x1b[6n";
            const REPLY: &[u8] = b"\x1b[1;1R";
            let _ = running.send(());
            let mut everything = Vec::new();
            let mut answered = 0_usize;
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                everything.extend_from_slice(&buffer[..read]);
                chunks
                    .lock()
                    .expect("the recording is not poisoned")
                    .push(buffer[..read].to_vec());
                let asked = everything
                    .windows(QUERY.len())
                    .filter(|window| *window == QUERY)
                    .count();
                while answered < asked {
                    if let Ok(mut writer) = writer.lock() {
                        let _ = writer.write_all(REPLY);
                        let _ = writer.flush();
                    }
                    answered += 1;
                }
            }
        })
    };
    started
        .recv()
        .expect("the thread that reads the pseudo-console started");
    let mut child = pty
        .slave
        .spawn_command(command)
        .expect("starts the command");
    drop(pty.slave);
    let started_at = Instant::now();
    let exit = loop {
        if let Some(status) = child.try_wait().expect("the command's state") {
            break Some(status.exit_code());
        }
        if started_at.elapsed() > PROGRAM_DEADLINE {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // The pseudo-console ends when its master is let go, and the pipe ends after whatever it had
    // left to say.
    drop(pty.master);
    reading.join().expect("the reading thread ends");
    drop(writer);
    let chunks = std::mem::take(&mut *chunks.lock().expect("the recording is not poisoned"));
    Recorded { chunks, exit }
}

/// Writes the recording `name` into the directory `KR_RECORD_DIR` names.
fn write_recording(name: &str, command: &str, marker: &str, recorded: &Recorded) {
    let directory = PathBuf::from(
        std::env::var_os(DIRECTORY_VARIABLE)
            .unwrap_or_else(|| panic!("{DIRECTORY_VARIABLE} names the directory to record into")),
    );
    std::fs::create_dir_all(&directory).expect("the recording directory");
    let mut text = String::new();
    text.push_str(
        "# A recording of what a pseudo-console's output pipe produced while a source of\n",
    );
    text.push_str("# mode 9001 ran in it. One chunk line for each read of the pipe, in order.\n");
    text.push_str(&format!("# source: {name}\n"));
    text.push_str(&format!("# command: {command}\n"));
    text.push_str(&format!("# marker: {marker}\n"));
    text.push_str(&format!("# windows: {}\n", windows_build()));
    text.push_str(
        "# console: portable-pty 0.9.0, flags: inherit cursor, resize quirk, win32 input mode\n",
    );
    text.push_str(&format!("# exit: {:?}\n", recorded.exit));
    for chunk in &recorded.chunks {
        text.push_str(&format!("chunk {}\n", spelled(chunk)));
    }
    let path = directory.join(format!("{name}.capture"));
    std::fs::write(&path, text).expect("writes the recording");
    let bytes: usize = recorded.chunks.iter().map(Vec::len).sum();
    println!(
        "recorded {name}: {} chunks, {bytes} bytes, exit {:?}, to {}",
        recorded.chunks.len(),
        recorded.exit,
        path.display()
    );
}

/// Checks that a recording holds the text the command printed, which is what says the source ran
/// and its output came through, and that the command ended by itself.
fn assert_the_source_ran(name: &str, marker: &str, recorded: &Recorded) {
    let everything: Vec<u8> = recorded.chunks.concat();
    assert!(
        String::from_utf8_lossy(&everything).contains(marker),
        "the recording of {name} does not hold {marker:?}: {}",
        spelled(&everything)
    );
    assert_eq!(
        recorded.exit,
        Some(0),
        "{name} did not end with 0 within {PROGRAM_DEADLINE:?}"
    );
}

/// The program a pseudo-console is inside of: this test binary, in the role the variable gives it.
/// It opens a pseudo-console of its own, runs a command in it, and writes what that produced to its
/// own output, which is the outer pseudo-console's input from the program.
#[test]
#[ignore = records!()]
fn the_pseudo_console_inside_the_pseudo_console() {
    if std::env::var_os(INNER_VARIABLE).is_none() {
        return;
    }
    let mut command = CommandBuilder::new(system32("cmd.exe"));
    command.args(["/c", "echo kr-capture-nested"]);
    let recorded = record_in_a_pseudo_console(command, 24, 80);
    let mut out = std::io::stdout().lock();
    for chunk in &recorded.chunks {
        out.write_all(chunk).expect("writes to the outer console");
        out.flush().expect("flushes the outer console");
    }
}

/// Records a program that has nothing to do with mode 9001 and a pseudo-console nested in another,
/// each in a pseudo-console of its own: the control, and the transition of one console inside
/// another.
#[test]
#[ignore = records!()]
fn record_a_plain_program_and_a_nested_pseudo_console() {
    let mut plain = CommandBuilder::new(system32("cmd.exe"));
    plain.args(["/c", "echo kr-capture-plain"]);
    let recorded = record_in_a_pseudo_console(plain, 24, 100);
    assert_the_source_ran("plain-program", "kr-capture-plain", &recorded);
    write_recording(
        "plain-program",
        "cmd.exe /c echo kr-capture-plain",
        "kr-capture-plain",
        &recorded,
    );

    let mut nested = CommandBuilder::new(std::env::current_exe().expect("this test binary"));
    nested.args([
        "--ignored",
        "--exact",
        "the_pseudo_console_inside_the_pseudo_console",
        "--nocapture",
        "--test-threads=1",
    ]);
    nested.env(INNER_VARIABLE, "1");
    let recorded = record_in_a_pseudo_console(nested, 24, 100);
    assert_the_source_ran("nested-pseudo-console", "kr-capture-nested", &recorded);
    write_recording(
        "nested-pseudo-console",
        "this test binary, which runs `cmd.exe /c echo kr-capture-nested` in a pseudo-console of its own and writes what that produced to the outer one",
        "kr-capture-nested",
        &recorded,
    );
}

/// What `wsl.exe` printed for `arguments`, which it writes in UTF-16 unless its environment asks
/// for UTF-8 with `WSL_UTF8=1`: the variable is taken out of the call's environment, so that the
/// text is always the encoding it is read in. A call that does not succeed stops the case, so that
/// no decision is made on the text of a failure.
fn wsl_text(arguments: &[&str]) -> String {
    let output = Command::new(system32("wsl.exe"))
        .args(arguments)
        .env_remove("WSL_UTF8")
        .output()
        .expect("wsl runs");
    assert!(
        output.status.success(),
        "wsl.exe {arguments:?} did not succeed: {}",
        output.status
    );
    utf16_text(&output.stdout)
}

/// UTF-16 text, little-endian, as `wsl.exe` writes it.
fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The distribution names in what `wsl.exe --list --quiet` or `--list --running --quiet` printed:
/// one to a line and nothing else on it, so no word of the display language is read.
fn listed_names(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Whether `distribution` is registered and not running, by the two lists `wsl.exe` prints. A name
/// is matched whole and without regard to case, so that a distribution whose name holds another's
/// (`Ubuntu-24.04` holds `Ubuntu`) is never taken for it. Anything else on a line of the running
/// list than the name of a registered distribution (a message in place of names) leaves it unknown,
/// and an unknown state is not stopped: the distribution is left alone.
fn is_stopped(distribution: &str, registered: &str, running: &str) -> bool {
    let registered = listed_names(registered);
    let running = listed_names(running);
    let is =
        |names: &[&str], wanted: &str| names.iter().any(|name| name.eq_ignore_ascii_case(wanted));
    is(&registered, distribution)
        && running.iter().all(|name| is(&registered, name))
        && !is(&running, distribution)
}

/// A command that ends a distribution the case started, run once when it is asked for or, if it
/// has not been asked for, when this is dropped, so that a case that fails after it started the
/// distribution still ends it. A failure of the command is the caller's when it asks, and is
/// written to the error output when the drop runs it, without a panic that would end the process
/// during an unwinding.
struct Terminate {
    command: Box<dyn FnMut() -> Result<(), String>>,
    ran: bool,
}

/// Runs a program of the system directory and says why when it does not succeed.
fn run_to_success(program: &Path, arguments: &[String]) -> Result<(), String> {
    match Command::new(program).args(arguments).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "{} {arguments:?} did not succeed: {status}",
            program.display()
        )),
        Err(error) => Err(format!(
            "{} {arguments:?} does not run: {error}",
            program.display()
        )),
    }
}

impl Terminate {
    /// The command that ends `distribution`, which the case found registered and stopped.
    fn of(distribution: &str) -> Self {
        let program = system32("wsl.exe");
        let arguments = vec!["--terminate".to_owned(), distribution.to_owned()];
        Self::running(move || run_to_success(&program, &arguments))
    }

    /// A guard over `command`, which a case that has to see what it did makes of an action on a
    /// path it holds as data.
    fn running(command: impl FnMut() -> Result<(), String> + 'static) -> Self {
        Self {
            command: Box::new(command),
            ran: false,
        }
    }

    /// Runs the command, when it has not run, and says why when it does not succeed.
    fn end(&mut self) -> Result<(), String> {
        if std::mem::replace(&mut self.ran, true) {
            return Ok(());
        }
        (self.command)()
    }
}

impl Drop for Terminate {
    fn drop(&mut self) {
        if let Err(why) = self.end() {
            let _ = writeln!(std::io::stderr(), "{why}");
        }
    }
}

/// Records `wsl.exe` running a command in the distribution, and ends the distribution again when
/// both lists showed it registered and stopped, whichever way the case ends, and fails the case when
/// ending it does not succeed. A distribution whose state the lists leave unknown is left as it is.
#[test]
#[ignore = records!()]
fn record_wsl_exe() {
    assert!(
        std::env::var(WSL_SWITCH).is_ok_and(|value| value == "1"),
        "this case starts the Windows Subsystem for Linux distribution; set {WSL_SWITCH}=1 where \
         that is wanted"
    );
    let distribution =
        std::env::var("KR_WSL_DISTRIBUTION").unwrap_or_else(|_| "Ubuntu-24.04".into());
    println!(
        "wsl before: {}",
        wsl_text(&["--list", "--verbose"])
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    let was_stopped = is_stopped(
        &distribution,
        &wsl_text(&["--list", "--quiet"]),
        &wsl_text(&["--list", "--running", "--quiet"]),
    );
    let mut command = CommandBuilder::new(system32("wsl.exe"));
    command.args([
        "--distribution",
        &distribution,
        "--exec",
        "/bin/sh",
        "-c",
        "echo kr-capture-wsl",
    ]);
    // The guard is made before the distribution is started, and only for one the lists showed
    // stopped.
    let mut terminate = was_stopped.then(|| Terminate::of(&distribution));
    let recorded = record_in_a_pseudo_console(command, 24, 100);
    if let Some(terminate) = terminate.as_mut() {
        terminate.end().unwrap_or_else(|why| panic!("{why}"));
        println!("wsl --terminate {distribution}: ended");
    }
    println!(
        "wsl after: {}",
        wsl_text(&["--list", "--verbose"])
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_the_source_ran("wsl-exe", "kr-capture-wsl", &recorded);
    write_recording(
        "wsl-exe",
        &format!("wsl.exe --distribution {distribution} --exec /bin/sh -c \"echo kr-capture-wsl\""),
        "kr-capture-wsl",
        &recorded,
    );
}

/// Whether a `whoami /groups /fo csv /nh` listing names an integrity level, which it does by the
/// level's SID, a field that begins `S-1-16-`, and not by the group's name, which the system
/// translates.
fn names_an_integrity_level(listing: &str) -> bool {
    listing.contains(",\"S-1-16-")
}

/// Whether this account is in the Administrators group.
fn is_in_administrators() -> bool {
    let output = Command::new(system32("whoami.exe"))
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami runs");
    assert!(output.status.success(), "whoami /groups failed");
    let listing = String::from_utf8_lossy(&output.stdout);
    // Every account's listing names the integrity level it runs at, so a listing without one is not
    // one, and an account is not taken for a standard one on the strength of an answer that is empty.
    assert!(
        names_an_integrity_level(&listing),
        "whoami /groups listed no integrity level: {listing:?}"
    );
    listing.contains("S-1-5-32-544")
}

/// Runs a program of the system directory and fails when it does not succeed.
fn run_ok(program: &Path, arguments: &[&str]) {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .expect("the program runs");
    assert!(
        output.status.success(),
        "{} {arguments:?}: {}{}",
        program.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A directory this case made and is to leave no trace of: it is removed, with what is in it, when
/// this is dropped, whichever way the case ends. The removal is tried once; a failure of it is
/// written to the error output, without a panic that would end the process during an unwinding.
struct Made(PathBuf);

impl Made {
    /// Makes `path`, which must not be there.
    fn directory(path: PathBuf) -> Self {
        std::fs::create_dir(&path).expect("the directory");
        Self(path)
    }
}

impl Drop for Made {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "{} is not removed: {error}",
                    self.0.display()
                );
            }
        }
    }
}

/// Records `ssh.exe` signed in to this machine's own `sshd` as this account, with a key pair made in
/// this account's profile and authorised only for this account, and removes the pair again.
///
/// It runs only as an account that is not an administrator and that is disposable, because it
/// writes the account's `.ssh` directory.
#[test]
#[ignore = records!()]
fn record_ssh_exe() {
    assert!(
        std::env::var(SSH_SWITCH).is_ok_and(|value| value == "1"),
        "this case signs in to this machine's sshd as the account that runs it; set {SSH_SWITCH}=1 \
         where that account is disposable"
    );
    assert!(
        !is_in_administrators(),
        "this case writes an account's .ssh directory; an administrator's is not one to write"
    );
    let profile = PathBuf::from(std::env::var_os("USERPROFILE").expect("the profile"));
    let account = std::env::var("USERNAME").expect("the account");
    let directory = profile.join(".ssh");
    assert!(
        !directory.exists(),
        "{} is there already; this case makes it and removes it",
        directory.display()
    );
    let made = Made::directory(directory.clone());
    let key = directory.join("kr_capture");
    let ssh_directory = system32("OpenSSH");
    run_ok(
        &ssh_directory.join("ssh-keygen.exe"),
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            &key.display().to_string(),
        ],
    );
    std::fs::copy(
        directory.join("kr_capture.pub"),
        directory.join("authorized_keys"),
    )
    .expect("the account authorises its own key");
    let known_hosts = directory.join("known_hosts");
    let mut command = CommandBuilder::new(ssh_directory.join("ssh.exe"));
    command.args([
        "-tt",
        "-i",
        &key.display().to_string(),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts.display()),
        &format!("{account}@127.0.0.1"),
        "echo kr-capture-ssh",
    ]);
    let recorded = record_in_a_pseudo_console(command, 24, 100);
    drop(made);
    assert!(
        !directory.exists(),
        "{} is removed again",
        directory.display()
    );
    assert_the_source_ran("ssh-exe", "kr-capture-ssh", &recorded);
    write_recording(
        "ssh-exe",
        "ssh.exe -tt -i <the account's own key> -o BatchMode=yes -o StrictHostKeyChecking=accept-new <the account>@127.0.0.1 \"echo kr-capture-ssh\"",
        "kr-capture-ssh",
        &recorded,
    );
}

#[test]
fn an_integrity_level_is_named_by_its_sid_whatever_the_language() {
    // The words of the first field are translated and the SID is not. The level's row has no
    // attributes. The first listing has the shape `whoami` prints in English; the second is an example
    // of a translation, not a recording.
    let english = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n\
                   \"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"\"\r\n";
    let translated = "\"Tout le monde\",\"Groupe connu\",\"S-1-1-0\",\"Groupe obligatoire\"\r\n\
                      \"Etiquette obligatoire\\Niveau moyen\",\"Etiquette\",\"S-1-16-8192\",\"\"\r\n";
    assert!(names_an_integrity_level(english));
    assert!(names_an_integrity_level(translated));
    assert!(
        !names_an_integrity_level(""),
        "an empty answer names no level"
    );
    assert!(
        !names_an_integrity_level(
            "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n"
        ),
        "a listing of groups without a level names none"
    );
}

/// A name that no other run has: the process's number and a random part.
fn unique(prefix: &str) -> String {
    let random = kr_ipc::new_uuid().to_string().replace('-', "");
    format!("{prefix}-{}-{}", std::process::id(), &random[..12])
}

/// The self-test of `Made`, over a parent directory it makes itself: the parent is made with
/// `create_dir`, which fails when something is there already, so what is in it and removed with it
/// is the test's own and a directory that is not is refused and left as it is.
fn check_a_made_directory_is_removed_with_what_is_in_it(parent: &Path) {
    std::fs::create_dir(parent).expect("a parent directory that was not there");
    let directory = parent.join(".ssh");
    let failed = std::panic::catch_unwind(|| {
        let _made = Made::directory(directory.clone());
        std::fs::write(directory.join("kr_capture"), b"a private key").expect("a key");
        std::fs::write(directory.join("authorized_keys"), b"its public half").expect("a file");
        panic!("a step after the directory was made fails");
    });
    let left = directory.exists();
    if left {
        // A run that is red removes what it made.
        let _ = std::fs::remove_dir_all(&directory);
    }
    std::fs::remove_dir(parent).expect("the parent directory, which holds nothing now, is removed");
    assert!(failed.is_err(), "the step failed");
    assert!(!left, "the directory and the key in it are left behind");
}

#[test]
fn a_directory_made_for_a_case_that_then_fails_is_removed_with_what_is_in_it() {
    check_a_made_directory_is_removed_with_what_is_in_it(
        &std::env::temp_dir().join(unique("kr-made-directory")),
    );
}

#[test]
fn a_parent_directory_that_is_there_already_is_refused_and_left_as_it_is() {
    let there = Made::directory(std::env::temp_dir().join(unique("kr-made-there")));
    std::fs::write(there.0.join("kept"), b"not the test's to remove").expect("a file in it");
    let refused = std::panic::catch_unwind(|| {
        check_a_made_directory_is_removed_with_what_is_in_it(&there.0);
    });
    assert!(refused.is_err(), "a parent that is there is refused");
    assert_eq!(
        std::fs::read(there.0.join("kept")).expect("the file is still there"),
        b"not the test's to remove"
    );
}

/// A guard that ends a distribution runs its command when the case that holds it fails, runs it
/// once, and the case fails when the command does not succeed. The command here is a closure that
/// makes a directory with `std::fs::create_dir`, in a folder whose name holds `&`, in place of
/// `wsl.exe --terminate`, which this case must not run on a distribution it did not start; the
/// command that fails is `cmd.exe` exiting with 3.
#[test]
fn a_distribution_the_case_started_is_ended_when_the_case_fails_after_that() {
    // The marker is in a folder whose name holds `&`, which `cmd.exe` would read as the end of a
    // command: the stand-in makes it as data, without a shell.
    let parent = std::env::temp_dir().join(unique("kr-a&b-terminate-test"));
    std::fs::create_dir(&parent).expect("a folder that was not there");
    let marker = parent.join("made");
    let make = |marker: PathBuf| {
        Terminate::running(move || {
            std::fs::create_dir(&marker).map_err(|error| format!("{}: {error}", marker.display()))
        })
    };
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _terminate = make(marker.clone());
        panic!("a step after the distribution was started fails");
    }));
    let ran = marker.is_dir();
    let removed = std::fs::remove_dir(&marker);

    // Asked for, it runs once, and the drop after that does not run it again: what the command
    // made is taken away before the drop, so a second run would make it again.
    let mut asked = make(marker.clone());
    let first = asked.end();
    let second = asked.end();
    let ran_once = marker.is_dir();
    let taken_away = std::fs::remove_dir(&marker);
    drop(asked);
    let ran_again = marker.exists();
    let _ = std::fs::remove_dir(&marker);

    // A command that does not succeed is the case's failure.
    let mut failing = Terminate::running(|| {
        run_to_success(
            &system32("cmd.exe"),
            &["/c".into(), "exit".into(), "3".into()],
        )
    });
    let refused = failing.end();
    let stray = std::fs::read_dir(&parent).map(|entries| entries.count());
    let parent_removed = std::fs::remove_dir(&parent);

    assert!(failed.is_err(), "the step failed");
    assert!(ran, "the guard ended the distribution when the case failed");
    removed.expect("the directory the command made is removed");
    assert!(first.is_ok() && second.is_ok(), "{first:?} {second:?}");
    assert!(ran_once, "and a command that was asked for ran");
    taken_away.expect("the directory the asked-for command made is removed");
    assert!(!ran_again, "the drop ran a command that had been run");
    assert!(
        refused.is_err_and(|why| why.contains("did not succeed")),
        "a command that does not succeed fails the case"
    );
    assert_eq!(
        stray.expect("the folder is read"),
        0,
        "nothing else was made in it"
    );
    parent_removed.expect("the folder holds nothing and is removed");
}

/// The distribution lists are read as the UTF-16 that `wsl.exe` writes even when the environment
/// asks it for UTF-8. It reads the lists and starts nothing; run it with `WSL_UTF8=1` set, which is
/// what it is about.
#[test]
#[ignore = "reads the Windows Subsystem for Linux's lists with WSL_UTF8=1 set, on a machine that has a distribution; it runs with --ignored by hand"]
fn the_distribution_lists_are_read_when_the_environment_asks_wsl_for_utf8() {
    assert!(
        std::env::var("WSL_UTF8").is_ok_and(|value| value == "1"),
        "this case is about an environment that asks wsl.exe for UTF-8; set WSL_UTF8=1"
    );
    let distribution =
        std::env::var("KR_WSL_DISTRIBUTION").unwrap_or_else(|_| "Ubuntu-24.04".into());
    let registered = wsl_text(&["--list", "--quiet"]);
    let names = listed_names(&registered);
    assert!(
        names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&distribution)),
        "the list names {distribution}, as the recording case reads it: {registered:?}"
    );
}

/// UTF-16 text, little-endian, as `wsl.exe` writes it.
fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn a_distribution_is_stopped_by_its_complete_name_whatever_the_language() {
    // The lists as `wsl.exe --list --quiet` and `--list --running --quiet` printed them, on build
    // 26100 with WSL 2.7.14.0, with Ubuntu-24.04 registered and stopped: its name and a line end in
    // UTF-16, and nothing at all for the running list.
    let registered = utf16_text(&utf16le("Ubuntu-24.04\r\n"));
    let running = utf16_text(&[]);
    assert!(is_stopped("Ubuntu-24.04", &registered, &running));

    // Lists of the same shape with two distributions, one whose name is the other's beginning. The
    // lists hold no state word, so a language that has other words reads the same.
    let both = "Ubuntu\r\nUbuntu-24.04\r\n";
    assert!(
        !is_stopped("Ubuntu", both, "Ubuntu\r\n"),
        "Ubuntu is running, and Ubuntu-24.04 being registered beside it does not make it stopped"
    );
    assert!(
        is_stopped("Ubuntu-24.04", both, "Ubuntu\r\n"),
        "Ubuntu-24.04 is not among the running ones, and Ubuntu's line does not make it so"
    );
    assert!(
        is_stopped("Ubuntu", both, "Ubuntu-24.04\r\n"),
        "Ubuntu is not among the running ones, and Ubuntu-24.04's line does not make it so"
    );
    assert!(
        !is_stopped("Ubuntu", both, "ubuntu\r\n"),
        "a name is matched without regard to case, so a running distribution is never ended"
    );
    assert!(
        !is_stopped("Debian", both, ""),
        "a distribution that is not registered is not one to end"
    );
    assert!(
        !is_stopped(
            "Ubuntu",
            both,
            "The Windows Subsystem for Linux has no running list\r\n"
        ),
        "a line that names no registered distribution leaves the state unknown, and unknown is not stopped"
    );
}
