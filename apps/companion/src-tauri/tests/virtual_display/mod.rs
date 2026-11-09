//! A virtual display for the checks that open a real window on a Linux host that has none.
//!
//! The window toolkit opens its windows on an X server. A host that runs the tests with no one
//! logged in, as a build server or a hosted runner does, has none, and no window can be opened on
//! it. The check then runs as a second copy of its own program under an `Xvfb` this module starts,
//! and the server is ended when the copy ends, whatever the copy came to, and when this process
//! goes (see `start`). The check runs in a copy
//! because the display is an environment variable, and a process cannot set one for itself
//! without `unsafe`, which the workspace forbids.
//!
//! A host that already has a display, a desktop or a wrapper such as `xvfb-run`, is used as it is.
//! A host with neither, and no `Xvfb` to start, stands down with a printed reason and passes,
//! unless `KR_REQUIRE_VIRTUAL_DISPLAY` is set: a run that has to show the window sets it, and the
//! check then fails.

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The switch that makes a host with no display, and no `Xvfb` to start one, a failed check.
const REQUIRE: &str = "KR_REQUIRE_VIRTUAL_DISPLAY";

/// How long the server is given to say which display it took.
///
/// Saying so is the server's own start, which on a host with every core busy takes as long as that
/// host takes; the wait ends the moment the server has said it, and an `Xvfb` that ends instead
/// ends the wait at once, so the bound only says that a server which does neither will not.
const SERVER_BOUND: Duration = Duration::from_secs(120);

/// Where the check is to run.
pub enum Hosted {
    /// This process has a display and shows the window on it.
    Here,
    /// The check ran as a second copy of this program under a display of its own, and this is the
    /// code the copy ended with.
    Ended(i32),
    /// There is no display and none could be started, and the check is not required to have one.
    /// Holds what to say.
    StandsDown(String),
    /// A display was needed and could not be had. Holds what to say.
    Failed(String),
}

/// Finds a display for the check, starting `Xvfb` and running the check under it where there is
/// none.
pub fn hosted() -> Hosted {
    if ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return Hosted::Here;
    }
    let (server, display) = match start() {
        Ok(started) => started,
        Err(Start::NotInstalled) => {
            let why = "this host has no display and no Xvfb to start one".to_owned();
            return if std::env::var_os(REQUIRE).is_some() {
                Hosted::Failed(format!("{REQUIRE} is set, and {why}"))
            } else {
                Hosted::StandsDown(why)
            };
        }
        Err(Start::Failed(why)) => return Hosted::Failed(why),
    };
    println!("host_events: the virtual display started, Xvfb {display}");
    let ran = std::env::current_exe().and_then(|program| {
        Command::new(program)
            .args(std::env::args_os().skip(1))
            // A virtual display has no graphics hardware, and the web view draws in software on it.
            .env("DISPLAY", &display)
            .env("GDK_BACKEND", "x11")
            .env("LIBGL_ALWAYS_SOFTWARE", "1")
            .env("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
            .env("NO_AT_BRIDGE", "1")
            .status()
    });
    // The server is ended whatever the check came to.
    drop(server);
    match ran {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt as _;

            if let Some(signal) = status.signal() {
                eprintln!("host_events: the check under Xvfb was ended by signal {signal}");
            }
            Hosted::Ended(status.code().unwrap_or(1))
        }
        Err(error) => Hosted::Failed(format!("the check could not be run under Xvfb: {error}")),
    }
}

/// Why a server was not started.
enum Start {
    /// There is no `Xvfb` on this host.
    NotInstalled,
    /// There is one, and it did not give a display.
    Failed(String),
}

/// How long a server is given to end once it has been asked to, before it is made to.
///
/// A server ends in a moment; the bound only says that one which does not will not hold the run.
const END_BOUND: Duration = Duration::from_secs(30);

/// A running `Xvfb`, ended when this is dropped.
///
/// It is asked to end first, with SIGTERM, so that it removes its socket under `/tmp/.X11-unix` as
/// it goes: a server that is killed outright leaves the socket behind. Only a server that has not
/// ended within [`END_BOUND`] is killed.
struct Server(Option<Child>);

impl Drop for Server {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        let pid = child.id();
        if !signal("TERM", pid) {
            // With no `kill` program to ask with, killing it is all that is left.
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(child.wait());
        });
        if receiver.recv_timeout(END_BOUND).is_err() {
            signal("KILL", pid);
            let _ = receiver.recv_timeout(END_BOUND);
        }
    }
}

/// Sends the signal `name` to `pid` with the `kill` program, and says whether it was sent.
fn signal(name: &str, pid: u32) -> bool {
    Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether `program` is an executable file in a directory of `PATH`.
fn on_path(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            std::fs::metadata(directory.join(program))
                .is_ok_and(|file| file.is_file() && file.permissions().mode() & 0o111 != 0)
        })
    })
}

/// Starts an `Xvfb` on a display it picks, and returns it with that display's name.
///
/// The server says the number it took on its standard output once it is serving, so no number is
/// guessed and no other run's display is taken.
///
/// The server is not to outlive this process, whatever ends it. Where the host has `setpriv`, the
/// server is started under it with `--pdeathsig TERM`, so the kernel signals the server when this
/// process goes: from the instant `setpriv` has set the signal, a few milliseconds after the start,
/// and so also in the time between the server saying its display and the copy starting. The signal
/// is tied to the thread that started the server, and this runs on the main thread, which lasts as
/// long as the process. `-terminate` covers a host without `setpriv`: the server then ends itself
/// when the last program using it goes, which ends it after a killed process only on the condition
/// that no X client outlives the copy (the D-Bus autolaunch of a host with `dbus-x11` and no
/// session bus starts one that stays until the server ends), and not at all when the process goes
/// before the copy has connected, because no client has then come or gone.
fn start() -> Result<(Server, String), Start> {
    if !on_path("Xvfb") {
        return Err(Start::NotInstalled);
    }
    let mut command = if on_path("setpriv") {
        let mut command = Command::new("setpriv");
        command.args(["--pdeathsig", "TERM", "--", "Xvfb"]);
        command
    } else {
        Command::new("Xvfb")
    };
    let mut child = command
        .args([
            "-displayfd",
            "1",
            "-screen",
            "0",
            "1280x720x24",
            "-nolisten",
            "tcp",
            "-terminate",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| Start::Failed(format!("Xvfb could not be started: {error}")))?;
    let stdout = child.stdout.take().expect("the server's output is piped");
    // From here the server is ended by the guard, whichever way this returns.
    let server = Server(Some(child));
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send(read.map(|_| line));
    });
    match receiver.recv_timeout(SERVER_BOUND) {
        Ok(Ok(line)) => match line.trim().parse::<u32>() {
            Ok(number) => Ok((server, format!(":{number}"))),
            Err(_) => Err(Start::Failed(format!(
                "Xvfb ended without saying which display it took: {line:?}"
            ))),
        },
        Ok(Err(error)) => Err(Start::Failed(format!(
            "Xvfb's output could not be read: {error}"
        ))),
        Err(_) => Err(Start::Failed(format!(
            "Xvfb did not say which display it took within {SERVER_BOUND:?}"
        ))),
    }
}
