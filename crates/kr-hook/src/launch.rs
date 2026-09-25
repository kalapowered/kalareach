//! `kr-hook launch`: the launcher an integrated invocation runs through.
//!
//! When the worker establishes a backend for an integrated invocation, the shell runs this in the
//! child it forked for that invocation, with the backend's registration path in its environment:
//!
//! ```text
//! kr-hook launch -- <executable> <command name> <arguments...>
//! ```
//!
//! The vector after the executable is the one the worker answered: what was typed, with the
//! integration's flags added. The registration's file name, `registration.<at>.<count>`, says where
//! those flags stand, so what was typed is known from the variable alone. The launcher presents
//! itself to the backend and, once admitted, says it is going; once the backend says the launch is
//! committed, it execs the program in place. It keeps its process identity when it does, so the
//! registration the backend published names the program before the program runs, and every hook and
//! channel the program starts finds it.
//!
//! Whatever else happens (the backend refuses, does not answer within its deadline, does not
//! commit, or cannot be reached), the invocation runs as typed: the registration variable is taken
//! out of the environment and the typed vector is executed. An agent started with the integration's
//! flags and no backend behind them is worse off than one started without them.

use std::ffi::OsString;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::registration::REGISTRATION_VARIABLE;

/// How long the launcher gives the backend to admit it, from the launcher's start: the connect,
/// every write and every read, together.
pub const ADMISSION_DEADLINE: Duration = Duration::from_secs(2);

/// How long the launcher gives the backend to commit the launch once it has said it is going.
pub const COMMIT_DEADLINE: Duration = Duration::from_secs(2);

/// The file beside the registration that says how to reach the backend.
pub const LAUNCH_RECORD_FILE: &str = "launch";

/// The start of a registration file's name; the rest says where the added flags stand.
pub const REGISTRATION_PREFIX: &str = "registration.";

/// The longest launch record this launcher reads.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// The longest answer the backend writes.
#[cfg(unix)]
const MAX_ANSWER_BYTES: usize = 4096;

/// How long the launcher waits before it connects again to an endpoint whose queue is full.
#[cfg(unix)]
const CONNECT_RETRY: Duration = Duration::from_millis(10);

/// The variables that name a backend, taken out of a program that runs without one.
const LAUNCH_VARIABLES: [&str; 2] = [REGISTRATION_VARIABLE, "KR_CREDENTIAL"];

/// The exit code of a launcher that runs nothing because its variable names no launch it could
/// have been given.
const EXIT_NOT_A_LAUNCH: u8 = 126;

/// What the backend's launch record says.
#[derive(Debug, serde::Deserialize)]
struct Record {
    /// Where the backend's endpoint is.
    endpoint: String,
    /// The backend's owner-only credential file, beside the record.
    credential: String,
}

/// Runs one invocation: presented, admitted and committed, or as typed.
///
/// `invocation` is the executable and then its argument vector, command name first. The return is
/// the exit code of a launcher that could not run the program at all; a launcher that runs it does
/// not return.
#[must_use]
pub fn run(
    invocation: &[OsString],
    hold_after_admission: Option<Duration>,
) -> std::process::ExitCode {
    let started = Instant::now();
    let Some((executable, vector)) = invocation
        .split_first()
        .filter(|(_, vector)| !vector.is_empty())
    else {
        crate::report("launch names no executable and no command to run");
        return std::process::ExitCode::from(crate::cli::EXIT_USAGE);
    };
    let executable = PathBuf::from(executable);
    let vector: Vec<OsString> = vector.to_vec();
    let Some(registration) = std::env::var_os(REGISTRATION_VARIABLE) else {
        // Not a launch: nothing names a backend, so the program runs exactly as it was given.
        return exec(&executable, &vector, false);
    };
    let registration = PathBuf::from(registration);
    let typed = match typed_vector(&registration, &vector) {
        Ok(typed) => typed,
        Err(why) => {
            crate::report(&format!(
                "{REGISTRATION_VARIABLE} names no launch this program could have been given ({why}), \
                 so nothing is run"
            ));
            return std::process::ExitCode::from(EXIT_NOT_A_LAUNCH);
        }
    };
    let record = match read_record(&registration) {
        Ok(record) => record,
        Err(why) => {
            crate::report(&format!(
                "the backend's launch record cannot be read ({why}), so the program runs as typed"
            ));
            return exec(&executable, &typed, true);
        }
    };
    match present(&executable, &vector, &registration, &record, started) {
        Ok(mut admitted) => {
            if let Some(hold) = hold_after_admission {
                std::thread::sleep(hold);
            }
            match go(&mut admitted) {
                Ok(()) => {
                    drop(admitted);
                    exec(&executable, &vector, false)
                }
                Err(why) => {
                    crate::report(&format!(
                        "the backend did not commit this launch ({why}), so the program runs as \
                         typed"
                    ));
                    drop(admitted);
                    exec(&executable, &typed, true)
                }
            }
        }
        Err(why) => {
            crate::report(&format!(
                "the backend did not admit this launch ({why}), so the program runs as typed"
            ));
            exec(&executable, &typed, true)
        }
    }
}

/// Returns what was typed: the answered vector without the added flags the registration's file
/// name places, `registration.<at>.<count>`.
///
/// # Errors
///
/// Returns why the name places no run of added flags in this vector.
pub fn typed_vector(registration: &Path, vector: &[OsString]) -> Result<Vec<OsString>, String> {
    let name = registration
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| "its file name is not text".to_owned())?;
    let (at, count) = name
        .strip_prefix(REGISTRATION_PREFIX)
        .and_then(|placed| placed.split_once('.'))
        .and_then(|(at, count)| Some((at.parse::<usize>().ok()?, count.parse::<usize>().ok()?)))
        .ok_or_else(|| format!("{name:?} does not say where the added flags stand"))?;
    let end = at
        .checked_add(count)
        .filter(|end| *end <= vector.len() && (count == 0 || at > 0))
        .ok_or_else(|| format!("{name:?} places added flags outside this vector"))?;
    let mut typed = vector.get(..at).unwrap_or_default().to_vec();
    typed.extend_from_slice(vector.get(end..).unwrap_or_default());
    Ok(typed)
}

/// Reads the launch record beside the registration, through the registration's directory and
/// without following a link.
fn read_record(registration: &Path) -> Result<Record, String> {
    let directory = registration
        .parent()
        .ok_or_else(|| format!("{} names no directory", registration.display()))?;
    let opened = cap_std::fs::Dir::open_ambient_dir(directory, cap_std::ambient_authority())
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let bytes = read_no_follow(&opened, Path::new(LAUNCH_RECORD_FILE), MAX_RECORD_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("the launch record is malformed: {error}"))
}

/// Reads one file in `directory`, refusing a link and anything past `limit` bytes, and returns its
/// bytes with its own metadata's verdict on who may read it.
fn read_no_follow(
    directory: &cap_std::fs::Dir,
    name: &Path,
    limit: u64,
) -> Result<Vec<u8>, String> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
    use std::io::Read as _;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|error| format!("{}: {error}", name.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", name.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", name.display()));
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        if metadata.uid() != kr_ipc::paths::current_uid() || metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "{} can be read by somebody other than this user",
                name.display()
            ));
        }
    }
    let mut content = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("{}: {error}", name.display()))?;
    if content.len() as u64 > limit {
        return Err(format!("{} is longer than {limit} bytes", name.display()));
    }
    Ok(content)
}

/// Presents this process to the backend and waits for its admission, all within
/// [`ADMISSION_DEADLINE`] of the launcher's start.
#[cfg(unix)]
fn present(
    executable: &Path,
    vector: &[OsString],
    registration: &Path,
    record: &Record,
    started: Instant,
) -> Result<std::os::unix::net::UnixStream, String> {
    let deadline = started + ADMISSION_DEADLINE;
    let credential = read_credential(registration, record)?;
    let identity = kr_ipc::identity::process_start_identity(std::process::id())
        .map_err(|error| format!("this process cannot be identified: {error}"))?;
    let executable_text = executable
        .to_str()
        .ok_or_else(|| "the executable's path is not text".to_owned())?;
    let arguments: Vec<&str> = vector
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<_>>()
        .ok_or_else(|| "an argument is not text".to_owned())?;
    let endpoint = Path::new(&record.endpoint);
    if !endpoint.is_absolute() {
        return Err("the launch record names no private endpoint".to_owned());
    }
    let mut stream = connect_by(endpoint, deadline)?;
    let rest = serde_json::json!({
        "pid": identity.pid.get(),
        "start": identity.start_value.get(),
        "executable": executable_text,
        "arguments": arguments,
    })
    .to_string();
    // `{"kr_launch":{"credential":"<hex>",` then the rest of the object without its opening brace.
    // The credential is hexadecimal, so it needs no escaping, and it is assembled in the host's own
    // zeroising buffer.
    let tail = rest.as_bytes().get(1..).unwrap_or_default();
    let opening: &[u8] = br#"{"kr_launch":{"credential":""#;
    let mut line = Vec::with_capacity(opening.len() + credential.len() + tail.len() + 4);
    line.extend_from_slice(opening);
    line.extend_from_slice(credential.expose());
    line.extend_from_slice(br#"","#);
    line.extend_from_slice(tail);
    line.extend_from_slice(b"}\n");
    let line = kr_crypto::secret::SecretVec::new(line);
    write_all_by(&mut stream, line.expose(), deadline)?;
    drop(line);
    let answer = read_line_by(&mut stream, deadline)?;
    if answers(&answer, "admitted") {
        Ok(stream)
    } else {
        Err("the backend answered something other than an admission".to_owned())
    }
}

/// Says the launch is going and waits, within [`COMMIT_DEADLINE`], for the backend to say it is
/// committed.
#[cfg(unix)]
fn go(stream: &mut std::os::unix::net::UnixStream) -> Result<(), String> {
    let deadline = Instant::now() + COMMIT_DEADLINE;
    write_all_by(stream, b"{\"kr_launch\":{\"going\":true}}\n", deadline)?;
    let answer = read_line_by(stream, deadline)?;
    if answers(&answer, "committed") {
        Ok(())
    } else {
        Err("the backend answered something other than a commit".to_owned())
    }
}

#[cfg(not(unix))]
fn go(stream: &mut std::convert::Infallible) -> Result<(), String> {
    match *stream {}
}

/// Returns true for the backend's `{"kr_launch":{"<word>":true}}`.
#[cfg(unix)]
fn answers(line: &str, word: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line).is_ok_and(|value| {
        value
            .get("kr_launch")
            .and_then(|launch| launch.get(word))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    })
}

/// The time left before `deadline`, or none once it has passed.
#[cfg(unix)]
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// Connects to the endpoint by `deadline`: on a non-blocking socket, and again while the kernel's
/// queue for the endpoint is full, so no connect waits past the deadline.
#[cfg(unix)]
fn connect_by(
    endpoint: &Path,
    deadline: Instant,
) -> Result<std::os::unix::net::UnixStream, String> {
    use rustix::io::Errno;
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
    let address = SocketAddrUnix::new(endpoint)
        .map_err(|error| format!("the endpoint cannot be named: {error}"))?;
    loop {
        let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
            .map_err(|error| format!("no socket could be made: {error}"))?;
        rustix::io::ioctl_fionbio(&socket, true)
            .map_err(|error| format!("the socket cannot be made non-blocking: {error}"))?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) => {
                let stream = std::os::unix::net::UnixStream::from(socket);
                stream
                    .set_nonblocking(false)
                    .map_err(|error| format!("the connection cannot be read: {error}"))?;
                return Ok(stream);
            }
            // The endpoint's queue is full: the same connect is tried again until the deadline.
            Err(Errno::AGAIN | Errno::INPROGRESS) => {
                let left = remaining(deadline).ok_or_else(|| {
                    "the endpoint's queue stayed full until the deadline".to_owned()
                })?;
                std::thread::sleep(CONNECT_RETRY.min(left));
            }
            Err(error) => return Err(format!("the endpoint cannot be reached: {error}")),
        }
    }
}

/// Writes all of `bytes` by `deadline`, each write given only the time left.
#[cfg(unix)]
fn write_all_by(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut written = 0;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        let left = remaining(deadline).ok_or_else(|| "the deadline passed".to_owned())?;
        stream
            .set_write_timeout(Some(left))
            .map_err(|error| format!("the endpoint cannot be bounded: {error}"))?;
        match stream.write(rest) {
            Ok(0) => return Err("the endpoint closed".to_owned()),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("the deadline passed".to_owned());
            }
            Err(error) => return Err(format!("the endpoint cannot be written: {error}")),
        }
    }
    Ok(())
}

/// Reads one line by `deadline`, each read given only the time left, so an answer that trickles
/// in cannot hold the launcher past it.
#[cfg(unix)]
fn read_line_by(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
) -> Result<String, String> {
    let mut line = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let left =
            remaining(deadline).ok_or_else(|| "the backend did not answer in time".to_owned())?;
        stream
            .set_read_timeout(Some(left))
            .map_err(|error| format!("the endpoint cannot be bounded: {error}"))?;
        match stream.read(&mut buffer) {
            Ok(0) if line.is_empty() => return Err("the backend refused it".to_owned()),
            Ok(0) => return Err("the endpoint closed in the middle of an answer".to_owned()),
            Ok(count) => {
                line.extend_from_slice(buffer.get(..count).unwrap_or_default());
                if let Some(end) = line.iter().position(|byte| *byte == b'\n') {
                    line.truncate(end);
                    return String::from_utf8(line)
                        .map_err(|_| "the backend's answer is not text".to_owned());
                }
                if line.len() > MAX_ANSWER_BYTES {
                    return Err("the backend's answer is too long".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("the backend did not answer in time".to_owned());
            }
            Err(error) => return Err(format!("the endpoint cannot be read: {error}")),
        }
    }
}

/// A platform with no private socket has no backend to present to.
#[cfg(not(unix))]
fn present(
    _executable: &Path,
    _vector: &[OsString],
    _registration: &Path,
    _record: &Record,
    _started: Instant,
) -> Result<std::convert::Infallible, String> {
    Err("this platform has no private endpoint to present to".to_owned())
}

/// Reads the backend's credential, which its record names beside the registration.
fn read_credential(
    registration: &Path,
    record: &Record,
) -> Result<kr_crypto::secret::SecretVec, String> {
    let credential = Path::new(&record.credential);
    let beside = credential.is_absolute()
        && credential
            .parent()
            .is_some_and(|directory| Some(directory) == registration.parent());
    let name = credential
        .file_name()
        .filter(|_| beside)
        .ok_or_else(|| "the launch record names a credential outside its directory".to_owned())?;
    let directory = registration
        .parent()
        .ok_or_else(|| "the registration names no directory".to_owned())?;
    let opened = cap_std::fs::Dir::open_ambient_dir(directory, cap_std::ambient_authority())
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let bytes = kr_crypto::secret::SecretVec::new(read_no_follow(
        &opened,
        Path::new(name),
        crate::registration::MAX_CREDENTIAL_BYTES,
    )?);
    let text = bytes.expose();
    let start = text
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    let trimmed = text.get(start..end).unwrap_or_default();
    if trimmed.len() != crate::registration::CREDENTIAL_HEX_LENGTH
        || !trimmed.iter().all(u8::is_ascii_hexdigit)
    {
        return Err("the credential is not the backend's".to_owned());
    }
    Ok(kr_crypto::secret::SecretVec::new(trimmed.to_vec()))
}

/// Runs the program in place of this process, and returns only when it could not be run.
#[cfg(unix)]
fn exec(executable: &Path, vector: &[OsString], without_backend: bool) -> std::process::ExitCode {
    use std::os::unix::process::CommandExt as _;
    let (name, arguments) = vector.split_first().map_or_else(
        || (executable.as_os_str().to_owned(), &[][..]),
        |(name, arguments)| (name.clone(), arguments),
    );
    let mut command = std::process::Command::new(executable);
    command.arg0(name).args(arguments);
    if without_backend {
        for variable in LAUNCH_VARIABLES {
            command.env_remove(variable);
        }
    }
    let error = command.exec();
    crate::report(&format!("{} cannot be run: {error}", executable.display()));
    std::process::ExitCode::from(if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

/// Runs the program and ends with its exit code, where a process cannot be replaced in place.
#[cfg(not(unix))]
fn exec(executable: &Path, vector: &[OsString], without_backend: bool) -> std::process::ExitCode {
    let arguments = vector.get(1..).unwrap_or_default();
    let mut command = std::process::Command::new(executable);
    command.args(arguments);
    if without_backend {
        for variable in LAUNCH_VARIABLES {
            command.env_remove(variable);
        }
    }
    match command.status() {
        Ok(status) => std::process::ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(crate::cli::EXIT_FAILURE),
        ),
        Err(error) => {
            crate::report(&format!("{} cannot be run: {error}", executable.display()));
            std::process::ExitCode::from(if error.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn typed(name: &str, parts: &[&str]) -> Result<Vec<OsString>, String> {
        typed_vector(&Path::new("/run/kr/c1/b2").join(name), &vector(parts))
    }

    #[test]
    fn the_registration_s_name_places_the_added_flags() {
        assert_eq!(
            typed(
                "registration.1.2",
                &["claude", "--flag", "value", "--", "prompt"]
            ),
            Ok(vector(&["claude", "--", "prompt"]))
        );
        assert_eq!(
            typed(
                "registration.3.2",
                &["claude", "--model", "o", "--flag", "value"]
            ),
            Ok(vector(&["claude", "--model", "o"]))
        );
        assert_eq!(
            typed("registration.0.0", &["claude", "-p"]),
            Ok(vector(&["claude", "-p"])),
            "nothing added, nothing taken"
        );
    }

    #[test]
    fn a_name_that_places_nothing_in_the_vector_is_not_a_launch() {
        for name in [
            "registration",
            "registration.x.2",
            "registration.1",
            "registration.2.9",
            "registration.0.1",
            "other.1.1",
        ] {
            assert!(typed(name, &["claude", "--flag"]).is_err(), "{name}");
        }
    }
}
