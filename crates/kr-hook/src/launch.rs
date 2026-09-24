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
//! integration's flags added. The launcher presents itself to the backend, and on its admission
//! says it is going and execs the program in place. It keeps its process identity when it does,
//! so the registration the backend published before answering names the program before the program
//! runs, and every hook and channel the program starts finds it.
//!
//! Whatever else happens (the backend refuses, does not answer within [`ADMISSION_DEADLINE`], or
//! cannot be reached), the invocation runs as typed: the flags the backend's launch record names
//! are taken out again, the registration variable is taken out of the environment, and the typed
//! vector is executed. An agent started with the integration's flags and no backend behind them is
//! worse off than one started without them.

use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::registration::REGISTRATION_VARIABLE;

/// How long the launcher waits for the backend to admit it.
pub const ADMISSION_DEADLINE: Duration = Duration::from_secs(2);

/// The file beside the registration that says how to reach the backend and which flags it added.
pub const LAUNCH_RECORD_FILE: &str = "launch";

/// The longest launch record this launcher reads.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// The longest answer the backend writes.
const MAX_ANSWER_BYTES: u64 = 4096;

/// The variables that name a backend, taken out of a program that runs without one.
const LAUNCH_VARIABLES: [&str; 2] = [REGISTRATION_VARIABLE, "KR_CREDENTIAL"];

/// What the backend's launch record says.
#[derive(Debug, serde::Deserialize)]
struct Record {
    /// Where the backend's endpoint is.
    endpoint: String,
    /// The backend's owner-only credential file, beside the record.
    credential: String,
    /// The flags the integration added to the typed vector.
    added: Vec<String>,
}

/// Runs one invocation: presented and admitted, or as typed.
///
/// `invocation` is the executable and then its argument vector, command name first. The return is
/// the exit code of a launcher that could not run the program at all; a launcher that runs it does
/// not return.
#[must_use]
pub fn run(
    invocation: &[OsString],
    hold_after_admission: Option<Duration>,
) -> std::process::ExitCode {
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
    let record = match read_record(&registration) {
        Ok(record) => record,
        Err(why) => {
            crate::report(&format!(
                "the backend's launch record cannot be read ({why}), so the program runs without \
                 the integration"
            ));
            return exec(&executable, &vector, true);
        }
    };
    match present(&executable, &vector, &registration, &record) {
        Ok(mut admitted) => {
            if let Some(hold) = hold_after_admission {
                std::thread::sleep(hold);
            }
            if say_going(&mut admitted).is_ok() {
                drop(admitted);
                return exec(&executable, &vector, false);
            }
            crate::report("the backend's endpoint closed before the launch went ahead");
            drop(admitted);
            exec(&executable, &typed(&vector, &record.added), true)
        }
        Err(why) => {
            crate::report(&format!(
                "the backend did not admit this launch ({why}), so the program runs as typed"
            ));
            exec(&executable, &typed(&vector, &record.added), true)
        }
    }
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

/// Presents this process to the backend and waits for its admission.
#[cfg(unix)]
fn present(
    executable: &Path,
    vector: &[OsString],
    registration: &Path,
    record: &Record,
) -> Result<std::os::unix::net::UnixStream, String> {
    let started = Instant::now();
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
    let mut stream = std::os::unix::net::UnixStream::connect(endpoint)
        .map_err(|error| format!("the endpoint cannot be reached: {error}"))?;
    let remaining = ADMISSION_DEADLINE
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "the admission deadline passed".to_owned())?;
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|error| format!("the endpoint cannot be bounded: {error}"))?;
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
    stream
        .write_all(line.expose())
        .and_then(|()| stream.flush())
        .map_err(|error| format!("the endpoint cannot be written: {error}"))?;
    drop(line);
    let mut answer = String::new();
    let read = std::io::BufReader::new(std::io::Read::take(&stream, MAX_ANSWER_BYTES))
        .read_line(&mut answer)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "the backend did not answer in time".to_owned()
            }
            _ => format!("the endpoint cannot be read: {error}"),
        })?;
    if read == 0 {
        return Err("the backend refused it".to_owned());
    }
    let admitted =
        serde_json::from_str::<serde_json::Value>(answer.trim_end()).is_ok_and(|value| {
            value
                .get("kr_launch")
                .and_then(|launch| launch.get("admitted"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        });
    if admitted {
        Ok(stream)
    } else {
        Err("the backend answered something other than an admission".to_owned())
    }
}

/// A platform with no private socket has no backend to present to.
#[cfg(not(unix))]
fn present(
    _executable: &Path,
    _vector: &[OsString],
    _registration: &Path,
    _record: &Record,
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

/// Tells the backend the launch is going ahead.
#[cfg(unix)]
fn say_going(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
    stream.write_all(b"{\"kr_launch\":{\"going\":true}}\n")?;
    stream.flush()
}

#[cfg(not(unix))]
fn say_going(stream: &mut std::convert::Infallible) -> std::io::Result<()> {
    match *stream {}
}

/// Returns the vector as it was typed: the answered one with the flags the integration added taken
/// out again.
///
/// The integration adds its flags as one run, each once, so the run is taken out where it stands.
/// Where no such run is found, each flag's first appearance is.
#[must_use]
pub fn typed(vector: &[OsString], added: &[String]) -> Vec<OsString> {
    if added.is_empty() {
        return vector.to_vec();
    }
    let added_os: Vec<OsString> = added.iter().map(OsString::from).collect();
    if let Some(at) = vector
        .windows(added_os.len())
        .position(|window| window == added_os.as_slice())
    {
        let mut kept = vector.to_vec();
        kept.drain(at..at + added_os.len());
        return kept;
    }
    let mut kept = vector.to_vec();
    for flag in &added_os {
        if let Some(at) = kept.iter().position(|argument| argument == flag) {
            kept.remove(at);
        }
    }
    kept
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

    #[test]
    fn the_added_run_is_taken_out_where_it_stands() {
        let added = vec!["--flag".to_owned(), "value".to_owned()];
        assert_eq!(
            typed(
                &vector(&["claude", "--flag", "value", "--", "prompt"]),
                &added
            ),
            vector(&["claude", "--", "prompt"])
        );
        assert_eq!(
            typed(
                &vector(&["claude", "--model", "o", "--flag", "value"]),
                &added
            ),
            vector(&["claude", "--model", "o"])
        );
        assert_eq!(
            typed(&vector(&["claude"]), &[]),
            vector(&["claude"]),
            "nothing added, nothing taken"
        );
    }
}
