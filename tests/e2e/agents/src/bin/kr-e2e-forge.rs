//! The forging launcher of the credential case: placed where the worker gives the shell its
//! launcher, with the real launcher beside it at `h/kr-hook`.
//!
//! For `launch -- <executable> <argv0> <arguments...>` it first makes one presentation to the
//! backend with a well-formed credential that is not the backend's, prints what the backend
//! answered, and then replaces itself with the real launcher in place, with the arguments it was
//! given, so the real launcher is the same process (the same identity) and makes the host's own
//! presentation for the same launch. Every other invocation runs the real launcher unchanged.
//!
//! The helper reads the launch record the backend wrote beside the registration, through the
//! directory of `KALAREACH_E2E_FORGE_ROOT` and a walk that follows no link at any component below
//! it; the registration, the record's endpoint and its credential file must lie below that root,
//! and the endpoint's last component must be a socket and not a link. It never reads the
//! credential file, writes no file, and bounds each wait on the backend.

#[cfg(unix)]
mod forge {
    use std::ffi::OsString;
    use std::io::{Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Component, Path, PathBuf};
    use std::time::Duration;

    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    /// The variable naming the directory every path the helper reads must lie below.
    const ROOT_VARIABLE: &str = "KALAREACH_E2E_FORGE_ROOT";
    /// The variable the host gives a launch, naming its registration.
    const REGISTRATION_VARIABLE: &str = "KR_REGISTRATION";
    /// The launch record's name beside the registration.
    const RECORD_FILE: &str = "launch";
    /// The bound on each wait on the backend.
    const BOUND: Duration = Duration::from_secs(5);
    /// The longest launch record read.
    const RECORD_AT_MOST: usize = 64 * 1024;
    /// A credential of the right form that is not the backend's.
    const FORGED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Why the helper did not present.
    enum Failure {
        /// A path is not below the root, or a link or the wrong kind of object is on the way:
        /// nothing is presented and nothing runs.
        Nothing(String),
        /// The presentation itself did not complete (no answer within the bound): the real
        /// launcher runs all the same.
        Stream(String),
    }

    fn nothing(why: impl Into<String>) -> Failure {
        Failure::Nothing(why.into())
    }

    /// The real launcher: `h/kr-hook` beside this program.
    fn real_launcher() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|own| own.parent().map(|directory| directory.join("h/kr-hook")))
            .unwrap_or_else(|| PathBuf::from("h/kr-hook"))
    }

    /// Replaces this process with the real launcher and `arguments`.
    fn exec_real(arguments: &[OsString]) -> std::process::ExitCode {
        let error = std::process::Command::new(real_launcher())
            .args(arguments)
            .exec();
        eprintln!("kr-e2e-forge: the real launcher does not start: {error}");
        std::process::ExitCode::from(127)
    }

    /// The directory `target` below `root`, opened by a walk from `root` that follows no link at
    /// any component below it.
    fn walk(root: &OwnedFd, root_path: &Path, target: &Path) -> Result<OwnedFd, Failure> {
        let relative = target
            .strip_prefix(root_path)
            .map_err(|_| nothing(format!("{} is not below the root", target.display())))?;
        let mut directory = rustix::io::fcntl_dupfd_cloexec(root, 0)
            .map_err(|error| nothing(format!("the root is not held: {error}")))?;
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(nothing(format!("{} is not a plain path", target.display())));
            };
            directory = rustix::fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                nothing(format!(
                    "a component is not a directory of the run: {error}"
                ))
            })?;
        }
        Ok(directory)
    }

    /// The launch record's text: a regular file of the directory, opened with no link followed
    /// and without waiting.
    fn read_record(directory: &OwnedFd) -> Result<Vec<u8>, Failure> {
        let file = rustix::fs::openat(
            directory,
            RECORD_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| nothing(format!("the launch record is not opened: {error}")))?;
        let stat = rustix::fs::fstat(&file).map_err(|error| nothing(error.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(nothing("the launch record is not a regular file"));
        }
        let mut bytes = Vec::new();
        std::fs::File::from(file)
            .take(RECORD_AT_MOST as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| nothing(format!("the launch record is not read: {error}")))?;
        if bytes.len() > RECORD_AT_MOST {
            return Err(nothing("the launch record is too long"));
        }
        Ok(bytes)
    }

    /// This process's environment as text, as the real launcher presents it to a backend that
    /// starts a server with it.
    fn environment_text() -> Result<std::collections::BTreeMap<String, String>, Failure> {
        let mut text = std::collections::BTreeMap::new();
        let mut bytes = 0_usize;
        for (name, value) in std::env::vars_os() {
            let (Some(name), Some(value)) = (name.to_str(), value.to_str()) else {
                return Err(Failure::Stream("a variable is not text".to_owned()));
            };
            bytes = bytes.saturating_add(name.len() + value.len());
            if bytes > kr_protocol::root::MAX_PRESENTED_ENVIRONMENT_BYTES {
                return Err(Failure::Stream("the environment is too long".to_owned()));
            }
            text.insert(name.to_owned(), value.to_owned());
        }
        Ok(text)
    }

    /// Makes the one forged presentation of this launch: whether the backend admitted it.
    fn present(invocation: &[OsString]) -> Result<(bool, u64, u64), Failure> {
        let root_path = PathBuf::from(
            std::env::var_os(ROOT_VARIABLE)
                .ok_or_else(|| nothing("no root names where to read"))?,
        );
        let registration = PathBuf::from(
            std::env::var_os(REGISTRATION_VARIABLE).ok_or_else(|| nothing("no registration"))?,
        );
        let root = rustix::fs::open(
            &root_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| nothing(format!("the root is not opened: {error}")))?;
        let directory = walk(
            &root,
            &root_path,
            registration
                .parent()
                .ok_or_else(|| nothing("the registration names no directory"))?,
        )?;
        let record: serde_json::Value = serde_json::from_slice(&read_record(&directory)?)
            .map_err(|error| nothing(format!("the launch record is malformed: {error}")))?;
        let endpoint = PathBuf::from(
            record["endpoint"]
                .as_str()
                .ok_or_else(|| nothing("the record names no endpoint"))?,
        );
        let credential = PathBuf::from(
            record["credential"]
                .as_str()
                .ok_or_else(|| nothing("the record names no credential file"))?,
        );
        if !credential.starts_with(&root_path) || !endpoint.starts_with(&root_path) {
            return Err(nothing(
                "the endpoint and the credential file lie below the root",
            ));
        }
        // The endpoint's directory is walked with no link followed, and its last component is looked
        // at with no link followed: a connect would follow one.
        let endpoint_directory = walk(
            &root,
            &root_path,
            endpoint
                .parent()
                .ok_or_else(|| nothing("the endpoint names no directory"))?,
        )?;
        let name = endpoint
            .file_name()
            .ok_or_else(|| nothing("the endpoint names no file"))?;
        let looked = rustix::fs::statat(&endpoint_directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| nothing(format!("the endpoint is not looked at: {error}")))?;
        if FileType::from_raw_mode(looked.st_mode) != FileType::Socket {
            return Err(nothing("the endpoint is not a socket"));
        }
        let (executable, vector) = invocation
            .split_first()
            .ok_or_else(|| nothing("the launch names no executable"))?;
        let executable = executable
            .to_str()
            .ok_or_else(|| nothing("the executable is not text"))?;
        let arguments: Vec<&str> = vector
            .iter()
            .map(|argument| argument.to_str())
            .collect::<Option<_>>()
            .ok_or_else(|| nothing("an argument is not text"))?;
        let identity = kr_ipc::identity::process_start_identity(std::process::id())
            .map_err(|error| nothing(format!("this process is not identified: {error}")))?;
        let mut hello = serde_json::json!({
            "pid": identity.pid.get(),
            "start": identity.start_value.get(),
            "executable": executable,
            "arguments": arguments,
        });
        if record
            .get("gateway")
            .is_some_and(|gateway| !gateway.is_null())
            && let Some(members) = hello.as_object_mut()
        {
            members.insert(
                "environment".to_owned(),
                serde_json::json!(environment_text()?),
            );
        }
        let rest = serde_json::to_vec(&hello)
            .map_err(|error| Failure::Stream(format!("the hello is not written: {error}")))?;
        // The same frame as the real launcher's: the credential first, then the rest of the object.
        let mut line = Vec::new();
        line.extend_from_slice(br#"{"kr_launch":{"credential":""#);
        line.extend_from_slice(FORGED.as_bytes());
        line.extend_from_slice(br#"","#);
        line.extend_from_slice(rest.get(1..).unwrap_or_default());
        line.extend_from_slice(b"}\n");
        let mut stream = UnixStream::connect(&endpoint)
            .map_err(|error| Failure::Stream(format!("the endpoint is not reached: {error}")))?;
        stream
            .set_read_timeout(Some(BOUND))
            .and_then(|()| stream.set_write_timeout(Some(BOUND)))
            .map_err(|error| Failure::Stream(error.to_string()))?;
        stream
            .write_all(&line)
            .map_err(|error| Failure::Stream(format!("the frame is not written: {error}")))?;
        let mut answer = Vec::new();
        let mut byte = [0_u8; 1];
        while answer.len() < 4096 {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => answer.push(byte[0]),
                Err(error) => {
                    return Err(Failure::Stream(format!("the answer is not read: {error}")));
                }
            }
        }
        let admitted = String::from_utf8_lossy(&answer).contains("\"admitted\":true");
        Ok((admitted, identity.pid.get(), identity.start_value.get()))
    }

    pub fn main() -> std::process::ExitCode {
        let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
        let is_launch = arguments.first().is_some_and(|word| word == "launch")
            && arguments.get(1).is_some_and(|word| word == "--");
        if !is_launch {
            return exec_real(&arguments);
        }
        match present(&arguments[2..]) {
            Ok((admitted, pid, start)) => eprintln!(
                "kr-e2e-forge: pid {pid} start {start} forged presentation {}",
                if admitted { "admitted" } else { "refused" }
            ),
            Err(Failure::Nothing(why)) => {
                eprintln!("kr-e2e-forge: nothing presented: {why}");
                return std::process::ExitCode::from(1);
            }
            Err(Failure::Stream(why)) => eprintln!("kr-e2e-forge: no answer: {why}"),
        }
        exec_real(&arguments)
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    forge::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("kr-e2e-forge: built for Unix only");
    std::process::exit(2);
}
