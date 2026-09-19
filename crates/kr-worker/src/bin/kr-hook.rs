//! The forwarder a launched agent runs to reach the worker that started it.
//!
//! Section 11 describes the pair: "a small registration file plus the core `kr-hook` forwarder".
//! This is the forwarder. It reads the registration the worker wrote for this launch, connects to
//! the endpoint it names, says who it is, and then carries bytes between the agent's own standard
//! input and output and that connection.
//!
//! It is deliberately small and it decides nothing. The worker authenticates it: the kernel names
//! the process on a private socket, the credential is the one the worker generated for this launch
//! and wrote to an owner-only file, and the process this forwarder reports is compared with the
//! process the worker started. A forwarder that lied about any of those would be refused by the
//! host rather than by anything here.
//!
//! Two paths come in through the environment, because an argument vector is visible in diagnostics
//! and section 12 keeps credentials out of one:
//!
//! * `KR_REGISTRATION` — the registration file: where to connect, which launch, which process.
//! * `KR_CREDENTIAL` — the owner-only file holding this launch's private exchange.
//!
//! Both are written after the process starts, because the registration names the process, so this
//! waits for them for a bounded time rather than failing the instant it starts.

use std::collections::BTreeMap;
use std::io::Write as _;

/// How long this forwarder waits for the worker to finish publishing its launch.
const REGISTRATION_APPEARS_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the registration is looked for again.
const LOOK_AGAIN: std::time::Duration = std::time::Duration::from_millis(20);

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(std::io::stderr(), "kr-hook: {failure}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let registration_path = required("KR_REGISTRATION")?;
    let credential_path = required("KR_CREDENTIAL")?;
    let registration = wait_for(&registration_path)?;
    let credential = wait_for(&credential_path)?;
    let fields = read_fields(&registration);
    let endpoint = fields
        .get("endpoint")
        .ok_or_else(|| "the registration names no endpoint".to_owned())?;
    let framing = fields.get("framing").map_or("json_lines", String::as_str);
    let hello = hello(credential.trim(), framing)?;
    connect_and_pump(endpoint, &hello)
}

/// Reads one required path out of the environment.
fn required(name: &str) -> Result<std::path::PathBuf, String> {
    std::env::var_os(name)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| format!("{name} names the file this forwarder reads, and it is not set"))
}

/// Waits for one file the worker writes after this process starts.
fn wait_for(path: &std::path::Path) -> Result<String, String> {
    let deadline = std::time::Instant::now() + REGISTRATION_APPEARS_WITHIN;
    loop {
        if let Ok(content) = std::fs::read_to_string(path) {
            return Ok(content);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "{} did not appear within {} seconds",
                path.display(),
                REGISTRATION_APPEARS_WITHIN.as_secs()
            ));
        }
        std::thread::sleep(LOOK_AGAIN);
    }
}

/// Reads the registration's `name=value` lines.
fn read_fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// Builds the one frame this forwarder writes before anything else.
fn hello(credential: &str, framing: &str) -> Result<Vec<u8>, String> {
    let pid = std::process::id();
    let identity = kr_ipc::identity::process_start_identity(pid)
        .map_err(|error| format!("this process cannot be read: {error}"))?;
    let body = serde_json::json!({
        "kr_hello": {
            "credential": credential,
            "pid": identity.pid.get(),
            "start": identity.start_value.get(),
            "session": std::env::var("KR_SESSION").ok(),
            "headers": serde_json::Map::new(),
        }
    })
    .to_string()
    .into_bytes();
    Ok(frame(&body, framing))
}

/// Wraps one body in the framing the registration named.
fn frame(body: &[u8], framing: &str) -> Vec<u8> {
    match framing {
        "length_prefixed" => {
            let mut framed = format!("{}\n", body.len()).into_bytes();
            framed.extend_from_slice(body);
            framed
        }
        "content_length" => {
            let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
            framed.extend_from_slice(body);
            framed
        }
        _ => {
            let mut framed = Vec::with_capacity(body.len() + 1);
            framed.extend_from_slice(body);
            framed.push(b'\n');
            framed
        }
    }
}

/// Connects to the endpoint, says who this is, and carries bytes both ways until either end ends.
#[cfg(unix)]
fn connect_and_pump(endpoint: &str, hello: &[u8]) -> Result<(), String> {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;

    // A private socket is a path and loopback is an address and a port. The registration renders
    // whichever this platform bound, and a path is the one that begins at the root.
    let mut stream = if endpoint.starts_with('/') {
        Connection::Socket(
            UnixStream::connect(endpoint)
                .map_err(|error| format!("could not reach {endpoint}: {error}"))?,
        )
    } else {
        Connection::Loopback(
            std::net::TcpStream::connect(endpoint)
                .map_err(|error| format!("could not reach {endpoint}: {error}"))?,
        )
    };
    stream
        .write_all(hello)
        .map_err(|error| format!("could not say who this is: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("could not say who this is: {error}"))?;

    // Both directions at once, each on its own thread, because either end may speak first and
    // neither waits for the other.
    let mut reading = stream
        .try_clone()
        .map_err(|error| format!("this connection cannot be read and written: {error}"))?;
    let outward = std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut chunk = [0_u8; 8192];
        while let Ok(read) = input.read(&mut chunk) {
            if read == 0 || stream.write_all(&chunk[..read]).is_err() {
                break;
            }
            let _ = stream.flush();
        }
    });
    let mut output = std::io::stdout().lock();
    let mut chunk = [0_u8; 8192];
    while let Ok(read) = reading.read(&mut chunk) {
        if read == 0 || output.write_all(&chunk[..read]).is_err() {
            break;
        }
        let _ = output.flush();
    }
    drop(outward);
    Ok(())
}

#[cfg(not(unix))]
fn connect_and_pump(endpoint: &str, hello: &[u8]) -> Result<(), String> {
    let _ = (endpoint, hello);
    Err(
        "this platform has no private socket, and its protected exchange is not built yet"
            .to_owned(),
    )
}

/// One connection, whichever kind this platform bound.
#[cfg(unix)]
enum Connection {
    Socket(std::os::unix::net::UnixStream),
    Loopback(std::net::TcpStream),
}

#[cfg(unix)]
impl Connection {
    fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            Self::Socket(stream) => stream.try_clone().map(Self::Socket),
            Self::Loopback(stream) => stream.try_clone().map(Self::Loopback),
        }
    }
}

#[cfg(unix)]
impl std::io::Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Socket(stream) => stream.read(buffer),
            Self::Loopback(stream) => stream.read(buffer),
        }
    }
}

#[cfg(unix)]
impl std::io::Write for Connection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Socket(stream) => stream.write(buffer),
            Self::Loopback(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Socket(stream) => stream.flush(),
            Self::Loopback(stream) => stream.flush(),
        }
    }
}
