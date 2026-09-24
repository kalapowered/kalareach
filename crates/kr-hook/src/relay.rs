//! The relay a launched agent runs to reach the worker that started it.
//!
//! It reads the registration the worker wrote for the launch, connects to the endpoint it names,
//! says who it is, and then carries bytes between its own standard input and output and that
//! connection, in the framing the registration names. It interprets nothing it carries.
//!
//! The worker authenticates it: the kernel names the process on a private socket, the credential
//! is the one the worker generated for this launch and wrote to an owner-only file, and the process
//! this relay reports is compared with the process the worker started. A relay that lied about any
//! of those would be refused by the host rather than by anything here.

use std::io::{Read as _, Write as _};
use std::time::Duration;

use crate::registration::{Endpoint, Paths, Registration};

/// How long the relay waits for the worker to finish publishing its launch.
///
/// Both files are written after the process starts, because the registration names the process.
pub const REGISTRATION_APPEARS_WITHIN: Duration = Duration::from_secs(10);

/// How long a relay started to close after its hello keeps the connection open first.
///
/// The worker reads the connecting process's identity when it accepts the connection, and that
/// reading needs the process to be there.
const HELD_BEFORE_CLOSING: Duration = Duration::from_millis(300);

/// Runs the relay until either end closes.
///
/// # Errors
///
/// Returns what went wrong, for the one line the caller writes to standard error.
pub fn run(close_after_hello: bool) -> Result<(), String> {
    let paths = Paths::from_environment()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "{} names the file this relay reads, and it is not set",
                crate::registration::REGISTRATION_VARIABLE
            )
        })?;
    let registration = Registration::read(&paths, REGISTRATION_APPEARS_WITHIN)
        .map_err(|error| error.to_string())?;
    let hello = registration
        .hello(None)
        .map_err(|error| error.to_string())?;
    let framed = kr_crypto::secret::SecretVec::new(registration.framing.encode(hello.expose()));
    drop(hello);
    connect_and_pump(&registration.endpoint, framed.expose(), close_after_hello)
}

/// Connects to the endpoint, says who this is, and carries bytes both ways until either end ends.
fn connect_and_pump(
    endpoint: &Endpoint,
    hello: &[u8],
    close_after_hello: bool,
) -> Result<(), String> {
    let mut stream = Connection::open(endpoint)?;
    stream
        .write_all(hello)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not say who this is: {error}"))?;

    if close_after_hello {
        std::thread::sleep(HELD_BEFORE_CLOSING);
        drop(stream);
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

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

/// One connection, whichever kind this platform bound.
enum Connection {
    #[cfg(unix)]
    Socket(std::os::unix::net::UnixStream),
    Loopback(std::net::TcpStream),
}

impl Connection {
    fn open(endpoint: &Endpoint) -> Result<Self, String> {
        match endpoint {
            #[cfg(unix)]
            Endpoint::PrivateSocket(path) => std::os::unix::net::UnixStream::connect(path)
                .map(Self::Socket)
                .map_err(|error| format!("could not reach {}: {error}", path.display())),
            #[cfg(not(unix))]
            Endpoint::PrivateSocket(path) => Err(format!(
                "could not reach {}: this platform has no private socket",
                path.display()
            )),
            Endpoint::Loopback(address) => std::net::TcpStream::connect(address)
                .map(Self::Loopback)
                .map_err(|error| format!("could not reach {address}: {error}")),
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            #[cfg(unix)]
            Self::Socket(stream) => stream.try_clone().map(Self::Socket),
            Self::Loopback(stream) => stream.try_clone().map(Self::Loopback),
        }
    }
}

impl std::io::Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Socket(stream) => stream.read(buffer),
            Self::Loopback(stream) => stream.read(buffer),
        }
    }
}

impl std::io::Write for Connection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Socket(stream) => stream.write(buffer),
            Self::Loopback(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Socket(stream) => stream.flush(),
            Self::Loopback(stream) => stream.flush(),
        }
    }
}
