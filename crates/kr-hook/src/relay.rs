//! The relay a launched agent runs to reach the worker that started it.
//!
//! It reads the registration the worker wrote for the launch, connects to the endpoint it names,
//! says who it is, and then carries bytes between its own standard input and output and that
//! connection, in the framing the registration names. It interprets nothing it carries.
//!
//! The worker authenticates it: the kernel names the process on a private socket or a named pipe,
//! the credential is the one the worker generated for this launch and wrote to an owner-only file,
//! and the process this relay reports is compared with the process the worker started. A relay that
//! lied about any of those would be refused by the host rather than by anything here.

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
    let paths = Paths::from_environment().ok_or_else(|| {
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
#[cfg(unix)]
fn connect_and_pump(
    endpoint: &Endpoint,
    hello: &[u8],
    close_after_hello: bool,
) -> Result<(), String> {
    use std::io::{Read as _, Write as _};

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

/// One connection to a private socket.
#[cfg(unix)]
enum Connection {
    Socket(std::os::unix::net::UnixStream),
}

#[cfg(unix)]
impl Connection {
    fn open(endpoint: &Endpoint) -> Result<Self, String> {
        match endpoint {
            Endpoint::PrivateSocket(path) => std::os::unix::net::UnixStream::connect(path)
                .map(Self::Socket)
                .map_err(|error| format!("could not reach {}: {error}", path.display())),
            Endpoint::NamedPipe(name) => Err(format!(
                "could not reach {}{name}: this platform has no named pipe",
                crate::registration::PIPE_PREFIX
            )),
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            Self::Socket(stream) => stream.try_clone().map(Self::Socket),
        }
    }
}

#[cfg(unix)]
impl std::io::Read for Connection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Socket(stream) => stream.read(buffer),
        }
    }
}

#[cfg(unix)]
impl std::io::Write for Connection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Socket(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Socket(stream) => stream.flush(),
        }
    }
}

/// Connects to the endpoint, says who this is, and carries bytes both ways until the worker's end
/// ends.
///
/// A named pipe is read and written through one overlapped handle, which a blocking read on one
/// thread and a blocking write on another could not share, so both directions run on one
/// single-threaded runtime. The relay ends when the worker's end does, as it does on Unix: standard
/// input ending only ends what is written to the worker.
#[cfg(windows)]
fn connect_and_pump(
    endpoint: &Endpoint,
    hello: &[u8],
    close_after_hello: bool,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt as _;

    let Endpoint::NamedPipe(name) = endpoint else {
        return Err("this platform has no private socket".to_owned());
    };
    let address = kr_ipc::paths::Endpoint::from_name(name.clone()).map_err(|error| {
        format!(
            "could not reach {}{name}: {error}",
            crate::registration::PIPE_PREFIX
        )
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the relay: {error}"))?;
    let outcome = runtime.block_on(async {
        let mut connection = kr_ipc::endpoint::Connection::connect(&address)
            .await
            .map_err(|error| {
                format!(
                    "could not reach {}{name}: {error}",
                    crate::registration::PIPE_PREFIX
                )
            })?;
        connection
            .write_all(hello)
            .await
            .and(connection.flush().await)
            .map_err(|error| format!("could not say who this is: {error}"))?;

        if close_after_hello {
            tokio::time::sleep(HELD_BEFORE_CLOSING).await;
            drop(connection);
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        let (mut reading, mut writing) = tokio::io::split(connection);
        let outward = async {
            let mut input = tokio::io::stdin();
            let _ = tokio::io::copy(&mut input, &mut writing).await;
            let _ = writing.flush().await;
            // Standard input ending ends only what is written to the worker; the answers still
            // come back until the worker ends its side.
            std::future::pending::<()>().await;
        };
        let inward = async {
            let mut output = tokio::io::stdout();
            let _ = tokio::io::copy(&mut reading, &mut output).await;
            let _ = output.flush().await;
        };
        tokio::select! {
            () = outward => {}
            () = inward => {}
        }
        Ok(())
    });
    // A read of standard input that is still waiting is a blocking task, and the process is about
    // to end: it must not hold the end back.
    runtime.shutdown_background();
    outcome
}
