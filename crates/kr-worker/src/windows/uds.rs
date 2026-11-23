//! A Unix-domain socket on Windows, and the process at the other end of one.
//!
//! The gateway's agent program speaks to a socket of this kind, so the gateway binds one here. What
//! an admission rests on is the **peer check**: the kernel names the process on the other end of a
//! connection (`SIO_AF_UNIX_GETPEERPID`) and that process's own token names its account, both read
//! before a byte of what the peer sent is. Nothing the connecting side says about itself is read.
//!
//! An elevated process of the same account counts as the owner: the check compares accounts, and
//! elevation is not one.
//!
//! The socket's file carries a protected list that names its owner only. That is defence in depth,
//! and no admission relies on it: a check at connect time is not something this module has shown
//! the system makes of a socket's file, and every account may traverse past a directory's list.
//!
//! A Windows build that does not name the process at the other end of a socket cannot be served, and
//! [`gateway_socket_names_its_peers`] says so once, before any launch is committed: the program is
//! then not told of a gateway and runs as typed. The probe binds a socket of its own in a private
//! folder, connects to it from this process and asks the control call who connected.
//!
//! The sockets are the operating system's own. The listening socket and the probe's sockets are made
//! here with `WSA_FLAG_NO_HANDLE_INHERIT`, so no process this worker starts can inherit one even in
//! the moment after it exists, and are handed to `uds_windows` to accept and to read and write.
//! Each is made non-blocking and registered with `async-io`'s reactor, and read and written through
//! the tokio traits. `uds_windows` makes the sockets it accepts inheritable and clears that a moment
//! later: the gap is the crate's, and a case measures where the flag stands afterwards.
//!
//! A socket's file is a reparse point of its own kind. Every read of it and every removal of it
//! opens it without following, and acts on what the open handle is: a path that names something
//! else by then is left alone. A bind learns which file is its own by connecting to the path and
//! finding that very connection in its own queue, the kernel naming this process as its maker, and
//! only a file so proved is protected or removed by the bind.

#![expect(
    unsafe_code,
    reason = "naming the process at the other end of a socket, lending a socket the reactor \
              registers, and marking a file for removal are calls whose guarantees only the \
              caller can state"
)]

use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{
    AsHandle as _, AsRawHandle as _, AsRawSocket, AsSocket, BorrowedSocket, FromRawSocket as _,
};
use std::path::Path;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use async_io::{Async, IoSafe};
use kr_protocol::identity::ProcessStartIdentity;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Networking::WinSock as sockets;
use windows_sys::Win32::Networking::WinSock::{SIO_AF_UNIX_GETPEERPID, WSAIoctl};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FileDispositionInfo, READ_CONTROL, SYNCHRONIZE, SetFileInformationByHandle, WRITE_DAC,
};
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_AF_UNIX;

use crate::broker::endpoint::WINDOWS_SOCKET_PATH_LIMIT;
use crate::windows::file::{self, Object};

/// How long the probe's own connection is waited for before the build is said not to answer.
///
/// The connection is made and accepted on one thread and stands in the listener's queue the moment
/// it is made, so this is only the bound on a system that does not behave so.
const PROBE_WAIT: Duration = Duration::from_secs(2);

/// How long each wait for the probe's connection lasts.
const PROBE_STEP: Duration = Duration::from_millis(10);

/// Starts the Windows socket interface for this process, once.
fn start_sockets() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let mut data = sockets::WSADATA::default();
        // SAFETY: the version asked for is 2.2, and `data` is a live local of the size the call
        // writes.
        let _ = unsafe { sockets::WSAStartup(0x0202, &raw mut data) };
    });
}

/// The failure the last socket call left, as the operating system states it.
fn last_socket_error() -> std::io::Error {
    // SAFETY: the call reads this thread's last socket error and has no other effect.
    std::io::Error::from_raw_os_error(unsafe { sockets::WSAGetLastError() })
}

/// The address of a socket at `path` and the length of it that the system is told.
fn address_of(path: &Path) -> std::io::Result<(sockets::SOCKADDR_UN, i32)> {
    let refused =
        |detail: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidInput, detail);
    let bytes = path
        .to_str()
        .ok_or_else(|| refused("the path is not text"))?
        .as_bytes();
    if bytes.contains(&0) {
        return Err(refused("the path has a NUL in it"));
    }
    let mut address = sockets::SOCKADDR_UN {
        sun_family: sockets::AF_UNIX,
        ..sockets::SOCKADDR_UN::default()
    };
    if bytes.len() >= address.sun_path.len() {
        return Err(refused("the path is longer than a socket's address holds"));
    }
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = i8::from_ne_bytes([*from]);
    }
    let length = std::mem::offset_of!(sockets::SOCKADDR_UN, sun_path) + bytes.len() + 1;
    Ok((address, i32::try_from(length).unwrap_or(i32::MAX)))
}

/// A new stream socket of the Unix family that no process this one starts can inherit, from the
/// moment it exists, and the length of the address of `path`.
///
/// `uds_windows` makes its sockets inheritable and clears that after, which a process started in
/// between could use; the flag here closes that. The socket belongs to the value returned and is
/// closed with it, whatever happens to the calls made on it.
fn new_socket_for(path: &Path) -> std::io::Result<(sockets::SOCKET, sockets::SOCKADDR_UN, i32)> {
    let (address, length) = address_of(path)?;
    start_sockets();
    // SAFETY: the values are plain, and no protocol information is given.
    let socket = unsafe {
        sockets::WSASocketW(
            i32::from(sockets::AF_UNIX),
            sockets::SOCK_STREAM,
            0,
            std::ptr::null(),
            0,
            sockets::WSA_FLAG_OVERLAPPED | sockets::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket == sockets::INVALID_SOCKET {
        return Err(last_socket_error());
    }
    Ok((socket, address, length))
}

/// Accepts one connection from the non-blocking listening socket `listener` and returns the socket
/// as the system made it, before anything is done to its flags.
///
/// `uds_windows` accepts a connection, makes the socket inheritable, and clears that, which leaves
/// a moment in which a process this worker starts could take it. A socket accepted from a listener
/// made without handle inheritance can start without it, and the case that reads it here says so.
fn accept_raw(listener: &impl AsRawSocket) -> std::io::Result<sockets::SOCKET> {
    let raw = usize::try_from(listener.as_raw_socket())
        .map_err(|_| std::io::Error::other("a socket handle that is not a handle"))?;
    // SAFETY: the listening socket is open for the call, and no address is asked for.
    let accepted = unsafe { sockets::accept(raw, std::ptr::null_mut(), std::ptr::null_mut()) };
    if accepted == sockets::INVALID_SOCKET {
        return Err(last_socket_error());
    }
    Ok(accepted)
}

#[cfg(test)]
thread_local! {
    /// Whether a case makes the clearing of the inherit flag fail on its own thread.
    static CLEAR_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Clears the flag that lets a process this one starts inherit `socket`.
fn clear_inherit(socket: sockets::SOCKET) -> std::io::Result<()> {
    #[cfg(test)]
    if CLEAR_FAILS.with(std::cell::Cell::get) {
        return Err(std::io::Error::other("the flag could not be cleared"));
    }
    // SAFETY: the socket is open and is a handle for this call, which changes one flag of it.
    let cleared = unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            socket as windows_sys::Win32::Foundation::HANDLE,
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
            0,
        )
    };
    if cleared == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Binds a listening socket at `path` that no process this one starts can inherit.
fn bind_uninheritable(path: &Path) -> std::io::Result<uds_windows::UnixListener> {
    let (socket, address, length) = new_socket_for(path)?;
    let raw =
        u64::try_from(socket).map_err(|_| std::io::Error::other("a socket that is not one"))?;
    // SAFETY: the socket was just made and nothing else holds it, so the listener owns it and
    // closes it when it is dropped, on every path below.
    let listener = unsafe { uds_windows::UnixListener::from_raw_socket(raw) };
    // SAFETY: the socket is open, and the address is a live local of the length told.
    if unsafe { sockets::bind(socket, (&raw const address).cast(), length) } != 0 {
        return Err(last_socket_error());
    }
    // SAFETY: the socket is open.
    if unsafe { sockets::listen(socket, 128) } != 0 {
        return Err(last_socket_error());
    }
    Ok(listener)
}

/// Connects a socket to the one at `path`, which no process this one starts can inherit.
fn connect_uninheritable(path: &Path) -> std::io::Result<uds_windows::UnixStream> {
    let (socket, address, length) = new_socket_for(path)?;
    let raw =
        u64::try_from(socket).map_err(|_| std::io::Error::other("a socket that is not one"))?;
    // SAFETY: as for the listener: the socket is new, and the stream owns it from here.
    let stream = unsafe { uds_windows::UnixStream::from_raw_socket(raw) };
    // SAFETY: the socket is open, and the address is a live local of the length told.
    if unsafe { sockets::connect(socket, (&raw const address).cast(), length) } != 0 {
        return Err(last_socket_error());
    }
    Ok(stream)
}

/// A socket lent to the reactor: it says which socket it is and nothing else.
#[derive(Debug)]
struct Registered<T>(T);

impl<T: AsRawSocket> AsSocket for Registered<T> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        // SAFETY: the socket belongs to `self.0`, which is not dropped or given up while this borrow
        // lives, because the borrow is tied to `self`.
        unsafe { BorrowedSocket::borrow_raw(self.0.as_raw_socket()) }
    }
}

impl Read for Registered<uds_windows::UnixStream> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for Registered<uds_windows::UnixStream> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

// SAFETY: reading and writing only call the socket's own read and write, which neither close the
// socket nor hand it to anything else, so the reactor's registration stays true.
unsafe impl IoSafe for Registered<uds_windows::UnixStream> {}

/// One accepted or connected byte stream.
///
/// It is read and written through the tokio traits, and dropping it closes the socket. A shutdown of
/// the writing half is a flush: the other end sees the stream end when this one is dropped.
#[derive(Debug)]
pub struct Stream {
    inner: Compat<Async<Registered<uds_windows::UnixStream>>>,
}

impl Stream {
    fn new(socket: uds_windows::UnixStream) -> std::io::Result<Self> {
        Ok(Self {
            inner: Async::new(Registered(socket))?.compat(),
        })
    }

    /// Connects to the socket at `path`.
    ///
    /// Only the cases that stand in for the connecting program use it: the product only accepts.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure.
    #[cfg(any(test, feature = "testing"))]
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        Self::new(uds_windows::UnixStream::connect(path)?)
    }

    /// Names the process at the other end of this connection and its account.
    ///
    /// The kernel names the process. That process is opened once, and its start identity and its
    /// token's account are both read from that one handle, so they describe one process and not two
    /// that held the identifier in turn. A process that has ended is refused, and so is one the
    /// kernel names differently once it is open. Nothing the connecting side wrote is read.
    ///
    /// # Errors
    ///
    /// Returns why the kernel did not name a process, or why the process could not be opened, is
    /// gone or has ended, or why its account could not be read.
    pub fn peer(&self) -> std::io::Result<Peer> {
        let socket = &self.inner.get_ref().get_ref().0;
        let named = peer_process_of(socket)?;
        let (process, owner) = kr_ipc::identity::running_process_start_identity_with(
            named,
            kr_ipc::starter::process_is_this_account,
        )
        .map_err(std::io::Error::other)?;
        let named_again = peer_process_of(socket)?;
        if named_again != named {
            return Err(std::io::Error::other(format!(
                "the kernel named process {named} and then process {named_again} for one connection"
            )));
        }
        Ok(Peer { process, owner })
    }
}

/// The process at the other end of a connection, as the kernel and that process's own handle say.
#[derive(Debug)]
pub struct Peer {
    /// The process and when it started.
    pub process: ProcessStartIdentity,
    /// Whether it runs as the account this process runs as.
    pub owner: bool,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Why a socket was not bound.
#[derive(Debug)]
pub enum BindFailure {
    /// The operating system refused the bind, or the socket could not be made ready.
    Bind(std::io::Error),
    /// This Windows build does not name the process at the other end of a socket, and what it said
    /// instead.
    NoPeerProcess(String),
    /// The socket's file could not be given the owner-only list it must carry, or does not carry it
    /// when read back from the file itself, or what stands at the path is not the socket this bind
    /// made. A file the bind proved to be its own was removed; anything else was left as found.
    Unprotected(String),
}

/// A bound, listening socket.
#[derive(Debug)]
pub struct Listener {
    inner: Async<Registered<uds_windows::UnixListener>>,
}

impl Listener {
    /// Binds a socket at `path`, which must not exist, and gives its file the owner-only list.
    ///
    /// What stands at the path after the bind is opened once, without following, and a connection
    /// to the path must come out of this listener's own queue before the file is taken for the one
    /// the bind made: a path that was replaced by then, by a file or by another socket, is left as
    /// it is and is neither protected nor removed. The list is set on that open handle, read back
    /// from it and required to be protected, so a directory whose inheritable list widens later
    /// does not reach the file. The identity of that file is returned with the listener: what the
    /// socket's end removes, and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`BindFailure::NoPeerProcess`] when this build cannot name the process at the other
    /// end of a connection, [`BindFailure::Bind`] when the system refuses, and
    /// [`BindFailure::Unprotected`] when the file's list cannot be set or read back as asked or the
    /// path is not the socket this bind made. A file proved to be the bind's own is removed when
    /// the bind fails after that; nothing else is.
    pub fn bind(path: &Path) -> Result<(Self, Object), BindFailure> {
        gateway_socket_names_its_peers().map_err(BindFailure::NoPeerProcess)?;
        let listener = bind_uninheritable(path).map_err(BindFailure::Bind)?;
        // Until the file is proved to be the bind's own, a failure leaves the path as it is: a
        // path cannot be named by identity before that, and removing by name would remove what
        // another program put there.
        let left_as_found = |detail: String| {
            BindFailure::Unprotected(format!(
                "the socket at {} could not be taken for the one this bind made, and is left as \
                 it is: {detail}",
                path.display()
            ))
        };
        listener
            .set_nonblocking(true)
            .map_err(|error| left_as_found(error.to_string()))?;
        #[cfg(test)]
        run_the_hook_after_the_bind(path);
        // The file the bind made is opened once, without following, and everything done to it is
        // done through that handle.
        let rights = FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | DELETE;
        let file = open_without_following(path, rights)
            .map_err(|error| left_as_found(format!("it could not be opened: {error}")))?;
        let made = prove_it_is_the_bound_socket(&listener, path, &file).map_err(left_as_found)?;
        // From here the handle holds the socket this bind made, and removing through it removes
        // that socket.
        match protect(&file, path) {
            Ok(()) => match Async::new(Registered(listener)) {
                Ok(inner) => Ok((Self { inner }, made)),
                Err(error) => {
                    let _ = delete_through(&file);
                    Err(BindFailure::Bind(error))
                }
            },
            Err(detail) => {
                drop(listener);
                let _ = delete_through(&file);
                Err(BindFailure::Unprotected(format!(
                    "the socket at {} is not owner-only: {detail}",
                    path.display()
                )))
            }
        }
    }

    /// Accepts one connection.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure.
    pub async fn accept(&self) -> std::io::Result<Stream> {
        let accepted = self
            .inner
            .read_with(|registered| accept_raw(&registered.0))
            .await?;
        // SAFETY: the socket was just accepted and nothing else holds it, so the stream owns it
        // from here and closes it when it is dropped, whatever the next call does.
        let owned = unsafe { uds_windows::UnixStream::from_raw_socket(accepted as u64) };
        // A socket the listening socket hands over is made as the listening socket is. Clearing the
        // flag again is a belt, and a case reads the socket before it.
        clear_inherit(accepted)?;
        Stream::new(owned)
    }
}

/// Shows that the open file at `path` is the socket `listener` bound, and returns its identity.
///
/// The file must be a socket's file, a connection to the path made here must reach `listener`'s own
/// queue, as the kernel's naming of the connection's maker shows, and the path must still name the
/// file's object afterwards. A path that names a file, or another
/// socket, or that was swapped again meanwhile, is none of those and is refused.
fn prove_it_is_the_bound_socket(
    listener: &uds_windows::UnixListener,
    path: &Path,
    file: &std::fs::File,
) -> Result<Object, String> {
    if file::reparse_tag_of(file).map_err(|error| error.to_string())?
        != Some(IO_REPARSE_TAG_AF_UNIX)
    {
        return Err("what stands there is not a socket's file".to_owned());
    }
    let made = file::object_of(file).map_err(|error| error.to_string())?;
    let _client = connect_uninheritable(path)
        .map_err(|error| format!("it could not be connected to: {error}"))?;
    let accepted = accept_within_the_wait(listener).map_err(|error| {
        format!("a connection to it did not reach the listener that bound it: {error}")
    })?;
    // The connection this listener takes first is not necessarily the one made above: another
    // process may have queued one before it replaced the path. The kernel names who made it, and
    // only this process's own connection proves the path led here.
    match peer_process_of(&accepted) {
        Ok(pid) if pid == std::process::id() => {}
        Ok(pid) => {
            return Err(format!(
                "the connection this listener accepted came from process {pid} and not from this \
                 one, so it does not show that the path leads to this socket"
            ));
        }
        Err(error) => {
            return Err(format!(
                "the process that made the accepted connection could not be named: {error}"
            ));
        }
    }
    if socket_object(path) != Some(made) {
        return Err("the path names another object than the one that was opened".to_owned());
    }
    Ok(made)
}

/// Gives the open file of a socket its protected owner-only list and reads the list back from the
/// same handle.
fn protect(file: &std::fs::File, path: &Path) -> Result<(), String> {
    kr_ipc::paths::protect_with_owner_only_list(file.as_handle())
        .map_err(|error| format!("its list could not be set: {error}"))?;
    kr_ipc::paths::check_access_list(file.as_handle(), &path.display().to_string(), true).map_err(
        |refusal| match refusal {
            kr_ipc::paths::AccessListRefusal::Policy(detail)
            | kr_ipc::paths::AccessListRefusal::Unreadable(detail) => detail,
        },
    )
}

/// Accepts one connection from a non-blocking `listener` that must already stand in its queue, and
/// waits no longer than [`PROBE_WAIT`] for it.
fn accept_within_the_wait(
    listener: &uds_windows::UnixListener,
) -> std::io::Result<uds_windows::UnixStream> {
    let mut waited = Duration::ZERO;
    loop {
        match accept_raw(listener) {
            // SAFETY: the socket was just accepted and nothing else holds it, so the stream owns it
            // and closes it when it is dropped.
            Ok(accepted) => {
                return Ok(unsafe { uds_windows::UnixStream::from_raw_socket(accepted as u64) });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && waited < PROBE_WAIT => {
                std::thread::sleep(PROBE_STEP);
                waited += PROBE_STEP;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
type AfterTheBind = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
thread_local! {
    /// What a case does to the path between the bind and the first open, on its own thread, once.
    static AFTER_THE_BIND: std::cell::RefCell<Option<AfterTheBind>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs, once, what a case put between the bind and the first open of the file.
#[cfg(test)]
fn run_the_hook_after_the_bind(path: &Path) {
    if let Some(hook) = AFTER_THE_BIND.with(|hook| hook.borrow_mut().take()) {
        hook(path);
    }
}

/// What the probe found, once for this process.
static PROBE: OnceLock<Result<(), String>> = OnceLock::new();

#[cfg(any(test, feature = "testing"))]
thread_local! {
    /// What a case makes the probe say on its own thread, in place of the build's answer.
    static FORCED: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// What a case that forces the control call to fail holds while it does: the failure is put back as
/// it was when this is dropped.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct ForcedProbeFailure(Option<String>);

#[cfg(any(test, feature = "testing"))]
impl Drop for ForcedProbeFailure {
    fn drop(&mut self) {
        FORCED.with(|forced| *forced.borrow_mut() = self.0.take());
    }
}

/// Makes the control call that names a connection's peer fail with `detail` on this thread until the
/// value returned is dropped, whatever the build answers.
///
/// The probe runs for real and says what it says of a failed call, so a case shows the refusal this
/// module writes, and not words the case wrote. While a failure is forced the probe is neither read
/// from the cache nor kept in it.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn force_the_ioctl_to_fail(detail: &str) -> ForcedProbeFailure {
    ForcedProbeFailure(FORCED.with(|forced| forced.borrow_mut().replace(detail.to_owned())))
}

/// Says whether this Windows build names the process at the other end of a Unix-domain socket.
///
/// It binds a socket in a private folder of its own, connects to it from this process, accepts and
/// asks the control call who connected, and requires it to name this process. The answer is read
/// once and kept for the life of the process: it is the build's, which does not change under a
/// running worker.
///
/// # Errors
///
/// Returns the refusal, which names the control call and the Windows build.
pub fn gateway_socket_names_its_peers() -> Result<(), String> {
    #[cfg(any(test, feature = "testing"))]
    if FORCED.with(|forced| forced.borrow().is_some()) {
        return probe();
    }
    PROBE.get_or_init(probe).clone()
}

/// Runs the probe in a folder of its own below the temporary directory, which it removes.
fn probe() -> Result<(), String> {
    probe_in(&std::env::temp_dir())
}

/// Runs the probe in a folder of its own below `base`, which it removes.
fn probe_in(base: &Path) -> Result<(), String> {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = base.join(format!("kr-q-{name}"));
    kr_ipc::paths::create_private_directory(&directory).map_err(|error| {
        format!(
            "the folder {} for asking this Windows build ({}) which process connects to a \
             Unix-domain socket could not be made: {error}",
            directory.display(),
            windows_build()
        )
    })?;
    // The folder is opened as itself, and what is removed is removed through handles: the socket
    // by the identity it had, and then the folder by the handle that opened it.
    let held = open_directory_without_following(
        &directory,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    .map_err(|error| {
        format!(
            "the folder {} for asking this Windows build ({}) which process connects to a \
             Unix-domain socket could not be opened: {error}",
            directory.display(),
            windows_build()
        )
    })?;
    let socket = directory.join("p.sock");
    let mut kept = None;
    let outcome = prove_the_build_names_a_peer(&socket, &mut kept);
    // Only the socket the probe made is removed, through the handle it opened right after its
    // bind: what stands at the path by now is not asked.
    if let Some(file) = kept.take() {
        let _ = delete_through(&file);
    }
    let _ = delete_through(&held);
    outcome
}

/// Binds a socket at `path`, connects to it from this process and reads the peer of the accepted
/// end.
fn prove_the_build_names_a_peer(
    path: &Path,
    kept: &mut Option<std::fs::File>,
) -> Result<(), String> {
    let build = windows_build();
    let own = std::process::id();
    match path.to_str() {
        None => {
            return Err(format!(
                "the probe's socket path {} is not text",
                path.display()
            ));
        }
        Some(text) if text.len() > WINDOWS_SOCKET_PATH_LIMIT => {
            return Err(format!(
                "the temporary directory leaves no room for the socket that asks this Windows \
                 build ({build}) which process connects to a Unix-domain socket: {text} is {} \
                 bytes and at most {WINDOWS_SOCKET_PATH_LIMIT} can be bound",
                text.len()
            ));
        }
        Some(_) => {}
    }
    let listener = bind_uninheritable(path).map_err(|error| {
        format!(
            "a Unix-domain socket could not be bound at {} on this Windows build ({build}): \
             {error}",
            path.display()
        )
    })?;
    // The file the bind made is opened at once and kept, so that what the probe removes is the
    // object that handle names and never what another process puts at the path afterwards.
    *kept = open_without_following(path, FILE_READ_ATTRIBUTES | DELETE)
        .ok()
        .filter(|file| file::reparse_tag_of(file).ok() == Some(Some(IO_REPARSE_TAG_AF_UNIX)));
    let _client = connect_uninheritable(path).map_err(|error| {
        format!(
            "the probe's socket at {} could not be connected to on this Windows build ({build}): \
             {error}",
            path.display()
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        format!(
            "the probe's socket could not be made non-blocking on this Windows build ({build}): \
             {error}"
        )
    })?;
    let accepted = accept_within_the_wait(&listener).map_err(|error| {
        format!(
            "the probe's socket did not accept its own connection on this Windows build \
             ({build}): {error}"
        )
    })?;
    match peer_process_of(&accepted) {
        Ok(pid) if pid == own => Ok(()),
        Ok(pid) => Err(format!(
            "this Windows build ({build}) answered SIO_AF_UNIX_GETPEERPID with process {pid} for a \
             connection from process {own}, so the process at the other end of a Unix-domain \
             socket cannot be told by it"
        )),
        Err(error) => Err(format!(
            "this Windows build ({build}) does not answer SIO_AF_UNIX_GETPEERPID ({error}), so the \
             process at the other end of a Unix-domain socket cannot be named"
        )),
    }
}

/// Asks the kernel for the process at the other end of a connected socket.
///
/// The count of bytes the call returns is not read: an older build answers with a valid process and
/// a count of zero. What is refused is no process.
fn peer_process_of(socket: &impl AsRawSocket) -> std::io::Result<u32> {
    #[cfg(any(test, feature = "testing"))]
    if let Some(forced) = FORCED.with(|forced| forced.borrow().clone()) {
        return Err(std::io::Error::other(forced));
    }
    let raw = usize::try_from(socket.as_raw_socket())
        .map_err(|_| std::io::Error::other("a socket handle that is not a handle"))?;
    let mut pid = 0_u32;
    let mut returned = 0_u32;
    let size = u32::try_from(std::mem::size_of::<u32>()).unwrap_or(0);
    // SAFETY: the socket is open for the call, there is no input, the output is a local of the size
    // told, and neither an overlapped structure nor a completion routine is given, so the call
    // finishes before it returns.
    let status = unsafe {
        WSAIoctl(
            raw,
            SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&raw mut pid).cast(),
            size,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        return Err(std::io::Error::other("the answer names no process"));
    }
    Ok(pid)
}

/// The Windows build this is, as the system states it.
#[must_use]
pub fn windows_build() -> String {
    let mut information = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap_or(0),
        ..OSVERSIONINFOW::default()
    };
    // SAFETY: `information` is a live buffer whose size field holds its size, as the call asks.
    let status = unsafe { RtlGetVersion(&raw mut information) };
    if status == 0 {
        format!(
            "Windows {}.{} build {}",
            information.dwMajorVersion, information.dwMinorVersion, information.dwBuildNumber
        )
    } else {
        "a Windows build the system did not state".to_owned()
    }
}

/// Opens what stands at `path` itself, a reparse point as the point and not what it names, with the
/// rights given.
fn open_without_following(path: &Path, rights: u32) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .access_mode(rights)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Opens the directory at `path` as itself, a reparse point as the point and not what it names, with
/// the rights and sharing given.
fn open_directory_without_following(
    path: &Path,
    rights: u32,
    share: u32,
) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .access_mode(rights)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// A directory held open, as itself, and the identity it had when it was opened.
///
/// The directory is opened with the right to traverse it, which takes part in sharing, and without
/// the sharing of delete: while it is held, no other open may ask for the right to rename it or
/// remove it, so its own name stays what it was. An open for its attributes alone takes no part in
/// sharing and would hold nothing. What is above it is not locked by this: whether a folder with an
/// open handle below it can be renamed is the file system's rule, which a guest records, and
/// [`HeldDirectory::is_still_named_by`] says where the path names another directory afterwards.
#[derive(Debug)]
pub struct HeldDirectory {
    held: std::fs::File,
    object: Object,
}

/// Opens and holds the directory at `path`.
///
/// # Errors
///
/// Returns the operating system's failure when the directory cannot be opened or its identity read.
pub fn hold_directory(path: &Path) -> std::io::Result<HeldDirectory> {
    let held = open_directory_without_following(
        path,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    let object = file::object_of(&held)?;
    Ok(HeldDirectory { held, object })
}

impl HeldDirectory {
    /// Returns where the held directory really is: its final path, every link in the way followed,
    /// as the system names it for the open handle.
    ///
    /// # Errors
    ///
    /// Returns the operating system's failure.
    pub fn final_path(&self) -> std::io::Result<std::path::PathBuf> {
        use std::os::windows::ffi::OsStringExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
        };
        let mut buffer = vec![0_u16; 512];
        loop {
            // SAFETY: the handle is open for the call, and the buffer is a live local of the
            // length told.
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    self.held.as_raw_handle().cast(),
                    buffer.as_mut_ptr(),
                    u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            };
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            if length == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if length < buffer.len() {
                return Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
                    &buffer[..length],
                )));
            }
            buffer.resize(length + 1, 0);
        }
    }

    /// Returns true when `path` names the directory that is held, opened now as itself.
    #[must_use]
    ///
    /// A directory that was converted to a junction in place keeps its object, and a path through it
    /// reaches what it points at, so the path must also name no link.
    pub fn is_still_named_by(&self, path: &Path) -> bool {
        let Ok(other) = open_directory_without_following(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) else {
            return false;
        };
        matches!(file::reparse_tag_of(&other), Ok(None))
            && file::object_of(&other).is_ok_and(|object| object == self.object)
    }
}

/// Turns an empty directory into a junction to `target` in place, as an account that may write to the
/// directory can whatever is held on it: the conversion changes what the path reaches and not the
/// object a handle holds.
#[cfg(test)]
pub(crate) fn convert_to_a_junction(directory: &Path, target: &Path) {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    let opened = open_directory_without_following(
        directory,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
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

/// The identity of the socket that stands at `path` now, or none where nothing does or something
/// else does.
///
/// A socket's file is a reparse point of its own kind, and the identity is the volume and id the
/// kernel gives the file object, the Windows analogue of a device and an inode.
#[must_use]
pub fn socket_object(path: &Path) -> Option<Object> {
    let file = open_without_following(path, FILE_READ_ATTRIBUTES).ok()?;
    (file::reparse_tag_of(&file).ok()? == Some(IO_REPARSE_TAG_AF_UNIX))
        .then(|| file::object_of(&file).ok())
        .flatten()
}

/// Removes what stands at `path` only when it is the socket whose identity `made` is: a path that
/// names another socket, a file or nothing is left as it is, because it is not what a bind made.
///
/// The identity is read from the handle that then removes the file, so a path that is replaced
/// between the two is not removed in its place.
pub fn remove_socket_made(path: &Path, made: Object) {
    let Ok(file) = open_without_following(path, FILE_READ_ATTRIBUTES | DELETE) else {
        return;
    };
    let is_the_socket = file::reparse_tag_of(&file).ok() == Some(Some(IO_REPARSE_TAG_AF_UNIX))
        && file::object_of(&file).ok() == Some(made);
    if is_the_socket {
        let _ = delete_through(&file);
    }
}

/// Marks the file an open handle names for removal when its last handle closes.
fn delete_through(file: &std::fs::File) -> std::io::Result<()> {
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle is open for the call with the right to delete, and the structure is a local
    // of the size told.
    let set = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            std::ptr::from_ref(&information).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(0),
        )
    };
    if set == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Checks the access list of what stands at `path`, read from the object itself and not from what
/// it names.
///
/// # Errors
///
/// Returns why the list cannot be read, or the account it names that this host does not trust, or
/// that it is inherited where `require_protected` asks for a protected one.
pub fn check_access_list(
    path: &Path,
    require_protected: bool,
) -> Result<(), kr_ipc::paths::AccessListRefusal> {
    let file =
        open_without_following(path, FILE_READ_ATTRIBUTES | READ_CONTROL).map_err(|error| {
            kr_ipc::paths::AccessListRefusal::Unreadable(format!(
                "{} could not be opened to read its access list: {error}",
                path.display()
            ))
        })?;
    kr_ipc::paths::check_access_list(
        file.as_handle(),
        &path.display().to_string(),
        require_protected,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A private directory that is removed when the value goes.
    struct Directory(std::path::PathBuf);

    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("kr-u-{}", kr_ipc::new_uuid()));
            kr_ipc::paths::create_private_directory(&path).expect("a private directory is made");
            Self(path)
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The Windows build answers the control call that names a connection's peer: the probe proves
    /// it, so this fails by name, with the build, where a build does not. The build is read from the
    /// system and stated as it says it.
    #[test]
    fn the_windows_build_names_the_process_that_connects_to_a_unix_socket() {
        let build = windows_build();
        assert!(
            build.starts_with("Windows 10.0 build "),
            "the system states its build: {build}"
        );
        if let Err(detail) = gateway_socket_names_its_peers() {
            panic!("the build ({build}) does not name its peers: {detail}");
        }
    }

    /// KR-REQ-07.45: the probe removes the folder it made and the socket in it, each through the
    /// handle that stands for it, and leaves nothing below the folder it was given.
    #[test]
    fn the_probe_leaves_nothing_behind() {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let base = std::env::temp_dir().join(format!("kr-t-{name}"));
        kr_ipc::paths::create_private_directory(&base).expect("a private directory is made");
        let outcome = probe_in(&base);
        let left: Vec<_> = std::fs::read_dir(&base)
            .expect("the folder is read")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        let _ = std::fs::remove_dir_all(&base);
        outcome.expect("this build names its peers");
        assert!(left.is_empty(), "the probe left {left:?}");
    }

    /// A build whose control call fails binds nothing: the refusal is the probe's own words, naming
    /// the call and the build, and no socket file is made.
    #[test]
    fn a_bind_where_the_probe_fails_makes_nothing_and_says_why() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let forced = force_the_ioctl_to_fail("the answer names no process");
        match Listener::bind(&path) {
            Err(BindFailure::NoPeerProcess(detail)) => {
                assert!(detail.contains("SIO_AF_UNIX_GETPEERPID"), "{detail}");
                assert!(
                    detail.contains(&format!("this Windows build ({})", windows_build())),
                    "{detail}"
                );
            }
            other => panic!("a refusal by name, not {other:?}"),
        }
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "no socket's file was made"
        );
        drop(forced);
        let (listener, made) =
            Listener::bind(&path).expect("it binds again once the probe is not forced");
        assert_eq!(socket_object(&path), Some(made));
        drop(listener);
    }

    /// A connection's peer is the process that connected, and its account is this one's.
    #[tokio::test]
    async fn an_accepted_stream_names_this_process_and_this_account() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        let connecting = Stream::connect(&path).expect("the socket is reached");
        let accepted = listener.accept().await.expect("the connection is accepted");
        let peer = accepted.peer().expect("the kernel names the peer");
        assert_eq!(peer.process.pid.get(), u64::from(std::process::id()));
        assert!(peer.owner, "its account is read from the process's handle");
        drop(connecting);
    }

    /// The variable that tells the process a case starts which socket to connect to.
    const CONNECT_VARIABLE: &str = "KR_UDS_CASE_CONNECT";

    /// The variable that makes that process say it connected and wait to be ended, where it would
    /// end.
    const HOLD_VARIABLE: &str = "KR_UDS_CASE_HOLD";

    /// What the line the waiting process prints to say it connected holds.
    const CONNECTED_MARKER: &str = "KR-UDS-CASE-CONNECTED";

    /// What the process a case starts runs, and only when that case names a socket: it connects,
    /// and ends with the test program, or, where told to hold, says it connected and waits for its
    /// input to close.
    #[test]
    fn a_process_that_connects_to_the_socket_it_is_told_and_ends() {
        if let Some(path) = std::env::var_os(CONNECT_VARIABLE) {
            let _stream = uds_windows::UnixStream::connect(Path::new(&path)).expect("it connects");
            if std::env::var_os(HOLD_VARIABLE).is_some() {
                let mut out = std::io::stdout();
                writeln!(out, "{CONNECTED_MARKER}").expect("it says so");
                out.flush().expect("it says so");
                let _ = std::io::stdin().read_to_end(&mut Vec::new());
            }
        }
    }

    /// KR-REQ-07.45: a peer that has ended is not named. Its account and start are read from one
    /// handle, and a process the kernel still names after it ended may no longer own its
    /// identifier, so what it was is not told.
    #[tokio::test]
    async fn a_peer_that_has_ended_is_refused() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        let mut peer = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "windows::uds::tests::a_process_that_connects_to_the_socket_it_is_told_and_ends",
                "--nocapture",
            ])
            .env(CONNECT_VARIABLE, &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the process starts");
        let accepted = tokio::time::timeout(Duration::from_secs(30), listener.accept())
            .await
            .expect("the process connected within the wait")
            .expect("the connection is accepted");
        // The process is held by this handle until it is dropped, so its identifier is its own.
        peer.wait().expect("the process ends");
        let named = accepted.peer();
        assert!(
            named.is_err(),
            "a peer that has ended is not named: {named:?}"
        );
    }

    /// The state of a socket's inherit flag, as the system reports it.
    fn is_inheritable(socket: &impl AsRawSocket) -> bool {
        let mut flags = 0_u32;
        // SAFETY: a socket is a handle for this call, which reads the handle's flags into a live
        // local and has no other effect.
        let read = unsafe {
            windows_sys::Win32::Foundation::GetHandleInformation(
                socket.as_raw_socket() as windows_sys::Win32::Foundation::HANDLE,
                &raw mut flags,
            )
        };
        assert_ne!(
            read,
            0,
            "the flag is read: {}",
            std::io::Error::last_os_error()
        );
        flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT != 0
    }

    /// KR-REQ-07.45: the listening socket and the probe's sockets are made so that no process this
    /// worker starts inherits them, and the socket the listener accepts is read as the system hands
    /// it over, before anything changes its flags, and again as the stream the module returns.
    #[tokio::test]
    async fn the_sockets_this_module_makes_are_not_inheritable() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        assert!(
            !is_inheritable(&listener.inner.get_ref().0),
            "the listening socket"
        );
        let client = connect_uninheritable(&path).expect("the socket is reached");
        assert!(!is_inheritable(&client), "the connecting socket");
        // The first connection is taken with the system's own call and read before anything is
        // done to it: this is the moment `uds_windows` leaves open, and a guest reports it.
        let first = (0..200)
            .find_map(|_| match accept_raw(&listener.inner.get_ref().0) {
                Ok(socket) => Some(socket),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
                Err(error) => panic!("the connection is accepted: {error}"),
            })
            .expect("the connection arrived");
        // SAFETY: the socket was just accepted and nothing else holds it.
        let first = unsafe {
            uds_windows::UnixStream::from_raw_socket(
                u64::try_from(first).expect("a socket that is a socket"),
            )
        };
        assert!(
            !is_inheritable(&first),
            "the accepted socket, as the system made it"
        );
        drop(first);
        let second = connect_uninheritable(&path).expect("the socket is reached again");
        let accepted = listener.accept().await.expect("the connection is accepted");
        assert!(
            !is_inheritable(&accepted.inner.get_ref().get_ref().0),
            "the accepted stream the module returns"
        );
        drop((client, second));
    }

    /// KR-REQ-07.45: a socket the listener accepted is owned before anything that can fail is done
    /// to it: where the flag cannot be cleared the accept fails and the socket is closed, so the
    /// peer reads the end of the stream and not a connection that waits.
    #[tokio::test]
    async fn an_accepted_socket_whose_flag_cannot_be_cleared_is_closed() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        let mut client = uds_windows::UnixStream::connect(&path).expect("the socket is reached");
        CLEAR_FAILS.with(|fails| fails.set(true));
        let refused = listener.accept().await;
        CLEAR_FAILS.with(|fails| fails.set(false));
        assert!(
            refused.is_err(),
            "the flag could not be cleared: {refused:?}"
        );
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a timeout is set");
        let mut byte = [0_u8; 1];
        let read = client.read(&mut byte);
        assert!(
            matches!(read, Ok(0)),
            "the accepted socket was closed, so the client reads the end: {read:?}"
        );
    }

    /// Bytes go both ways through the tokio traits.
    #[tokio::test]
    async fn bytes_pass_both_ways() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        let mut connecting = Stream::connect(&path).expect("the socket is reached");
        let mut accepted = listener.accept().await.expect("the connection is accepted");
        connecting.write_all(b"ping").await.expect("written");
        let mut received = [0_u8; 4];
        accepted.read_exact(&mut received).await.expect("read");
        assert_eq!(&received, b"ping");
        accepted.write_all(b"pong").await.expect("written");
        connecting.read_exact(&mut received).await.expect("read");
        assert_eq!(&received, b"pong");
        drop(accepted);
        let mut rest = Vec::new();
        connecting
            .read_to_end(&mut rest)
            .await
            .expect("the end is read");
        assert!(rest.is_empty(), "the accepted end closed with nothing more");
    }

    /// A path at the same address is refused, and the socket that stands there is left in place.
    #[test]
    fn a_second_bind_at_the_same_path_is_refused_and_leaves_the_first_in_place() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (first, made) = Listener::bind(&path).expect("the socket binds");
        assert!(matches!(Listener::bind(&path), Err(BindFailure::Bind(_))));
        assert_eq!(socket_object(&path), Some(made), "the first socket stands");
        drop(first);
        remove_socket_made(&path, made);
        assert_eq!(socket_object(&path), None);
    }

    /// A file that is not a socket has no socket's identity, and is not removed as one.
    #[test]
    fn a_file_that_is_not_a_socket_has_no_socket_identity_and_stays() {
        let directory = Directory::new();
        let path = directory.0.join("f");
        std::fs::write(&path, b"a file").expect("a file is made");
        assert_eq!(socket_object(&path), None);
        let socket = directory.0.join("p.sock");
        let (other, made) = Listener::bind(&socket).expect("the socket binds");
        remove_socket_made(&path, made);
        assert_eq!(std::fs::read(&path).expect("the file stays"), b"a file");
        drop(other);
    }

    /// The bound socket's file carries a protected list that names its owner only, read from the
    /// file's own handle.
    #[test]
    fn a_bound_socket_s_file_carries_a_protected_owner_only_list() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let (listener, _) = Listener::bind(&path).expect("the socket binds");
        check_access_list(&path, true).expect("the list is protected and names no other account");
        drop(listener);
    }

    /// Puts `hook` between the next bind on this thread and its first open of the file.
    fn after_the_bind(hook: impl FnOnce(&Path) + 'static) {
        AFTER_THE_BIND.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    /// KR-REQ-12.07: a path that an ordinary file replaced after the bind is not the socket the bind
    /// made: the bind is refused, and the file is neither protected nor removed.
    #[test]
    fn a_file_that_replaces_the_socket_before_it_is_protected_is_left_in_place() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        after_the_bind(|path| {
            std::fs::remove_file(path).expect("the socket's file is taken away");
            std::fs::write(path, b"a file").expect("a file stands there");
        });
        match Listener::bind(&path) {
            Err(BindFailure::Unprotected(detail)) => {
                assert!(detail.contains("left as it is"), "{detail}");
            }
            other => panic!("a refusal that leaves the path, not {other:?}"),
        }
        assert_eq!(
            std::fs::read(&path).expect("the file was not removed"),
            b"a file"
        );
    }

    /// KR-REQ-12.07: a path that another socket took after the bind is not the socket this bind
    /// made: the bind is refused, and the other socket stays, reachable and with the list it had.
    #[test]
    fn a_socket_that_replaces_the_socket_before_it_is_protected_is_left_in_place() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let other = std::rc::Rc::new(std::cell::RefCell::new(None));
        let keeps = std::rc::Rc::clone(&other);
        after_the_bind(move |path| {
            std::fs::remove_file(path).expect("the socket's file is taken away");
            *keeps.borrow_mut() =
                Some(uds_windows::UnixListener::bind(path).expect("another socket binds"));
        });
        match Listener::bind(&path) {
            Err(BindFailure::Unprotected(detail)) => {
                assert!(detail.contains("left as it is"), "{detail}");
            }
            other => panic!("a refusal that leaves the path, not {other:?}"),
        }
        assert!(
            socket_object(&path).is_some(),
            "the other program's socket stands"
        );
        assert!(
            uds_windows::UnixStream::connect(&path).is_ok(),
            "the other program's socket is reachable"
        );
        assert!(
            check_access_list(&path, true).is_err(),
            "the other program's socket kept the list it was made with"
        );
        drop(other);
    }

    /// KR-REQ-12.07: a connection that another process queued before the path was replaced does not
    /// prove the replacement is the socket this bind made. The process connects to the new socket
    /// and waits, the file is removed and another socket bound at the path, and the bind's own
    /// connection goes to the other socket while its listener accepts the first one: the kernel
    /// names a process that is not this one, and the bind leaves the other socket as it found it.
    #[test]
    fn a_connection_queued_before_the_path_was_replaced_does_not_prove_the_replacement() {
        use std::io::BufRead as _;
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let kept = std::rc::Rc::new(std::cell::RefCell::new(None));
        let keeps = std::rc::Rc::clone(&kept);
        after_the_bind(move |path| {
            let mut peer = std::process::Command::new(
                std::env::current_exe().expect("this program"),
            )
            .args([
                "--exact",
                "windows::uds::tests::a_process_that_connects_to_the_socket_it_is_told_and_ends",
                "--nocapture",
            ])
            .env(CONNECT_VARIABLE, path)
            .env(HOLD_VARIABLE, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the process starts");
            let mut lines = std::io::BufReader::new(peer.stdout.take().expect("its output"));
            let mut line = String::new();
            loop {
                line.clear();
                let read = lines.read_line(&mut line).expect("its output is read");
                assert!(read > 0, "the process ended before it connected");
                if line.contains(CONNECTED_MARKER) {
                    break;
                }
            }
            std::fs::remove_file(path).expect("the socket's file is taken away");
            let other = uds_windows::UnixListener::bind(path).expect("another socket binds");
            *keeps.borrow_mut() = Some((peer, other, lines));
        });
        let bound = Listener::bind(&path);
        let (mut peer, other, _lines) = kept.borrow_mut().take().expect("the hook ran");
        match bound {
            Err(BindFailure::Unprotected(detail)) => {
                assert!(detail.contains("left as it is"), "{detail}");
            }
            other => panic!("a refusal that leaves the path, not {other:?}"),
        }
        assert!(socket_object(&path).is_some(), "the other socket stands");
        assert!(
            check_access_list(&path, true).is_err(),
            "the other socket kept the list it was made with"
        );
        peer.kill().expect("the process is ended");
        let _ = peer.wait();
        drop(other);
    }

    /// The access list of an ordinary file is read from the file: an entry for another account is
    /// refused, where the owner's own list is not.
    #[test]
    fn a_file_whose_list_names_another_account_is_refused() {
        let directory = Directory::new();
        let path = directory.0.join("f");
        std::fs::write(&path, b"a file").expect("a file is made");
        check_access_list(&path, false).expect("the file carries the owner's own list");
        // Everyone, by its well-known identifier, may read the file.
        let granted = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .expect("icacls runs");
        assert!(granted.status.success(), "the entry is added: {granted:?}");
        match check_access_list(&path, false) {
            Err(kr_ipc::paths::AccessListRefusal::Policy(detail)) => {
                assert!(
                    detail.contains(&path.display().to_string()),
                    "the refusal names the file: {detail}"
                );
            }
            other => panic!("a policy refusal, not {other:?}"),
        }
    }
}
