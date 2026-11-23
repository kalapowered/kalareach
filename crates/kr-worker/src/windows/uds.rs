//! A Unix-domain socket on Windows, and the process at the other end of one.
//!
//! The gateway's agent program speaks to a socket of this kind, so the gateway binds one here. What
//! an admission rests on is the **peer check**: the kernel names the process on the other end of a
//! connection (`SIO_AF_UNIX_GETPEERPID`) and that process's own token names its account, both read
//! before a byte of what the peer sent is. Nothing the connecting side says about itself is read.
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
//! The sockets are the operating system's own and `uds_windows` binds and accepts them. Each is
//! made non-blocking and registered with `async-io`'s reactor, and read and written through the
//! tokio traits. `uds_windows` makes its sockets inheritable and clears that a moment later, so a
//! process this worker starts in that moment could inherit one: the gap is the crate's, and it is
//! not closed here.
//!
//! A socket's file is a reparse point of its own kind. Every read of it and every removal of it
//! opens it without following, and acts on what the open handle is: a path that names something
//! else by then is left alone. A bind learns which file is its own by connecting to the path and
//! finding the connection in its own queue, and only a file so proved is protected or removed by
//! the bind.

#![expect(
    unsafe_code,
    reason = "naming the process at the other end of a socket, lending a socket the reactor \
              registers, and marking a file for removal are calls whose guarantees only the \
              caller can state"
)]

use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{
    AsHandle as _, AsRawHandle as _, AsRawSocket, AsSocket, BorrowedSocket,
};
use std::path::Path;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use async_io::{Async, IoSafe};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Networking::WinSock::{SIO_AF_UNIX_GETPEERPID, WSAIoctl};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, READ_CONTROL,
    SetFileInformationByHandle, WRITE_DAC,
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

    /// Returns the process the kernel says is at the other end of this connection.
    ///
    /// # Errors
    ///
    /// Returns why the kernel did not name one, which is the Windows build's own answer.
    pub fn peer_process(&self) -> std::io::Result<u32> {
        peer_process_of(&self.inner.get_ref().get_ref().0)
    }
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
        let listener = uds_windows::UnixListener::bind(path).map_err(BindFailure::Bind)?;
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
        let (socket, _) = self
            .inner
            .read_with(|registered| registered.0.accept())
            .await?;
        Stream::new(socket)
    }
}

/// Shows that the open file at `path` is the socket `listener` bound, and returns its identity.
///
/// The file must be a socket's file, a connection to the path must reach `listener`'s own queue, and
/// the path must still name the file's object afterwards. A path that names a file, or another
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
    let _client = uds_windows::UnixStream::connect(path)
        .map_err(|error| format!("it could not be connected to: {error}"))?;
    let _accepted = accept_within_the_wait(listener).map_err(|error| {
        format!("a connection to it did not reach the listener that bound it: {error}")
    })?;
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
        match listener.accept() {
            Ok((accepted, _)) => return Ok(accepted),
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

/// What a case that forces the probe to fail holds while it does: the failure is put back as it was
/// when this is dropped.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct ForcedProbeFailure(Option<String>);

#[cfg(any(test, feature = "testing"))]
impl Drop for ForcedProbeFailure {
    fn drop(&mut self) {
        FORCED.with(|forced| *forced.borrow_mut() = self.0.take());
    }
}

/// Makes the probe fail with `detail` on this thread until the value returned is dropped, whatever
/// the build answers.
///
/// A case on a build that answers the control call uses it to show what a build that does not
/// answer it does.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn force_the_probe_to_fail(detail: &str) -> ForcedProbeFailure {
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
    if let Some(forced) = FORCED.with(|forced| forced.borrow().clone()) {
        return Err(forced);
    }
    PROBE.get_or_init(probe).clone()
}

/// Runs the probe in a folder of its own, which it removes.
fn probe() -> Result<(), String> {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("kr-q-{name}"));
    kr_ipc::paths::create_private_directory(&directory).map_err(|error| {
        format!(
            "the folder {} for asking this Windows build ({}) which process connects to a \
             Unix-domain socket could not be made: {error}",
            directory.display(),
            windows_build()
        )
    })?;
    let outcome = prove_the_build_names_a_peer(&directory.join("p.sock"));
    let _ = std::fs::remove_dir_all(&directory);
    outcome
}

/// Binds a socket at `path`, connects to it from this process and reads the peer of the accepted
/// end.
fn prove_the_build_names_a_peer(path: &Path) -> Result<(), String> {
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
    let listener = uds_windows::UnixListener::bind(path).map_err(|error| {
        format!(
            "a Unix-domain socket could not be bound at {} on this Windows build ({build}): \
             {error}",
            path.display()
        )
    })?;
    let _client = uds_windows::UnixStream::connect(path).map_err(|error| {
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
fn windows_build() -> String {
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

/// Returns true when the process `pid` runs as the account this process runs as, read from the
/// process's own token.
///
/// # Errors
///
/// Returns why the process or its token cannot be read, which includes a process of another account
/// whose token this one may not open.
pub fn process_is_this_account(pid: u32) -> std::io::Result<bool> {
    kr_ipc::starter::process_facts(pid).map(|facts| facts.same_user)
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

    /// A build whose probe fails binds nothing: the refusal is the probe's own words, and no socket
    /// file is made.
    #[test]
    fn a_bind_where_the_probe_fails_makes_nothing_and_says_why() {
        let directory = Directory::new();
        let path = directory.0.join("p.sock");
        let forced = force_the_probe_to_fail("SIO_AF_UNIX_GETPEERPID is not answered on build 0");
        match Listener::bind(&path) {
            Err(BindFailure::NoPeerProcess(detail)) => {
                assert!(detail.contains("SIO_AF_UNIX_GETPEERPID"), "{detail}");
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
        let pid = accepted.peer_process().expect("the kernel names the peer");
        assert_eq!(pid, std::process::id());
        assert!(process_is_this_account(pid).expect("the account is read"));
        drop(connecting);
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

    /// The access list of a file is read from the file: an entry for another account is refused,
    /// where the owner's own list is not.
    #[test]
    fn a_socket_whose_file_has_another_account_in_its_list_is_refused() {
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
