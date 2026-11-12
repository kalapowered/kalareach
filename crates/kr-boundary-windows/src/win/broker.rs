//! The broker service: the pipe the host speaks to, the maintenance state, and the proofs.
//!
//! Windows runs the broker as SYSTEM with the privileges the installation named and no others.
//! It makes its pipe first, so a program that took the name earlier stops it from starting, and
//! it answers each connection on a thread of its own, up to a fixed number at once. The caller's
//! identity comes from the pipe: a request that changes the state or asks for a proof needs a
//! caller that is an elevated administrator, and no message carries a process, a token or a
//! program.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::process::ExitCode;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};

use crate::frame::{self, Class, FrameError, Refusal, Request, Response};
use crate::manifest::Manifest;

use super::ffi::{Sid, wide};
use super::install::{Paths, SERVICE};
use super::pipe::{Connection, Listener, Stop};
use super::proof;
use super::token::enable_privilege;

/// The most connections served at once: one fewer than the pipe may have instances, so that the
/// instance that waits for the next client is never the one that is missing.
const MAX_CONNECTIONS: usize = super::pipe::MAX_INSTANCES as usize - 1;
/// How long a connection may take to send its first frame. The installer's own first message
/// follows its open at once; a client that has had the pipe for this long and sent nothing is not
/// waiting for an answer, and its slot goes to the next client.
const FIRST_FRAME: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a connection of a person who is not an administrator may stay without a request. A
/// person's client asks for the status right after hello, so a connection that has been quiet for as
/// long as the first frame is allowed is not waiting for an answer, and its slot goes to the next
/// client: seven such connections would otherwise hold every slot.
const PERSON_IDLE: std::time::Duration = FIRST_FRAME;
/// How long an administrator's connection may stay without a request. The installer's removal asks
/// the broker for its maintenance state, then writes the policy and waits for the platform's events
/// (each wait is bounded by 300 seconds at most) with the connection open, and asks for the release
/// after them, so this is longer than those waits together; an administrator holds the right to
/// stop the service, so the bound only ends a connection that nobody uses any more.
const ADMINISTRATOR_IDLE: std::time::Duration = std::time::Duration::from_secs(900);
/// How long the write of an answer may take. An answer is a small frame that the pipe's buffer
/// takes whole, so a write that waits this long has a client that reads nothing.
const ANSWER_WRITE: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a cycle of proofs lasts, all the proofs of it together: the log names the rule about
/// 170 s after the start of Windows. A cycle has one absolute deadline, and every wait, every query
/// of the log and every program of a proof stays within it. The first cycle begins with the
/// broker's start. A proof asked after the open cycle has ended is a new cycle of its own, which
/// begins with that request and has its own deadline; it never extends the one that ended.
pub const PROOF_BOUND: Duration = Duration::from_secs(300);

/// The error mode of the broker and, by inheritance, of every child it starts: the system shows no
/// critical-error box, invokes no Windows Error Reporting for a crash, and shows no open-file box.
const ERROR_MODE: u32 = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;

static ERROR_MODE_SET: Once = Once::new();

/// Sets the broker's error mode, once, at the start of the program. Nothing changes it afterwards:
/// the mode belongs to the whole process, so a mode that is set and restored around a launch would
/// leave a window in which a concurrent crash is handled by the other mode.
///
/// A child inherits its parent's error mode when it is created, which is how the mode reaches the
/// programs the broker starts. **What this claims, and no more:** the system's own crash
/// reporting is not invoked for the broker, nor for a child that inherits the mode, on the
/// Windows builds the cases have run on. The broker's crash leaves no dump of its memory, which
/// holds invocations' data, and a hostile Git's crash leaves none either. A process that asks for
/// the default mode, or that writes a dump of itself, is outside the claim, and so is a computer
/// on which an administrator configured error reporting for the broker's own program. The job's
/// limit that ends a process on an unhandled exception is a second wall and does not keep a
/// fail-fast from leaving a dump.
pub fn init() {
    ERROR_MODE_SET.call_once(|| {
        // SAFETY: sets the process's error mode, which has no memory safety condition.
        unsafe {
            SetErrorMode(ERROR_MODE);
        }
    });
}

static STOP: OnceLock<Arc<Stop>> = OnceLock::new();
static STATUS: OnceLock<usize> = OnceLock::new();

/// The slots that bound how many connections are served at once.
#[derive(Debug)]
pub struct Slots {
    active: AtomicUsize,
    most: usize,
}

/// One slot in use, given back when this value is dropped, however its thread ended: a return, an
/// error or a panic.
#[derive(Debug)]
pub struct Slot(Arc<Slots>);

impl Slots {
    /// Slots for at most `most` connections.
    #[must_use]
    pub fn new(most: usize) -> Arc<Slots> {
        Arc::new(Slots {
            active: AtomicUsize::new(0),
            most,
        })
    }

    /// Takes a slot, or none when all are in use.
    #[must_use]
    pub fn take(self: &Arc<Slots>) -> Option<Slot> {
        let mut seen = self.active.load(Ordering::SeqCst);
        loop {
            if seen >= self.most {
                return None;
            }
            match self
                .active
                .compare_exchange(seen, seen + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Slot(Arc::clone(self))),
                Err(now) => seen = now,
            }
        }
    }

    /// How many slots are in use.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What every connection shares.
struct State {
    manifest: Manifest,
    paths: Paths,
    maintenance: AtomicBool,
    stop: Arc<Stop>,
    /// The deadline of the cycle of proofs that is open. The first ends [`PROOF_BOUND`] after the
    /// broker's start.
    cycle: Mutex<Instant>,
}

impl State {
    /// The state of a broker that began serving now.
    fn begun(manifest: Manifest, paths: Paths, stop: Arc<Stop>) -> State {
        State::with_first_cycle(manifest, paths, stop, Instant::now() + PROOF_BOUND)
    }

    fn with_first_cycle(
        manifest: Manifest,
        paths: Paths,
        stop: Arc<Stop>,
        first_deadline: Instant,
    ) -> State {
        State {
            manifest,
            paths,
            maintenance: AtomicBool::new(false),
            stop,
            cycle: Mutex::new(first_deadline),
        }
    }

    /// The deadline of a proof that is asked for now: that of the open cycle, so that the proofs of
    /// both classes asked within it share it. When the open cycle has ended, this request begins
    /// the next one, [`PROOF_BOUND`] long, and the deadline of the earlier one is not touched.
    fn proof_deadline(&self) -> Instant {
        let mut open = self.cycle.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if now >= *open {
            *open = now + PROOF_BOUND;
        }
        *open
    }
}

fn report(state: u32, exit_code: u32, wait_hint: u32) {
    let Some(handle) = STATUS.get() else { return };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    // SAFETY: the handle is the one the service manager gave this process.
    unsafe {
        SetServiceStatus(*handle as SERVICE_STATUS_HANDLE, &raw const status);
    }
}

unsafe extern "system" fn control(
    request: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match request {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0, 30_000);
            if let Some(stop) = STOP.get() {
                stop.set();
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(SERVICE);
    // SAFETY: the name is NUL-terminated and the handler is a function of this program.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if handle.is_null() {
        return;
    }
    let _ = STATUS.set(handle as usize);
    report(SERVICE_START_PENDING, 0, 15_000);
    let code = match serve() {
        Ok(()) => 0,
        Err(reason) => {
            // The service manager keeps only the number; the reason goes to the event log's
            // service failure entry through the exit code, and to the error stream for a console run.
            eprintln!("kr-boundary-broker: {reason}");
            1
        }
    };
    report(SERVICE_STOPPED, code, 0);
}

fn serve() -> Result<(), String> {
    let stop = Stop::new().map_err(|error| error.to_string())?;
    let _ = STOP.set(Arc::clone(&stop));
    let paths = Paths::system().map_err(|error| error.to_string())?;
    let manifest = Manifest::load(&paths.manifest).map_err(|error| error.to_string())?;
    for privilege in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        enable_privilege(privilege).map_err(|error| error.to_string())?;
    }
    let people: Vec<Sid> = manifest
        .persons
        .iter()
        .filter_map(|text| Sid::parse(text).ok())
        .collect();
    let mut listener =
        Listener::bind(&people, Arc::clone(&stop)).map_err(|error| error.to_string())?;
    // The cycle begins before the service reports that it runs, so a client that sees it running
    // begins its own count no earlier than the broker's.
    let state = Arc::new(State::begun(manifest, paths, Arc::clone(&stop)));
    report(SERVICE_RUNNING, 0, 0);
    run(&mut listener, &state)
}

/// Takes connections and answers each on a thread of its own, until the service is told to stop.
///
/// A thread that could not give its privileges back ends the whole process at once, so nothing here
/// sees the latch set in a running broker. The checks are for the connections that outlive a
/// stand-in for that end in a case: none is accepted, and none that is open is served again.
fn run(listener: &mut Listener, state: &Arc<State>) -> Result<(), String> {
    let slots = Slots::new(MAX_CONNECTIONS);
    let mut threads = Vec::new();
    let mut ended = Ok(());
    loop {
        // A client is taken only when a slot is free. The listener's waiting instance stays where
        // it is meanwhile, so no client is dropped for want of a slot and the pipe's name is held.
        let slot = loop {
            if listener.stopped() || super::privilege::revert_failed() {
                break None;
            }
            if let Some(slot) = slots.take() {
                break Some(slot);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let Some(slot) = slot else {
            break;
        };
        let connection = match listener.accept() {
            Ok(Some(connection)) => connection,
            Ok(None) => break,
            Err(failure) => {
                ended = Err(failure.to_string());
                break;
            }
        };
        if super::privilege::revert_failed() {
            break;
        }
        let shared = Arc::clone(state);
        threads.push(std::thread::spawn(move || {
            // The slot goes back when this thread ends, a panic included.
            let _slot = slot;
            answer(connection, &shared);
        }));
        threads.retain(|thread| !thread.is_finished());
    }
    // However the loop ended, the connections that are open end with it, and the service reports
    // that it stopped only after they have.
    state.stop.set();
    for thread in threads {
        let _ = thread.join();
    }
    if super::privilege::revert_failed() {
        return Err("a thread could not give its privileges back".to_owned());
    }
    ended
}

/// What the cases use to run the broker's loop in their own process.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::Arc;

    use crate::manifest::Manifest;

    use super::super::ffi::Sid;
    use super::super::install::Paths;
    use super::super::pipe::{Listener, Stop};
    use super::{State, run};

    /// Binds the service's pipe for these people and serves it until `stop` is set or a thread
    /// could not give its privileges back, as the service does.
    ///
    /// # Errors
    ///
    /// Returns the reason the pipe could not be made or the loop ended.
    pub fn serve(
        manifest: Manifest,
        paths: Paths,
        people: &[Sid],
        stop: Arc<Stop>,
    ) -> Result<(), String> {
        let mut listener =
            Listener::bind(people, Arc::clone(&stop)).map_err(|error| error.to_string())?;
        let state = Arc::new(State::begun(manifest, paths, stop));
        run(&mut listener, &state)
    }
}

fn refuse(reason: Refusal, detail: &str) -> Response {
    Response::Refused {
        reason,
        detail: detail.to_owned(),
    }
}

/// Writes one answer within [`ANSWER_WRITE`].
fn send(connection: &mut Connection, response: &Response) -> Result<(), FrameError> {
    connection.set_deadline(Some(std::time::Instant::now() + ANSWER_WRITE));
    frame::write(connection, response)
}

/// Serves one connection until it ends. Every read and every write has a deadline, so a client
/// that sends nothing or reads nothing gives its slot back.
fn answer(mut connection: Connection, state: &State) {
    // The platform lets a server take on a client's identity only after it has read from the pipe,
    // so the first message is read before the caller is identified. Nothing is done with it until
    // the caller is known.
    connection.set_deadline(Some(std::time::Instant::now() + FIRST_FRAME));
    let first = frame::read::<_, Request>(&mut connection);
    // A connection that sent no first frame by its deadline, or that failed, is closed.
    if !matches!(first, Ok(_) | Err(FrameError::Malformed(_))) {
        return;
    }
    let identity = match connection.identity() {
        Ok(identity) => identity,
        Err(error) => {
            let _ = send(
                &mut connection,
                &refuse(Refusal::Failed, &error.to_string()),
            );
            return;
        }
    };
    match first {
        Ok(Request::Hello { version }) if version == frame::VERSION => {
            if send(
                &mut connection,
                &Response::Hello {
                    version: frame::VERSION,
                },
            )
            .is_err()
            {
                return;
            }
        }
        Ok(Request::Hello { .. }) => {
            let _ = send(
                &mut connection,
                &refuse(
                    Refusal::Version,
                    "the broker speaks another protocol version; repair the installation",
                ),
            );
            return;
        }
        _ => {
            let _ = send(
                &mut connection,
                &refuse(Refusal::Malformed, "the first message must be hello"),
            );
            return;
        }
    }
    let idle = if identity.administrator {
        ADMINISTRATOR_IDLE
    } else {
        PERSON_IDLE
    };
    loop {
        connection.set_deadline(Some(std::time::Instant::now() + idle));
        let request = match frame::read::<_, Request>(&mut connection) {
            Ok(request) => request,
            Err(FrameError::Malformed(reason)) => {
                let _ = send(&mut connection, &refuse(Refusal::Malformed, &reason));
                return;
            }
            Err(_) => return,
        };
        // A request that arrives after a thread failed to give its privileges back is not served.
        if super::privilege::revert_failed() {
            return;
        }
        let response = match request {
            Request::Hello { .. } => refuse(Refusal::Malformed, "hello was already said"),
            Request::Status {} => Response::Status {
                maintenance: state.maintenance.load(Ordering::SeqCst),
            },
            Request::Maintenance { on } => {
                if identity.administrator {
                    state.maintenance.store(on, Ordering::SeqCst);
                    Response::Done {}
                } else {
                    refuse(
                        Refusal::Caller,
                        "only an administrator may change the broker's state",
                    )
                }
            }
            Request::Prove { class } | Request::Release { class } if !identity.administrator => {
                let _: Class = class;
                refuse(Refusal::Caller, "only an administrator may ask for a proof")
            }
            Request::Prove { class } => {
                let result = proof::prove(
                    &state.manifest,
                    class,
                    &state.paths.staging,
                    state.proof_deadline(),
                    &state.stop,
                );
                Response::Proof {
                    ready: result.ready,
                    detail: result.detail,
                }
            }
            Request::Release { class } => {
                let result = proof::release(
                    &state.manifest,
                    class,
                    &state.paths.staging,
                    Instant::now() + PROOF_BOUND,
                    &state.stop,
                );
                Response::Proof {
                    ready: result.ready,
                    detail: result.detail,
                }
            }
        };
        if send(&mut connection, &response).is_err() {
            return;
        }
    }
}

/// What the guest cases ask of a broker they start: to crash after it has set its error mode, with
/// or without the default mode asked for again. A build that ships has no such request.
#[cfg(feature = "testing")]
fn crash_when_asked() {
    let arguments: Vec<String> = std::env::args().collect();
    let Some(kind) = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--crash-after-init="))
    else {
        return;
    };
    if arguments
        .iter()
        .any(|argument| argument == "--default-error-mode")
    {
        // SAFETY: sets the process's error mode, which has no memory safety condition.
        unsafe {
            SetErrorMode(0);
        }
    }
    match kind {
        // SAFETY: a deliberate access violation: the case exists to see what the system does.
        "access-violation" => unsafe { std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1) },
        // SAFETY: a deliberate fail-fast, for the same reason.
        "fail-fast" => unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::RaiseFailFastException(
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
        },
        _ => {}
    }
}

/// Runs the broker as the service the service manager started.
pub fn main() -> ExitCode {
    init();
    #[cfg(feature = "testing")]
    crash_when_asked();
    let name = wide(SERVICE);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table is terminated by a null entry and outlives the call, which returns when
    // the service has stopped.
    let started = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if started == 0 {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            eprintln!(
                "kr-boundary-broker runs as a Windows service and is started by the service manager"
            );
        } else {
            eprintln!("kr-boundary-broker could not connect to the service manager: error {code}");
        }
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_first_cycle_ending(deadline: Instant) -> State {
        State::with_first_cycle(
            Manifest::begin(),
            Paths::system().expect("the system's folders are read"),
            Stop::new().expect("an event is made"),
            deadline,
        )
    }

    #[test]
    fn the_proofs_of_an_open_cycle_share_its_deadline() {
        let ends = Instant::now() + Duration::from_secs(3600);
        let state = state_with_first_cycle_ending(ends);
        assert_eq!(state.proof_deadline(), ends);
        assert_eq!(state.proof_deadline(), ends, "the second class shares it");
    }

    #[test]
    fn a_proof_asked_after_the_cycle_ended_begins_a_cycle_of_its_own_that_later_requests_share() {
        let ended = Instant::now();
        let state = state_with_first_cycle_ending(ended);
        let asked = Instant::now();
        let next = state.proof_deadline();
        assert!(next >= asked + PROOF_BOUND, "a window of its own");
        assert!(
            next > ended + PROOF_BOUND / 2,
            "the ended cycle gives it nothing"
        );
        assert_eq!(
            state.proof_deadline(),
            next,
            "the cycle's other requests share it"
        );
    }
}
