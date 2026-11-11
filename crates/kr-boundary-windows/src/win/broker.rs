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
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

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

/// The most connections served at once.
const MAX_CONNECTIONS: usize = 8;
/// How long a proof may wait for the policy to bind.
const PROOF_BOUND: Duration = Duration::from_secs(240);

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

/// What every connection shares.
struct State {
    manifest: Manifest,
    paths: Paths,
    maintenance: AtomicBool,
    active: AtomicUsize,
    stop: Arc<Stop>,
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
    let paths = Paths::system();
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
    let state = Arc::new(State {
        manifest,
        paths,
        maintenance: AtomicBool::new(false),
        active: AtomicUsize::new(0),
        stop: Arc::clone(&stop),
    });
    report(SERVICE_RUNNING, 0, 0);
    let mut threads = Vec::new();
    while let Some(connection) = listener.accept().map_err(|error| error.to_string())? {
        if state.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            continue;
        }
        state.active.fetch_add(1, Ordering::SeqCst);
        let shared = Arc::clone(&state);
        threads.push(std::thread::spawn(move || {
            answer(connection, &shared);
            shared.active.fetch_sub(1, Ordering::SeqCst);
        }));
        threads.retain(|thread| !thread.is_finished());
    }
    for thread in threads {
        let _ = thread.join();
    }
    Ok(())
}

fn refuse(reason: Refusal, detail: &str) -> Response {
    Response::Refused {
        reason,
        detail: detail.to_owned(),
    }
}

/// Serves one connection until it ends.
fn answer(mut connection: Connection, state: &State) {
    // The platform lets a server take on a client's identity only after it has read from the pipe,
    // so the first message is read before the caller is identified. Nothing is done with it until
    // the caller is known.
    let first = frame::read::<_, Request>(&mut connection);
    let identity = match connection.identity() {
        Ok(identity) => identity,
        Err(error) => {
            let _ = frame::write(
                &mut connection,
                &refuse(Refusal::Failed, &error.to_string()),
            );
            return;
        }
    };
    match first {
        Ok(Request::Hello { version }) if version == frame::VERSION => {
            if frame::write(
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
            let _ = frame::write(
                &mut connection,
                &refuse(
                    Refusal::Version,
                    "the broker speaks another protocol version; repair the installation",
                ),
            );
            return;
        }
        _ => {
            let _ = frame::write(
                &mut connection,
                &refuse(Refusal::Malformed, "the first message must be hello"),
            );
            return;
        }
    }
    loop {
        let request = match frame::read::<_, Request>(&mut connection) {
            Ok(request) => request,
            Err(FrameError::Malformed(reason)) => {
                let _ = frame::write(&mut connection, &refuse(Refusal::Malformed, &reason));
                return;
            }
            Err(_) => return,
        };
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
                    PROOF_BOUND,
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
                    PROOF_BOUND,
                    &state.stop,
                );
                Response::Proof {
                    ready: result.ready,
                    detail: result.detail,
                }
            }
        };
        if frame::write(&mut connection, &response).is_err() {
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
