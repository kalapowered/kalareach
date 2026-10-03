//! Which of the worker's handles a process it starts holds, run on Windows.
//!
//! A launch gives its agent the ends of two pipes, and makes them inheritable only for the call that
//! creates the agent. A backend's output reaches its end of file when the last holder of the write
//! end lets go, so a stranger that held the end would keep the reader waiting for as long as it ran.
//! What keeps the ends from strangers is two rules: the agent is given exactly the handles it lists,
//! and every process this worker starts takes the one lock a launch's window holds.
//!
//! Each test stands in for the window with an event of its own that is inheritable for a while, and
//! asks the kernel how many handles name it. One holder is this test; a second is a process that
//! inherited it. The control in each test is a process started without the rule, which does hold it,
//! so a count of one means something.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-12.02 | An agent holds the handles its launch lists and no other handle of the worker; a launch waits for a window another start holds; a start made by another part of the worker, the desktop reading and the time reading, waits for a launch's window |
//!
//! These tests run one at a time in a process of their own: a process any other test started while
//! an event was inheritable would hold it too.

#![cfg(windows)]

use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use kr_worker::windows::job::{AgentJob, SessionJob};
use kr_worker::windows::launch::{Spec, inheriting, start};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
};
use windows_sys::Win32::System::Threading::CreateEventW;

/// How long a window is held open while a start that must wait is watched.
const WINDOW: Duration = Duration::from_millis(1500);

/// How long a test waits for a process to go.
const PATIENCE: Duration = Duration::from_secs(60);

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Makes this test the only one running, however an earlier one ended.
fn alone() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the kernel says of an object, in the layout its basic information has.
#[repr(C)]
#[derive(Default)]
struct ObjectBasic {
    attributes: u32,
    granted_access: u32,
    handle_count: u32,
    pointer_count: u32,
    paged_pool_charge: u32,
    non_paged_pool_charge: u32,
    reserved: [u32; 3],
    name_information: u32,
    type_information: u32,
    security_descriptor: u32,
    creation_time: i64,
}

/// An event of this test's own, whose holders the kernel counts.
struct Event(HANDLE);

impl Event {
    #[expect(unsafe_code, reason = "creating an event has no safe form")]
    fn new() -> Self {
        // SAFETY: no attributes and no name make an event nothing else can open, and a handle this
        // process alone holds, which no process inherits until a test says so.
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        assert!(!handle.is_null(), "an event is made");
        Self(handle)
    }

    /// Makes the event's handle inheritable, or not.
    #[expect(unsafe_code, reason = "setting a handle's flags has no safe form")]
    fn inheritable(&self, on: bool) {
        // SAFETY: the handle is open for the call, and the mask and flags are values.
        let set = unsafe {
            SetHandleInformation(
                self.0,
                HANDLE_FLAG_INHERIT,
                if on { HANDLE_FLAG_INHERIT } else { 0 },
            )
        };
        assert_ne!(set, 0, "the handle's flag is set");
    }

    /// How many handles in the whole system name this event.
    #[expect(
        unsafe_code,
        reason = "asking the kernel about an object has no safe form"
    )]
    fn holders(&self) -> u32 {
        let mut basic = ObjectBasic::default();
        // SAFETY: the handle is open for the call, and the buffer is a local of the layout the
        // class returns and at least as long as the length given.
        let status = unsafe {
            NtQueryObject(
                self.0,
                ObjectBasicInformation,
                std::ptr::from_mut(&mut basic).cast(),
                u32::try_from(std::mem::size_of::<ObjectBasic>()).unwrap_or(0),
                std::ptr::null_mut(),
            )
        };
        assert!(status >= 0, "the kernel describes the event: {status:#x}");
        basic.handle_count
    }

    /// Waits until only this test holds the event.
    fn wait_until_alone(&self) {
        let deadline = Instant::now() + PATIENCE;
        while self.holders() != 1 {
            assert!(
                Instant::now() < deadline,
                "a process that held the event never let it go"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Event {
    #[expect(unsafe_code, reason = "closing a handle has no safe form")]
    fn drop(&mut self) {
        // SAFETY: the handle is this value's own and nothing else closes it.
        unsafe { CloseHandle(self.0) };
    }
}

/// A program in the system directory, which every Windows machine has.
fn system_program(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join(name)
}

/// Starts `ping` the way any code that spawns a child does, with no rule of this worker's.
fn ping_the_plain_way(count: &str) -> std::process::Child {
    std::process::Command::new(system_program("ping.exe"))
        .args(["-n", count, "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ping starts")
}

/// What a launch of `ping` needs, held for as long as it runs.
struct Jobs {
    session: Arc<SessionJob>,
    agent: Arc<AgentJob>,
}

impl Jobs {
    fn new() -> Self {
        Self {
            session: Arc::new(SessionJob::create().expect("a session job")),
            agent: Arc::new(AgentJob::create().expect("an agent job")),
        }
    }

    /// Starts `ping`, with pipes for its streams, as a launch does.
    fn launch(&self) -> std::io::Result<kr_worker::windows::launch::Child> {
        start(&Spec {
            program: &system_program("ping.exe"),
            arguments: &["-n".to_owned(), "600".to_owned(), "127.0.0.1".to_owned()],
            directory: &std::env::temp_dir(),
            environment: &[],
            session: Some(&*self.session),
            agent: &self.agent,
            pipe_input: true,
            pipe_output: true,
        })
    }
}

impl Drop for Jobs {
    fn drop(&mut self) {
        let _ = self.agent.terminate(1);
    }
}

/// Holds a launch's window open for a while, as a launch does, with `site` started meanwhile on a
/// thread of its own, and returns the most handles that named the event at once.
///
/// A start that takes the window's lock waits for it, and holds nothing of the event once it goes
/// on, because the event is private again by then. A start that does not take it runs in the window
/// and holds the event.
fn most_holders_while_a_window_is_open(site: impl FnOnce() + Send + 'static) -> u32 {
    let event = Event::new();
    let window = inheriting();
    event.inheritable(true);
    let site = std::thread::spawn(site);
    let begun = Instant::now();
    let mut most = 0;
    while begun.elapsed() < WINDOW {
        most = most.max(event.holders());
        std::thread::sleep(Duration::from_millis(2));
    }
    event.inheritable(false);
    drop(window);
    site.join()
        .expect("the start returns once the window is closed");
    most
}

/// KR-REQ-12.02: a launch gives its agent the handles it lists and no other handle of the worker.
/// Control: a process started the plain way holds a handle that is inheritable, so the count sees
/// one.
#[test]
fn kr_req_12_02_a_launch_gives_its_agent_only_the_handles_it_lists() {
    let _alone = alone();
    let event = Event::new();
    event.inheritable(true);
    let mut plain = ping_the_plain_way("600");
    assert_eq!(
        event.holders(),
        2,
        "the process started the plain way holds the event"
    );
    let _ = plain.kill();
    let _ = plain.wait();
    event.wait_until_alone();

    let jobs = Jobs::new();
    let agent = jobs.launch().expect("the agent starts");
    assert_eq!(
        event.holders(),
        1,
        "the agent a launch started holds none of the worker's other handles"
    );
    drop(agent);
}

/// KR-REQ-12.02: a launch does not create its agent while another start holds the window, so what
/// it makes inheritable is never inherited by two starts at once. Control: it goes on and starts
/// the agent once the window is closed.
#[test]
fn kr_req_12_02_a_launch_waits_while_another_start_holds_the_window() {
    let _alone = alone();
    let jobs = Arc::new(Jobs::new());
    let window = inheriting();
    let launching = {
        let jobs = Arc::clone(&jobs);
        std::thread::spawn(move || jobs.launch())
    };
    let begun = Instant::now();
    while begun.elapsed() < WINDOW {
        assert!(
            jobs.agent.process_ids().expect("the job lists").is_empty(),
            "the launch created its agent in a window another start held"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(window);
    let agent = launching
        .join()
        .expect("the launch returns")
        .expect("and starts its agent");
    assert!(
        jobs.agent
            .process_ids()
            .expect("the job lists")
            .contains(&agent.id()),
        "the agent is in its job once the window is closed"
    );
}

/// KR-REQ-12.02: the desktop reading starts its programs in a launch's window only after the
/// window is closed. Control: a start with no lock holds the event.
#[test]
fn kr_req_12_02_the_desktop_reading_waits_for_a_launchs_window() {
    let _alone = alone();
    let plain = most_holders_while_a_window_is_open(|| {
        let _ = ping_the_plain_way("2").wait();
    });
    assert_eq!(plain, 2, "a start with no lock holds the event");
    let waiting = most_holders_while_a_window_is_open(|| {
        let _ = kr_worker::desktop::platform::read_login(0);
    });
    assert_eq!(waiting, 1, "the desktop reading held nothing of the event");
}

/// KR-REQ-12.02: the time reading starts its program in a launch's window only after the window is
/// closed. Control: as above.
#[test]
fn kr_req_12_02_the_time_reading_waits_for_a_launchs_window() {
    use kr_worker::action::adapter::{PlatformTimeAdapter, TimeAdapter as _};
    let _alone = alone();
    let plain = most_holders_while_a_window_is_open(|| {
        let _ = ping_the_plain_way("2").wait();
    });
    assert_eq!(plain, 2, "a start with no lock holds the event");
    let waiting = most_holders_while_a_window_is_open(|| {
        let _ = PlatformTimeAdapter::new().read();
    });
    assert_eq!(waiting, 1, "the time reading held nothing of the event");
}
