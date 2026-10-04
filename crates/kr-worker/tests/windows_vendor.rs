//! A vendor's own sandbox under the session's job, run on Windows.
//!
//! Section 7 asks that a vendor sandbox's nested jobs be qualified under the session's job, and
//! that one that cannot run there produce a named launch failure or an explicitly selected
//! reduced-ownership profile, never a silently disabled sandbox and never blanket breakaway. Every
//! test here starts the agent through the launch the broker makes, as a real process in real jobs;
//! the vendor is a stand-in that does what a sandbox does (a job of its own with limits on
//! processes, memory and the user interface, a process in it, a try at breaking away), and the
//! suite's last two tests run the real agent where the environment names one.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.64 | A sandbox that nests a limited job under the session's launches, breakaway is still refused, and closing the session ends every process the vendor made, the closure reading complete coverage; a session whose job restricts desktops refuses the launch by name and starts nothing; the profile the configuration selected starts the agent in a job of its own, tracked by start identity, ended by the closure and by a worker that dies, and the coverage never reads complete |

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_protocol::broker::{
    AgentOwnership, AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile,
};
use kr_protocol::gateway::NativeFraming;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ApplicationInstanceId, EnvironmentId, LaunchProfileId, PluginId, SessionId,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::session::OwnershipCoverage;
use kr_worker::broker::{
    AgentChild, Broker, BrokerError, Framing, Launched, NativeGateway, NativeLaunch,
};
use kr_worker::ownership::{OwnedProcesses, OwnershipBoundary, force_stop};
use kr_worker::persistence::JournalHealth;
use kr_worker::windows::job::{AgentJob, SessionJob};

mod common;

use common::LIVENESS_DEADLINE;

/// The restriction on a job's user interface that a vendor's own desktop cannot be made under.
const DESKTOP: u32 = 0x40;

fn session_id() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn package() -> PluginId {
    PluginId::new("kalareach/codex").expect("valid")
}

fn this_executable() -> PathBuf {
    std::env::current_exe().expect("this test's executable")
}

/// Eight hexadecimal digits that name a directory of a test's own.
fn short_name() -> String {
    kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect()
}

/// A private directory, made the way the host makes one, and removed by the caller.
fn private_directory() -> PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-wv-{}", short_name()));
    kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
    directory
}

fn launch_for(which: u8) -> NativeLaunch {
    NativeLaunch {
        profile_id: LaunchProfileId::new(format!("lp-{which}")).expect("valid"),
        expected_process: None,
        native_terminal: None,
        application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([which; 16])),
        plugin_id: package(),
        installed_protocol_version: "1".to_owned(),
        framing: Framing::new(NativeFraming::JsonLines),
        site: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        os_user: "agent-user".to_owned(),
        working_directory: std::env::temp_dir(),
    }
}

fn profile(which: u8, arguments: &[String], ownership: AgentOwnership) -> LaunchProfile {
    LaunchProfile {
        profile_id: LaunchProfileId::new(format!("lp-{which}")).expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        binary: BinaryIdentity {
            resolved_path: this_executable().to_string_lossy().into_owned(),
            digest: Digest256::from_bytes([3; 32]),
            version: "1".to_owned(),
            distribution: "build".to_owned(),
        },
        arguments: arguments.to_vec(),
        authentication: AuthenticationState::Authenticated,
        mode: IntegrationMode::Gateway,
        ownership,
        vendor_mode: Nullable::null(),
        resolved_at: TimestampMs::new(1),
    }
}

/// What the stand-in vendor reports once it has set its sandbox up.
#[derive(Debug)]
struct Report {
    /// The process the vendor put in the job of its own.
    nested: u32,
    /// What a try at breaking away from every job did.
    breakaway: String,
    /// Whether the process that reported runs under a restricted token, as a vendor sandbox's
    /// command does.
    restricted: Option<bool>,
}

/// An agent this host started, ended with everything in its jobs when the test ends, however it
/// ends.
struct Launch {
    gateway: Option<NativeGateway>,
    directory: PathBuf,
    report: PathBuf,
    child: Option<AgentChild>,
    process: ProcessStartIdentity,
    session: Arc<SessionJob>,
    /// A directory of the launch's own beside the private one, removed with it.
    work: Option<PathBuf>,
    /// Whether dropping this ends the agent's job: a test about what happens when the worker
    /// dies lets go of everything and watches the agent instead.
    end_on_drop: bool,
}

impl Launch {
    /// Starts the stand-in vendor as the agent of `package`, in `session`, under `ownership`.
    fn start(
        which: u8,
        ownership: AgentOwnership,
        session: &Arc<SessionJob>,
    ) -> Result<Self, BrokerError> {
        let directory = private_directory();
        let report = directory.join("report");
        let broker = Arc::new(
            Broker::open(None, session_id(), JournalHealth::shared()).expect("the broker opens"),
        );
        let mut gateway = NativeGateway::bind(Arc::clone(&broker), &directory, launch_for(which))
            .expect("the endpoint binds")
            .in_session(Arc::clone(session));
        let arguments: Vec<String> = [
            "--ignored",
            "--exact",
            "vendor_stand_in",
            "--nocapture",
            "--test-threads=1",
            report.to_string_lossy().as_ref(),
        ]
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
        let intent = broker
            .prepare_launch(
                profile(which, &arguments, ownership),
                kr_worker::broker::ForegroundMark::idle(4),
                None,
            )
            .expect("the launch is prepared");
        let outcome = gateway.launch(
            &intent,
            &kr_worker::broker::ForegroundMark::idle(4),
            IntegrationMode::Gateway,
            TimestampMs::new(1),
        );
        match outcome {
            Ok(Launched { child, process, .. }) => Ok(Self {
                gateway: Some(gateway),
                directory,
                report,
                child: Some(child),
                process,
                session: Arc::clone(session),
                work: None,
                end_on_drop: true,
            }),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&directory);
                Err(error)
            }
        }
    }

    /// Waits until the vendor has set its sandbox up, and says what it did.
    fn report(&mut self) -> Report {
        use std::io::Read as _;

        let started = Instant::now();
        let text = loop {
            if let Ok(text) = std::fs::read_to_string(&self.report) {
                break text;
            }
            if started.elapsed() >= LIVENESS_DEADLINE {
                let child = self.child.as_mut().expect("the agent's handle");
                let status = child.try_wait().expect("the agent's status");
                let mut said = String::new();
                if status.is_some()
                    && let Some(output) = child.stdout.as_mut()
                {
                    let _ = output.read_to_string(&mut said);
                }
                panic!(
                    "the vendor never reported; the agent's status is {status:?} and it said {said:?}"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("the report names {name}: {text}"))
                .to_owned()
        };
        Report {
            nested: field("nested").parse().expect("a process identifier"),
            breakaway: field("breakaway"),
            restricted: text
                .lines()
                .find_map(|line| line.strip_prefix("restricted="))
                .map(|word| word == "true"),
        }
    }

    /// Closes the end of the agent's standard input this host writes, so an agent that reads it
    /// reads the end of its input: `codex sandbox` runs its command once it has none to wait for.
    fn close_input(&self) {
        if let Some(input) = self.child.as_ref().and_then(|child| child.stdin.as_ref()) {
            input.close().expect("the agent's input closes");
        }
    }

    fn agent_job(&self) -> Arc<AgentJob> {
        kr_worker::windows::job::agent_job(&self.process).expect("the launch's job is kept")
    }

    /// Lets go of every handle this worker held for the launch, and leaves the agent running for
    /// whatever the closing of its jobs does to it.
    fn the_worker_dies(mut self) -> AgentChild {
        self.end_on_drop = false;
        let child = self.child.take().expect("the agent's handle");
        kr_worker::windows::job::release_agent(&self.process);
        self.gateway = None;
        child
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        if self.end_on_drop {
            if let Some(job) = kr_worker::windows::job::agent_job(&self.process) {
                let _ = job.terminate(1);
            }
            let _ = self.session.terminate(1);
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        kr_worker::windows::job::release_agent(&self.process);
        let _ = std::fs::remove_dir_all(&self.directory);
        if let Some(work) = self.work.as_ref() {
            let _ = std::fs::remove_dir_all(work);
        }
    }
}

/// Waits until `condition` holds, for as long as a liveness wait lasts.
fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < LIVENESS_DEADLINE, "never: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the kernel says the process this identity names has ended.
fn ended(identity: &ProcessStartIdentity) -> bool {
    matches!(
        kr_ipc::identity::process_state(identity),
        kr_ipc::identity::ProcessState::Ended
    )
}

fn identity_of(pid: u32) -> ProcessStartIdentity {
    kr_ipc::identity::process_start_identity(pid).expect("a running process")
}

/// The record a closure keeps of the session whose job is `session`, as the worker keeps it.
fn closure_record(launch: &Launch) -> OwnedProcesses {
    let root = u32::try_from(launch.process.pid.get()).expect("a process identifier");
    kr_worker::windows::job::record(root, &launch.session);
    OwnedProcesses::establish(
        OwnershipBoundary::JobObject { root },
        launch.process.clone(),
    )
}

// ---------------------------------------------------------------------------------------------
// The stand-in vendor: a process of its own, which does nothing unless a test starts it with
// `--ignored`. It builds the job a vendor sandbox builds, puts a process in it, tries to break
// away, says what happened and stays until it is ended.

#[expect(
    unsafe_code,
    reason = "a vendor's own job is made with the system calls that make one; no safe wrapper in \
              this repository does it, and this is the stand-in for what a vendor does"
)]
fn vendor_job_with_limits() -> windows_sys::Win32::Foundation::HANDLE {
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    // SAFETY: both arguments are the documented "no security attributes, no name".
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    assert!(!job.is_null(), "the vendor's job is made");
    // SAFETY: all zeroes is the state that means no limit is set.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 8;
    limits.ProcessMemoryLimit = 512 * 1024 * 1024;
    // SAFETY: the handle is open, and the structure is a local with its own declared size.
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    assert_ne!(set, 0, "the vendor's limits are set");
    // Every user-interface restriction but the desktop's, which is the one no sandbox of this
    // kind can run under and which another test stands in front of the launch.
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: 0xFF & !DESKTOP,
    };
    // SAFETY: as above.
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            std::ptr::from_ref(&ui).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>()).unwrap_or(0),
        )
    };
    assert_ne!(set, 0, "the vendor's user-interface limits are set");
    job
}

#[expect(unsafe_code, reason = "moving a process into a job has no safe form")]
fn assign(job: windows_sys::Win32::Foundation::HANDLE, child: &std::process::Child) {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
    // SAFETY: both handles are open for the call.
    let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) };
    assert_ne!(
        assigned,
        0,
        "the vendor's job nests under the session's: {}",
        std::io::Error::last_os_error()
    );
}

#[expect(
    unsafe_code,
    reason = "reading whether a token is restricted has no safe form"
)]
fn this_token_is_restricted() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{IsTokenRestricted, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = std::ptr::null_mut();
    // SAFETY: the pseudo-handle names this process and the out-parameter is a local.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
    assert_ne!(opened, 0, "this process's token opens");
    // SAFETY: the token is open for the call and closed once afterwards.
    let restricted = unsafe { IsTokenRestricted(token) } != 0;
    // SAFETY: the handle is the one the call above opened.
    unsafe { CloseHandle(token) };
    restricted
}

fn waiting_program() -> std::process::Command {
    let mut command = std::process::Command::new(
        Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
            .join("System32")
            .join("ping.exe"),
    );
    command
        .args(["-n", "600", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

/// The vendor a launch starts: a sandbox with a limited job of its own and a process in it, and an
/// attempt to leave every job that the jobs it runs under refuse.
#[test]
#[ignore = "a process the tests below start as the launched vendor"]
fn vendor_stand_in() {
    use std::os::windows::process::CommandExt as _;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    let report = PathBuf::from(std::env::args().last().expect("the report's path"));
    let job = vendor_job_with_limits();
    let nested = waiting_program()
        .spawn()
        .expect("the sandboxed process starts");
    assign(job, &nested);
    let breakaway = match waiting_program()
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Ok(mut escaped) => {
            let _ = escaped.kill();
            "created".to_owned()
        }
        Err(error) => format!("refused {}", error.raw_os_error().unwrap_or_default()),
    };
    // Whole or not at all, so the test never reads half a report.
    let partial = report.with_extension("partial");
    std::fs::write(
        &partial,
        format!("nested={}\nbreakaway={breakaway}\n", nested.id()),
    )
    .expect("the report is written");
    std::fs::rename(&partial, &report).expect("the report is published");
    std::thread::sleep(Duration::from_secs(600));
}

// ---------------------------------------------------------------------------------------------
// The first outcome: the sandbox nests under the session's job.

/// KR-REQ-07.64: a vendor sandbox that makes a job of its own, limited in processes, memory and
/// the user interface, nests under the session's job. The agent launches, the process inside the
/// sandbox is held by the session's job and by the agent's, a try at breaking away is refused, and
/// the closure ends every process the vendor made and reads its ownership coverage as complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_sandbox_that_nests_under_the_session_job_launches_and_the_closure_ends_all_of_it()
 {
    let session = Arc::new(SessionJob::create().expect("a session job"));
    let mut launch = Launch::start(1, AgentOwnership::Full, &session).expect("the agent launches");
    let report = launch.report();

    assert!(
        report.breakaway.starts_with("refused"),
        "breakaway is not granted to make a sandbox start: {report:?}"
    );
    let members = session.process_ids().expect("the session's processes");
    assert!(
        members.contains(&report.nested),
        "the process in the vendor's own job is held by the session's: {members:?}"
    );
    assert!(
        launch
            .agent_job()
            .process_ids()
            .expect("the agent's processes")
            .contains(&report.nested),
        "and by the agent's"
    );
    assert_eq!(
        session.ui_restrictions().expect("the session's limits") & DESKTOP,
        0,
        "the product's own job restricts no desktop"
    );

    let vendor_made = identity_of(report.nested);
    let mut closure = closure_record(&launch);
    closure.observe();
    force_stop(&closure);
    eventually("the closure ends what the vendor made", || {
        ended(&vendor_made)
    });
    eventually("the session's job is empty", || {
        session.process_ids().is_ok_and(|held| held.is_empty())
    });
    closure.observe();
    assert!(
        closure
            .terminated()
            .iter()
            .any(|process| process.identity == vendor_made),
        "the process the vendor made is a terminated owned process"
    );
    assert!(closure.surviving().is_empty(), "{:?}", closure.surviving());
    assert_eq!(
        closure.coverage(),
        OwnershipCoverage::Complete,
        "{:?}",
        closure.unestablished()
    );
}

// ---------------------------------------------------------------------------------------------
// The second outcome: a sandbox the session's job is incompatible with.

/// KR-REQ-07.64: where the session's job restricts desktops, which a vendor's own sandbox cannot
/// run under, the full launch is refused by name before anything starts, and nothing of the
/// vendor's sandbox is touched to make it start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_session_job_that_restricts_desktops_refuses_the_launch_by_name_and_starts_nothing()
 {
    let session = Arc::new(SessionJob::create_restricting(DESKTOP).expect("a restricted job"));
    assert_ne!(
        session.ui_restrictions().expect("the limits") & DESKTOP,
        0,
        "the kernel reads the restriction back"
    );
    let refused = Launch::start(2, AgentOwnership::Full, &session)
        .err()
        .expect("the launch is refused");
    match refused {
        BrokerError::PreconditionFailed { detail } => {
            assert!(
                detail.contains("desktops"),
                "the restriction is named: {detail}"
            );
            assert!(detail.contains("reduced"), "and what avoids it: {detail}");
        }
        other => panic!("a named launch failure was expected: {other:?}"),
    }
    assert!(
        session
            .process_ids()
            .expect("the session's processes")
            .is_empty(),
        "nothing was started in the session"
    );
    assert!(
        session.reduced_agents().is_empty(),
        "and no agent was recorded as running under reduced ownership"
    );
}

/// KR-REQ-07.64: the same session job, with the package's agent explicitly selected for reduced
/// ownership, starts the agent in a job of its own alone. Its processes are listed by start
/// identity and the vendor's own job nests under that one, breakaway is still refused, and the
/// closure ends all of it, reading the coverage as incomplete with the reason in the receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_selected_reduced_profile_starts_the_agent_in_a_job_of_its_own_and_never_reads_complete()
 {
    let session = Arc::new(SessionJob::create_restricting(DESKTOP).expect("a restricted job"));
    let mut launch = Launch::start(3, AgentOwnership::Reduced, &session)
        .expect("the explicitly selected profile starts the agent");
    let report = launch.report();

    assert!(
        report.breakaway.starts_with("refused"),
        "reduced ownership grants no breakaway either: {report:?}"
    );
    let agent = launch.agent_job();
    assert!(
        agent.kills_on_close().expect("the limits"),
        "the agent's job ends what it holds when the last handle to it closes"
    );
    assert!(
        !agent.breakaway_permitted().expect("the limits"),
        "and permits no breakaway"
    );
    assert!(
        session
            .process_ids()
            .expect("the session's processes")
            .is_empty(),
        "the agent is not in the session's job"
    );
    assert_eq!(session.reduced_agents().len(), 1, "the session records it");
    let held = agent.process_ids().expect("the agent's processes");
    assert!(
        held.contains(&report.nested),
        "the process in the vendor's own job is held by the agent's: {held:?}"
    );

    let vendor_made = identity_of(report.nested);
    let mut closure = closure_record(&launch);
    closure.observe();
    assert!(
        closure
            .surviving()
            .iter()
            .any(|process| process == &launch.process)
            && closure.surviving().contains(&vendor_made),
        "the agent and what it made are tracked by start identity: {:?}",
        closure.surviving()
    );
    force_stop(&closure);
    eventually("the closure ends what the vendor made", || {
        ended(&vendor_made)
    });
    eventually("the agent's job is empty", || {
        agent.process_ids().is_ok_and(|held| held.is_empty())
    });
    closure.observe();
    assert!(closure.surviving().is_empty(), "{:?}", closure.surviving());
    assert!(
        closure
            .terminated()
            .iter()
            .any(|process| process.identity == vendor_made),
        "the process the vendor made is a terminated owned process"
    );
    assert_eq!(
        closure.coverage(),
        OwnershipCoverage::Incomplete,
        "coverage never reads complete for an agent outside the session's job"
    );
    assert!(
        closure
            .surviving_resources()
            .iter()
            .any(|resource| resource.kind == "unestablished"
                && resource.detail.contains("reduced-ownership")),
        "the receipt says why: {:?}",
        closure.surviving_resources()
    );
}

/// KR-REQ-07.64: an agent under reduced ownership is in a job nothing but this worker holds, so a
/// worker that dies, and lets go of every handle to it, takes the agent and everything the vendor
/// made down with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_07_64_a_worker_that_dies_takes_a_reduced_agent_and_what_it_made_with_it() {
    let session = Arc::new(SessionJob::create().expect("a session job"));
    let mut launch = Launch::start(4, AgentOwnership::Reduced, &session)
        .expect("the selected profile starts the agent");
    let report = launch.report();
    let vendor_made = identity_of(report.nested);
    let agent = launch.process.clone();
    let mut child = launch.the_worker_dies();
    assert!(
        child.try_wait().expect("the agent's status").is_none(),
        "the agent is running while the worker holds its job"
    );
    drop(session);
    eventually("the agent ends with the worker's last handle", || {
        child.try_wait().expect("the agent's status").is_some()
    });
    eventually("and so does what the vendor made", || ended(&vendor_made));
    assert!(ended(&agent));
}

// ---------------------------------------------------------------------------------------------
// The real agent, where the environment names one.

/// The Codex build a native run uses, from the environment, or nothing.
fn native_codex() -> Option<PathBuf> {
    std::env::var_os("KR_NATIVE_CODEX").map(PathBuf::from)
}

/// What the native Codex run's sandboxed command does: it starts a process of its own, tries to
/// break away, says what happened and stays until it is ended.
#[test]
#[ignore = "a process the native tests start inside Codex's own sandbox"]
fn native_codex_sandboxed_command() {
    use std::os::windows::process::CommandExt as _;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    let report = PathBuf::from(std::env::args().last().expect("the report's path"));
    let held = waiting_program()
        .spawn()
        .expect("a process of its own starts");
    let breakaway = match waiting_program()
        .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Ok(escaped) => format!("created {}", escaped.id()),
        Err(error) => format!("refused {}", error.raw_os_error().unwrap_or_default()),
    };
    let partial = report.with_extension("partial");
    std::fs::write(
        &partial,
        format!(
            "nested={}\nbreakaway={breakaway}\nrestricted={}\n",
            held.id(),
            this_token_is_restricted()
        ),
    )
    .expect("the report is written");
    std::fs::rename(&partial, &report).expect("the report is published");
    std::thread::sleep(Duration::from_secs(600));
}

/// Starts the real Codex as the agent, running `codex sandbox` on the sandboxed command above in a
/// working directory of its own: no sign-in, no model turn, and the vendor's sandbox exactly as
/// the vendor made it.
fn start_native_codex(
    which: u8,
    ownership: AgentOwnership,
    session: &Arc<SessionJob>,
    codex: &Path,
) -> Result<Launch, BrokerError> {
    let directory = private_directory();
    // An ordinary directory, because the sandbox gives its restricted token access to the
    // working directory by an entry of its own on it, and a directory closed to every account but
    // the owner is not one that entry can open.
    let work = std::env::temp_dir().join(format!("kr-wv-work-{}", short_name()));
    std::fs::create_dir_all(&work).expect("the working directory");
    // The sandboxed command runs from the working directory, where the sandbox lets it write.
    let helper = work.join("vendor-helper.exe");
    std::fs::copy(this_executable(), &helper).expect("the helper is placed");
    let report = work.join("report");
    let broker = Arc::new(
        Broker::open(None, session_id(), JournalHealth::shared()).expect("the broker opens"),
    );
    let mut launch = launch_for(which);
    launch.working_directory = work.clone();
    let mut gateway = NativeGateway::bind(Arc::clone(&broker), &directory, launch)
        .expect("the endpoint binds")
        .in_session(Arc::clone(session));
    let arguments: Vec<String> = [
        "sandbox",
        "-P",
        ":workspace",
        "-C",
        work.to_string_lossy().as_ref(),
        "--",
        helper.to_string_lossy().as_ref(),
        "--ignored",
        "--exact",
        "native_codex_sandboxed_command",
        "--nocapture",
        "--test-threads=1",
        report.to_string_lossy().as_ref(),
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect();
    let mut codex_profile = profile(which, &arguments, ownership);
    codex_profile.binary.resolved_path = codex.to_string_lossy().into_owned();
    let intent = broker
        .prepare_launch(
            codex_profile,
            kr_worker::broker::ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let Launched { child, process, .. } = gateway.launch(
        &intent,
        &kr_worker::broker::ForegroundMark::idle(4),
        IntegrationMode::Gateway,
        TimestampMs::new(1),
    )?;
    Ok(Launch {
        gateway: Some(gateway),
        directory,
        report,
        child: Some(child),
        process,
        session: Arc::clone(session),
        work: Some(work),
        end_on_drop: true,
    })
}

/// KR-REQ-07.64, against the real Codex: its sandbox runs the command as a restricted-token child
/// of its own under the session's job, the launch succeeds, and the closure ends every process the
/// vendor made. Run with `KR_NATIVE_CODEX` naming the pinned `codex.exe`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the pinned Codex build: set KR_NATIVE_CODEX to its codex.exe"]
async fn native_codex_nests_under_the_session_job_and_the_closure_ends_everything_it_made() {
    let codex = native_codex().expect("KR_NATIVE_CODEX names the pinned codex.exe");
    let session = Arc::new(SessionJob::create().expect("a session job"));
    let mut launch = start_native_codex(11, AgentOwnership::Full, &session, &codex)
        .expect("Codex launches under the session's job");
    launch.close_input();
    let report = launch.report();
    assert_eq!(
        report.restricted,
        Some(true),
        "Codex's own sandbox ran the command, under its restricted token: {report:?}"
    );
    let members = session.process_ids().expect("the session's processes");
    println!("native Codex under the session's job: {report:?}; the job holds {members:?}");
    assert!(
        members.contains(&report.nested),
        "the command Codex's sandbox ran is held by the session's job: {members:?}"
    );
    assert!(
        members.len() >= 3,
        "Codex, its sandboxed command and what it made: {members:?}"
    );

    let vendor_made: Vec<ProcessStartIdentity> =
        members.iter().map(|pid| identity_of(*pid)).collect();
    let mut closure = closure_record(&launch);
    closure.observe();
    force_stop(&closure);
    eventually("every process the vendor made ends", || {
        vendor_made.iter().all(ended)
    });
    eventually("the session's job is empty", || {
        session.process_ids().is_ok_and(|held| held.is_empty())
    });
    closure.observe();
    assert!(closure.surviving().is_empty(), "{:?}", closure.surviving());
    assert_eq!(
        closure.coverage(),
        OwnershipCoverage::Complete,
        "{:?}",
        closure.unestablished()
    );
}

/// KR-REQ-07.64, against the real Codex: under a session job that restricts desktops, the full
/// launch is a named failure that starts nothing, and the explicitly selected reduced profile
/// starts Codex in a job of its own, its sandbox runs the command, the closure ends all of it and
/// the coverage reads incomplete. Run with `KR_NATIVE_CODEX` naming the pinned `codex.exe`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the pinned Codex build: set KR_NATIVE_CODEX to its codex.exe"]
async fn native_codex_under_a_desktop_restricting_session_job_fails_by_name_or_runs_reduced() {
    let codex = native_codex().expect("KR_NATIVE_CODEX names the pinned codex.exe");
    let session = Arc::new(SessionJob::create_restricting(DESKTOP).expect("a restricted job"));
    let refused = start_native_codex(12, AgentOwnership::Full, &session, &codex)
        .err()
        .expect("the full launch is refused");
    assert!(
        matches!(&refused, BrokerError::PreconditionFailed { detail } if detail.contains("desktops")),
        "{refused:?}"
    );
    assert!(
        session
            .process_ids()
            .expect("the session's processes")
            .is_empty()
    );

    let mut launch = start_native_codex(13, AgentOwnership::Reduced, &session, &codex)
        .expect("the selected profile starts Codex");
    launch.close_input();
    let report = launch.report();
    assert_eq!(
        report.restricted,
        Some(true),
        "Codex's own sandbox ran the command, under its restricted token: {report:?}"
    );
    let agent = launch.agent_job();
    let held = agent.process_ids().expect("the agent's processes");
    println!("native Codex under reduced ownership: {report:?}; its own job holds {held:?}");
    assert!(
        held.contains(&report.nested),
        "the command Codex's sandbox ran is held by the agent's job: {held:?}"
    );
    assert!(
        session
            .process_ids()
            .expect("the session's processes")
            .is_empty(),
        "and none of it is in the session's"
    );
    let vendor_made: Vec<ProcessStartIdentity> = held.iter().map(|pid| identity_of(*pid)).collect();
    let mut closure = closure_record(&launch);
    closure.observe();
    force_stop(&closure);
    eventually("every process the vendor made ends", || {
        vendor_made.iter().all(ended)
    });
    closure.observe();
    assert!(closure.surviving().is_empty(), "{:?}", closure.surviving());
    assert_eq!(closure.coverage(), OwnershipCoverage::Incomplete);
}
