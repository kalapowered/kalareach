//! What every description test needs: identifiers, clock readings and the shipped profiles.
//!
//! Only the pieces that no test could avoid are here. A helper that belongs to one area - a queue
//! context, a validated result, a service over the deterministic runtime - stays in the file that
//! drives that area, where a reader can see what it does without leaving the test.
#![allow(dead_code)]

use kr_crypto::keys::AuthorisationKeyPair;
use kr_describe::budget::GIB;
use kr_describe::context::ContextBinding;
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment};
use kr_describe::profile::catalogue::{self, Catalogue};
use kr_describe::profile::{ModelProfile, ProfileDocument, ProfileTrust, SignedProfile};
use kr_describe::resource::{HostConditions, PowerSource, ThermalState};
use kr_describe::time::Reading;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::scalars::Uuid;

/// The target the tests select profiles for.
pub const MAC: &str = "aarch64-apple-darwin";

/// A session identifier a test can name twice.
pub fn session(seed: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([seed; 16]))
}

/// An environment identifier a test can name twice.
pub fn environment_id(seed: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([seed | 0x80; 16]))
}

/// A native execution environment.
pub fn native(seed: u8) -> ExecutionEnvironment {
    ExecutionEnvironment::new(environment_id(seed), EnvironmentKind::Native)
}

/// The binding a session is described under.
pub fn binding() -> ContextBinding {
    ContextBinding::new("desktop-1/terminal/epoch-1")
}

/// One reading of both clocks, at a monotonic millisecond a test chooses.
pub fn at(monotonic_ms: u64) -> Reading {
    Reading::new(monotonic_ms, 1_700_000_000_000 + monotonic_ms)
}

/// The profiles this build ships.
pub fn built_in() -> Catalogue {
    Catalogue::builtin().expect("this build ships profiles it can run")
}

/// The default profile.
pub fn default_profile() -> ModelProfile {
    built_in().default_profile().clone()
}

/// A catalogue of one profile: the default profile's document with some of its text replaced,
/// signed with a key of the test's own and verified as every profile is before it is used.
///
/// Each edit names text the document holds, so an edit that matches nothing is a mistake in the
/// test and stops it.
pub fn catalogue_with(edits: &[(&str, &str)]) -> Catalogue {
    let mut document = catalogue::DEFAULT_PROFILE_DOCUMENT.to_owned();
    for (find, replace) in edits {
        assert!(document.contains(find), "the document holds no {find}");
        document = document.replace(find, replace);
    }
    let keys = AuthorisationKeyPair::generate().expect("a keypair");
    let document = ProfileDocument::new(document.into_bytes());
    let transcript = document.transcript().expect("a transcript");
    let signature = kr_crypto::sign::sign(&keys, &transcript).expect("a signature");
    let signed = SignedProfile {
        document,
        key: *keys.public(),
        signature,
    };
    let profile = ProfileTrust::new(vec![*keys.public()])
        .verify(&signed)
        .expect("a profile this build would run");
    Catalogue::new(vec![profile]).expect("a catalogue of one default")
}

/// Conditions a host with plenty of everything reports.
pub fn roomy() -> HostConditions {
    HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Nominal,
    )
}

/// Opens a second connection to a store on disk that holds a pin in a write transaction it has not
/// committed, which is where a pin written by another connection is while a publication races it.
pub fn a_pin_not_yet_committed(
    root: &std::path::Path,
    session_id: &SessionId,
) -> rusqlite::Connection {
    let other = rusqlite::Connection::open(root.join("descriptions.sqlite3"))
        .expect("a second connection to the same store");
    other
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the second connection takes the write lock");
    other
        .execute(
            "INSERT INTO describe_pins (session_id, title, pinned_by, pinned_at_ms)
             VALUES (?1, 'Release prep', 'local:501', 1700000000000)",
            [session_id.to_string()],
        )
        .expect("a pin, not yet committed");
    other
}

/// What a read on the calling thread reports of its background class. On Linux: its scheduling
/// policy and priority, its niceness and its I/O class, all the thread's own. On macOS: the
/// priority the kernel reports for the thread, as `ps -M` shows it and not the thread library's
/// record of it, and the I/O class, which is the process's there, as the processor class is. On the
/// other Unix systems: its scheduling policy and priority.
/// The server does not hand out the model thread's identifier, so a case reads the class on the
/// thread that runs the work.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    #[cfg(not(target_os = "macos"))]
    pub policy: thread_priority::unix::ThreadSchedulePolicy,
    #[cfg(not(target_os = "macos"))]
    pub priority: i32,
    #[cfg(target_os = "macos")]
    pub kernel_priority: Option<i32>,
    #[cfg(target_os = "linux")]
    pub nice: i32,
    pub io: Option<kr_ipc::background::IoClass>,
}

/// Reads the background class of the calling thread.
#[cfg(unix)]
pub fn held_by_this_thread() -> Held {
    #[cfg(not(target_os = "macos"))]
    let (policy, params) =
        thread_priority::unix::thread_schedule_policy_param(thread_priority::thread_native_id())
            .expect("the system reports the thread's scheduling class");
    Held {
        #[cfg(not(target_os = "macos"))]
        policy,
        #[cfg(not(target_os = "macos"))]
        priority: params.sched_priority,
        #[cfg(target_os = "macos")]
        kernel_priority: kr_ipc::background::thread_priority(),
        #[cfg(target_os = "linux")]
        nice: nice_of_this_thread(),
        io: kr_ipc::background::io_class(),
    }
}

/// The niceness the system reports for the calling thread: field 19 of its stat. The name in field
/// 2 may hold spaces and brackets, so the fields are counted from its closing bracket.
#[cfg(target_os = "linux")]
fn nice_of_this_thread() -> i32 {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("the thread's stat");
    let after_name = stat.rsplit_once(')').expect("a name in the stat").1;
    after_name
        .split_whitespace()
        .nth(16)
        .expect("a niceness in the stat")
        .parse()
        .expect("a whole number")
}

#[cfg(unix)]
impl Held {
    /// Whether the thread holds the processor class this build lowers a model thread to: the batch
    /// policy at niceness 19 on Linux, the background priority the kernel reports on macOS, and the
    /// lowest priority its policy has on the other Unix systems.
    pub fn cpu_is_lowered(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            use thread_priority::unix::{NormalThreadSchedulePolicy, ThreadSchedulePolicy};
            self.policy == ThreadSchedulePolicy::Normal(NormalThreadSchedulePolicy::Batch)
                && self.nice == 19
        }
        #[cfg(target_os = "macos")]
        {
            self.kernel_priority
                .is_some_and(|priority| priority <= kr_ipc::background::BACKGROUND_THREAD_PRIORITY)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            thread_priority::ThreadPriority::Min
                .to_posix(self.policy)
                .is_ok_and(|lowest| self.priority == lowest)
        }
    }

    /// Whether the thread holds the I/O class this build lowers to: idle on Linux, and the
    /// throttled disk policy of the process on macOS.
    pub fn io_is_lowered(&self) -> bool {
        use kr_ipc::background::IoClass;
        self.io
            == Some(if cfg!(target_os = "linux") {
                IoClass::Idle
            } else {
                IoClass::Throttled
            })
    }
}
