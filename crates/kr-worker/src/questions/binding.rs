//! Binding a helper to the session it is actually running in.
//!
//! A tool call arrives on the worker's own private socket. Before anything is created, the worker
//! establishes which session the caller is in, and it asks the kernel rather than the caller:
//!
//! 1. **Peer credentials.** The listener has already refused any user but this one, and the kernel
//!    names the calling process.
//! 2. **Process identity.** That process identifier is paired with the kernel's start value, so a
//!    recycled identifier cannot pass as the process that called a moment ago.
//! 3. **Session membership.** The process is looked for inside the boundary this session owns: the
//!    control group or the controlling terminal and process group the root shell leads.
//! 4. **Ancestry.** The parent chain is walked to the root shell. Every link is read from the
//!    kernel and checked for consistency: a parent that started *after* its child is not that
//!    child's parent, whatever the identifier says, so an identifier reused since the child was
//!    created does not complete a chain.
//! 5. **The local broker.** The same walk, to an agent this session's broker launched. An agent
//!    whose backend the worker started runs outside the terminal and its process group, and the
//!    helper that backend starts is this session's all the same, because the broker started that
//!    backend for this session and knows it by its start identity.
//!
//! Any of the last three admits a source; the first two are recorded, and the third is recorded
//! as the agent binding below. None of them is a defence against arbitrary code running under the
//! same operating-system account: section 11 places that inside the operating system's trust
//! boundary and says so plainly. What they do establish is that this process belongs to *this*
//! session rather than another one, which is what decides where a question is created.
//!
//! A helper that presents the private launch channel it inherited is recorded as having done so.
//! This build's root shell does not yet hand one down, so that flag is false and the binding rests
//! on the kernel checks above.
//!
//! Environment variables take no part in any of this. `KR_SESSION` helps a helper find a socket;
//! what happens after it connects is decided here.
//!
//! # The agent a source belongs to
//!
//! A session is one binding; the agent a question comes from is another. Section 11 records an
//! agent thread or binding revision only when a qualified bridge supplies one, and invalidates the
//! unanswered questions asked under a binding when a switch is detected. [`AgentBindings`] is how
//! this ledger learns both: which bridged application instance a calling process belongs to and at
//! which revision, and where that instance's binding stands now. The worker's broker answers it
//! for the agents it launched, whose upstream owner and selected thread it tracks. A source that
//! no bridge describes gets no revision, its question is application-scoped, and no thread-switch
//! detection is claimed for it.

use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId, ConnectionId};

use crate::ownership::OwnershipBoundary;
use crate::questions::error::{QuestionError, Result};

/// How many parent links are followed before the walk gives up.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// What the worker knows about the session a caller might be inside.
#[derive(Clone, Debug)]
pub struct SessionBoundary {
    /// The boundary this session's processes live in.
    pub boundary: OwnershipBoundary,
    /// The root shell every member descends from.
    pub root: ProcessStartIdentity,
}

/// One caller the worker has bound to this session.
#[derive(Clone, Debug)]
pub struct VerifiedSource {
    /// The calling process, with the kernel's start value.
    pub process: ProcessStartIdentity,
    /// The executable it is running, where the platform names it.
    pub executable: Option<String>,
    /// True when the process is inside the session's own boundary.
    pub session_member: bool,
    /// True when its parent chain reaches the root shell.
    pub ancestry: bool,
    /// True when the helper presented an inherited private launch channel.
    pub launch_channel: bool,
    /// The connection it called on.
    pub connection_id: ConnectionId,
}

impl VerifiedSource {
    /// Returns the key that identifies this application across its calls.
    ///
    /// It is the process and its start value, which is what section 11 means by the verified
    /// originating application: a new execution under the same name is a different key, so it
    /// cannot inherit the pending decisions of the one before it.
    #[must_use]
    pub fn key(&self) -> String {
        let source = match self.process.source {
            ProcessStartSource::LinuxProcStat => "linux",
            ProcessStartSource::MacosProcBsdInfo => "macos",
            ProcessStartSource::WindowsProcessStartSeconds => "windows",
        };
        format!(
            "{}:{source}:{}",
            self.process.pid.get(),
            self.process.start_value.get()
        )
    }
}

/// The bridged application instance a source belongs to, and the binding a question from it is
/// asked under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentBinding {
    /// The application instance, as the worker's broker names it.
    pub application_instance_id: ApplicationInstanceId,
    /// The revision its binding is at: it advances when the upstream owner or the selected thread
    /// changes.
    pub revision: AgentBindingRevision,
}

/// What a qualified bridge says about the agents in this session.
///
/// Implemented by the worker's broker. A ledger with none of these records no binding revision and
/// invalidates nothing on a switch, which is the application-scoped case section 11 allows for a
/// helper no bridge describes.
pub trait AgentBindings: Send + Sync + std::fmt::Debug {
    /// Returns the bridged instance a calling process belongs to, and its revision now.
    ///
    /// A process belongs to an instance when it is that instance's process or descends from it, by a
    /// parent chain the kernel confirms link by link. None when no bridged instance holds it.
    fn binding_of(&self, process: &ProcessStartIdentity) -> Option<AgentBinding>;

    /// Returns the revision one instance's binding is at now, or None when the instance has ended.
    fn current(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<AgentBindingRevision>;
}

/// Binds the caller on this connection to this session.
///
/// # Errors
///
/// Returns [`QuestionError::NotInSession`] when the kernel will not name the caller, when the
/// session has no running root shell, or when the caller is in neither the session's boundary nor
/// its process tree nor the tree of an agent the session's broker launched.
pub fn verify(
    peer_pid: Option<u32>,
    admitted: Option<&ProcessStartIdentity>,
    connection_id: ConnectionId,
    session: Option<&SessionBoundary>,
    agents: Option<&dyn AgentBindings>,
) -> Result<VerifiedSource> {
    let Some(pid) = peer_pid else {
        return Err(QuestionError::unbound(
            "the operating system did not name the calling process on this connection",
        ));
    };
    let process = kr_ipc::identity::process_start_identity(pid).map_err(|error| {
        QuestionError::unbound(format!(
            "the calling process could not be identified: {error}"
        ))
    })?;
    // The identity is the connection's, read when it was accepted. A process identifier the kernel
    // recycles while this connection is open names a different program, and answering it as though
    // it were the caller that opened the connection is exactly what pairing an identifier with its
    // start value prevents. A connection whose identity was never captured cannot acquire one
    // later from whatever holds that identifier now, so it is refused outright.
    let Some(admitted) = admitted else {
        return Err(QuestionError::unbound(
            "this connection's calling process was never identified, so nothing can be bound to it",
        ));
    };
    if !process.matches(admitted) {
        return Err(QuestionError::unbound(
            "the process on this connection is no longer the one that opened it",
        ));
    }
    let Some(session) = session else {
        return Err(QuestionError::unbound(
            "this session has no running root shell, so nothing is inside it",
        ));
    };
    let session_member = contains(&session.boundary, pid);
    // The walk starts from the identity that was verified, not from a fresh reading of the
    // identifier: the evidence has to be about the process that called, not about whatever holds
    // its identifier now.
    let ancestry = descends_from(&process, &session.root);
    let bridged = || agents.is_some_and(|agents| agents.binding_of(&process).is_some());
    if !session_member && !ancestry && !bridged() {
        return Err(QuestionError::unbound(
            "the calling process is not in this session's process boundary and descends neither \
             from its root shell nor from an agent its broker launched",
        ));
    }
    // Everything above read the operating system while this function ran, and the evidence is
    // only about the caller if the caller is still the caller. Read once more, last.
    let settled = kr_ipc::identity::process_start_identity(pid).map_err(|error| {
        QuestionError::unbound(format!(
            "the calling process could not be identified: {error}"
        ))
    })?;
    if !settled.matches(&process) {
        return Err(QuestionError::unbound(
            "the process on this connection changed while its session was being established",
        ));
    }
    Ok(VerifiedSource {
        process,
        executable: platform::executable(pid),
        session_member,
        ancestry,
        // Reserved for the inherited launch channel. Nothing hands one down yet, and claiming one
        // that was never presented would put a fact in the identity header that nobody checked.
        launch_channel: false,
        connection_id,
    })
}

/// Returns whether the boundary this session owns currently holds this process.
fn contains(boundary: &OwnershipBoundary, pid: u32) -> bool {
    match boundary {
        OwnershipBoundary::TerminalGroup { group, terminal } => {
            let members = match terminal {
                Some(terminal) => kr_ipc::identity::processes_on_terminal(*terminal),
                None => kr_ipc::identity::processes_in_group(*group),
            };
            members.is_ok_and(|members| members.contains(&pid))
        }
        OwnershipBoundary::ControlGroup { path } => {
            let Ok(listed) = std::fs::read_to_string(path.join("cgroup.procs")) else {
                return false;
            };
            listed
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .any(|member| member == pid)
        }
        // The job holds every descendant, so its own process list is the answer.
        #[cfg(windows)]
        OwnershipBoundary::JobObject { root } => crate::windows::job::holding(*root)
            .and_then(|job| job.process_ids().ok())
            .is_some_and(|members| members.contains(&pid)),
        // No job exists on this platform, so nothing is ever held by one.
        #[cfg(not(windows))]
        OwnershipBoundary::JobObject { .. } => false,
    }
}

/// Returns whether the parent chain from this process reaches the session's root shell.
///
/// Each link is checked by start identity, so a parent identifier that has been recycled since the
/// child was created does not complete the chain.
fn descends_from(from: &ProcessStartIdentity, root: &ProcessStartIdentity) -> bool {
    nearest_of(from, std::slice::from_ref(root)).is_some()
}

/// Returns the nearest of `candidates` that is `from` itself or one of its ancestors.
///
/// Every link is read from the kernel, and a candidate matches only by its full start identity, so
/// an identifier recycled since the candidate's process started is not it.
pub(crate) fn nearest_of(
    from: &ProcessStartIdentity,
    candidates: &[ProcessStartIdentity],
) -> Option<usize> {
    let mut current = from.clone();
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if let Some(found) = candidates
            .iter()
            .position(|candidate| candidate.matches(&current))
        {
            return Some(found);
        }
        let current_pid = u32::try_from(current.pid.get()).unwrap_or(u32::MAX);
        let parent_pid = platform::parent(current_pid)?;
        if parent_pid == 0 || parent_pid == current_pid {
            return None;
        }
        let parent = kr_ipc::identity::process_start_identity(parent_pid).ok()?;
        // A parent starts before its child. Every source's start value increases with time within
        // one boot, so a candidate parent that started later is an identifier the kernel has
        // handed to something else since this child was created, and the chain stops there rather
        // than climbing through a stranger.
        if parent.source != current.source || parent.start_value.get() > current.start_value.get() {
            return None;
        }
        // The child is read again, identity and parent together. If its identifier changed owners
        // between the first read and this one, both parent readings describe the replacement's
        // family rather than this one's, and the chain stops rather than climbing somebody else's.
        let again = kr_ipc::identity::process_start_identity(current_pid).ok()?;
        if !again.matches(&current) || platform::parent(current_pid) != Some(parent_pid) {
            return None;
        }
        current = parent;
    }
    None
}

#[cfg(target_os = "linux")]
mod platform {
    /// Returns the executable one process is running.
    pub(super) fn executable(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.display().to_string())
    }

    /// Returns the parent of one process.
    ///
    /// `/proc/<pid>/stat` begins `pid (comm) state ppid`, and the command name can contain spaces
    /// and brackets, so the fields are read after the last closing bracket.
    pub(super) fn parent(pid: u32) -> Option<u32> {
        let line = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = &line[line.rfind(')')? + 1..];
        after.split_whitespace().nth(1)?.parse().ok()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libproc::bsd_info::BSDInfo;
    use libproc::proc_pid::{pidinfo, pidpath};

    pub(super) fn executable(pid: u32) -> Option<String> {
        pidpath(i32::try_from(pid).ok()?).ok()
    }

    pub(super) fn parent(pid: u32) -> Option<u32> {
        let info: BSDInfo = pidinfo(i32::try_from(pid).ok()?, 0).ok()?;
        Some(info.pbi_ppid)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};

    fn look(pid: u32, read: impl Fn(&sysinfo::Process) -> Option<String>) -> Option<String> {
        let mut system = sysinfo::System::new();
        let target = sysinfo::Pid::from_u32(pid);
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing(),
        );
        system.process(target).and_then(read)
    }

    pub(super) fn executable(pid: u32) -> Option<String> {
        look(pid, |process| {
            process.exe().map(|path| path.display().to_string())
        })
    }

    pub(super) fn parent(pid: u32) -> Option<u32> {
        look(pid, |process| {
            process.parent().map(|parent| parent.as_u32().to_string())
        })
        .and_then(|text| text.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    /// KR-REQ-05.09: a caller the kernel will not name is in no session, whatever it says.
    #[test]
    fn a_connection_the_kernel_will_not_name_is_not_in_a_session() {
        let error = verify(
            None,
            None,
            ConnectionId::new(Uuid::from_bytes([1; 16])),
            None,
            None,
        )
        .expect_err("no");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::NotInKrSession);
        assert!(error.to_string().contains("kr new --attach"));
    }

    #[test]
    fn a_session_without_a_root_shell_holds_nothing() {
        let error = verify(
            Some(std::process::id()),
            None,
            ConnectionId::new(Uuid::from_bytes([2; 16])),
            None,
            None,
        )
        .expect_err("no");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::NotInKrSession);
    }

    #[test]
    fn this_process_descends_from_itself() {
        let identity =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        assert!(descends_from(&identity, &identity));
    }

    /// KR-REQ-05.09: a parent chain counts as evidence of a session only when it reaches that
    /// session's root shell itself: the root's identifier with another start value does not
    /// complete it.
    #[test]
    fn a_process_that_is_not_an_ancestor_does_not_complete_the_chain() {
        let mine =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        let mut root = mine.clone();
        // The same process, with a start value the kernel never reported. A chain that reached the
        // identifier but not the identity must not complete.
        root.start_value = kr_protocol::scalars::U64::new(root.start_value.get() ^ 0xFFFF);
        assert!(!descends_from(&mine, &root));
    }

    #[test]
    fn a_connection_whose_caller_was_never_identified_binds_to_nothing() {
        let boundary = SessionBoundary {
            boundary: OwnershipBoundary::TerminalGroup {
                group: 1,
                terminal: None,
            },
            root: kr_ipc::identity::process_start_identity(std::process::id())
                .expect("an identity"),
        };
        let error = verify(
            Some(std::process::id()),
            None,
            ConnectionId::new(Uuid::from_bytes([5; 16])),
            Some(&boundary),
            None,
        )
        .expect_err("refused");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::NotInKrSession);
        assert!(error.to_string().contains("never identified"));
    }

    /// KR-REQ-05.09: the binding is about the process the kernel named when the connection was
    /// made, and a different process presenting itself later is refused.
    #[test]
    fn a_process_that_is_not_the_one_that_connected_is_refused() {
        let mut admitted =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        admitted.start_value = kr_protocol::scalars::U64::new(admitted.start_value.get() ^ 0xFFFF);
        let error = verify(
            Some(std::process::id()),
            Some(&admitted),
            ConnectionId::new(Uuid::from_bytes([4; 16])),
            None,
            None,
        )
        .expect_err("refused");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::NotInKrSession);
        assert!(
            error
                .to_string()
                .contains("no longer the one that opened it")
        );
    }

    #[test]
    fn the_nearest_managed_ancestor_is_found_by_its_full_identity() {
        let mine =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        let parent_pid = platform::parent(std::process::id()).expect("a parent");
        let parent = kr_ipc::identity::process_start_identity(parent_pid).expect("its identity");
        // This process is its own nearest candidate, and its parent is found when it is not one.
        assert_eq!(nearest_of(&mine, &[parent.clone(), mine.clone()]), Some(1));
        assert_eq!(nearest_of(&mine, std::slice::from_ref(&parent)), Some(0));
        // The same identifiers with start values the kernel never reported are nobody's.
        let mut recycled = parent;
        recycled.start_value = kr_protocol::scalars::U64::new(recycled.start_value.get() ^ 0xFFFF);
        let mut stranger = mine.clone();
        stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
        assert_eq!(nearest_of(&mine, &[recycled, stranger]), None);
    }

    #[test]
    fn a_source_key_names_the_process_and_its_start_value() {
        let source = VerifiedSource {
            process: ProcessStartIdentity::new(42, ProcessStartSource::LinuxProcStat, 9),
            executable: None,
            session_member: true,
            ancestry: false,
            launch_channel: false,
            connection_id: ConnectionId::new(Uuid::from_bytes([3; 16])),
        };
        assert_eq!(source.key(), "42:linux:9");
    }
}
