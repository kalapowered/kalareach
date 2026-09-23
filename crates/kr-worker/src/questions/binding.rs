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
//!
//! Either of the last two admits a source, and both are recorded. Neither is a defence against
//! arbitrary code running under the same operating-system account: section 11 places that inside
//! the operating system's trust boundary and says so plainly. What they do establish is that this
//! process belongs to *this* session rather than another one, which is what decides where a
//! question is created.
//!
//! A helper that presents the private launch channel it inherited is recorded as having done so.
//! This build's root shell does not yet hand one down, so that flag is false and the binding rests
//! on the kernel checks above.
//!
//! Environment variables take no part in any of this. `KR_SESSION` helps a helper find a socket;
//! what happens after it connects is decided here.

use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::ConnectionId;

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

/// Binds the caller on this connection to this session.
///
/// # Errors
///
/// Returns [`QuestionError::NotInSession`] when the kernel will not name the caller, when the
/// session has no running root shell, or when the caller is in neither the session's boundary nor
/// its process tree.
pub fn verify(
    peer_pid: Option<u32>,
    admitted: Option<&ProcessStartIdentity>,
    connection_id: ConnectionId,
    session: Option<&SessionBoundary>,
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
    if !session_member && !ancestry {
        return Err(QuestionError::unbound(
            "the calling process is not in this session's process boundary and does not descend \
             from its root shell",
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
    let root_pid = u32::try_from(root.pid.get()).unwrap_or(u32::MAX);
    let mut current = from.clone();
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let current_pid = u32::try_from(current.pid.get()).unwrap_or(u32::MAX);
        if current_pid == root_pid {
            return current.matches(root);
        }
        let Some(parent_pid) = platform::parent(current_pid) else {
            return false;
        };
        if parent_pid == 0 || parent_pid == current_pid {
            return false;
        }
        let Ok(parent) = kr_ipc::identity::process_start_identity(parent_pid) else {
            return false;
        };
        // A parent starts before its child. Every source's start value increases with time within
        // one boot, so a candidate parent that started later is an identifier the kernel has
        // handed to something else since this child was created, and the chain stops there rather
        // than climbing through a stranger.
        if parent.source != current.source || parent.start_value.get() > current.start_value.get() {
            return false;
        }
        // The child is read again, identity and parent together. If its identifier changed owners
        // between the first read and this one, both parent readings describe the replacement's
        // family rather than this one's, and the chain stops rather than climbing somebody else's.
        let Ok(again) = kr_ipc::identity::process_start_identity(current_pid) else {
            return false;
        };
        if !again.matches(&current) || platform::parent(current_pid) != Some(parent_pid) {
            return false;
        }
        current = parent;
    }
    false
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

    /// KR-REQ-05.09: a caller is bound to a session only by a parent chain the kernel reports
    /// reaching that session's root shell.
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
