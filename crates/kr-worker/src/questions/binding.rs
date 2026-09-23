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
//!    control group, or the controlling terminal and process group the root shell leads.
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
//! The answer has three values, not two. A caller is inside when any check finds it there. It is
//! outside, `NOT_IN_KR_SESSION`, only when membership and ancestry both read everything they
//! needed and found it in neither, and the broker does not place it under an agent it launched. A reading that failed, or that changed while it was taken, establishes nothing, so
//! a caller whose answer rests on one is neither: it is refused as
//! [`QuestionError::Undetermined`]. Both refusals create nothing. They differ for a caller that has
//! to refuse whatever it cannot establish, such as the guard in front of a host's first-owner
//! confirmation, which may go on for an established outside and for nothing else.
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
//! unanswered questions asked under a binding when a switch is detected. A shared or multiplexed
//! helper must supply verified per-request source context; without it, its questions are
//! application-scoped and no thread-switch detection is claimed for them.
//!
//! [`AgentBindings`] is how this ledger learns what a bridge can say: which application instance a
//! calling process belongs to, whether that instance is still live, and, only when the bridge can
//! attest the request's own thread, the binding revision the request was made under. The worker's
//! broker is the bridge for the agents it launched. It proves membership by the kernel's parent
//! chain, which says nothing about which of an agent's threads a request came from, so it attests
//! no revision: a helper under a launched agent asks application-scoped questions, and they end
//! with the agent's instance. A source that no bridge describes is application-scoped as well.

use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId, ConnectionId};

use crate::ownership::OwnershipBoundary;
use crate::questions::error::{QuestionError, Result};

/// How many parent links are followed before the walk gives up.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// The identifier every Unix process tree hangs from.
///
/// The system's first process never exits, so an identifier naming it is never a reused one, and
/// its only parent is the kernel. A chain that reaches it has reached the top without needing to
/// read it, which matters where the kernel will not describe it to this user at all.
#[cfg(unix)]
const FIRST_PROCESS: u32 = 1;

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

/// The bridged application instance a source belongs to, and the thread binding a request was made
/// under when the bridge can say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentBinding {
    /// The application instance, as the bridge names it.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision the request was made under, when the bridge attests the request's own
    /// thread.
    ///
    /// Membership of an application is not that: a helper shared by several threads, or one that
    /// outlives a switch, carries requests from more than one of them. Without verified
    /// per-request context this is None, the question is application-scoped and no thread-switch
    /// detection is claimed for it; it still ends with its application instance.
    pub revision: Option<AgentBindingRevision>,
}

/// What a qualified bridge says about the agents in this session.
///
/// Implemented by the worker's broker. A ledger with none of these binds no question to an agent,
/// which is the application-scoped case section 11 allows for a helper no bridge describes.
pub trait AgentBindings: Send + Sync + std::fmt::Debug {
    /// Returns the bridged instance a calling process belongs to, with the revision its request was
    /// made under when the bridge can attest that.
    ///
    /// None when no bridged instance holds the process.
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
/// Returns [`QuestionError::NotInSession`] when the caller is established to be outside this
/// session: the session has not started its root shell, or the caller is in neither the session's
/// boundary nor its process tree nor the tree of an agent the session's broker launched. Returns
/// [`QuestionError::Undetermined`] when that cannot be established: the kernel will not name or
/// identify the caller, the caller is no longer the process that opened the connection, or a
/// reading either check needed failed or changed.
pub fn verify(
    peer_pid: Option<u32>,
    admitted: Option<&ProcessStartIdentity>,
    connection_id: ConnectionId,
    session: Option<&SessionBoundary>,
    agents: Option<&dyn AgentBindings>,
) -> Result<VerifiedSource> {
    bind(&Kernel, peer_pid, admitted, connection_id, session, agents)
}

/// [`verify`], reading processes from `table`.
fn bind(
    table: &impl ProcessTable,
    peer_pid: Option<u32>,
    admitted: Option<&ProcessStartIdentity>,
    connection_id: ConnectionId,
    session: Option<&SessionBoundary>,
    agents: Option<&dyn AgentBindings>,
) -> Result<VerifiedSource> {
    // Before its root shell starts, a session has started nothing, so nothing is inside it,
    // whoever is asking and whatever can be read about them.
    let Some(session) = session else {
        return Err(QuestionError::unbound(
            "this session has not started its root shell, so nothing is inside it",
        ));
    };
    let Some(pid) = peer_pid else {
        return Err(QuestionError::undetermined(
            "the operating system did not name the calling process on this connection",
        ));
    };
    // The identity is the connection's, read when it was accepted. A process identifier the kernel
    // recycles while this connection is open names a different program, and answering it as though
    // it were the caller that opened the connection is exactly what pairing an identifier with its
    // start value prevents. A connection whose identity was never captured cannot acquire one
    // later from whatever holds that identifier now, so nothing is established about it.
    let Some(admitted) = admitted else {
        return Err(QuestionError::undetermined(
            "this connection's calling process was never identified, so nothing can be \
             established about it",
        ));
    };
    let process = match table.identity(pid) {
        Reading::Found(process) if process.matches(admitted) => process,
        Reading::Found(_) | Reading::Absent => {
            return Err(QuestionError::undetermined(
                "the process on this connection is no longer the one that opened it",
            ));
        }
        Reading::Failed(why) => {
            return Err(QuestionError::undetermined(format!(
                "the calling process could not be identified: {why}"
            )));
        }
    };
    let member = contains(table, &session.boundary, pid);
    // The walk starts from the identity that was verified, not from a fresh reading of the
    // identifier: the evidence has to be about the process that called, not about whatever holds
    // its identifier now.
    let ancestry = descends_from(table, &process, &session.root);
    // The broker places a process under an agent it launched, which runs outside the terminal and
    // its process group. Its answer admits a caller and puts none outside, so it is asked only for
    // a caller the two checks above do not place inside, and a caller it does not place is decided
    // by them.
    let decided = match member.clone().either(ancestry.clone()) {
        Finding::Inside => Finding::Inside,
        _ if agents.is_some_and(|agents| agents.binding_of(&process).is_some()) => Finding::Inside,
        other => other,
    };
    // Everything above read the operating system while this function ran, and the evidence is
    // only about the caller if the caller is still the caller, whichever way it points. Read once
    // more, last.
    match table.identity(pid) {
        Reading::Found(settled) if settled.matches(&process) => {}
        Reading::Failed(why) => {
            return Err(QuestionError::undetermined(format!(
                "the calling process could not be identified again: {why}"
            )));
        }
        Reading::Found(_) | Reading::Absent => {
            return Err(QuestionError::undetermined(
                "the process on this connection changed while its session was being established",
            ));
        }
    }
    match decided {
        Finding::Inside => Ok(VerifiedSource {
            process,
            executable: table.executable(pid),
            session_member: member == Finding::Inside,
            ancestry: ancestry == Finding::Inside,
            // Reserved for the inherited launch channel. Nothing hands one down yet, and claiming one
            // that was never presented would put a fact in the identity header that nobody checked.
            launch_channel: false,
            connection_id,
        }),
        Finding::Outside => Err(QuestionError::unbound(
            "the calling process is not in this session's process boundary and descends neither \
             from its root shell nor from an agent its broker launched",
        )),
        Finding::Undetermined(why) => Err(QuestionError::undetermined(why)),
    }
}

/// What one check established about the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Finding {
    /// The check found the caller in this session.
    Inside,
    /// The check read everything it needed, and the caller is not there.
    Outside,
    /// A reading the check needed failed, or changed while it was taken, for the reason given.
    Undetermined(String),
}

impl Finding {
    const fn found(found: bool) -> Self {
        if found { Self::Inside } else { Self::Outside }
    }

    /// Combines two checks either of which admits a caller.
    ///
    /// Inside when either finds the caller there; outside only when both establish that it is not;
    /// undetermined otherwise. A check that could not read what it needed says nothing either way,
    /// so it can neither admit a caller nor put one outside.
    fn either(self, other: Self) -> Self {
        match (self, other) {
            (Self::Inside, _) | (_, Self::Inside) => Self::Inside,
            (Self::Outside, Self::Outside) => Self::Outside,
            (Self::Undetermined(first), Self::Undetermined(second)) => {
                Self::Undetermined(format!("{first}; {second}"))
            }
            (Self::Undetermined(why), Self::Outside) | (Self::Outside, Self::Undetermined(why)) => {
                Self::Undetermined(why)
            }
        }
    }
}

/// What the kernel said about one process identifier.
#[derive(Clone, Debug)]
enum Reading {
    /// The process holding it, with its start value.
    Found(ProcessStartIdentity),
    /// No process holds it.
    Absent,
    /// The kernel did not answer, so neither of the others is established.
    Failed(String),
}

/// One process's place in the process tree, as one reading from the kernel gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Placement {
    /// Its parent's identifier, zero where it has none.
    parent: u32,
    /// Its process group, where the platform has them.
    group: Option<u32>,
    /// Its controlling terminal, where it has one.
    terminal: Option<u32>,
}

/// Where the binding reads processes from.
///
/// In every build that is the kernel. The seam lets a test put a failing or a changing reading
/// exactly where it wants one, which no real kernel will do on request, and that is the only way to
/// show that such a reading is never taken for an answer.
trait ProcessTable {
    /// Reads one process's start identity, telling a process that is not there from a reading
    /// that failed.
    fn identity(&self, pid: u32) -> Reading;

    /// Reads one process's parent, process group and controlling terminal.
    fn placement(&self, pid: u32) -> std::result::Result<Placement, String>;

    /// Returns the executable one process is running, where the platform names it.
    fn executable(&self, pid: u32) -> Option<String>;
}

/// The operating system's own process table.
struct Kernel;

impl ProcessTable for Kernel {
    fn identity(&self, pid: u32) -> Reading {
        // This reading is the one that tells the two apart: a process the kernel reports absent
        // comes back carrying the reserved unread start value, and every other failure stays a
        // failure. A denied or failed query is never taken for a process that has gone.
        match kr_ipc::identity::started_process_identity(pid) {
            Ok(identity) if identity.start_value.get() == kr_ipc::identity::START_VALUE_UNREAD => {
                Reading::Absent
            }
            Ok(identity) => Reading::Found(identity),
            Err(error) => Reading::Failed(error.to_string()),
        }
    }

    fn placement(&self, pid: u32) -> std::result::Result<Placement, String> {
        platform::placement(pid)
    }

    fn executable(&self, pid: u32) -> Option<String> {
        platform::executable(pid)
    }
}

/// Returns whether the boundary this session owns holds this process.
fn contains(table: &impl ProcessTable, boundary: &OwnershipBoundary, pid: u32) -> Finding {
    match boundary {
        // The caller's own record names the terminal and the group it is in, so one reading of
        // that one process decides it. A listing of every process on the terminal would pass over
        // an entry it could not read, and so answer "not there" for a reading that failed.
        OwnershipBoundary::TerminalGroup { group, terminal } => match table.placement(pid) {
            Ok(placement) => Finding::found(match terminal {
                Some(terminal) => placement.terminal == Some(*terminal),
                None => placement.group == Some(*group),
            }),
            Err(why) => Finding::Undetermined(format!(
                "the terminal and process group of the calling process could not be read: {why}"
            )),
        },
        OwnershipBoundary::ControlGroup { path } => control_group_holds(path, pid),
        // The job holds every descendant, so its own process list is the answer.
        #[cfg(windows)]
        OwnershipBoundary::JobObject { root } => {
            let Some(job) = crate::windows::job::holding(*root) else {
                return Finding::Undetermined(
                    "the job that holds this session's processes is not open".to_owned(),
                );
            };
            match job.process_ids() {
                Ok(members) => Finding::found(members.contains(&pid)),
                Err(error) => Finding::Undetermined(format!(
                    "the processes this session's job holds could not be listed: {error}"
                )),
            }
        }
        // No job exists on this platform, so nothing is ever held by one.
        #[cfg(not(windows))]
        OwnershipBoundary::JobObject { .. } => Finding::Outside,
    }
}

/// Returns whether a control group lists this process.
///
/// The kernel writes the whole list in one reading. A list that cannot be read, or a line in it
/// that is not a process identifier, decides nothing.
fn control_group_holds(path: &std::path::Path, pid: u32) -> Finding {
    let listing = path.join("cgroup.procs");
    let listed = match std::fs::read_to_string(&listing) {
        Ok(listed) => listed,
        Err(error) => {
            return Finding::Undetermined(format!(
                "{} could not be read: {error}",
                listing.display()
            ));
        }
    };
    let mut found = false;
    for line in listed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        match line.parse::<u32>() {
            Ok(member) => found |= member == pid,
            Err(_) => {
                return Finding::Undetermined(format!(
                    "{} lists {line:?}, which is not a process identifier",
                    listing.display()
                ));
            }
        }
    }
    Finding::found(found)
}

/// Where one parent link of the walk leads.
enum Link {
    /// The process has no parent: the chain has reached the top.
    Top,
    /// The process names a parent that has ended.
    Ended,
    /// The process names this parent.
    Parent(ProcessStartIdentity),
}

/// Returns whether the parent chain from this process reaches the session's root shell.
///
/// Each link is checked by start identity, so a parent identifier that has been recycled since the
/// child was created does not complete the chain. The chain is outside the session where it ends
/// before the root shell: at the top, at a parent that has ended, or at a process that started
/// before the root shell did. It is undetermined where a link cannot be read, where the child
/// changes while its link is read, or where it is longer than the walk follows.
fn descends_from(
    table: &impl ProcessTable,
    from: &ProcessStartIdentity,
    root: &ProcessStartIdentity,
) -> Finding {
    // A root shell that had ended before the kernel would describe it is nothing a running process
    // can be found descending from.
    if root.start_value.get() == kr_ipc::identity::START_VALUE_UNREAD {
        return Finding::Outside;
    }
    let root_pid = u32::try_from(root.pid.get()).unwrap_or(u32::MAX);
    let mut current = from.clone();
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let current_pid = u32::try_from(current.pid.get()).unwrap_or(u32::MAX);
        if current_pid == root_pid {
            // Only the root shell itself completes the chain. Another process holding its
            // identifier is not it, and the root shell is not further up: two running processes
            // never hold one identifier.
            return Finding::found(current.matches(root));
        }
        if current.source != root.source {
            return Finding::Undetermined(format!(
                "process {current_pid} and the root shell were read from different sources"
            ));
        }
        // A process that started before the root shell is not one of its descendants, and nor is
        // anything further up, which started earlier still. Stopping here also means the walk
        // never has to read the processes above this one, some of which the kernel may not
        // describe to this user at all.
        if current.start_value.get() < root.start_value.get() {
            return Finding::Outside;
        }
        let link = match read_link(table, &current, root_pid) {
            Ok(link) => link,
            Err(why) => return Finding::Undetermined(why),
        };
        match link {
            Link::Top | Link::Ended => return Finding::Outside,
            Link::Parent(parent) => current = parent,
        }
    }
    Finding::Undetermined(format!(
        "the chain of parents is longer than the {MAX_ANCESTRY_DEPTH} links that are followed"
    ))
}

/// Reads where one process's parent link leads, and checks that the reading is about that process.
fn read_link(
    table: &impl ProcessTable,
    current: &ProcessStartIdentity,
    root_pid: u32,
) -> std::result::Result<Link, String> {
    let current_pid = u32::try_from(current.pid.get()).unwrap_or(u32::MAX);
    let parent_pid = table
        .placement(current_pid)
        .map_err(|why| format!("the parent of process {current_pid} could not be read: {why}"))?
        .parent;
    let link = if parent_pid == 0 {
        Link::Top
    } else if parent_pid == current_pid {
        return Err(format!("process {current_pid} names itself as its parent"));
    } else if is_first_process(parent_pid, root_pid) {
        Link::Top
    } else {
        match table.identity(parent_pid) {
            Reading::Found(parent) => Link::Parent(parent),
            Reading::Absent => Link::Ended,
            Reading::Failed(why) => {
                return Err(format!(
                    "process {parent_pid}, the parent of process {current_pid}, could not be \
                     identified: {why}"
                ));
            }
        }
    };
    // The child is read again, identity and parent together. If its identifier changed owners
    // between the first read and this one, the parent reading describes the replacement's family
    // rather than this one's; if the child has a new parent, the old one ended while it was being
    // read. Either way the reading establishes nothing.
    let unchanged = matches!(table.identity(current_pid), Reading::Found(again) if again.matches(current))
        && table
            .placement(current_pid)
            .is_ok_and(|again| again.parent == parent_pid);
    if !unchanged {
        return Err(format!(
            "process {current_pid} changed while its parent was being read"
        ));
    }
    match link {
        Link::Parent(parent) if parent.source != current.source => Err(format!(
            "process {parent_pid} and its child {current_pid} were read from different sources"
        )),
        // A parent starts before its child. Every source's start value increases with time within
        // one boot, so a candidate parent that started later is an identifier the kernel has
        // handed to something else since this child was created: the child's own parent has
        // ended, and the chain ends with it rather than climbing through a stranger.
        Link::Parent(parent) if parent.start_value.get() > current.start_value.get() => {
            Ok(Link::Ended)
        }
        link => Ok(link),
    }
}

/// Returns the nearest of `candidates` that is `from` itself or one of its ancestors.
///
/// Every link is read from the kernel, and a candidate matches only by its full start identity, so
/// an identifier recycled since the candidate's process started is not it. The answer is one of
/// two: a candidate found, or none, whether because the chain ends without one or because a link
/// could not be read. The broker places a caller under an agent with it, and a caller it does not
/// place is decided by the session's own checks.
pub(crate) fn nearest_of(
    from: &ProcessStartIdentity,
    candidates: &[ProcessStartIdentity],
) -> Option<usize> {
    let table = Kernel;
    let mut current = from.clone();
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if let Some(found) = candidates
            .iter()
            .position(|candidate| candidate.matches(&current))
        {
            return Some(found);
        }
        let current_pid = u32::try_from(current.pid.get()).unwrap_or(u32::MAX);
        let parent_pid = table.placement(current_pid).ok()?.parent;
        if parent_pid == 0 || parent_pid == current_pid {
            return None;
        }
        let Reading::Found(parent) = table.identity(parent_pid) else {
            return None;
        };
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
        let Reading::Found(again) = table.identity(current_pid) else {
            return None;
        };
        if !again.matches(&current)
            || table
                .placement(current_pid)
                .ok()
                .map(|placed| placed.parent)
                != Some(parent_pid)
        {
            return None;
        }
        current = parent;
    }
    None
}

/// Returns whether an identifier names the system's first process, where the root shell is not it.
#[cfg(unix)]
const fn is_first_process(pid: u32, root_pid: u32) -> bool {
    pid == FIRST_PROCESS && root_pid != FIRST_PROCESS
}

/// No identifier is special on this platform: its system processes describe themselves.
#[cfg(not(unix))]
const fn is_first_process(_pid: u32, _root_pid: u32) -> bool {
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

    /// Reads one process's parent, process group and controlling terminal from one reading of
    /// `/proc/<pid>/stat`.
    ///
    /// The line begins `pid (comm) state ppid pgrp session tty_nr`, and the command name can
    /// contain spaces and brackets, so the fields are counted after the last closing bracket. A
    /// field that is missing or is not a number is a failed reading, never a zero.
    pub(super) fn placement(pid: u32) -> Result<super::Placement, String> {
        let path = format!("/proc/{pid}/stat");
        let line = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
        let fields: Vec<&str> = line
            .rfind(')')
            .map(|end| line[end + 1..].split_whitespace().collect())
            .ok_or_else(|| format!("{path} names no command"))?;
        let field = |index: usize, what: &str| {
            fields
                .get(index)
                .and_then(|field| number(field))
                .ok_or_else(|| format!("{path} gives no {what}"))
        };
        let parent = field(1, "parent")?;
        let group = field(2, "process group")?;
        let terminal = field(4, "controlling terminal")?;
        Ok(super::Placement {
            parent,
            group: Some(group),
            // Zero is no controlling terminal at all.
            terminal: (terminal != 0).then_some(terminal),
        })
    }

    /// Reads one numeric field as the kernel prints it.
    ///
    /// `tty_nr` is printed as a signed value, so it is read as one and kept as the same bit
    /// pattern, exactly as the session's own terminal was read when its boundary was made.
    fn number(field: &str) -> Option<u32> {
        field
            .parse::<i32>()
            .ok()
            .map(i32::cast_unsigned)
            .or_else(|| field.parse::<u32>().ok())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libproc::bsd_info::BSDInfo;
    use libproc::proc_pid::{pidinfo, pidpath};

    pub(super) fn executable(pid: u32) -> Option<String> {
        pidpath(i32::try_from(pid).ok()?).ok()
    }

    /// Reads one process's parent, process group and controlling terminal from one call.
    ///
    /// The kernel answers this only for this user's own processes: another user's, including the
    /// system's `login` and `launchd`, is a failed reading.
    pub(super) fn placement(pid: u32) -> Result<super::Placement, String> {
        let id = i32::try_from(pid).map_err(|_| format!("{pid} is not a process identifier"))?;
        let info: BSDInfo = pidinfo(id, 0).map_err(|error| format!("process {pid}: {error}"))?;
        Ok(super::Placement {
            parent: info.pbi_ppid,
            group: Some(info.pbi_pgid),
            // `NODEV` where the process has no controlling terminal, exactly as the session's own
            // terminal was read when its boundary was made.
            terminal: (info.e_tdev != u32::MAX).then_some(info.e_tdev),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};

    fn look<T>(pid: u32, read: impl FnOnce(&sysinfo::Process) -> T) -> Option<T> {
        let mut system = sysinfo::System::new();
        let target = sysinfo::Pid::from_u32(pid);
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[target]),
            true,
            ProcessRefreshKind::nothing(),
        );
        system.process(target).map(read)
    }

    pub(super) fn executable(pid: u32) -> Option<String> {
        look(pid, |process| {
            process.exe().map(|path| path.display().to_string())
        })
        .flatten()
    }

    /// Reads one process's parent.
    ///
    /// This platform has neither process groups nor controlling terminals: a session's boundary
    /// here is its job object.
    pub(super) fn placement(pid: u32) -> Result<super::Placement, String> {
        look(pid, |process| super::Placement {
            parent: process.parent().map_or(0, sysinfo::Pid::as_u32),
            group: None,
            terminal: None,
        })
        .ok_or_else(|| format!("process {pid} is not in the process table"))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};

    use kr_protocol::error::ErrorCode;
    use kr_protocol::scalars::Uuid;

    use super::*;

    /// The source every scripted identity is read from.
    const SOURCE: ProcessStartSource = ProcessStartSource::LinuxProcStat;

    /// The root shell of every scripted session: process 100, started at 10.
    fn root() -> ProcessStartIdentity {
        identity(100, 10)
    }

    fn identity(pid: u32, start: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(u64::from(pid), SOURCE, start)
    }

    fn placed(parent: u32) -> std::result::Result<Placement, String> {
        Ok(Placement {
            parent,
            group: Some(7),
            terminal: None,
        })
    }

    fn connection() -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([1; 16]))
    }

    /// A process table whose readings a test writes down in advance.
    ///
    /// Each identifier has its own queue of readings for each question. A reading is taken from the
    /// front while more than one is queued, and the last one answers every later question, so a
    /// test scripts a change by queueing two. A question about an identifier the test did not
    /// script fails the test: the walk read something the test says it must not need.
    #[derive(Default)]
    struct Scripted {
        identities: RefCell<BTreeMap<u32, VecDeque<Reading>>>,
        placements: RefCell<BTreeMap<u32, VecDeque<std::result::Result<Placement, String>>>>,
    }

    impl Scripted {
        fn identity(self, pid: u32, readings: &[Reading]) -> Self {
            self.identities
                .borrow_mut()
                .insert(pid, readings.iter().cloned().collect());
            self
        }

        fn found(self, process: &ProcessStartIdentity) -> Self {
            let pid = u32::try_from(process.pid.get()).expect("a small identifier");
            self.identity(pid, &[Reading::Found(process.clone())])
        }

        fn placement(self, pid: u32, readings: &[std::result::Result<Placement, String>]) -> Self {
            self.placements
                .borrow_mut()
                .insert(pid, readings.iter().cloned().collect());
            self
        }

        fn next<T: Clone>(queues: &RefCell<BTreeMap<u32, VecDeque<T>>>, pid: u32) -> T {
            let mut queues = queues.borrow_mut();
            let queue = queues
                .get_mut(&pid)
                .unwrap_or_else(|| panic!("process {pid} was read, and nothing needs it"));
            if queue.len() > 1 {
                queue.pop_front().expect("a queued reading")
            } else {
                queue.front().cloned().expect("a queued reading")
            }
        }
    }

    impl ProcessTable for Scripted {
        fn identity(&self, pid: u32) -> Reading {
            Self::next(&self.identities, pid)
        }

        fn placement(&self, pid: u32) -> std::result::Result<Placement, String> {
            Self::next(&self.placements, pid)
        }

        fn executable(&self, _pid: u32) -> Option<String> {
            None
        }
    }

    fn undetermined(finding: &Finding) -> &str {
        match finding {
            Finding::Undetermined(why) => why,
            other => panic!("expected an undetermined finding, found {other:?}"),
        }
    }

    // The walk up the parent chain.

    #[test]
    fn a_chain_that_reaches_the_root_shell_is_inside() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(200)])
            .found(&identity(200, 20))
            .placement(200, &[placed(100)])
            .found(&root());
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Inside
        );
    }

    #[test]
    fn a_chain_that_reaches_the_top_is_outside() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(0)]);
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
    }

    #[test]
    fn a_process_that_started_before_the_root_shell_ends_the_chain_unread() {
        // Process 50 started before the root shell, so nothing above it is read: its placement is
        // not scripted, and reading it would fail the test.
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(50)])
            .found(&identity(50, 5));
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
        assert_eq!(
            descends_from(&Scripted::default(), &identity(300, 3), &root()),
            Finding::Outside,
            "a caller older than the root shell is not read at all"
        );
    }

    #[test]
    fn a_parent_that_has_ended_ends_the_chain() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(250)])
            .identity(250, &[Reading::Absent]);
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
    }

    #[test]
    fn a_parent_identifier_now_held_by_a_later_process_ends_the_chain() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(250)])
            .found(&identity(250, 40));
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
    }

    #[test]
    fn the_root_shells_identifier_held_by_another_process_is_outside() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(100)])
            .found(&identity(100, 25));
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_parent_that_is_the_first_process_ends_the_chain_unread() {
        // Nothing about process 1 is scripted: the kernel may not describe it to this user, and
        // the walk must not need it to.
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(1)]);
        assert_eq!(
            descends_from(&table, &identity(300, 30), &root()),
            Finding::Outside
        );
    }

    #[test]
    fn a_parent_link_that_cannot_be_read_decides_nothing() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[Err("Operation not permitted".to_owned())]);
        let finding = descends_from(&table, &identity(300, 30), &root());
        assert!(
            undetermined(&finding).contains("Operation not permitted"),
            "{finding:?}"
        );
    }

    #[test]
    fn a_parent_that_cannot_be_identified_decides_nothing() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(250)])
            .identity(
                250,
                &[Reading::Failed("Operation not permitted".to_owned())],
            );
        let finding = descends_from(&table, &identity(300, 30), &root());
        assert!(
            undetermined(&finding).contains("could not be identified"),
            "{finding:?}"
        );
    }

    #[test]
    fn a_child_that_changes_while_its_parent_is_read_decides_nothing() {
        // The identifier has changed owners by the second reading.
        let replaced = Scripted::default()
            .found(&identity(300, 31))
            .placement(300, &[placed(0)]);
        let finding = descends_from(&replaced, &identity(300, 30), &root());
        assert!(undetermined(&finding).contains("changed"), "{finding:?}");
        // The child is given a new parent between the two readings: the old one ended.
        let reparented = Scripted::default()
            .found(&identity(300, 30))
            .placement(300, &[placed(250), placed(1)])
            .identity(250, &[Reading::Absent]);
        let finding = descends_from(&reparented, &identity(300, 30), &root());
        assert!(undetermined(&finding).contains("changed"), "{finding:?}");
        // The child has gone by the second reading.
        let gone = Scripted::default()
            .identity(300, &[Reading::Absent])
            .placement(300, &[placed(0)]);
        let finding = descends_from(&gone, &identity(300, 30), &root());
        assert!(undetermined(&finding).contains("changed"), "{finding:?}");
    }

    #[test]
    fn a_chain_longer_than_the_walk_follows_decides_nothing() {
        // Process 1000 + n is the child of 1000 + n + 1, each started after the root shell.
        let mut table = Scripted::default();
        for n in 0..70_u32 {
            let pid = 1000 + n;
            table = table
                .found(&identity(pid, 100 - u64::from(n)))
                .placement(pid, &[placed(pid + 1)]);
        }
        let finding = descends_from(&table, &identity(1000, 100), &root());
        assert!(undetermined(&finding).contains("longer"), "{finding:?}");
    }

    #[test]
    fn a_root_shell_that_ended_unread_has_no_descendants() {
        let ended = ProcessStartIdentity::new(100, SOURCE, kr_ipc::identity::START_VALUE_UNREAD);
        assert_eq!(
            descends_from(&Scripted::default(), &identity(300, 30), &ended),
            Finding::Outside
        );
    }

    // The boundary.

    #[test]
    fn the_terminal_the_caller_holds_decides_membership() {
        let boundary = OwnershipBoundary::TerminalGroup {
            group: 7,
            terminal: Some(5),
        };
        let on = |terminal: Option<u32>| {
            Scripted::default().placement(
                300,
                &[Ok(Placement {
                    parent: 1,
                    group: Some(8),
                    terminal,
                })],
            )
        };
        assert_eq!(contains(&on(Some(5)), &boundary, 300), Finding::Inside);
        assert_eq!(contains(&on(Some(6)), &boundary, 300), Finding::Outside);
        assert_eq!(contains(&on(None), &boundary, 300), Finding::Outside);
        let unread = Scripted::default().placement(300, &[Err("denied".to_owned())]);
        let finding = contains(&unread, &boundary, 300);
        assert!(undetermined(&finding).contains("denied"), "{finding:?}");
    }

    #[test]
    fn the_process_group_decides_membership_where_no_terminal_is_named() {
        let boundary = OwnershipBoundary::TerminalGroup {
            group: 7,
            terminal: None,
        };
        let in_group = |group: u32| {
            Scripted::default().placement(
                300,
                &[Ok(Placement {
                    parent: 1,
                    group: Some(group),
                    terminal: Some(5),
                })],
            )
        };
        assert_eq!(contains(&in_group(7), &boundary, 300), Finding::Inside);
        assert_eq!(contains(&in_group(8), &boundary, 300), Finding::Outside);
    }

    #[test]
    fn a_control_group_decides_membership_only_where_its_list_can_be_read() {
        let directory = tempfile::tempdir().expect("a directory");
        let boundary = OwnershipBoundary::ControlGroup {
            path: directory.path().to_path_buf(),
        };
        let table = Scripted::default();
        let finding = contains(&table, &boundary, 300);
        assert!(
            undetermined(&finding).contains("could not be read"),
            "a list that is not there decides nothing: {finding:?}"
        );
        let listing = directory.path().join("cgroup.procs");
        std::fs::write(&listing, "1\n300\n").expect("a list");
        assert_eq!(contains(&table, &boundary, 300), Finding::Inside);
        std::fs::write(&listing, "1\n2\n").expect("a list");
        assert_eq!(contains(&table, &boundary, 300), Finding::Outside);
        std::fs::write(&listing, "1\nthree\n").expect("a list");
        let finding = contains(&table, &boundary, 300);
        assert!(
            undetermined(&finding).contains("not a process identifier"),
            "{finding:?}"
        );
    }

    // The whole binding.

    fn session(boundary: OwnershipBoundary) -> SessionBoundary {
        SessionBoundary {
            boundary,
            root: root(),
        }
    }

    fn on_terminal(terminal: u32) -> OwnershipBoundary {
        OwnershipBoundary::TerminalGroup {
            group: 7,
            terminal: Some(terminal),
        }
    }

    /// Process 300, started at 30, on terminal 6, whose parent chain reaches the top.
    fn outsider() -> Scripted {
        Scripted::default().found(&identity(300, 30)).placement(
            300,
            &[Ok(Placement {
                parent: 0,
                group: Some(8),
                terminal: Some(6),
            })],
        )
    }

    #[test]
    fn a_caller_established_outside_is_not_in_the_session() {
        let error = bind(
            &outsider(),
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("outside");
        assert_eq!(error.code(), ErrorCode::NotInKrSession);
        assert!(error.to_string().contains("kr new --attach"), "{error}");
    }

    #[test]
    fn a_failed_boundary_reading_is_neither_inside_nor_outside() {
        let directory = tempfile::tempdir().expect("a directory");
        let session = session(OwnershipBoundary::ControlGroup {
            path: directory.path().join("gone"),
        });
        let error = bind(
            &outsider(),
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable, "{error}");
        assert!(error.to_string().contains("could not be read"), "{error}");
        assert!(!error.to_string().contains("kr new --attach"), "{error}");
    }

    /// A bridge that places every process under one agent it launched.
    #[derive(Debug)]
    struct Launched;

    impl AgentBindings for Launched {
        fn binding_of(&self, _process: &ProcessStartIdentity) -> Option<AgentBinding> {
            Some(AgentBinding {
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([7; 16])),
                revision: None,
            })
        }

        fn current(
            &self,
            _application_instance_id: ApplicationInstanceId,
        ) -> Option<AgentBindingRevision> {
            None
        }
    }

    #[test]
    fn a_caller_the_broker_places_under_its_agent_is_bound() {
        // Established outside by the session's own checks: the broker's placement admits it.
        let source = bind(
            &outsider(),
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            Some(&Launched),
        )
        .expect("bound under the agent");
        assert!(!source.session_member && !source.ancestry);
        // Not established either way by them: the broker's placement admits it too.
        let directory = tempfile::tempdir().expect("a directory");
        let unread = session(OwnershipBoundary::ControlGroup {
            path: directory.path().join("gone"),
        });
        bind(
            &outsider(),
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&unread),
            Some(&Launched),
        )
        .expect("bound under the agent");
    }

    #[test]
    fn a_failed_ancestry_reading_is_neither_inside_nor_outside() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(
                300,
                &[Ok(Placement {
                    parent: 250,
                    group: Some(8),
                    terminal: Some(6),
                })],
            )
            .identity(
                250,
                &[Reading::Failed("Operation not permitted".to_owned())],
            );
        let error = bind(
            &table,
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable, "{error}");
        assert!(
            error.to_string().contains("Operation not permitted"),
            "{error}"
        );
    }

    #[test]
    fn a_caller_in_the_boundary_is_bound_where_its_ancestry_is_undetermined() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(
                300,
                &[Ok(Placement {
                    parent: 250,
                    group: Some(8),
                    terminal: Some(5),
                })],
            )
            .identity(
                250,
                &[Reading::Failed("Operation not permitted".to_owned())],
            );
        let source = bind(
            &table,
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect("bound");
        assert!(source.session_member);
        assert!(
            !source.ancestry,
            "an undetermined walk is not recorded as ancestry"
        );
    }

    #[test]
    fn a_caller_whose_chain_reaches_the_root_shell_is_bound() {
        let table = Scripted::default()
            .found(&identity(300, 30))
            .placement(
                300,
                &[Ok(Placement {
                    parent: 100,
                    group: Some(8),
                    terminal: Some(6),
                })],
            )
            .found(&root());
        let source = bind(
            &table,
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect("bound");
        assert!(!source.session_member);
        assert!(source.ancestry);
    }

    /// KR-REQ-05.09: a caller the kernel will not name is bound to no session, whatever it says:
    /// nothing establishes where it runs.
    #[test]
    fn a_connection_the_kernel_will_not_name_is_undetermined() {
        let error = bind(
            &Scripted::default(),
            None,
            None,
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
        assert!(error.to_string().contains("did not name"), "{error}");
    }

    #[test]
    fn a_connection_whose_caller_was_never_identified_is_undetermined() {
        let error = bind(
            &outsider(),
            Some(300),
            None,
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
        assert!(error.to_string().contains("never identified"), "{error}");
    }

    /// KR-REQ-05.09: the binding is about the process the kernel named when the connection was
    /// made, and a different process presenting itself later is refused.
    #[test]
    fn a_process_that_is_not_the_one_that_connected_is_undetermined() {
        let error = bind(
            &outsider(),
            Some(300),
            Some(&identity(300, 29)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
        assert!(
            error
                .to_string()
                .contains("no longer the one that opened it"),
            "{error}"
        );
        let unreadable = Scripted::default().identity(300, &[Reading::Failed("denied".to_owned())]);
        let error = bind(
            &unreadable,
            Some(300),
            Some(&identity(300, 30)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
        assert!(error.to_string().contains("denied"), "{error}");
    }

    #[test]
    fn a_caller_that_changes_while_it_is_bound_is_undetermined() {
        // Found in the boundary, but by the last reading the identifier belongs to another process,
        // so the evidence is not about the caller. The caller started before the root shell, so
        // the walk reads nothing about it, and its identity is read exactly twice: first and last.
        let table = Scripted::default()
            .identity(
                300,
                &[
                    Reading::Found(identity(300, 5)),
                    Reading::Found(identity(300, 6)),
                ],
            )
            .placement(
                300,
                &[Ok(Placement {
                    parent: 0,
                    group: Some(8),
                    terminal: Some(5),
                })],
            );
        let error = bind(
            &table,
            Some(300),
            Some(&identity(300, 5)),
            connection(),
            Some(&session(on_terminal(5))),
            None,
        )
        .expect_err("undetermined");
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
        assert!(error.to_string().contains("changed"), "{error}");
    }

    #[test]
    fn a_session_without_a_root_shell_holds_nothing() {
        // Established from the session alone, so even a caller nothing can be read about is outside.
        let error =
            bind(&Scripted::default(), None, None, connection(), None, None).expect_err("no");
        assert_eq!(error.code(), ErrorCode::NotInKrSession);
        assert!(error.to_string().contains("kr new --attach"), "{error}");
    }

    // The kernel's own readings.

    #[test]
    fn this_process_descends_from_itself() {
        let identity =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        assert_eq!(
            descends_from(&Kernel, &identity, &identity),
            Finding::Inside
        );
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
        assert_eq!(descends_from(&Kernel, &mine, &root), Finding::Outside);
    }

    #[cfg(unix)]
    #[test]
    fn this_process_descends_from_its_parent() {
        let mine =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        let parent = kr_ipc::identity::process_start_identity(std::os::unix::process::parent_id())
            .expect("the parent's identity");
        assert_eq!(descends_from(&Kernel, &mine, &parent), Finding::Inside);
    }

    #[cfg(unix)]
    #[test]
    fn the_kernel_places_this_process_under_its_parent_and_in_its_group() {
        let placement = Kernel
            .placement(std::process::id())
            .expect("this process's placement");
        assert_eq!(placement.parent, std::os::unix::process::parent_id());
        assert_eq!(
            placement.group,
            Some(
                rustix::process::getpgrp()
                    .as_raw_nonzero()
                    .get()
                    .cast_unsigned()
            )
        );
        let mine =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        // A root shell no process descends from: nothing is running under its identifier, and it
        // started after everything that is.
        let elsewhere =
            ProcessStartIdentity::new(u64::from(u32::MAX - 1), mine.source, u64::MAX - 1);
        let source = bind(
            &Kernel,
            Some(std::process::id()),
            Some(&mine),
            connection(),
            Some(&SessionBoundary {
                boundary: OwnershipBoundary::TerminalGroup {
                    group: placement.group.expect("a group"),
                    terminal: None,
                },
                root: elsewhere,
            }),
            None,
        )
        .expect("this process is in its own group");
        assert!(source.session_member);
        assert!(!source.ancestry);
    }

    #[test]
    fn the_nearest_managed_ancestor_is_found_by_its_full_identity() {
        let mine =
            kr_ipc::identity::process_start_identity(std::process::id()).expect("an identity");
        let parent_pid = Kernel
            .placement(std::process::id())
            .expect("a placement")
            .parent;
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
