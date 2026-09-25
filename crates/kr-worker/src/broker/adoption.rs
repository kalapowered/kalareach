//! Adoption: a program the integrated route did not launch, detected and observed.
//!
//! Section 12 keeps manual launches valid: they trigger the same detection and capability process,
//! and detection never creates a gateway after the fact. A Claude Code started by absolute path,
//! with its integration disabled, after a refused or retired launch, in a form the shell does not
//! ask about, or from a shell that does not ask, is found here. While the terminal's foreground
//! group is not the root shell's, each process in that group that the root shell started itself,
//! that no instance of this broker holds, and whose executable an installed connector recognises is
//! recorded as a native terminal instance with the profile it was observed running. It gets no
//! registration, no endpoint and no credential, so none of its bridges is admitted, and its
//! announcement says so. It is watched by its identity and ended when it exits.
//!
//! A program takes the terminal when the root shell starts a command, and the session knows when
//! that can happen: the input it accepts, the output it produces and a command the shell's
//! integration reports starting all mark its [`crate::lifecycle::Activity`]. The watch looks when
//! it is marked and on each [`WATCH_INTERVAL`] for [`SETTLE`] after that. It also looks on each
//! interval while a command has the terminal and while a program it adopted is still to be ended.
//! Otherwise it waits for the next mark, on no clock, because a session sitting idle has to cost
//! nothing (KR-PERF-003). While the root shell has the terminal a look is one read of the
//! foreground group and nothing else: no process is asked about, no executable is read and nothing
//! is allocated.
//!
//! What that leaves out is a program the root shell starts more than [`SETTLE`] after the latest
//! mark, with nothing reported in between, which then neither reads nor writes the terminal. It is
//! found at the session's next input or output, whichever comes first.
//!
//! A program the integration launched is not adopted: the launch registered the process that
//! presented itself, and that process keeps its identity when it execs the program, so the broker
//! holds it from its admission on.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, EnvironmentId};
use kr_protocol::projection::AgentInstanceSummary;
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Nullable, Uuid};

use crate::broker::Broker;
use crate::broker::connectors::ConnectorSources;
use crate::broker::image::HashedFiles;

/// How often the foreground is looked at while the watch is looking.
pub const WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// How long the watch goes on looking after a mark while the root shell has the terminal.
///
/// Input is marked as it is queued for the terminal, before the shell has read it, and the shell
/// gives the terminal to the command a line names only once it has read the line, run its own
/// hooks and started the command. A look the mark asks for can therefore come before the command
/// has the terminal, and this is how long the ones after it go on.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Why an adopted instance's bridges are refused, as its announcement says.
pub const ADOPTED_REFUSAL: &str = "it was not launched through the integration, so no \
                                   registration names it and none of its bridges is admitted";

/// What one look at the foreground reads from the session.
#[derive(Clone, Debug)]
pub struct Foreground {
    /// The process group the terminal has in the foreground.
    pub group: i32,
    /// The session's root shell.
    pub root_shell: ProcessStartIdentity,
    /// Each executable the latest prompt generation's resolves named, with the bypass it was
    /// answered with or none.
    pub answered: Vec<(String, Option<CommandBypassReason>)>,
}

/// One program this session adopted.
#[derive(Clone, Debug)]
struct Adopted {
    /// The process, by its whole identity.
    process: ProcessStartIdentity,
    /// What the session's views were told it is.
    summary: AgentInstanceSummary,
}

/// One session's adoptions.
///
/// Identifying a program (its process, its executable, its argument vector and the image it runs)
/// takes no lock, and can take as long as reading the image takes. Recording an adoption, ending
/// one and announcing either take the session's lock first, where there is a session to tell, and
/// this set's own lock second, so the views hear each instance's start before its end, and a
/// session that closes, which ends every adoption under its own lock, is never entered afterwards.
pub struct Adoptions {
    broker: Arc<Broker>,
    sources: Arc<ConnectorSources>,
    environment_id: EnvironmentId,
    /// The executables already hashed, by identity, so a program adopted again costs a lookup.
    hashed: HashedFiles,
    /// Set when the session closes: a reading in progress stops, and nothing is adopted after.
    stopped: AtomicBool,
    /// Wakes a watch that is waiting for the session to do something, because it has closed.
    closing: tokio::sync::Notify,
    adopted: Mutex<BTreeMap<ApplicationInstanceId, Adopted>>,
    /// The session whose views are told, where there is one.
    views: Option<Weak<crate::runtime::SessionRuntime>>,
    /// Where the next identification stops before it reads the image, for this host's own tests.
    #[cfg(feature = "testing")]
    reading_pause: Mutex<Option<ReadingPause>>,
}

/// The two ends of one armed pause before an image is read, taken on the identifying thread.
#[cfg(feature = "testing")]
type ReadingPause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

impl std::fmt::Debug for Adoptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Adoptions")
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

impl Adoptions {
    /// Builds one session's adoptions, from the connectors the installation handed over.
    #[must_use]
    pub fn new(
        broker: Arc<Broker>,
        sources: Arc<ConnectorSources>,
        environment_id: EnvironmentId,
    ) -> Self {
        Self {
            broker,
            sources,
            environment_id,
            hashed: HashedFiles::default(),
            stopped: AtomicBool::new(false),
            closing: tokio::sync::Notify::new(),
            adopted: Mutex::new(BTreeMap::new()),
            views: None,
            #[cfg(feature = "testing")]
            reading_pause: Mutex::new(None),
        }
    }

    /// Tells this session's views what is adopted and what ends.
    #[must_use]
    pub fn with_views(mut self, runtime: Weak<crate::runtime::SessionRuntime>) -> Self {
        self.views = Some(runtime);
        self
    }

    /// Stops the next identification before it reads the image, for this host's own tests: a
    /// reading that takes its time.
    ///
    /// Returns the end that says the identification has arrived there and the end that lets it go
    /// on. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_reading(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (arrived, watch) = std::sync::mpsc::channel();
        let (release, go) = std::sync::mpsc::channel();
        *self
            .reading_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Looks at the foreground once, adopts each program it finds there, and returns what was
    /// adopted, which the session's views are told as it is recorded.
    ///
    /// Nothing is looked at while no connector is installed, which is what could recognise a
    /// program, or while the root shell's own group has the terminal, which is the shell at its
    /// prompt.
    #[must_use]
    pub fn look(&self, foreground: &Foreground) -> Vec<AgentInstanceSummary> {
        if !self.can_adopt() {
            return Vec::new();
        }
        let root_group = group_of(&foreground.root_shell);
        if root_group == Some(foreground.group) {
            return Vec::new();
        }
        let Ok(group) = u32::try_from(foreground.group) else {
            return Vec::new();
        };
        let Ok(members) = kr_ipc::identity::processes_in_group(group) else {
            return Vec::new();
        };
        members
            .into_iter()
            .filter_map(|pid| self.consider(pid, foreground))
            .collect()
    }

    /// Ends each adopted instance whose program has exited, and returns what ended, which the
    /// session's views are told as it ends.
    #[must_use]
    pub fn sweep(&self) -> Vec<AgentInstanceSummary> {
        // Nothing adopted is nothing to end, and the session is not locked to find that out.
        if !self.holds_any() {
            return Vec::new();
        }
        self.told(|adopted| {
            let ended: Vec<ApplicationInstanceId> = adopted
                .iter()
                .filter(|(_, held)| {
                    matches!(
                        kr_ipc::identity::process_state(&held.process),
                        kr_ipc::identity::ProcessState::Ended
                    )
                })
                .map(|(id, _)| *id)
                .collect();
            ended
                .into_iter()
                .filter_map(|id| adopted.remove(&id))
                .map(|held| self.ended(held))
                .collect()
        })
    }

    /// Ends every adopted instance and stops adopting, because the session is closing, and returns
    /// what the session is to announce.
    ///
    /// It is called with the session's lock held, so it takes no other lock of the session's: the
    /// session announces what this returns. An identification still reading an image stops, and
    /// one that finishes later records nothing.
    #[must_use]
    pub fn close(&self) -> Vec<AgentInstanceSummary> {
        self.stopped.store(true, Ordering::SeqCst);
        self.closing.notify_one();
        let mut adopted = self
            .adopted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *adopted)
            .into_values()
            .map(|held| self.ended(held))
            .collect()
    }

    /// Returns whether the session has closed.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Returns whether a look could adopt anything: a connector is installed to recognise a
    /// program, and the session is still open.
    fn can_adopt(&self) -> bool {
        !self.sources.is_empty() && !self.is_stopped()
    }

    /// Returns whether this session holds an adoption, whose program's end is still to be found.
    fn holds_any(&self) -> bool {
        !self
            .adopted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// Waits until the session closes, which is when a watch waiting for anything else ends.
    async fn closed(&self) {
        if !self.is_stopped() {
            self.closing.notified().await;
        }
    }

    /// Returns the instance this session adopted for `process`, where it adopted one.
    #[must_use]
    pub fn adopted(&self, process: &ProcessStartIdentity) -> Option<ApplicationInstanceId> {
        self.adopted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(_, held)| held.process.matches(process))
            .map(|(id, _)| *id)
    }

    /// Ends one adopted instance on the broker and returns its end.
    fn ended(&self, held: Adopted) -> AgentInstanceSummary {
        let _ = self.broker.end(
            held.summary.application_instance_id,
            crate::broker::InstanceEnding::NativeExit,
        );
        let mut summary = held.summary;
        summary.ended_at = Nullable::some(kr_ipc::now_ms());
        summary
    }

    /// Changes the adopted set and tells the session's views what changed, the session's lock
    /// first and this set's second, where there is a session to tell.
    fn told(
        &self,
        change: impl FnOnce(&mut BTreeMap<ApplicationInstanceId, Adopted>) -> Vec<AgentInstanceSummary>,
    ) -> Vec<AgentInstanceSummary> {
        let runtime = self.views.as_ref().and_then(Weak::upgrade);
        let mut session = runtime.as_ref().map(|runtime| runtime.session());
        let told = change(
            &mut self
                .adopted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if let Some(session) = session.as_mut() {
            for summary in &told {
                session.announce_instance(summary.clone());
            }
        }
        told
    }

    /// Adopts one process of the foreground group, where it is a program to adopt.
    fn consider(&self, pid: u32, foreground: &Foreground) -> Option<AgentInstanceSummary> {
        let process = kr_ipc::identity::process_start_identity(pid).ok()?;
        if self.adopted(&process).is_some() {
            return None;
        }
        // The root shell's own child, read from the kernel's parent link and checked by start
        // identity: a program something else started is that program's to report.
        let parent = crate::questions::binding::parent_of(&process)?;
        if !parent.matches(&foreground.root_shell) {
            return None;
        }
        let executable = crate::questions::binding::executable_of(pid)?;
        let connector = self.sources.matching(&executable)?;
        // Asked only once the process runs the program: a launch registers the process that
        // presents itself before that process execs, so a program the integration launched is held
        // by now, and one it did not launch never will be.
        if self.broker.holds_process(&process) {
            return None;
        }
        let arguments = arguments_of(pid)?;
        // The executable and the arguments are this process's only if it still has its identity,
        // and so is the answer about who holds it.
        if !kr_ipc::identity::process_start_identity(pid).is_ok_and(|again| again.matches(&process))
        {
            return None;
        }
        #[cfg(feature = "testing")]
        {
            let armed = self
                .reading_pause
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some((arrived, go)) = armed {
                let _ = arrived.send(());
                let _ = go.recv_timeout(READING_PAUSE_LIMIT);
            }
        }
        // Bounded by the file's size, and stopped when the session closes.
        let hashed = crate::broker::image::read_identity(
            &running_image(pid, &executable),
            &self.hashed,
            &self.stopped,
        )
        .ok()?;
        let now = kr_ipc::now_ms();
        let profile = LaunchProfile {
            profile_id: crate::broker::profiles::new_profile_id(now).ok()?,
            environment_id: self.environment_id,
            binary: BinaryIdentity {
                resolved_path: executable.clone(),
                digest: hashed.digest,
                version: connector
                    .qualified_version(&hashed.digest)
                    .unwrap_or("unknown")
                    .to_owned(),
                distribution: "adopted".to_owned(),
            },
            arguments,
            authentication: AuthenticationState::Unknown,
            mode: IntegrationMode::NativeTerminal,
            resolved_at: now,
        };
        let application_instance_id =
            ApplicationInstanceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()));
        let summary = AgentInstanceSummary {
            application_instance_id,
            plugin_id: Nullable::some(connector.plugin_id()),
            profile_id: Nullable::some(profile.profile_id.clone()),
            mode: IntegrationMode::NativeTerminal,
            bypass: Nullable(bypass_for(&executable, &foreground.answered)),
            started_at: now,
            ended_at: Nullable::null(),
            refusal: Nullable::some(ADOPTED_REFUSAL.to_owned()),
        };
        // Recorded under the session's lock, where there is a session, so a session that closed
        // meanwhile, which stopped this set under that lock, is not entered.
        self.told(|adopted| {
            if self.is_stopped() || adopted.values().any(|held| held.process.matches(&process)) {
                return Vec::new();
            }
            if self
                .broker
                .adopt_instance(profile, application_instance_id, None)
                .is_err()
            {
                return Vec::new();
            }
            adopted.insert(
                application_instance_id,
                Adopted {
                    process,
                    summary: summary.clone(),
                },
            );
            vec![summary]
        })
        .into_iter()
        .next()
    }
}

/// How long a paused reading waits to be let go before it goes on by itself.
#[cfg(feature = "testing")]
const READING_PAUSE_LIMIT: Duration = Duration::from_secs(5);

/// Watches one session's foreground until the session closes or goes.
///
/// The session is read under its lock only for what a look needs, and the processes are read with
/// that lock given back, so a foreground with many processes holds nobody's keystrokes.
pub async fn watch(adoptions: Arc<Adoptions>, runtime: Weak<crate::runtime::SessionRuntime>) {
    let Some(activity) = runtime
        .upgrade()
        .map(|runtime| runtime.session().activity())
    else {
        return;
    };
    let grouping = Weak::clone(&runtime);
    watch_foreground(
        adoptions,
        activity,
        move || {
            grouping
                .upgrade()
                .map(|runtime| runtime.session().foreground_group())
        },
        move || {
            runtime
                .upgrade()
                .map(|runtime| runtime.session().foreground())
        },
    )
    .await;
}

/// Watches the foreground `group` and `read` describe, when `activity` asks it to, until they say
/// the session has gone (`None`) or the adoptions are closed.
///
/// The watch looks for [`SETTLE`] from its start, because a shell that has just started can run a
/// program from its startup files before anything is typed. It looks again whenever `activity` is
/// marked and on each [`WATCH_INTERVAL`] for [`SETTLE`] after that, and on each interval while a
/// command has the terminal, while a program it adopted is still to be ended and while an
/// identification is under way. Otherwise it waits for the next mark, on no clock.
///
/// A look reads `group` alone while the root shell has the terminal. When a command has it, `read`
/// gives the look the rest, and each process in the command's group is identified on a thread of its
/// own, one identification at a time: identifying reads an image and can take as long as that
/// takes, so a tick that finds one still running starts no other and waits for none, and every
/// tick ends what exited, whatever else is under way.
pub async fn watch_foreground(
    adoptions: Arc<Adoptions>,
    activity: Arc<crate::lifecycle::Activity>,
    mut group: impl FnMut() -> Option<Option<i32>>,
    mut read: impl FnMut() -> Option<Option<Foreground>>,
) {
    let mut identifying: Option<tokio::task::JoinHandle<Vec<AgentInstanceSummary>>> = None;
    // Read once: a root shell leads its own process group for as long as it runs.
    let mut root_group: Option<i32> = None;
    // Whether a command had the terminal at the last look.
    let mut command = false;
    let mut settle_until = tokio::time::Instant::now() + SETTLE;
    loop {
        let looking = command
            || identifying.is_some()
            || adoptions.holds_any()
            || tokio::time::Instant::now() < settle_until;
        if looking {
            tokio::select! {
                () = tokio::time::sleep(WATCH_INTERVAL) => {}
                () = adoptions.closed() => return,
            }
            if activity.take_foreground() {
                settle_until = tokio::time::Instant::now() + SETTLE;
            }
        } else {
            tokio::select! {
                () = activity.foreground_marked() => {}
                () = adoptions.closed() => return,
            }
            // A mark an earlier look already took leaves its wake behind, with nothing new to look
            // at.
            if !activity.take_foreground() {
                continue;
            }
            settle_until = tokio::time::Instant::now() + SETTLE;
        }
        if adoptions.is_stopped() {
            return;
        }
        let _ = adoptions.sweep();
        if identifying
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            identifying = None;
        }
        let Some(now) = group() else {
            return;
        };
        // No foreground to read, or the root shell at its prompt: the group was the whole look.
        if now.is_none() || (root_group.is_some() && now == root_group) {
            command = false;
            continue;
        }
        let Some(foreground) = read() else {
            return;
        };
        let Some(foreground) = foreground else {
            command = false;
            continue;
        };
        if root_group.is_none() {
            root_group = group_of(&foreground.root_shell);
        }
        command = root_group != Some(foreground.group);
        if command && identifying.is_none() && adoptions.can_adopt() {
            let looking = Arc::clone(&adoptions);
            identifying = Some(tokio::task::spawn_blocking(move || {
                looking.look(&foreground)
            }));
        }
    }
}

/// Returns the process group a process is in, where it can be read.
fn group_of(process: &ProcessStartIdentity) -> Option<i32> {
    let pid = i32::try_from(process.pid.get()).ok()?;
    let pid = rustix::process::Pid::from_raw(pid)?;
    rustix::process::getpgid(Some(pid))
        .ok()
        .map(rustix::process::Pid::as_raw_nonzero)
        .map(std::num::NonZeroI32::get)
}

/// Returns the argument vector a process was started with, as the kernel keeps it:
/// `/proc/<pid>/cmdline`, one argument after each NUL-terminated one.
#[cfg(target_os = "linux")]
fn arguments_of(pid: u32) -> Option<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
    if bytes.is_empty() {
        return None;
    }
    Some(
        bytes
            .split(|byte| *byte == 0)
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect(),
    )
}

/// Returns the argument vector a process was started with, as the kernel keeps it: macOS's
/// `KERN_PROCARGS2`, read through `sysinfo`.
#[cfg(not(target_os = "linux"))]
fn arguments_of(pid: u32) -> Option<Vec<String>> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

    let mut system = sysinfo::System::new();
    let target = sysinfo::Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let process = system.process(target)?;
    let arguments: Vec<String> = process
        .cmd()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    (!arguments.is_empty()).then_some(arguments)
}

/// Returns where the image a process runs is read from: on Linux the kernel's own link to it,
/// which names the image even after its path was replaced, and elsewhere the path the kernel
/// reports.
fn running_image(pid: u32, executable: &str) -> std::path::PathBuf {
    if cfg!(target_os = "linux") {
        std::path::PathBuf::from(format!("/proc/{pid}/exe"))
    } else {
        std::path::PathBuf::from(executable)
    }
}

/// Returns the bypass the latest prompt generation answered this executable with, where it
/// answered one: the shell names the path its search found, which can be a link to the file the
/// kernel reports, so both are compared as the files they name.
fn bypass_for(
    executable: &str,
    answered: &[(String, Option<CommandBypassReason>)],
) -> Option<CommandBypassReason> {
    let running = std::fs::canonicalize(executable).ok()?;
    answered
        .iter()
        .rev()
        .find(|(named, _)| {
            std::fs::canonicalize(Path::new(named)).is_ok_and(|named| named == running)
        })
        .and_then(|(_, bypass)| *bypass)
}
