//! Adoption: a program the integrated route did not launch, detected and observed.
//!
//! Section 12 keeps manual launches valid: they trigger the same detection and capability process,
//! and detection never creates a gateway after the fact. A Claude Code started by absolute path,
//! with its integration disabled, after a refused or retired launch, in a form the shell does not
//! ask about, or from a shell that does not ask, is found here. Every [`WATCH_INTERVAL`], while the
//! terminal's foreground group is not the root shell's, each process in that group that the root
//! shell started itself, that no instance of this broker holds, and whose executable an installed
//! connector recognises is recorded as a native terminal instance with the profile it was observed
//! running. It gets no registration, no endpoint and no credential, so none of its bridges is
//! admitted, and its announcement says so. It is watched by its identity and ended when it exits.
//!
//! A program the integration launched is not adopted: the launch registered the process that
//! presented itself, and that process keeps its identity when it execs the program, so the broker
//! holds it from its admission on.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
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

/// How often the foreground is looked at.
pub const WATCH_INTERVAL: Duration = Duration::from_millis(250);

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
pub struct Adoptions {
    broker: Arc<Broker>,
    sources: Arc<ConnectorSources>,
    environment_id: EnvironmentId,
    /// The executables already hashed, by identity, so a program adopted again costs a lookup.
    hashed: HashedFiles,
    /// Never set: an adoption's reading of an executable is not stopped part way.
    running: AtomicBool,
    adopted: Mutex<BTreeMap<ApplicationInstanceId, Adopted>>,
}

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
            running: AtomicBool::new(false),
            adopted: Mutex::new(BTreeMap::new()),
        }
    }

    /// Looks at the foreground once, adopts each program it finds there, and returns what the
    /// session's views are to be told.
    ///
    /// Nothing is looked at while no connector is installed, which is what could recognise a
    /// program, or while the root shell's own group has the terminal, which is the shell at its
    /// prompt.
    #[must_use]
    pub fn look(&self, foreground: &Foreground) -> Vec<AgentInstanceSummary> {
        if self.sources.is_empty() {
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

    /// Ends each adopted instance whose program has exited, and returns what the session's views
    /// are to be told.
    #[must_use]
    pub fn sweep(&self) -> Vec<AgentInstanceSummary> {
        let mut adopted = self
            .adopted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let mut told = Vec::new();
        for id in ended {
            if let Some(held) = adopted.remove(&id) {
                let _ = self
                    .broker
                    .end(id, crate::broker::InstanceEnding::NativeExit);
                let mut summary = held.summary;
                summary.ended_at = Nullable::some(kr_ipc::now_ms());
                told.push(summary);
            }
        }
        told
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
        let hashed = crate::broker::image::read_identity(
            &running_image(pid, &executable),
            &self.hashed,
            &self.running,
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
        let profile_id = profile.profile_id.clone();
        self.broker
            .adopt_instance(profile, application_instance_id, None)
            .ok()?;
        let summary = AgentInstanceSummary {
            application_instance_id,
            plugin_id: Nullable::some(connector.plugin_id()),
            profile_id: Nullable::some(profile_id),
            mode: IntegrationMode::NativeTerminal,
            bypass: Nullable(bypass_for(&executable, &foreground.answered)),
            started_at: now,
            ended_at: Nullable::null(),
            refusal: Nullable::some(ADOPTED_REFUSAL.to_owned()),
        };
        self.adopted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                application_instance_id,
                Adopted {
                    process,
                    summary: summary.clone(),
                },
            );
        Some(summary)
    }
}

/// Watches one session's foreground until the session has gone, and tells its views what it
/// adopted and what ended.
///
/// The session is read under its lock for what the look needs, and the processes are read with
/// that lock given back, so a foreground with many processes holds nobody's keystrokes.
pub async fn watch(adoptions: Arc<Adoptions>, runtime: Weak<crate::runtime::SessionRuntime>) {
    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;
        let Some(held) = runtime.upgrade() else {
            return;
        };
        let foreground = held.session().foreground();
        let looking = Arc::clone(&adoptions);
        let told = tokio::task::spawn_blocking(move || {
            let mut told = looking.sweep();
            if let Some(foreground) = foreground {
                told.extend(looking.look(&foreground));
            }
            told
        })
        .await
        .unwrap_or_default();
        if !told.is_empty() {
            let mut session = held.session();
            for summary in told {
                session.announce_instance(summary);
            }
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
