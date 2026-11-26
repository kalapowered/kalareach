//! Adoption: a program the integrated route did not launch, detected, observed and bound.
//!
//! Section 12 keeps manual launches valid: they trigger the same detection and capability process,
//! and detection never creates a gateway after the fact. A Claude Code started by absolute path,
//! with its integration disabled, after a refused or retired launch, in a form the shell does not
//! ask about, or from a shell that does not ask, is found here. While the terminal's foreground
//! group is not the root shell's, each process in that group that the root shell started itself,
//! that no instance of this broker holds, and whose executable an admitted package recognises is
//! recorded as a native terminal instance with the profile it was observed running, and bound to
//! that package in the same step. The package is the one the software development kit's rule
//! selects among every package the admissions this worker holds admit, with nothing selected: the
//! worker reads every rule as a guess, and a rule that names the installation location outranks one
//! that names only the executable among the packages of one publisher through one repository.
//! Packages that recognise the program equally well are not chosen between: the program is adopted
//! as a native terminal instance bound to none of them, and its announcement names the packages
//! that tie. A package with no connector table is adopted and bound the same way. An adopted
//! instance gets no registration, no endpoint and no credential, so none of its bridges is
//! admitted, and its announcement says so; the process it was found running as places the
//! questions it asks, and nothing more. It is watched by its identity and ended when it exits. A
//! bind the broker refuses leaves nothing adopted, and the next look tries again.
//!
//! A program is identified from one reading of its process. Its image is opened and hashed and its
//! arguments are read once, in one call to the kernel: a record that the kernel does not lay out as
//! observed is read as nothing, and a reading that fills its buffer is made again whole or refused,
//! never continued. Then the image the kernel reports, by the bytes of its path, the file that was
//! hashed, by device, file number, size and both times, the file the image is read from now and the
//! process's identity must all be what they were, or nothing is adopted and the next look reads
//! again. What is recorded is what that reading found: the path, the digest and the arguments of one
//! image. A process that executes another program and then the first again between the reads is
//! read as one program, which the reading cannot tell apart; a change after the last read is not
//! part of the record; and where the platform names the image by its path, as macOS does, the file
//! a path names when the image is opened is the one hashed, though it may have replaced the running
//! image just before.
//!
//! A program takes the terminal when the root shell starts a command, and the session knows when
//! that is likely: the input it accepts, the output it produces, and an invocation the shell's
//! integration asks about or a command it reports starting all mark its
//! [`crate::lifecycle::Activity`]. A shell with the integration asks about each command of a typed
//! line just before it runs it, so there the mark comes with the launch itself. The watch looks at
//! once when it is marked, and on each [`WATCH_INTERVAL`] while a command has the terminal and while
//! a program it adopted is still to be ended.
//!
//! No mark comes when the shell asks nothing, or runs the program from a function, a trap or a
//! subshell, which do not ask either, and neither it nor the program uses the terminal first. So
//! the watch goes on looking without one, less often the longer nothing happens: each wait is a
//! quarter of the time since the watch last had a reason to look, from [`WATCH_INTERVAL`] up to
//! [`IDLE_LOOK`]. A program the shell gives the terminal to some time after the session's latest
//! traffic is looked at within a quarter of that time, and within [`IDLE_LOOK`] at the most. One
//! that exits sooner can be missed, as one shorter than [`WATCH_INTERVAL`] always could.
//!
//! A session sitting idle costs one look every [`IDLE_LOOK`] (KR-PERF-003). While the root shell
//! has the terminal a look is one read of the foreground group and nothing else: no process is
//! asked about, no executable is read and nothing is allocated.
//!
//! A program the integration launched is not adopted: the launch registered the process that
//! presented itself, and that process keeps its identity when it execs the program, so the broker
//! holds it from its admission on.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_protocol::broker::{
    AgentOwnership, AuthenticationState, BinaryIdentity, IntegrationMode, LaunchProfile,
};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, EnvironmentId};
use kr_protocol::projection::AgentInstanceSummary;
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Nullable, Uuid};

use crate::broker::Broker;
use crate::broker::binder::{MatchedExecutable, Recognition};
use crate::broker::image::HashedFiles;

/// How often the foreground is looked at while a look is likely to find something: while a command
/// has the terminal, while a program the watch adopted is still to be ended, and just after the
/// session's traffic.
pub const WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// The longest the watch waits between two looks: the slow cadence the supervision keeps for what
/// no event reports.
pub const IDLE_LOOK: Duration = crate::lifecycle::IDLE_SWEEP_INTERVAL;

/// How the wait between two looks grows while nothing happens: it is this fraction of the time since
/// the watch last had a reason to look.
const QUIET_SHARE: u32 = 4;

/// Why an adopted instance's bridges are refused, as its announcement says.
pub const ADOPTED_REFUSAL: &str = "it was not launched through the integration, so no \
                                   registration names it and none of its bridges is admitted";

/// Why a tied program's bridges are refused, as its announcement says: the packages that recognise
/// it equally well, named, and that the host chose none of them.
fn tie_refusal(plugins: &[kr_protocol::ids::PluginId]) -> String {
    let names: Vec<&str> = plugins
        .iter()
        .map(kr_protocol::ids::PluginId::as_str)
        .collect();
    let named = match names.as_slice() {
        [rest @ .., last] if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.join(", "),
    };
    format!(
        "it was not launched through the integration, and {named} recognise it equally well, so \
         no package was chosen for it and none of its bridges is admitted"
    )
}

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
    /// What follows the looks this set's watch takes, to say what holds the terminal, where
    /// something does.
    following: Option<Mutex<crate::application::Following>>,
    /// Where the next identification stops before it reads the image, for this host's own tests.
    #[cfg(feature = "testing")]
    reading_pause: Mutex<Option<Pause>>,
    /// Where the next identification stops before it reads the arguments, for this host's own
    /// tests.
    #[cfg(feature = "testing")]
    arguments_pause: Mutex<Option<Pause>>,
    /// Where the next identification stops after it has read the arguments, for this host's own
    /// tests.
    #[cfg(feature = "testing")]
    arguments_read_pause: Mutex<Option<Pause>>,
    /// Where the next identification stops between its image comparison and its second reading of
    /// the process's identity, for this host's own tests.
    #[cfg(feature = "testing")]
    identity_pause: Mutex<Option<Pause>>,
    /// Where the next identification stops after its last comparison, for this host's own tests.
    #[cfg(feature = "testing")]
    bracket_pause: Mutex<Option<Pause>>,
    /// Where the next adoption stops between recording the instance and binding it, for this
    /// host's own tests.
    #[cfg(feature = "testing")]
    binding_pause: Mutex<Option<Pause>>,
}

/// The two ends of one armed pause, taken on the thread that stops at it.
#[cfg(feature = "testing")]
type Pause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

impl std::fmt::Debug for Adoptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Adoptions")
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

impl Adoptions {
    /// Builds one session's adoptions, from the admissions `broker` holds.
    #[must_use]
    pub fn new(broker: Arc<Broker>, environment_id: EnvironmentId) -> Self {
        Self {
            broker,
            environment_id,
            hashed: HashedFiles::default(),
            stopped: AtomicBool::new(false),
            closing: tokio::sync::Notify::new(),
            adopted: Mutex::new(BTreeMap::new()),
            views: None,
            following: None,
            #[cfg(feature = "testing")]
            reading_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            arguments_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            arguments_read_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            identity_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            bracket_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            binding_pause: Mutex::new(None),
        }
    }

    /// Tells this session's views what is adopted and what ends.
    #[must_use]
    pub fn with_views(mut self, runtime: Weak<crate::runtime::SessionRuntime>) -> Self {
        self.views = Some(runtime);
        self
    }

    /// Has the producer of the session's application follow every look this set's watch takes.
    #[must_use]
    pub fn following(mut self, producer: Arc<crate::application::Producer>) -> Self {
        self.following = Some(Mutex::new(crate::application::Following::new(producer)));
        self
    }

    /// Tells whoever follows the looks what one found: `None` when the root shell holds the
    /// terminal, and what was read when a command does.
    fn followed(&self, foreground: Option<&Foreground>) {
        if let Some(following) = &self.following {
            following
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .look(foreground);
        }
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
        arm(&self.reading_pause)
    }

    /// Stops the next identification just before it reads the arguments, for this host's own
    /// tests: a program that changes between the reading of its image and the reading of its
    /// arguments.
    ///
    /// Returns the end that says the identification has arrived there and the end that lets it go
    /// on. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_arguments(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        arm(&self.arguments_pause)
    }

    /// Stops the next identification just after it has read the arguments, for this host's own
    /// tests: a program that changes between the reading of its arguments and the check of its
    /// image.
    ///
    /// Returns the end that says the identification has arrived there and the end that lets it go
    /// on. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_after_arguments(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        arm(&self.arguments_read_pause)
    }

    /// Stops the next identification after its image comparison and before it reads the process's
    /// identity the second time, for this host's own tests: a process that ends there.
    ///
    /// Returns the end that says the identification has arrived there and the end that lets it go
    /// on. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_second_identity(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        arm(&self.identity_pause)
    }

    /// Stops the next identification after its last comparison, for this host's own tests: a
    /// program that changes once everything has been read and checked.
    ///
    /// Returns the end that says the identification has arrived there and the end that lets it go
    /// on. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_after_bracket(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        arm(&self.bracket_pause)
    }

    /// Stops the next adoption between the moment its instance is recorded and the moment it is
    /// bound, for this host's own tests: whatever else the broker does in that interval.
    ///
    /// Returns the end that says the adoption has arrived there and the end that lets it go on. It
    /// is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_binding(
        &self,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        arm(&self.binding_pause)
    }

    /// Looks at the foreground once, adopts each program it finds there, and returns what was
    /// adopted, which the session's views are told as it is recorded.
    ///
    /// Nothing is looked at while the admissions admit no package, which is what could recognise a
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

    /// Ends each adopted instance whose program has exited, and tells what the instances are now
    /// where a later snapshot has bound a tied program to the one package left. It returns what
    /// the session's views are told: each end, and each such binding.
    #[must_use]
    pub fn sweep(&self) -> Vec<AgentInstanceSummary> {
        // Nothing adopted is nothing to end, and the session is not locked to find that out.
        if !self.holds_any() {
            return Vec::new();
        }
        self.told(|adopted| {
            let bound = self.bound_since_the_tie(adopted);
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
            // An instance that ends in the same sweep is announced by its end, which carries what
            // it was bound to.
            let mut told: Vec<AgentInstanceSummary> = bound
                .into_iter()
                .filter(|summary| !ended.contains(&summary.application_instance_id))
                .collect();
            told.extend(
                ended
                    .into_iter()
                    .filter_map(|id| adopted.remove(&id))
                    .map(|held| self.ended(held)),
            );
            told
        })
    }

    /// Updates each adopted instance that was recorded as a tie and is bound to a package now, and
    /// returns what each is now. A snapshot that admits only one of the packages that tied binds
    /// the instance to it, and what the views were told then names no package and says that none
    /// was chosen, which is no longer so.
    fn bound_since_the_tie(
        &self,
        adopted: &mut BTreeMap<ApplicationInstanceId, Adopted>,
    ) -> Vec<AgentInstanceSummary> {
        if adopted
            .values()
            .all(|held| held.summary.plugin_id.is_present())
        {
            return Vec::new();
        }
        let live = self.broker.live_bindings();
        adopted
            .values_mut()
            .filter(|held| !held.summary.plugin_id.is_present())
            .filter_map(|held| {
                let release = live
                    .iter()
                    .find(|binding| {
                        binding.application_instance_id == held.summary.application_instance_id
                    })?
                    .release
                    .clone();
                held.summary.plugin_id = Nullable::some(release.plugin_id);
                held.summary.refusal = Nullable::some(ADOPTED_REFUSAL.to_owned());
                Some(held.summary.clone())
            })
            .collect()
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

    /// Returns whether a look could adopt anything: a package is admitted to recognise a program,
    /// and the session is still open.
    fn can_adopt(&self) -> bool {
        self.broker.admits_any() && !self.is_stopped()
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
        let _ = self.broker.end(held.summary.application_instance_id);
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
        // The image as the kernel reports it, with the bytes it has; the text a rule is matched on
        // and a profile records is the same path as text, as before.
        let image = crate::questions::binding::executable_path_of(pid)?;
        let executable = image.display().to_string();
        let recognition = match self.broker.recognise(&executable) {
            Recognition::Nothing => return None,
            found => found,
        };
        // Asked only once the process runs the program: a launch registers the process that
        // presents itself before that process execs, so a program the integration launched is held
        // by now, and one it did not launch never will be.
        if self.broker.holds_process(&process) {
            return None;
        }
        // One reading of one program: the image is opened and hashed, then the arguments are read
        // once, and then the image's path, the opened file's whole identity, the file the image is
        // read from and the process's identity must all still be what they were. A program that
        // executed another meanwhile, whose file was replaced or written to, or that ended, is
        // adopted on no pair of them: the next look reads again.
        #[cfg(feature = "testing")]
        stop_if_armed(&self.reading_pause);
        // Bounded by the file's size, and stopped when the session closes. The file stays open to
        // the last comparison, so its number cannot name another file meanwhile.
        let (hashed, held) = crate::broker::image::read_holding(
            &running_image(pid, &image),
            &self.hashed,
            &self.stopped,
        )
        .ok()?;
        #[cfg(feature = "testing")]
        stop_if_armed(&self.arguments_pause);
        let arguments = arguments_of(pid)?;
        #[cfg(feature = "testing")]
        stop_if_armed(&self.arguments_read_pause);
        if !still_runs(pid, &image, &held, &hashed.file) {
            return None;
        }
        drop(held);
        #[cfg(feature = "testing")]
        stop_if_armed(&self.identity_pause);
        // The executable and the arguments are this process's only if it still has its identity,
        // and so is the answer about who holds it.
        if !kr_ipc::identity::process_start_identity(pid).is_ok_and(|again| again.matches(&process))
        {
            return None;
        }
        #[cfg(feature = "testing")]
        stop_if_armed(&self.bracket_pause);
        let now = kr_ipc::now_ms();
        let profile = LaunchProfile {
            profile_id: crate::broker::profiles::new_profile_id(now).ok()?,
            environment_id: self.environment_id,
            binary: BinaryIdentity {
                resolved_path: executable.clone(),
                digest: hashed.digest,
                version: match &recognition {
                    Recognition::Package(admitted) => admitted.version_of(&hashed.digest),
                    _ => None,
                }
                .unwrap_or("unknown")
                .to_owned(),
                distribution: "adopted".to_owned(),
            },
            arguments: arguments.vector,
            authentication: AuthenticationState::Unknown,
            mode: IntegrationMode::NativeTerminal,
            // Started by the person's shell, so held by whatever holds the session's own
            // processes.
            ownership: AgentOwnership::Full,
            vendor_mode: Nullable::null(),
            resolved_at: now,
        };
        let application_instance_id =
            ApplicationInstanceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()));
        let mut summary = AgentInstanceSummary {
            application_instance_id,
            plugin_id: match &recognition {
                Recognition::Package(admitted) => Nullable::some(admitted.plugin_id.clone()),
                _ => Nullable::null(),
            },
            profile_id: Nullable::some(profile.profile_id.clone()),
            mode: IntegrationMode::NativeTerminal,
            bypass: Nullable(bypass_for(&executable, &foreground.answered)),
            started_at: now,
            ended_at: Nullable::null(),
            refusal: Nullable::some(match &recognition {
                Recognition::Tied(plugins) => tie_refusal(plugins),
                _ => ADOPTED_REFUSAL.to_owned(),
            }),
        };
        // Recorded under the session's lock, where there is a session, so a session that closed
        // meanwhile, which stopped this set under that lock, is not entered.
        self.told(|adopted| {
            if self.is_stopped() || adopted.values().any(|held| held.process.matches(&process)) {
                return Vec::new();
            }
            if self
                .broker
                .adopt_instance(profile, application_instance_id, process.clone(), None)
                .is_err()
            {
                return Vec::new();
            }
            // Adopted and bound in one step: a bind refused leaves nothing adopted, unless a
            // snapshot applied meanwhile has bound the instance, which keeps that binding. A
            // program that several packages recognise equally well is adopted bound to none of
            // them.
            #[cfg(feature = "testing")]
            stop_if_armed(&self.binding_pause);
            if let Recognition::Package(admitted) = &recognition {
                let bound = self.broker.bind_adopted(
                    kr_protocol::ids::BrokerBindingId::new(kr_ipc::new_uuid()),
                    application_instance_id,
                    admitted.package_digest,
                    admitted.frame,
                    MatchedExecutable {
                        path: executable.clone(),
                        digest: hashed.digest,
                    },
                    now,
                );
                match bound {
                    Err(_) => return Vec::new(),
                    // A snapshot that bound the instance meanwhile may have found another package
                    // for the program: the instance is announced as the binding it holds is for,
                    // since that is the plugin its actions are taken from.
                    Ok(Some(kept)) => summary.plugin_id = Nullable::some(kept),
                    Ok(None) => {}
                }
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

/// How long a paused step waits to be let go before it goes on by itself.
#[cfg(feature = "testing")]
const PAUSE_LIMIT: Duration = Duration::from_secs(5);

/// Arms `slot`: the next step that stops at it tells the first end it has arrived and waits for the
/// second.
#[cfg(feature = "testing")]
fn arm(
    slot: &Mutex<Option<Pause>>,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (arrived, watch) = std::sync::mpsc::channel();
    let (release, go) = std::sync::mpsc::channel();
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
    (watch, release)
}

/// Stops at `slot` where it is armed, once.
#[cfg(feature = "testing")]
fn stop_if_armed(slot: &Mutex<Option<Pause>>) {
    let armed = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some((arrived, go)) = armed {
        let _ = arrived.send(());
        let _ = go.recv_timeout(PAUSE_LIMIT);
    }
}

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

/// Watches the foreground `group` and `read` describe, at the pace `activity` sets, until they say
/// the session has gone (`None`) or the adoptions are closed.
///
/// The watch starts as if it had just been marked, because a shell that has just started can run a
/// program from its startup files before anything is typed. It looks at once when `activity` is
/// marked, on each [`WATCH_INTERVAL`] while a command has the terminal, while a program it adopted
/// is still to be ended and while an identification is under way, and otherwise less often the
/// longer it has had no reason to look, from [`WATCH_INTERVAL`] up to [`IDLE_LOOK`] apart.
///
/// A look reads `group` alone while the root shell has the terminal. When a command has it, `read`
/// gives the look the rest, and each process in the command's group is identified on a thread of
/// its own, one identification at a time: identifying reads an image and can take as long as that
/// takes, so a look that finds one still running starts no other and waits for none, and every look
/// ends what exited, whatever else is under way.
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
    let mut pace = Pace::new(tokio::time::Instant::now());
    loop {
        if command || identifying.is_some() || adoptions.holds_any() {
            pace.reason_at_look();
        }
        // A look as slow as the supervision's sweep falls on the session's beat, which the sweep
        // keeps, so the two wake the host once.
        let due = tokio::time::Instant::from_std(
            activity.on_the_beat(pace.due().into_std(), pace.looked.into_std()),
        );
        if pace.wait() <= WATCH_INTERVAL {
            // A mark made meanwhile is taken at the look rather than waking the watch early, so a
            // session that prints steadily is looked at once an interval and no more.
            tokio::select! {
                () = tokio::time::sleep_until(due) => {}
                () = adoptions.closed() => return,
            }
        } else {
            tokio::select! {
                () = tokio::time::sleep_until(due) => {}
                () = activity.foreground_marked() => {
                    // A mark an earlier look already took leaves its wake behind, with nothing new
                    // to look at.
                    if !activity.take_foreground() {
                        continue;
                    }
                    pace.reason(tokio::time::Instant::now());
                }
                () = adoptions.closed() => return,
            }
        }
        let now = tokio::time::Instant::now();
        if activity.take_foreground() {
            pace.reason(now);
        }
        pace.looked(now);
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
        let Some(holding) = group() else {
            return;
        };
        // No foreground to read, or the root shell at its prompt: the group was the whole look.
        if holding.is_none() || (root_group.is_some() && holding == root_group) {
            if holding.is_some() {
                adoptions.followed(None);
            }
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
        adoptions.followed(command.then_some(&foreground));
        if command && identifying.is_none() && adoptions.can_adopt() {
            let looking = Arc::clone(&adoptions);
            identifying = Some(tokio::task::spawn_blocking(move || {
                looking.look(&foreground)
            }));
        }
    }
}

/// When the watch looks next.
///
/// Each wait is a quarter of the time from the watch's latest reason to look to its latest look,
/// from [`WATCH_INTERVAL`] up to [`IDLE_LOOK`]. A reason is a mark, and a look that found a command
/// with the terminal, a program still to be ended or an identification under way. A program that
/// takes the terminal some time after the latest reason is looked at within a quarter of that time,
/// and within [`WATCH_INTERVAL`] at the least.
#[derive(Debug)]
struct Pace {
    /// When the watch last had a reason to look.
    reason: tokio::time::Instant,
    /// When it last looked.
    looked: tokio::time::Instant,
}

impl Pace {
    /// A pace whose reason to look is `now`, as a mark would be.
    const fn new(now: tokio::time::Instant) -> Self {
        Self {
            reason: now,
            looked: now,
        }
    }

    /// Records a reason to look at `now`.
    fn reason(&mut self, now: tokio::time::Instant) {
        self.reason = now;
    }

    /// Records that the latest look found something to go on looking at.
    fn reason_at_look(&mut self) {
        self.reason = self.looked;
    }

    /// Records a look at `now`.
    fn looked(&mut self, now: tokio::time::Instant) {
        self.looked = now;
    }

    /// Returns the wait from the latest look to the next.
    fn wait(&self) -> Duration {
        (self.looked.saturating_duration_since(self.reason) / QUIET_SHARE)
            .clamp(WATCH_INTERVAL, IDLE_LOOK)
    }

    /// Returns when the next look is due.
    fn due(&self) -> tokio::time::Instant {
        self.looked + self.wait()
    }
}

/// Returns the process group a process is in, where it can be read.
pub(crate) fn group_of(process: &ProcessStartIdentity) -> Option<i32> {
    let pid = i32::try_from(process.pid.get()).ok()?;
    let pid = rustix::process::Pid::from_raw(pid)?;
    rustix::process::getpgid(Some(pid))
        .ok()
        .map(rustix::process::Pid::as_raw_nonzero)
        .map(std::num::NonZeroI32::get)
}

/// What one reading of a process's argument area found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arguments {
    /// The argument vector, each argument as text with any invalid UTF-8 replaced: what a profile
    /// records.
    pub vector: Vec<String>,
    /// The second argument, the one an interpreter is given its script as, as the exact bytes the
    /// kernel holds: present only where the reading proves that these bytes are the second argument
    /// and that they are an absolute path. An empty first argument on macOS, an empty second
    /// argument, a reading of one argument, a relative path or an option leave it absent, and so
    /// does a Linux reading that does not end where an argument area ends. A reading that cannot
    /// be made exact, as a macOS record not laid out as observed, gives no `Arguments` at all.
    pub script_argument: Option<OsString>,
}

/// Returns the second argument as the script it names, where it names one: an absolute path.
fn script_of(second: &[u8]) -> Option<OsString> {
    use std::os::unix::ffi::OsStringExt as _;

    second
        .starts_with(b"/")
        .then(|| OsString::from_vec(second.to_vec()))
}

/// The size of the first buffer a process's argument area is read into, in bytes.
#[cfg(any(target_os = "linux", feature = "testing"))]
pub const FIRST_READING: usize = 64 * 1024;

/// The size of the buffer the whole argument area is read into where the first reading filled its
/// buffer, in bytes: 6 MiB, which is `_STK_LIM / 4 * 3`, the most that the kernel lets the argument
/// and environment strings of a program take (`bprm_stack_limits` in `fs/exec.c`, Linux 6.12 line
/// 528, which also takes eight bytes of that for each string's pointer). The argument area alone is
/// below that, so no area of a program started in the usual way fills this buffer; one that does,
/// which a process with the right to move its own area could make, is refused.
#[cfg(any(target_os = "linux", feature = "testing"))]
pub const LARGEST_AREA: usize = 6 * 1024 * 1024;

/// What one read call of a process's argument area gave.
#[cfg(any(target_os = "linux", feature = "testing"))]
#[derive(Debug, PartialEq, Eq)]
pub enum CmdlineReading {
    /// The call gave fewer bytes than its buffer holds, so it gave the whole area.
    Whole(Vec<u8>),
    /// The call filled its buffer, so the area may be longer than what it gave.
    Filled,
}

/// Reads `source` with one read call into a buffer of `capacity` bytes. `None` where the call
/// failed.
///
/// One call, because the kernel answers one call from the memory map the process has at that moment
/// (`get_task_cmdline` in `fs/proc/base.c` takes and releases it inside the call, and `get_mm_cmdline`
/// copies up to the end of the argument area or the buffer, whichever comes first), so what it gave
/// is one program's. Calls that continue where an earlier one ended can each find another program's
/// memory, which is how an exec to the same image between two calls would pass for one reading.
#[cfg(any(target_os = "linux", feature = "testing"))]
#[must_use]
pub fn read_in_one_call(
    source: &mut impl std::io::Read,
    capacity: usize,
) -> Option<CmdlineReading> {
    let mut buffer = vec![0_u8; capacity];
    let length = source.read(&mut buffer).ok()?;
    if length >= capacity {
        return Some(CmdlineReading::Filled);
    }
    buffer.truncate(length);
    Some(CmdlineReading::Whole(buffer))
}

/// Returns the arguments `open` gives access to the area of: one read call into the first buffer,
/// and, where that call filled its buffer, a new reading from the start, one call into the largest
/// buffer. A reading that fills the largest buffer is refused, and no reading is ever continued
/// from where an earlier one ended. `open` is called once for each reading.
#[cfg(any(target_os = "linux", feature = "testing"))]
#[must_use]
pub fn arguments_from<R: std::io::Read>(mut open: impl FnMut() -> Option<R>) -> Option<Arguments> {
    let bytes = match read_in_one_call(&mut open()?, FIRST_READING)? {
        CmdlineReading::Whole(bytes) => bytes,
        CmdlineReading::Filled => match read_in_one_call(&mut open()?, LARGEST_AREA)? {
            CmdlineReading::Whole(bytes) => bytes,
            CmdlineReading::Filled => return None,
        },
    };
    parse_cmdline(&bytes)
}

/// Reads what one read call of `/proc/<pid>/cmdline` gave: one argument after each NUL-terminated
/// one.
///
/// Every position is exact, empty arguments included. A reading that does not end in a zero byte is
/// one a process rewrote, as a process that sets its title does, and names no script. An empty
/// reading, as a process that has ended or is still being started gives, and a reading of one
/// empty argument are read as nothing.
#[cfg(any(target_os = "linux", feature = "testing"))]
#[must_use]
pub fn parse_cmdline(bytes: &[u8]) -> Option<Arguments> {
    let area = bytes.strip_suffix(&[0]);
    let arguments: Vec<&[u8]> = area.unwrap_or(bytes).split(|byte| *byte == 0).collect();
    if arguments == [b"".as_slice()] {
        return None;
    }
    Some(Arguments {
        vector: arguments
            .iter()
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect(),
        script_argument: area
            .and(arguments.get(1))
            .and_then(|second| script_of(second)),
    })
}

/// Returns the arguments a process was started with, as the kernel keeps them:
/// `/proc/<pid>/cmdline`, read with one call into a buffer the area fits, as [`arguments_from`]
/// reads it.
#[cfg(target_os = "linux")]
#[must_use]
pub fn arguments_of(pid: u32) -> Option<Arguments> {
    arguments_from(|| std::fs::File::open(format!("/proc/{pid}/cmdline")).ok())
}

/// Returns the arguments a process was started with, as the kernel keeps them: macOS's
/// `KERN_PROCARGS2`, read once into a buffer as long as the kernel lets arguments and environment
/// be, and refused when the kernel's answer fills the buffer, since it might be cut.
#[cfg(target_os = "macos")]
#[must_use]
pub fn arguments_of(pid: u32) -> Option<Arguments> {
    let mut buffer = vec![0_u8; argument_limit()?];
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROCARGS2,
        libc::c_int::try_from(pid).ok()?,
    ];
    let length = kernel_read(&mut mib, &mut buffer)?;
    if length >= buffer.len() {
        return None;
    }
    parse_kern_procargs2(buffer.get(..length)?)
}

/// Returns how many bytes of arguments and environment the kernel allows a program, read once.
#[cfg(target_os = "macos")]
fn argument_limit() -> Option<usize> {
    static LIMIT: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        let mut value = [0_u8; 4];
        let length = kernel_read(&mut mib, &mut value)?;
        let limit = usize::try_from(libc::c_int::from_ne_bytes(value)).ok()?;
        (length == value.len() && limit > 0).then_some(limit)
    })
}

/// Reads one `sysctl` value into `out` and returns how many bytes the kernel wrote, or `None` where
/// the kernel refused or reported more than `out` holds.
///
/// This is the only unsafe code of the argument reader. The caller holds three things: `mib` names
/// the value and its length is the count passed with it, `out` is the whole buffer the kernel may
/// write, and nothing is passed in to set: the length variable is set to the buffer's length before
/// the call, the new-value pointer is null and its length is zero.
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "sysctl(3) has no safe form for the process-argument record: libproc binds no call \
              for it and the sysctl crate reads by name, so the call is made once, with a live \
              writable buffer of exactly the length it is told, which the kernel writes at most \
              and keeps no pointer to"
)]
fn kernel_read(mib: &mut [libc::c_int], out: &mut [u8]) -> Option<usize> {
    let mut length: libc::size_t = out.len();
    let count = libc::c_uint::try_from(mib.len()).ok()?;
    // SAFETY: `mib` is a live, writable array of `count` integers for the whole call. `out` is a
    // live, writable buffer of `length` bytes, which the kernel writes at most and then sets
    // `length` to the number it wrote. No new value is passed (a null pointer and a length of
    // zero), and the kernel keeps no pointer to anything after it returns.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            count,
            out.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && length <= out.len()).then_some(length)
}

/// How many bytes the kernel pads the path a program was executed by to, with at least one zero
/// byte after it (macOS 27.2.1: the arguments start at the next multiple of eight).
#[cfg(any(target_os = "macos", feature = "testing"))]
const PATH_PADDING: usize = 8;

/// Reads macOS's `KERN_PROCARGS2` record: the argument count, the path the program was executed
/// by, zero bytes, the arguments and then the environment.
///
/// The zero bytes after the path are the padding that brings the path to a multiple of eight
/// bytes, and one more for each empty argument at the front, so with that layout every position is
/// known and the arguments are read one after another, empty ones included. A record that is not
/// laid out that way, with fewer zero bytes than the padding, more empty arguments at the front
/// than the count, or fewer arguments than it counts, is read as nothing: the record does not say
/// where the arguments end, so nothing that follows the path is taken as an argument.
/// The second argument is also left out where an empty first argument or an empty second one means
/// that it cannot be told from padding or from nothing.
#[cfg(any(target_os = "macos", feature = "testing"))]
#[must_use]
pub fn parse_kern_procargs2(buffer: &[u8]) -> Option<Arguments> {
    let argc = usize::try_from(i32::from_ne_bytes(buffer.get(..4)?.try_into().ok()?))
        .ok()
        .filter(|count| *count > 0)?;
    let record = buffer.get(4..)?;
    let path_length = record.iter().position(|byte| *byte == 0)?;
    let after_path = record.get(path_length..)?;
    let zeros = after_path.iter().take_while(|byte| **byte == 0).count();
    let rest = after_path.get(zeros..)?;
    let empty_first = zeros.checked_sub(PATH_PADDING - path_length % PATH_PADDING)?;
    read_by_position(argc, empty_first, rest)
}

/// Reads `argc` arguments of which the first `empty_first` are empty and the rest follow in `rest`,
/// each ended by a zero byte, or returns `None` where `empty_first` is more than `argc` or `rest`
/// holds fewer.
#[cfg(any(target_os = "macos", feature = "testing"))]
fn read_by_position(argc: usize, empty_first: usize, rest: &[u8]) -> Option<Arguments> {
    // Checked before anything is made of `empty_first`, which a record's run of zero bytes sets.
    let counted = argc.checked_sub(empty_first)?;
    let mut arguments: Vec<&[u8]> = std::iter::repeat_n(b"".as_slice(), empty_first).collect();
    let mut remaining = rest;
    for _ in 0..counted {
        let end = remaining.iter().position(|byte| *byte == 0)?;
        arguments.push(remaining.get(..end)?);
        remaining = remaining.get(end + 1..)?;
    }
    Some(Arguments {
        vector: arguments
            .iter()
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect(),
        script_argument: if empty_first == 0 {
            arguments.get(1).and_then(|second| script_of(second))
        } else {
            None
        },
    })
}

/// Returns where the image a process runs is read from: on Linux the kernel's own link to it,
/// which names the image even after its path was replaced, and elsewhere the path the kernel
/// reports.
fn running_image(pid: u32, image: &Path) -> std::path::PathBuf {
    if cfg!(target_os = "linux") {
        std::path::PathBuf::from(format!("/proc/{pid}/exe"))
    } else {
        image.to_path_buf()
    }
}

/// Returns whether the process still runs the image that was read: the executable the kernel
/// reports is the one it reported before, byte for byte; the file that was opened and hashed, which
/// `held` is, still has the whole identity it had when it was hashed (device, file number, size and
/// both times), so a write to it in place after the hash is seen; and the file the image is read
/// from now is that file, by device and file number.
///
/// On Linux that file is the one the process runs, so a replaced image, whose path the kernel
/// reports with a suffix that says it is deleted, is refused by the first comparison, and a
/// replacement executed at the same path by the last. On macOS the file is the one the path names
/// now, which a replacement inside the reading changes.
fn still_runs(
    pid: u32,
    image: &Path,
    held: &std::fs::File,
    opened: &crate::broker::image::FileIdentity,
) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    // The bytes of the two paths are compared, not their text and not their components: two paths
    // that differ in a byte are two paths.
    let Some(now) = crate::questions::binding::executable_path_of(pid) else {
        return false;
    };
    if now.as_os_str().as_bytes() != image.as_os_str().as_bytes() {
        return false;
    }
    if crate::broker::image::FileIdentity::of_file(held)
        .ok()
        .as_ref()
        != Some(opened)
    {
        return false;
    }
    std::fs::metadata(running_image(pid, image))
        .is_ok_and(|file| file.dev() == opened.device && u128::from(file.ino()) == opened.inode)
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kr_protocol::ids::PluginId;

    use super::{ADOPTED_REFUSAL, IDLE_LOOK, Pace, WATCH_INTERVAL, tie_refusal};

    #[test]
    fn a_quiet_watch_waits_a_quarter_of_the_quiet_time_between_the_interval_and_the_idle_look() {
        let marked = tokio::time::Instant::now();
        let mut pace = Pace::new(marked);
        assert_eq!(pace.wait(), WATCH_INTERVAL, "just after a reason to look");

        pace.looked(marked + Duration::from_secs(4));
        assert_eq!(
            pace.wait(),
            Duration::from_secs(1),
            "a quarter of the quiet time"
        );
        assert_eq!(pace.due(), marked + Duration::from_secs(5));

        pace.looked(marked + Duration::from_secs(600));
        assert_eq!(pace.wait(), IDLE_LOOK, "and no more than the idle look");

        pace.reason_at_look();
        assert_eq!(
            pace.wait(),
            WATCH_INTERVAL,
            "a look that found something to go on looking at is a reason of its own"
        );

        pace.reason(marked + Duration::from_secs(601));
        assert_eq!(pace.wait(), WATCH_INTERVAL, "and so is a mark");
    }

    #[test]
    fn each_wait_is_at_most_a_quarter_of_the_quiet_time_before_it() {
        // Whenever a program takes the terminal, the look that finds it is no further away than a
        // quarter of the time since the latest reason, or one interval.
        let marked = tokio::time::Instant::now();
        let mut pace = Pace::new(marked);
        for _ in 0..200 {
            let due = pace.due();
            let quiet = pace.looked.saturating_duration_since(marked);
            assert!(
                due.saturating_duration_since(pace.looked) <= (quiet / 4).max(WATCH_INTERVAL),
                "a wait of {:?} after {quiet:?} of quiet",
                pace.wait()
            );
            pace.looked(due);
        }
        assert_eq!(
            pace.wait(),
            IDLE_LOOK,
            "a watch left alone settles on the idle look"
        );
    }

    /// KR-REQ-12.23: a view says "the host says" and then the refusal as the host wrote it, then a
    /// full stop of its own. So each refusal an adopted instance can carry, the adopted form and a
    /// tie among any number of packages, says something, starts in lower case and ends in a letter
    /// or a digit, with no space at either end.
    #[test]
    fn each_refusal_an_adopted_instance_carries_reads_between_the_host_says_and_a_full_stop() {
        let tied = |names: &[&str]| {
            let plugins: Vec<PluginId> = names
                .iter()
                .map(|name| PluginId::new(*name).expect("an identifier"))
                .collect();
            tie_refusal(&plugins)
        };
        let refusals = [
            ("an adopted program", ADOPTED_REFUSAL.to_owned()),
            (
                "a tie of two packages",
                tied(&["kalareach/claude-one", "kalareach/claude-two"]),
            ),
            (
                "a tie of three packages",
                tied(&["kalareach/a", "kalareach/b", "kalareach/c"]),
            ),
            (
                "a tie of four packages",
                tied(&["kalareach/a", "kalareach/b", "kalareach/c", "kalareach/d"]),
            ),
        ];
        for (which, words) in &refusals {
            assert!(
                !words.trim().is_empty(),
                "{which} says something: {words:?}"
            );
            assert_eq!(
                words.trim(),
                words,
                "{which} has no space at either end: {words:?}"
            );
            assert!(
                words.chars().next().is_some_and(char::is_lowercase),
                "{which} starts in lower case: {words:?}"
            );
            assert!(
                words.ends_with(char::is_alphanumeric),
                "{which} ends in a letter or a digit, so the view's full stop is the only one: {words:?}"
            );
        }
    }
}
