//! The native bridge an application starts beside its unchanged terminal.
//!
//! Section 11 lets a package install "a minimal bridge in an application's documented native
//! plugin or hook location", and prefers "a small registration file plus the core `kr-hook`
//! forwarder". The application then starts the forwarder itself, as often as its own
//! configuration says: once for a channel server that lives as long as the session, and once for
//! every hook it runs. None of those processes is the process this host launched. Each is a process
//! the launched application started, and that is what this module admits.
//!
//! A bridge connection is admitted only when all of these hold, and each is checked by the host
//! rather than believed:
//!
//! * **The local peer.** On a private socket the kernel names the connecting process and its user,
//!   and the process the hello presents must be the one the kernel named.
//! * **The launch binding.** The connecting process is the launched application or one it started,
//!   found by the kernel's parent chain with every link checked by its start identity.
//! * **The private exchange.** The hello carries the credential this host generated for the launch
//!   and wrote to an owner-only file.
//! * **The installation.** The hello declares which bridge it is, and the declaration must name the
//!   application and a surface the installation recorded for this launch; the connecting process
//!   must be running the forwarder the installation put in place, where the platform can say what a
//!   process is running.
//!
//! A session identifier in the environment is carried in the hello and decides none of them.
//! Section 5: "An environment variable can identify a candidate session to an integration. It is
//! not a credential. The host validates the integration's local peer, installation and session
//! binding before accepting events or actions."
//!
//! # What an admitted hook reports
//!
//! One observation, in the host's own terms. A thread starting or ending moves the instance's
//! binding, and so invalidates the questions asked under the binding it left. Only a hook the
//! launched application started itself reports the application's own selection. Hooks are separate
//! processes on separate connections, so their reports are ordered by what the kernel recorded when
//! the application started each one rather than by when they arrive; reports that cannot be
//! ordered and disagree leave no thread vouched for and suspend rich mutations, as section 12 asks
//! when a native selection cannot be observed reliably. A finished contact question names its
//! request, which is how a question is placed in the thread that asked it: see
//! [`crate::questions::AgentBindings::attested`].

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    AgentBindingRevision, AgentThreadId, ApplicationInstanceId, PluginId, StreamCursor,
};
use kr_protocol::scalars::TimestampMs;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;

/// How long an admitted bridge has to send a frame the host is waiting for.
///
/// A hook sends its one observation straight after its hello, so anything slower than this is a
/// bridge that is not going to send it.
pub const BRIDGE_FRAME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// One of the registrations an installed bridge put into the application's configuration.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSurface {
    /// A lifecycle or tool hook: one short-lived process per event, which observes.
    Hook,
    /// A channel server: one process for as long as the application's session lasts.
    Channel,
}

impl BridgeSurface {
    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::Channel => "channel",
        }
    }
}

/// What a connecting bridge says it is.
///
/// It is a claim. [`InstalledBridge::validate`] is what decides whether the installation this host
/// recorded for the launch includes it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeDeclaration {
    /// The application whose registration started the bridge.
    pub application: String,
    /// Which of its registrations it was.
    pub surface: BridgeSurface,
}

/// The native bridge an installation put in place for one launch's application.
///
/// It is what the host recorded when the connector package's bridge was installed: the package it
/// came from, the application name its registration invokes the forwarder for, the surfaces the
/// recipe registered, and the forwarder executable it points the application at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledBridge {
    /// The connector package whose native bridge this is.
    pub plugin_id: PluginId,
    /// The application name the installed registration invokes the forwarder for.
    pub application: String,
    /// The surfaces the installed recipe registered.
    pub surfaces: BTreeSet<BridgeSurface>,
    /// The forwarder executable the installed registration starts.
    pub forwarder: PathBuf,
}

impl InstalledBridge {
    /// Checks one bridge's declaration, and the executable its process runs, against this
    /// installation.
    ///
    /// `running` is the executable the operating system says the connecting process is running,
    /// where the platform can name one. A process whose executable cannot be named is refused: the
    /// installation cannot be validated for a process nobody can identify.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming what did not match.
    pub fn validate(&self, declared: &BridgeDeclaration, running: Option<&Path>) -> Result<()> {
        if declared.application != self.application {
            return Err(BrokerError::denied(format!(
                "this connection declares a bridge for {:?}, and the bridge installed for this \
                 launch is {:?}'s",
                declared.application, self.application
            )));
        }
        if !self.surfaces.contains(&declared.surface) {
            return Err(BrokerError::denied(format!(
                "this connection declares the {} registration, which the installed bridge does not \
                 have",
                declared.surface.as_str()
            )));
        }
        let Some(running) = running else {
            return Err(BrokerError::denied(
                "the operating system did not name the executable this connection runs, so it \
                 cannot be the installed forwarder",
            ));
        };
        let installed = std::fs::canonicalize(&self.forwarder).map_err(|error| {
            BrokerError::denied(format!(
                "the installed forwarder {} cannot be read: {error}",
                self.forwarder.display()
            ))
        })?;
        let running = std::fs::canonicalize(running).map_err(|error| {
            BrokerError::denied(format!(
                "the executable this connection runs, {}, cannot be read: {error}",
                running.display()
            ))
        })?;
        if running != installed {
            return Err(BrokerError::denied(format!(
                "this connection runs {}, and the installed forwarder is {}",
                running.display(),
                installed.display()
            )));
        }
        Ok(())
    }
}

/// A bridge this host admitted.
///
/// A hook is then served by [`NativeGateway::observe_hook`], which reads and applies its one
/// observation. A channel's connection is handed to whatever serves the application's Channels
/// traffic: its stream carries the application's own notifications as JSON lines, both ways, each
/// within the gateway's native frame bound, in the connector's own shapes (`method` and `params`,
/// correlated at `params.request_id`). Turning a relayed approval into a pending resource and an
/// answer into a verdict is the arbitration's, not the stream's.
///
/// [`NativeGateway::observe_hook`]: crate::broker::attach::NativeGateway::observe_hook
#[derive(Debug)]
pub struct AdmittedBridge {
    /// Which registration it is.
    pub surface: BridgeSurface,
    /// The process, as the kernel named it where it could, and what the kernel recorded about its
    /// start.
    pub process: BridgeProcess,
    /// The connection it speaks on.
    pub stream: BridgeStream,
}

/// The connection one admitted bridge speaks on.
///
/// Frames are read and written in the connector's own framing, and each is bounded by the gateway's
/// native frame bound. Whatever was read past the hello before the bridge was admitted is held
/// here and read first, so nothing a bridge pipelined behind its hello is lost or read twice.
pub struct BridgeStream {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    held: Vec<u8>,
    framing: Framing,
}

impl std::fmt::Debug for BridgeStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BridgeStream")
            .field("held", &self.held.len())
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl BridgeStream {
    /// Wraps the two halves of an admitted connection.
    #[must_use]
    pub fn new(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
        held: Vec<u8>,
        framing: Framing,
    ) -> Self {
        Self {
            reader,
            writer,
            held,
            framing,
        }
    }

    /// Reads one whole frame, or `None` when the bridge has closed the connection between frames.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for a frame past the bound or a connection that
    /// ends in the middle of one, and [`BrokerError::UpstreamUnavailable`] when reading fails.
    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let mut chunk = [0_u8; 8192];
        loop {
            if let Some(body) = self.framing.decode(&mut self.held)? {
                return Ok(Some(body));
            }
            let read = self.reader.read(&mut chunk).await.map_err(|error| {
                BrokerError::UpstreamUnavailable {
                    detail: format!("the bridge's connection could not be read: {error}"),
                }
            })?;
            if read == 0 {
                if self.held.is_empty() {
                    return Ok(None);
                }
                return Err(BrokerError::invalid(
                    "the bridge closed its connection in the middle of a frame",
                ));
            }
            self.held.extend_from_slice(&chunk[..read]);
        }
    }

    /// Writes one frame.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for a frame past the bound, and
    /// [`BrokerError::UpstreamUnavailable`] when the write fails.
    pub async fn write_frame(&mut self, body: &[u8]) -> Result<()> {
        if body.len() > crate::broker::gateway::MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "a frame for a bridge is at most {} bytes and this one is {}",
                crate::broker::gateway::MAX_NATIVE_FRAME_BYTES,
                body.len()
            )));
        }
        let framed = self.framing.encode(body);
        self.writer
            .write_all(&framed)
            .await
            .and(self.writer.flush().await)
            .map_err(|error| BrokerError::UpstreamUnavailable {
                detail: format!("the bridge's connection could not be written: {error}"),
            })
    }

    /// Closes the host's direction, so the bridge reads the end of what this host sends.
    pub async fn close(&mut self) {
        let _ = self.writer.shutdown().await;
    }
}

/// The frame an admitted bridge is answered with, before anything else this host writes to it.
#[must_use]
pub fn admission_frame(surface: BridgeSurface) -> Vec<u8> {
    serde_json::json!({ "kr_bridge": { "admitted": surface.as_str() } })
        .to_string()
        .into_bytes()
}

impl crate::broker::Broker {
    /// Checks the private exchange a bridge presents against the launch it claims.
    ///
    /// The launch's record holds the credential, so this is where it is compared, and the
    /// credential never leaves it. The comparison is the host's own constant-time one.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance, and
    /// [`BrokerError::PermissionDenied`] when this host launched nothing for it or the credential
    /// is not the launch's.
    pub fn admit_bridge_exchange(
        &self,
        application_instance_id: ApplicationInstanceId,
        presented: &[u8],
    ) -> Result<()> {
        let state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| crate::broker::unknown_instance(application_instance_id))?;
        let launched = instance.process.as_ref().ok_or_else(|| {
            BrokerError::denied(
                "this host did not launch this application, so no bridge it started can be \
                 authenticated against it",
            )
        })?;
        if !launched.authenticates_exchange(presented) {
            return Err(BrokerError::denied(
                "this connection did not present the private exchange of the launch it claims",
            ));
        }
        Ok(())
    }
}

/// How many contact requests one instance remembers a bridge placing in a thread.
pub const MAX_ATTESTED_REQUESTS: usize = 256;

/// The longest detail an observation carries: a tool's name, a notification's kind, a reason.
pub const MAX_OBSERVATION_DETAIL_BYTES: usize = 256;

/// The longest text an observation carries: a notification's message.
pub const MAX_OBSERVATION_TEXT_BYTES: usize = 4096;

/// The longest contact request identifier an observation carries, which is the longest a question's
/// own request identifier may be.
pub const MAX_CONTACT_REQUEST_BYTES: usize = 256;

/// A bridge process as the kernel recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeProcess {
    /// The process.
    pub identity: ProcessStartIdentity,
    /// The process that started it, where the kernel's parent chain could name one.
    pub starter: Option<ProcessStartIdentity>,
    /// When the kernel recorded it starting, on a clock that only moves forward, where the platform
    /// keeps such a record.
    pub started: Option<u64>,
}

/// Whether a hook started after, in the same tick as, or before the hook of a report this host has
/// already applied, as the kernel's forward-only clock recorded both; `None` where the platform
/// keeps no such record.
///
/// Both hooks were started by the application process itself: the caller has checked that. Two in
/// one tick are not ordered by anything here: see [`BridgeThreads`].
fn placed(report: Option<u64>, applied: Option<u64>) -> Option<std::cmp::Ordering> {
    Some(report?.cmp(&applied?))
}

/// What an instance's native bridge has reported about its threads.
///
/// The application's selection is what the application process itself reports: its registration
/// has it start each hook directly, with nothing between them. A hook some other process started
/// (another program the application runs, or a wrapper between the two) reports that process's
/// threads, not the application's selection, and decides nothing.
///
/// Hooks are separate processes on separate connections, so their reports can arrive in any order.
/// Each is placed by when the kernel recorded the application starting its hook, on a clock that
/// only moves forward and that the kernel sets while the application is starting the process, so
/// it does not depend on when the hook was first scheduled. A bridge whose record the platform
/// keeps but cannot read is not admitted, so every report here has one where the platform keeps
/// them. Two hooks in one tick of that clock are not placed against each other: nothing the host
/// can verify says which came first. The forwarder makes that rare where it matters, by answering
/// a thread's start or end no sooner than two ticks after its hook started, so a hook the
/// application starts after waiting for that one falls in a later tick.
///
/// The newest report decides the thread. An older one still matters when its hook started after,
/// or in the same tick as, the report that began the binding's current revision: a thread
/// starting or ending there, or another thread going on, is a switch the host learned of late,
/// which a question bound to that revision may have been asked across, so the binding advances to
/// a new revision of what the newest report says holds. One whose hook started before the current
/// revision began changes nothing. A report that cannot be placed against the newest, because the
/// two fall in one tick or the platform keeps no record, and that would change the binding
/// whichever came first, leaves no thread vouched for, leaves the thread the binding had so nothing
/// bound to it survives, and suspends rich mutations until a report whose hook started in a later
/// tick than the newest settles it. Every report that could not be placed falls in the newest
/// one's tick, so that later report follows all of them.
#[derive(Debug, Default)]
pub(crate) struct BridgeThreads {
    /// The newest thread report applied.
    newest: Option<Reported>,
    /// When the hook started whose report began the binding's current revision, where one did.
    began: Option<u64>,
    /// True while the thread is not verified: a report could not be placed against the newest, or
    /// the thread reported could not be selected. Rich mutations are suspended meanwhile, for this
    /// reason of the bridge's own, which nothing else lifts and which lifts nothing else.
    unsettled: bool,
    /// Contact requests a hook reported finishing, oldest first, with the thread that ran each.
    attested: std::collections::VecDeque<(String, AgentThreadId)>,
}

/// One thread report, as the bridge keeps it.
#[derive(Debug)]
struct Reported {
    /// When its hook started, as [`BridgeProcess::started`].
    started: Option<u64>,
    /// The thread it leaves selected, or none.
    selects: Option<AgentThreadId>,
}

impl BridgeThreads {
    /// Why this bridge suspends rich mutations, while it does.
    pub(crate) fn suspension(&self) -> Option<&'static str> {
        self.unsettled.then_some(UNVERIFIED_THREAD)
    }

    fn remember_request(&mut self, request_id: String, thread: AgentThreadId) {
        self.attested.push_back((request_id, thread));
        while self.attested.len() > MAX_ATTESTED_REQUESTS {
            self.attested.pop_front();
        }
    }

    /// The one thread every report of this request names, when they agree.
    fn attested_thread(&self, request_id: &str) -> Option<AgentThreadId> {
        let mut named = self
            .attested
            .iter()
            .filter(|(request, _)| request == request_id)
            .map(|(_, thread)| thread);
        let first = named.next()?;
        named.all(|thread| thread == first).then(|| first.clone())
    }
}

/// What one hook reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedEvent {
    /// The application selected a thread: it started one, resumed one, cleared into a new one,
    /// forked one. Each is a new selection, even of a thread selected before.
    ThreadStarted,
    /// The selected thread goes on in a new context of its own, as a compaction makes. It is not a
    /// new selection.
    ThreadContinued,
    /// The application's thread ended.
    ThreadEnded,
    /// A tool the application ran finished.
    ToolFinished,
    /// A tool the application ran failed.
    ToolFailed,
    /// The application raised a notification.
    Notification,
}

impl ObservedEvent {
    /// The kind the observed history records it under.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::ThreadStarted => "thread.started",
            Self::ThreadContinued => "thread.continued",
            Self::ThreadEnded => "thread.ended",
            Self::ToolFinished => "tool.finished",
            Self::ToolFailed => "tool.failed",
            Self::Notification => "notification",
        }
    }
}

/// One observation a hook reports, in the host's own terms.
///
/// The forwarder translates the application's hook payload into this, so the host reads one
/// shape whatever the application. Every member is a claim of the admitted bridge, which the host
/// authenticated and validated before reading this; the host still bounds each one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// What happened.
    pub event: ObservedEvent,
    /// The application's own identifier of the thread it happened in.
    pub thread: AgentThreadId,
    /// A short detail: how a thread started, why it ended, which tool, which notification.
    #[serde(default)]
    pub detail: Option<String>,
    /// A notification's text.
    #[serde(default)]
    pub text: Option<String>,
    /// The request identifier of a contact question the finished tool call asked.
    ///
    /// It is the application's own report of which thread ran the call that asked, which is the
    /// per-request source context section 11 asks of a bridge before a question records a thread
    /// binding.
    #[serde(default)]
    pub contact_request: Option<String>,
}

impl Observation {
    /// Reads one observation frame, `{"kr_observation":{...}}`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for a frame that is not exactly that, or whose
    /// members are past their bounds.
    pub fn from_frame(body: &[u8]) -> Result<Self> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Frame {
            kr_observation: Observation,
        }
        let frame: Frame = serde_json::from_slice(body).map_err(|error| {
            BrokerError::invalid(format!(
                "this is not an observation a hook reports: {error}"
            ))
        })?;
        let observation = frame.kr_observation;
        observation.check()?;
        Ok(observation)
    }

    fn check(&self) -> Result<()> {
        if self
            .detail
            .as_ref()
            .is_some_and(|detail| detail.len() > MAX_OBSERVATION_DETAIL_BYTES)
        {
            return Err(BrokerError::invalid(format!(
                "an observation's detail is at most {MAX_OBSERVATION_DETAIL_BYTES} bytes"
            )));
        }
        if self
            .text
            .as_ref()
            .is_some_and(|text| text.len() > MAX_OBSERVATION_TEXT_BYTES)
        {
            return Err(BrokerError::invalid(format!(
                "an observation's text is at most {MAX_OBSERVATION_TEXT_BYTES} bytes"
            )));
        }
        if let Some(request) = &self.contact_request {
            if self.event != ObservedEvent::ToolFinished {
                return Err(BrokerError::invalid(
                    "only a finished tool call places a contact request in a thread",
                ));
            }
            // The rule a question's own request identifier is held to when it is asked.
            if request.trim().is_empty() || request.len() > MAX_CONTACT_REQUEST_BYTES {
                return Err(BrokerError::invalid(format!(
                    "a contact request identifier is 1 to {MAX_CONTACT_REQUEST_BYTES} bytes of \
                     text"
                )));
            }
        }
        Ok(())
    }

    /// The text the observed history records.
    fn summary(&self) -> String {
        match (self.event, &self.detail, &self.text) {
            (ObservedEvent::Notification, _, Some(text)) => text.clone(),
            (_, Some(detail), _) => detail.clone(),
            _ => String::new(),
        }
    }
}

/// What the thread binding did with one observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadChange {
    /// The observation selected its thread, and the binding advanced to this revision.
    Selected(AgentBindingRevision),
    /// The observation left no thread selected, and the binding advanced to this revision.
    Ended(AgentBindingRevision),
    /// The binding already said what the observation says, or the observation says nothing
    /// about threads.
    Unchanged,
    /// The observation's hook started before the report that began the binding's current revision:
    /// it changes nothing.
    Stale,
    /// The observation's hook started before the newest report's and after the report that began
    /// the binding's current revision, and the thread changed there: the binding advanced to this
    /// new revision of what the newest report says holds.
    Overtaken(AgentBindingRevision),
    /// The observation's hook was not started by the application process itself, so it does not
    /// report the application's selection: it changes nothing.
    Indirect,
    /// The observation's hook cannot be placed against the newest report's, and it would change
    /// the binding whichever came first. No thread is vouched for, the thread the binding had is
    /// left so nothing bound to it survives, and rich mutations are suspended until a report the
    /// host can place settles it.
    Unordered,
    /// Selecting the thread was refused. No thread is vouched for, and rich mutations are
    /// suspended until a later report settles it.
    Refused(String),
}

/// What one hook's observation did, once applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookReport {
    /// The observation.
    pub observation: Observation,
    /// What it did to the thread binding.
    pub thread: ThreadChange,
    /// Where it sits in the instance's observed history.
    pub cursor: StreamCursor,
}

/// Why rich mutations are suspended while an instance's bridge cannot vouch for its thread,
/// whatever unsettled it.
pub const UNVERIFIED_THREAD: &str = "the application's thread is not verified: its bridge reported \
                                     threads the host could not order or could not select";

impl crate::broker::Broker {
    /// Applies what one of an instance's native bridge hooks observed.
    ///
    /// This is the production caller of the binding's advance. Only a hook the launched
    /// application process started itself reports its selection. Reports are placed by the
    /// kernel's forward-only record of when the application started each hook; two from one tick of
    /// it are not placed against each other. The newest report decides the thread: a
    /// thread starting selects it and advances the binding revision, even when it is the thread
    /// already selected (a resume is a new selection); a thread ending leaves none selected; a
    /// thread continuing (a compaction) confirms the one selected. An older report of a change
    /// after the current revision began advances the binding again; one from before changes
    /// nothing; one that cannot be placed and would change the binding leaves no thread vouched
    /// for and suspends rich mutations. A finished tool call that asked a contact question is
    /// recorded with its thread.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn observe_bridge(
        &self,
        application_instance_id: ApplicationInstanceId,
        reporter: &BridgeProcess,
        observation: &Observation,
        now: TimestampMs,
    ) -> Result<(ThreadChange, StreamCursor)> {
        let mut state = self.state();
        let thread = match observation.event {
            ObservedEvent::ThreadStarted
            | ObservedEvent::ThreadContinued
            | ObservedEvent::ThreadEnded => decide(
                &mut state,
                application_instance_id,
                observation,
                reporter,
                now,
            )?,
            _ => ThreadChange::Unchanged,
        };
        let instance = instance_of(&mut state, application_instance_id)?;
        if let (ObservedEvent::ToolFinished, Some(request)) =
            (observation.event, &observation.contact_request)
        {
            instance
                .bridge
                .remember_request(request.clone(), observation.thread.clone());
        }
        let cursor = instance
            .semantic
            .append(observation.event.kind(), observation.summary(), now);
        Ok((thread, cursor))
    }

    /// Returns the thread every report of one contact request names, when the reports agree.
    ///
    /// A request two reports place in two threads is placed in none.
    #[must_use]
    pub fn attested_thread(
        &self,
        application_instance_id: ApplicationInstanceId,
        request_id: &str,
    ) -> Option<AgentThreadId> {
        self.state()
            .instances
            .get(&application_instance_id)?
            .bridge
            .attested_thread(request_id)
    }

    /// Returns the thread an instance has selected and the revision it was selected at, while the
    /// instance's bridge can vouch for it.
    #[must_use]
    pub fn verified_selection(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<(AgentThreadId, AgentBindingRevision)> {
        let state = self.state();
        let instance = state.instances.get(&application_instance_id)?;
        if instance.bridge.unsettled {
            return None;
        }
        instance
            .thread_id
            .clone()
            .map(|thread| (thread, instance.binding_revision))
    }
}

fn instance_of(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
) -> Result<&mut crate::broker::Instance> {
    state
        .instances
        .get_mut(&application_instance_id)
        .ok_or_else(|| crate::broker::unknown_instance(application_instance_id))
}

/// Applies one report of a thread starting, continuing or ending, under the lock the caller holds.
fn decide(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    observation: &Observation,
    reporter: &BridgeProcess,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let instance = instance_of(state, application_instance_id)?;
    // The application's selection is what the application itself reports. The kernel's parent
    // link, checked by start identity, says which process started the hook.
    let launched = instance.process.as_ref().map(|launched| &launched.process);
    if launched.is_none() || reporter.starter.as_ref() != launched {
        return Ok(ThreadChange::Indirect);
    }
    let bridge = &instance.bridge;
    let place = match &bridge.newest {
        None => Some(std::cmp::Ordering::Greater),
        Some(newest) => placed(reporter.started, newest.started),
    };
    // Started before the report that began the binding's current revision: every question bound
    // to that revision was asked after this, whatever it says.
    let before_revision = bridge
        .began
        .zip(reporter.started)
        .is_some_and(|(began, started)| started < began);
    match place {
        Some(std::cmp::Ordering::Greater) => {
            newest(state, application_instance_id, observation, reporter, now)
        }
        Some(std::cmp::Ordering::Less) if before_revision => Ok(ThreadChange::Stale),
        Some(std::cmp::Ordering::Less) => {
            overtaken(state, application_instance_id, observation, now)
        }
        Some(std::cmp::Ordering::Equal) | None => {
            unplaced(state, application_instance_id, observation, now)
        }
    }
}

/// Applies the newest report there is: what it says is what holds now.
fn newest(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    observation: &Observation,
    reporter: &BridgeProcess,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let current = instance_of(state, application_instance_id)?
        .thread_id
        .clone();
    let thread = &observation.thread;
    let selects = match observation.event {
        ObservedEvent::ThreadEnded => None,
        _ => Some(thread.clone()),
    };
    let change = match observation.event {
        ObservedEvent::ThreadContinued if current.as_ref() == Some(thread) => {
            ThreadChange::Unchanged
        }
        // Whichever thread ended, none is selected after it: a thread the host did not know was
        // selected ending says the host's view was already behind.
        ObservedEvent::ThreadEnded if current.is_none() => ThreadChange::Unchanged,
        _ => establish(state, application_instance_id, selects.clone(), now)?,
    };
    let instance = instance_of(state, application_instance_id)?;
    instance.bridge.newest = Some(Reported {
        started: reporter.started,
        selects,
    });
    if change != ThreadChange::Unchanged {
        instance.bridge.began = reporter.started;
    }
    instance.bridge.unsettled = matches!(change, ThreadChange::Refused(_));
    Ok(change)
}

/// Applies a report older than the newest, whose hook started after the report that began the
/// binding's current revision.
fn overtaken(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    observation: &Observation,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let instance = instance_of(state, application_instance_id)?;
    let current = instance.thread_id.clone();
    let switched = match observation.event {
        ObservedEvent::ThreadStarted | ObservedEvent::ThreadEnded => true,
        _ => current.as_ref() != Some(&observation.thread),
    };
    if !switched {
        return Ok(ThreadChange::Unchanged);
    }
    if instance.bridge.unsettled {
        // Nothing is vouched for already; whatever the binding holds now is left too.
        if current.is_some() {
            state.advance_binding(application_instance_id, None, now)?;
        }
        return Ok(ThreadChange::Unordered);
    }
    // The thread changed after the current revision began, and the host learned of it late. A
    // question bound to that revision may have been asked across the change, so none of them
    // survives, and what the newest report says still holds.
    let (holds, newest_started) = instance
        .bridge
        .newest
        .as_ref()
        .map_or((None, None), |newest| {
            (newest.selects.clone(), newest.started)
        });
    let change = establish(state, application_instance_id, holds, now)?;
    let instance = instance_of(state, application_instance_id)?;
    instance.bridge.began = newest_started;
    instance.bridge.unsettled = matches!(change, ThreadChange::Refused(_));
    Ok(match change {
        ThreadChange::Selected(revision) | ThreadChange::Ended(revision) => {
            ThreadChange::Overtaken(revision)
        }
        other => other,
    })
}

/// Applies a report that cannot be placed against the newest one.
fn unplaced(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    observation: &Observation,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let current = instance_of(state, application_instance_id)?
        .thread_id
        .clone();
    // Which came first cannot be read. That does not matter when the report leaves the binding as
    // it is in either order: an end when none is selected, or the selected thread going on. A
    // start is a new selection whichever came first.
    let agrees = match observation.event {
        ObservedEvent::ThreadEnded => current.is_none(),
        ObservedEvent::ThreadContinued => current.as_ref() == Some(&observation.thread),
        _ => false,
    };
    if agrees {
        return Ok(ThreadChange::Unchanged);
    }
    // Otherwise neither decides. The binding leaves the thread it had, so nothing bound to it
    // outlives a switch the host could not place.
    if current.is_some() {
        state.advance_binding(application_instance_id, None, now)?;
    }
    instance_of(state, application_instance_id)?
        .bridge
        .unsettled = true;
    Ok(ThreadChange::Unordered)
}

/// Moves the binding to a new revision that selects `selects`, or none.
///
/// A thread this instance cannot own is refused: the thread the binding had is left, since it is
/// not the application's any more, and the caller leaves no thread vouched for. Section 12: suspend
/// rich mutations until the binding can be verified.
fn establish(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    selects: Option<AgentThreadId>,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let Some(thread) = selects else {
        return Ok(ThreadChange::Ended(state.advance_binding(
            application_instance_id,
            None,
            now,
        )?));
    };
    match state.advance_binding(application_instance_id, Some(thread), now) {
        Ok(revision) => Ok(ThreadChange::Selected(revision)),
        Err(error @ BrokerError::UnknownSubject { .. }) => Err(error),
        Err(error) => {
            if instance_of(state, application_instance_id)?
                .thread_id
                .is_some()
            {
                state.advance_binding(application_instance_id, None, now)?;
            }
            Ok(ThreadChange::Refused(format!(
                "the application selected a thread this host refused: {error}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::gateway::NativeFraming;

    fn installed(forwarder: PathBuf) -> InstalledBridge {
        InstalledBridge {
            plugin_id: PluginId::new("kalareach/claude-code").expect("valid"),
            application: "claude-code".to_owned(),
            surfaces: [BridgeSurface::Hook, BridgeSurface::Channel]
                .into_iter()
                .collect(),
            forwarder,
        }
    }

    fn declared(application: &str, surface: BridgeSurface) -> BridgeDeclaration {
        BridgeDeclaration {
            application: application.to_owned(),
            surface,
        }
    }

    /// KR-REQ-05.09: the declaration and the executable are checked against the installation the
    /// host recorded, and each part that does not match refuses the connection.
    #[test]
    fn kr_req_05_09_a_bridge_is_the_installation_or_it_is_refused() {
        let this = std::env::current_exe().expect("this test's executable");
        let bridge = installed(this.clone());
        for surface in [BridgeSurface::Hook, BridgeSurface::Channel] {
            bridge
                .validate(&declared("claude-code", surface), Some(&this))
                .expect("the installation's own forwarder, for a surface it registered");
        }

        let refusals = [
            bridge.validate(&declared("codex", BridgeSurface::Hook), Some(&this)),
            bridge.validate(&declared("claude-code", BridgeSurface::Hook), None),
            bridge.validate(
                &declared("claude-code", BridgeSurface::Hook),
                Some(Path::new("/nonexistent/kalareach/kr-hook")),
            ),
        ];
        for refused in refusals {
            let refused = refused.expect_err("refused");
            assert_eq!(
                refused.code(),
                kr_protocol::error::ErrorCode::PermissionDenied,
                "{refused}"
            );
        }

        // A surface the recipe did not register is not one this installation has.
        let hooks_only = InstalledBridge {
            surfaces: std::iter::once(BridgeSurface::Hook).collect(),
            ..bridge
        };
        assert!(
            hooks_only
                .validate(
                    &declared("claude-code", BridgeSurface::Channel),
                    Some(&this)
                )
                .is_err()
        );
        // And another executable is not the installed forwarder, wherever it lives.
        let elsewhere = installed(PathBuf::from("/nonexistent/kalareach/kr-hook"));
        assert!(
            elsewhere
                .validate(&declared("claude-code", BridgeSurface::Hook), Some(&this))
                .is_err()
        );
    }

    #[test]
    fn a_declaration_names_exactly_an_application_and_a_surface() {
        let parsed: BridgeDeclaration =
            serde_json::from_str(r#"{"application":"claude-code","surface":"hook"}"#)
                .expect("a declaration");
        assert_eq!(parsed, declared("claude-code", BridgeSurface::Hook));
        for refused in [
            r#"{"application":"claude-code","surface":"tool"}"#,
            r#"{"application":"claude-code"}"#,
            r#"{"application":"claude-code","surface":"hook","grant":"all"}"#,
        ] {
            assert!(
                serde_json::from_str::<BridgeDeclaration>(refused).is_err(),
                "{refused}"
            );
        }
    }

    #[tokio::test]
    async fn a_stream_reads_what_was_held_first_and_refuses_a_cut_frame() {
        let (here, mut there) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(here);
        let mut stream = BridgeStream::new(
            Box::new(reader),
            Box::new(writer),
            b"{\"held\":1}\n{\"hel".to_vec(),
            Framing::new(NativeFraming::JsonLines),
        );
        there.write_all(b"d\":2}\n").await.expect("written");
        assert_eq!(
            stream.read_frame().await.expect("read"),
            Some(b"{\"held\":1}".to_vec())
        );
        assert_eq!(
            stream.read_frame().await.expect("read"),
            Some(b"{\"held\":2}".to_vec())
        );
        there.write_all(b"{\"cut\"").await.expect("written");
        drop(there);
        assert!(stream.read_frame().await.is_err(), "a cut frame is refused");
    }

    /// A frame read from a bridge is bounded however its bytes arrive: exactly the bound is a frame,
    /// and one byte more is refused when the newline comes in the final read.
    #[tokio::test]
    async fn a_frame_read_from_a_bridge_is_bounded_whichever_read_ends_it() {
        let bound = crate::broker::gateway::MAX_NATIVE_FRAME_BYTES;
        for (length, accepted) in [(bound, true), (bound + 1, false)] {
            let (here, mut there) = tokio::io::duplex(1 << 16);
            let (reader, writer) = tokio::io::split(here);
            // Everything but the last byte was read before; the last byte and the newline come in
            // the read that ends the frame.
            let mut stream = BridgeStream::new(
                Box::new(reader),
                Box::new(writer),
                vec![b'x'; length - 1],
                Framing::new(NativeFraming::JsonLines),
            );
            there.write_all(b"x\n").await.expect("written");
            let read = stream.read_frame().await;
            if accepted {
                assert_eq!(
                    read.expect("a frame at the bound").map(|body| body.len()),
                    Some(bound)
                );
            } else {
                assert!(read.is_err(), "a body of {length} bytes is refused");
            }
        }
    }

    fn observed(event: ObservedEvent, thread: &str) -> Observation {
        Observation {
            event,
            thread: AgentThreadId::new(thread).expect("valid"),
            detail: None,
            text: None,
            contact_request: None,
        }
    }

    fn start(thread: &str) -> Observation {
        observed(ObservedEvent::ThreadStarted, thread)
    }

    fn end(thread: &str) -> Observation {
        observed(ObservedEvent::ThreadEnded, thread)
    }

    fn continued(thread: &str) -> Observation {
        observed(ObservedEvent::ThreadContinued, thread)
    }

    fn asked(thread: &str, request: &str) -> Observation {
        Observation {
            contact_request: Some(request.to_owned()),
            ..observed(ObservedEvent::ToolFinished, thread)
        }
    }

    /// The process this host launched for an instance.
    fn application(id: ApplicationInstanceId) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            100 + u64::from(id.get().as_bytes()[0]),
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            1,
        )
    }

    /// A hook the application started, whose start the kernel's forward-only clock recorded as
    /// `kernel`.
    fn reporter(id: ApplicationInstanceId, kernel: u64) -> BridgeProcess {
        BridgeProcess {
            identity: ProcessStartIdentity::new(
                4_000 + kernel,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                kernel,
            ),
            starter: Some(application(id)),
            started: Some(kernel),
        }
    }

    /// A hook the application started on a platform that keeps no forward-only record of a start.
    fn unrecorded(id: ApplicationInstanceId, pid: u64) -> BridgeProcess {
        BridgeProcess {
            identity: ProcessStartIdentity::new(
                pid,
                kr_protocol::identity::ProcessStartSource::WindowsProcessCreationTime,
                50,
            ),
            starter: Some(application(id)),
            started: None,
        }
    }

    fn apply_as(
        broker: &crate::broker::Broker,
        id: ApplicationInstanceId,
        reporter: &BridgeProcess,
        observation: &Observation,
    ) -> ThreadChange {
        broker
            .observe_bridge(id, reporter, observation, TimestampMs::new(1))
            .expect("applied")
            .0
    }

    fn broker_with(instances: &[ApplicationInstanceId]) -> crate::broker::Broker {
        use crate::broker::process::{
            BrokerTransport, CREDENTIAL_BYTES, Credential, ManagedProcess, TransportHandle,
        };
        let broker = crate::broker::Broker::open(
            None,
            kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            crate::persistence::fault::JournalHealth::shared(),
        )
        .expect("a broker");
        for instance in instances {
            let launched = ManagedProcess::new(
                *instance,
                application(*instance),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: *instance,
                    executable_digest: kr_protocol::scalars::Digest256::from_bytes([3; 32]),
                    process: application(*instance),
                },
                Credential::from_bytes([9; CREDENTIAL_BYTES]),
                true,
                TimestampMs::new(1),
            );
            broker
                .register_instance(
                    *instance,
                    kr_protocol::broker::IntegrationMode::NativeBridge,
                    None,
                    Some(launched),
                )
                .expect("registered");
        }
        broker
    }

    fn instance(byte: u8) -> ApplicationInstanceId {
        ApplicationInstanceId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn apply(
        broker: &crate::broker::Broker,
        id: ApplicationInstanceId,
        kernel: u64,
        observation: &Observation,
    ) -> ThreadChange {
        broker
            .observe_bridge(id, &reporter(id, kernel), observation, TimestampMs::new(1))
            .expect("applied")
            .0
    }

    fn selected(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> Option<String> {
        broker
            .binding_state(id)
            .expect("known")
            .thread_id
            .as_ref()
            .map(|thread| thread.as_str().to_owned())
    }

    fn vouched(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> Option<String> {
        broker
            .verified_selection(id)
            .map(|(thread, _)| thread.as_str().to_owned())
    }

    fn revision(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> AgentBindingRevision {
        broker.binding_state(id).expect("known").binding_revision
    }

    fn suspended(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> bool {
        broker
            .binding_state(id)
            .expect("known")
            .rich_mutations_suspended
    }

    /// KR-REQ-11.62: the report whose hook the kernel says started last decides the thread. A thread
    /// starting selects it and advances the binding, even when it is the thread already selected,
    /// because a resume is a new selection; a compaction continues the thread without a switch; an
    /// end leaves none selected, including the end of a thread the host did not know was selected.
    /// A report whose hook started earlier changes nothing, whichever arrived first, so a resume
    /// that overtakes the end before it still leaves the revision before the end behind.
    #[test]
    fn kr_req_11_62_the_report_whose_hook_started_last_decides_the_thread() {
        let id = instance(2);
        let broker = broker_with(&[id]);
        let first = revision(&broker, id);

        assert_eq!(
            apply(&broker, id, 10, &start("t1")),
            ThreadChange::Selected(AgentBindingRevision::new(first.get() + 1))
        );
        let t1 = revision(&broker, id);
        assert_eq!(
            apply(&broker, id, 11, &continued("t1")),
            ThreadChange::Unchanged
        );
        assert_eq!(revision(&broker, id), t1, "a compaction is not a switch");

        // A resume of the selected thread overtakes the report of its end.
        assert!(matches!(
            apply(&broker, id, 30, &start("t1")),
            ThreadChange::Selected(resumed) if resumed > t1
        ));
        assert_eq!(apply(&broker, id, 20, &end("t1")), ThreadChange::Stale);
        assert_eq!(selected(&broker, id).as_deref(), Some("t1"));

        assert!(matches!(
            apply(&broker, id, 50, &start("t2")),
            ThreadChange::Selected(_)
        ));
        assert_eq!(apply(&broker, id, 40, &start("t1")), ThreadChange::Stale);
        assert_eq!(apply(&broker, id, 45, &end("t2")), ThreadChange::Stale);

        // The end of a thread the host never saw selected: the host was behind, and none is
        // selected after it. That thread's older start, arriving later, changes nothing; a later
        // start of it is a resume.
        assert!(matches!(
            apply(&broker, id, 70, &end("t3")),
            ThreadChange::Ended(_)
        ));
        assert_eq!(selected(&broker, id), None);
        assert_eq!(apply(&broker, id, 60, &start("t3")), ThreadChange::Stale);
        assert_eq!(selected(&broker, id), None);
        assert!(matches!(
            apply(&broker, id, 80, &start("t3")),
            ThreadChange::Selected(_)
        ));
        assert!(matches!(
            apply(&broker, id, 90, &end("t3")),
            ThreadChange::Ended(_)
        ));
        assert_eq!(apply(&broker, id, 95, &end("t9")), ThreadChange::Unchanged);

        // A tool or a notification never moves the binding.
        let at = revision(&broker, id);
        for event in [
            ObservedEvent::ToolFinished,
            ObservedEvent::ToolFailed,
            ObservedEvent::Notification,
        ] {
            assert_eq!(
                apply(&broker, id, 100, &observed(event, "t4")),
                ThreadChange::Unchanged
            );
        }
        assert_eq!(revision(&broker, id), at);
        assert!(!suspended(&broker, id));
    }

    fn suspension(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> Option<String> {
        broker.binding_state(id).expect("known").suspension_reason.0
    }

    /// KR-REQ-11.62: a switch the host learns of only after a later report still invalidates the
    /// revision it followed. A compaction reported before the end, the other thread and the
    /// resume that came between leaves the thread as it was, but the first of those late reports
    /// advances the binding, so nothing bound before the switch survives; the rest started before
    /// that new revision began and change nothing. A late report of another thread going on is a
    /// switch too, and one of the selected thread going on is not.
    #[test]
    fn kr_req_11_62_a_switch_learned_late_still_invalidates_the_revision_it_followed() {
        let id = instance(3);
        let broker = broker_with(&[id]);
        assert!(matches!(
            apply(&broker, id, 10, &start("a")),
            ThreadChange::Selected(_)
        ));
        let asked_under = revision(&broker, id);
        assert_eq!(
            apply(&broker, id, 60, &continued("a")),
            ThreadChange::Unchanged
        );
        assert_eq!(revision(&broker, id), asked_under);

        let change = apply(&broker, id, 20, &end("a"));
        assert!(
            matches!(change, ThreadChange::Overtaken(revision) if revision > asked_under),
            "{change:?}"
        );
        assert_eq!(selected(&broker, id).as_deref(), Some("a"));
        assert_eq!(vouched(&broker, id).as_deref(), Some("a"));
        let after = revision(&broker, id);
        for (kernel, late) in [(30, start("b")), (40, end("b")), (50, start("a"))] {
            assert_eq!(apply(&broker, id, kernel, &late), ThreadChange::Stale);
        }
        assert_eq!(revision(&broker, id), after);

        assert!(matches!(
            apply(&broker, id, 110, &start("x")),
            ThreadChange::Selected(_)
        ));
        assert_eq!(
            apply(&broker, id, 160, &continued("x")),
            ThreadChange::Unchanged
        );
        assert_eq!(
            apply(&broker, id, 140, &continued("x")),
            ThreadChange::Unchanged
        );
        assert!(matches!(
            apply(&broker, id, 130, &continued("y")),
            ThreadChange::Overtaken(_)
        ));
        assert_eq!(selected(&broker, id).as_deref(), Some("x"));
        assert!(!suspended(&broker, id));
    }

    /// KR-REQ-11.62: two reports from one tick of the kernel's clock are not placed against each
    /// other, whichever was applied first. A report that would change the binding whichever came
    /// first leaves no thread vouched for, even the start of a thread that may have come before
    /// the end the host already applied; the first report from a later tick settles it.
    #[test]
    fn kr_req_11_62_reports_from_one_tick_are_not_placed_and_a_later_tick_settles_them() {
        let id = instance(8);
        let broker = broker_with(&[id]);
        assert!(matches!(
            apply(&broker, id, 200, &start("a")),
            ThreadChange::Selected(_)
        ));
        let before = revision(&broker, id);
        assert_eq!(apply(&broker, id, 200, &end("a")), ThreadChange::Unordered);
        assert!(
            revision(&broker, id) > before,
            "nothing bound to a survives"
        );
        assert_eq!(
            apply(&broker, id, 200, &start("b")),
            ThreadChange::Unordered
        );
        assert_eq!(
            apply(&broker, id, 200, &start("a")),
            ThreadChange::Unordered
        );
        assert_eq!(selected(&broker, id), None);
        assert_eq!(vouched(&broker, id), None);
        assert!(suspended(&broker, id));
        assert_eq!(apply(&broker, id, 199, &start("a")), ThreadChange::Stale);
        assert!(suspended(&broker, id));

        assert!(matches!(
            apply(&broker, id, 201, &start("b")),
            ThreadChange::Selected(_)
        ));
        assert_eq!(vouched(&broker, id).as_deref(), Some("b"));
        assert!(!suspended(&broker, id));

        use std::cmp::Ordering::{Equal, Greater, Less};
        assert_eq!(placed(Some(11), Some(10)), Some(Greater));
        assert_eq!(placed(Some(10), Some(10)), Some(Equal));
        assert_eq!(placed(Some(9), Some(10)), Some(Less));
        assert_eq!(placed(None, Some(10)), None);
        assert_eq!(placed(Some(10), None), None);
    }

    /// KR-REQ-11.62: where the platform keeps no forward-only record of a start, reports cannot be
    /// placed. One that leaves the binding as it is whichever came first changes nothing; any other
    /// leaves the thread the binding had, so nothing bound to it survives, vouches for no thread
    /// and suspends rich mutations. A start is a new selection whichever came first, so it never
    /// leaves the binding as it is.
    #[test]
    fn kr_req_11_62_reports_the_host_cannot_place_leave_no_thread_vouched_for() {
        let id = instance(4);
        let broker = broker_with(&[id]);
        assert!(matches!(
            apply_as(&broker, id, &unrecorded(id, 100), &start("t1")),
            ThreadChange::Selected(_)
        ));
        assert_eq!(
            apply_as(&broker, id, &unrecorded(id, 104), &continued("t1")),
            ThreadChange::Unchanged
        );
        assert_eq!(vouched(&broker, id).as_deref(), Some("t1"));

        let before = revision(&broker, id);
        assert_eq!(
            apply_as(&broker, id, &unrecorded(id, 108), &start("t1")),
            ThreadChange::Unordered
        );
        assert!(
            revision(&broker, id) > before,
            "nothing bound to t1 survives"
        );
        assert_eq!(selected(&broker, id), None);
        assert_eq!(vouched(&broker, id), None);
        assert_eq!(suspension(&broker, id).as_deref(), Some(UNVERIFIED_THREAD));
        assert_eq!(
            apply_as(&broker, id, &unrecorded(id, 112), &end("t2")),
            ThreadChange::Unchanged
        );
        assert_eq!(
            apply_as(&broker, id, &unrecorded(id, 116), &start("t2")),
            ThreadChange::Unordered
        );
        assert!(suspended(&broker, id));
        assert_eq!(vouched(&broker, id), None);
    }

    /// The bridge's suspension is its own. Lifting a suspension placed for another reason leaves
    /// the bridge's in place, and the bridge settling leaves the other in place.
    #[test]
    fn a_bridge_suspension_and_any_other_are_each_lifted_by_their_own() {
        let id = instance(12);
        let broker = broker_with(&[id]);
        apply(&broker, id, 10, &start("t1"));
        assert_eq!(
            apply_as(&broker, id, &unrecorded(id, 7), &start("t2")),
            ThreadChange::Unordered
        );
        broker
            .suspend_rich_mutations(id, "something else")
            .expect("suspended");
        broker.resume_rich_mutations(id).expect("resumed");
        assert_eq!(suspension(&broker, id).as_deref(), Some(UNVERIFIED_THREAD));
        assert_eq!(vouched(&broker, id), None);

        broker
            .suspend_rich_mutations(id, "something else")
            .expect("suspended");
        apply(&broker, id, 11, &start("t2"));
        assert_eq!(vouched(&broker, id).as_deref(), Some("t2"));
        assert_eq!(suspension(&broker, id).as_deref(), Some("something else"));
        broker.resume_rich_mutations(id).expect("resumed");
        assert!(!suspended(&broker, id));
    }

    /// KR-REQ-11.62: only a hook the launched application started itself reports its selection.
    /// A hook another process started, or one whose starter the kernel could not name, is recorded
    /// and moves nothing, and it unsettles nothing either.
    #[test]
    fn kr_req_11_62_only_a_hook_the_application_started_itself_reports_its_thread() {
        let id = instance(9);
        let broker = broker_with(&[id]);
        apply(&broker, id, 10, &start("t1"));
        let at = revision(&broker, id);
        let stranger = ProcessStartIdentity::new(
            77,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            5,
        );
        for starter in [Some(stranger), None] {
            let started_elsewhere = BridgeProcess {
                starter,
                ..reporter(id, 20)
            };
            for observation in [start("t2"), end("t1"), continued("t2")] {
                assert_eq!(
                    apply_as(&broker, id, &started_elsewhere, &observation),
                    ThreadChange::Indirect
                );
            }
        }
        assert_eq!(selected(&broker, id).as_deref(), Some("t1"));
        assert_eq!(revision(&broker, id), at);
        assert!(!suspended(&broker, id));
        // The application's own later hook still decides.
        assert!(matches!(
            apply(&broker, id, 11, &start("t2")),
            ThreadChange::Selected(_)
        ));
    }

    /// KR-REQ-11.62: a thread another live execution already owns is not selected. The thread the
    /// binding had is left, no thread is vouched for and rich mutations are suspended. A report
    /// from before the refusal settles nothing; the next one settles it.
    #[test]
    fn kr_req_11_62_a_thread_another_execution_owns_leaves_no_thread_vouched_for() {
        let (first, second) = (instance(6), instance(7));
        let broker = broker_with(&[first, second]);
        apply(&broker, first, 10, &start("shared"));
        apply(&broker, second, 10, &start("own"));
        let before = revision(&broker, second);
        let change = apply(&broker, second, 11, &start("shared"));
        assert!(matches!(change, ThreadChange::Refused(_)), "{change:?}");
        assert!(
            revision(&broker, second) > before,
            "the thread it had is left"
        );
        assert_eq!(selected(&broker, second), None);
        assert_eq!(vouched(&broker, second), None);
        assert!(suspended(&broker, second));
        assert_eq!(
            apply(&broker, second, 9, &start("elsewhere")),
            ThreadChange::Stale
        );
        assert!(suspended(&broker, second));
        assert!(matches!(
            apply(&broker, second, 12, &start("elsewhere")),
            ThreadChange::Selected(_)
        ));
        assert!(!suspended(&broker, second));
    }

    /// KR-REQ-11.62: a finished contact question's report places its request in the thread that
    /// ran it and selects nothing; a request two reports place in two threads is placed in none.
    #[test]
    fn kr_req_11_62_a_contact_request_is_placed_in_the_thread_every_report_names() {
        let id = instance(5);
        let broker = broker_with(&[id]);
        assert_eq!(
            apply(&broker, id, 10, &asked("t1", "r-1")),
            ThreadChange::Unchanged
        );
        assert_eq!(
            selected(&broker, id),
            None,
            "a tool's report selects nothing"
        );
        assert_eq!(
            broker
                .attested_thread(id, "r-1")
                .map(|thread| thread.as_str().to_owned())
                .as_deref(),
            Some("t1")
        );
        apply(&broker, id, 11, &asked("t1", "r-1"));
        assert!(
            broker.attested_thread(id, "r-1").is_some(),
            "two agreeing reports"
        );
        apply(&broker, id, 12, &asked("t2", "r-1"));
        assert_eq!(
            broker.attested_thread(id, "r-1"),
            None,
            "two threads for one request"
        );
        assert_eq!(broker.attested_thread(id, "r-2"), None);
    }

    #[test]
    fn an_observation_frame_is_exactly_one_and_bounded() {
        let parsed = Observation::from_frame(
            br#"{"kr_observation":{"event":"tool_finished","thread":"t1","detail":"Bash","contact_request":"r-1"}}"#,
        )
        .expect("an observation");
        assert_eq!(parsed.contact_request.as_deref(), Some("r-1"));
        let long_detail = format!(
            r#"{{"kr_observation":{{"event":"notification","thread":"t1","detail":"{}"}}}}"#,
            "x".repeat(MAX_OBSERVATION_DETAIL_BYTES + 1)
        );
        for refused in [
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1","extra":1}}"#[..],
            &br#"{"kr_observation":{"event":"thread_started","thread":"t1","started":1}}"#[..],
            &br#"{"kr_observation":{"event":"session_started","thread":"t1"}}"#[..],
            &br#"{"kr_observation":{"event":"thread_started","thread":""}}"#[..],
            &br#"{"kr_observation":{"event":"thread_started","thread":"t1","contact_request":"r"}}"#[..],
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1","contact_request":"  "}}"#[..],
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1"},"more":1}"#[..],
            long_detail.as_bytes(),
        ] {
            assert!(
                Observation::from_frame(refused).is_err(),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[tokio::test]
    async fn a_frame_past_the_bound_is_not_written() {
        let (here, _there) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(here);
        let mut stream = BridgeStream::new(
            Box::new(reader),
            Box::new(writer),
            Vec::new(),
            Framing::new(NativeFraming::JsonLines),
        );
        let oversized = vec![b'x'; crate::broker::gateway::MAX_NATIVE_FRAME_BYTES + 1];
        assert!(stream.write_frame(&oversized).await.is_err());
        assert_eq!(
            admission_frame(BridgeSurface::Channel),
            br#"{"kr_bridge":{"admitted":"channel"}}"#.to_vec()
        );
    }
}
