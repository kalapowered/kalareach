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
//! binding, and so invalidates the questions asked under the binding it left. Hooks are separate
//! processes on separate connections, so their reports are ordered by when each hook started
//! ([`ReportOrder`]) rather than by when they arrive; what cannot be ordered moves nothing and
//! suspends rich mutations, as section 12 asks when a native selection cannot be observed
//! reliably. A finished contact question names its request, which is how a question is placed in
//! the thread that asked it: see [`crate::questions::AgentBindings::attested`].

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
    /// The process, as the kernel named it where it could.
    pub process: ProcessStartIdentity,
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

/// How many threads one instance keeps its bridge's last reports of.
pub const MAX_REMEMBERED_THREADS: usize = 64;

/// How many contact requests one instance remembers a bridge placing in a thread.
pub const MAX_ATTESTED_REQUESTS: usize = 256;

/// The longest detail an observation carries: a tool's name, a notification's kind, a reason.
pub const MAX_OBSERVATION_DETAIL_BYTES: usize = 256;

/// The longest text an observation carries: a notification's message.
pub const MAX_OBSERVATION_TEXT_BYTES: usize = 4096;

/// The longest contact request identifier an observation carries, which is the longest a question's
/// own request identifier may be.
pub const MAX_CONTACT_REQUEST_BYTES: usize = 256;

/// Where one hook's report stands in the order of reports.
///
/// Hooks are separate processes on separate connections, so their reports can arrive in any order.
/// An application starts the hook for a later event later, so reports are ordered by when their
/// hook process started: first by the start value the kernel reports for the process, which the
/// host reads itself, and then, between two processes the kernel's clock cannot tell apart, by the
/// boot-clock reading the forwarder took when it started. Two reports equal in both are not ordered
/// at all, and a decision that would need that order is not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReportOrder {
    /// The kernel's start value for the hook process.
    pub kernel: u64,
    /// The boot-clock reading, in milliseconds, the forwarder took when it started.
    pub started: u64,
}

/// What one instance's bridge last reported about one thread.
#[derive(Clone, Copy, Debug, Default)]
struct ThreadReports {
    /// The newest report of the thread starting.
    started: Option<ReportOrder>,
    /// The newest report of the thread ending.
    ended: Option<ReportOrder>,
}

/// What an instance's native bridge has reported about its threads.
///
/// The selection moves only on a report newer than the one in force, and a report of a thread
/// starting is set against the newest report of that same thread ending, whichever arrived first.
/// When the order two reports would need cannot be read, the binding is not moved on a guess: the
/// instance's rich mutations are suspended until a report settles it, and no question is placed in
/// a thread meanwhile.
#[derive(Debug, Default)]
pub(crate) struct BridgeThreads {
    /// The order of the report that decided the selection in force.
    in_force: Option<ReportOrder>,
    /// What was last reported about each thread, least recently reported first.
    threads: std::collections::VecDeque<(AgentThreadId, ThreadReports)>,
    /// The suspension this bridge placed on rich mutations, while it stands.
    suspended: Option<String>,
    /// Contact requests a hook reported finishing, oldest first, with the thread that ran each.
    attested: std::collections::VecDeque<(String, AgentThreadId)>,
}

impl BridgeThreads {
    /// Returns the record of one thread, as the most recently reported one.
    fn reports(&mut self, thread: &AgentThreadId) -> &mut ThreadReports {
        let held = self
            .threads
            .iter()
            .position(|(reported, _)| reported == thread)
            .and_then(|at| self.threads.remove(at))
            .map_or_else(ThreadReports::default, |(_, reports)| reports);
        self.threads.push_back((thread.clone(), held));
        while self.threads.len() > MAX_REMEMBERED_THREADS {
            self.threads.pop_front();
        }
        &mut self.threads.back_mut().expect("just pushed").1
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
    /// The application selected a thread: it started one, resumed one, cleared into a new one.
    ThreadStarted,
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
    /// The boot-clock reading, in milliseconds, the forwarder took when it started.
    ///
    /// It orders two reports whose hook processes the kernel's clock cannot tell apart. It is the
    /// bridge's claim, like everything else here, and one from the future is refused.
    pub started: u64,
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
    /// The observation ended the selected thread, and the binding advanced to this revision.
    Ended(AgentBindingRevision),
    /// The binding already said what the observation says, or the observation says nothing
    /// about threads.
    Unchanged,
    /// A newer report already decided what this one would have: this one changes nothing.
    Stale,
    /// The report cannot be ordered against the one it would have to overrule, so the binding
    /// was not moved and rich mutations are suspended until a report settles it.
    Unordered,
    /// Selecting the thread was refused, and rich mutations are suspended until it is verified.
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

/// The suspension a bridge places on rich mutations when the application's thread cannot be read.
const UNORDERED: &str = "the application's bridge reported threads in an order this host cannot \
                         read, so its thread is not verified";

impl crate::broker::Broker {
    /// Applies what one of an instance's native bridge hooks observed.
    ///
    /// This is the production caller of the binding's advance. A hook that reports a thread the
    /// binding does not have selects it; a hook that reports the selected thread ending leaves the
    /// instance with none; both advance the binding revision, which is what invalidates the
    /// questions asked under the binding that was left. A report older than the one in force
    /// changes nothing, and so does a report of a thread starting that an equally new or newer
    /// report of the same thread ending already overrules. A report that cannot be ordered against
    /// the one it would overrule moves nothing and suspends rich mutations. A finished tool call
    /// that asked a contact question is recorded with its thread.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance, and
    /// [`BrokerError::InvalidArgument`] for a report that says it started in the future.
    pub fn observe_bridge(
        &self,
        application_instance_id: ApplicationInstanceId,
        reporter: &ProcessStartIdentity,
        observation: &Observation,
        now: TimestampMs,
    ) -> Result<(ThreadChange, StreamCursor)> {
        if observation.started > kr_ipc::clock::boot_elapsed_ms() {
            return Err(BrokerError::invalid(
                "this report says its hook started later than now",
            ));
        }
        let order = ReportOrder {
            kernel: reporter.start_value.get(),
            started: observation.started,
        };
        let mut state = self.state();
        let thread = match observation.event {
            ObservedEvent::ThreadStarted => started(
                &mut state,
                application_instance_id,
                &observation.thread,
                order,
                now,
            )?,
            ObservedEvent::ThreadEnded => ended(
                &mut state,
                application_instance_id,
                &observation.thread,
                order,
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
        if instance.bridge.suspended.is_some() {
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

/// How one report stands against the report in force.
fn against(in_force: Option<ReportOrder>, order: ReportOrder) -> std::cmp::Ordering {
    in_force.map_or(std::cmp::Ordering::Greater, |in_force| order.cmp(&in_force))
}

/// Applies a report of one thread starting, under the lock the caller holds.
fn started(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    thread: &AgentThreadId,
    order: ReportOrder,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let instance = instance_of(state, application_instance_id)?;
    let current = instance.thread_id.as_ref() == Some(thread);
    let in_force = instance.bridge.in_force;
    let reports = instance.bridge.reports(thread);
    reports.started = reports.started.max(Some(order));
    // The same thread ending, reported by a hook that started no earlier, overrules this start
    // whichever arrived first.
    match reports.ended.map(|ended| ended.cmp(&order)) {
        Some(std::cmp::Ordering::Greater) => return Ok(ThreadChange::Stale),
        Some(std::cmp::Ordering::Equal) => return Ok(unordered(state, application_instance_id)),
        _ => {}
    }
    match against(in_force, order) {
        std::cmp::Ordering::Less => Ok(ThreadChange::Stale),
        std::cmp::Ordering::Equal if current => Ok(ThreadChange::Unchanged),
        std::cmp::Ordering::Equal => Ok(unordered(state, application_instance_id)),
        std::cmp::Ordering::Greater if current => {
            let instance = instance_of(state, application_instance_id)?;
            instance.bridge.in_force = Some(order);
            settle(instance);
            Ok(ThreadChange::Unchanged)
        }
        std::cmp::Ordering::Greater => {
            match state.advance_binding(application_instance_id, Some(thread.clone()), now) {
                Ok(revision) => {
                    let instance = instance_of(state, application_instance_id)?;
                    instance.bridge.in_force = Some(order);
                    settle(instance);
                    Ok(ThreadChange::Selected(revision))
                }
                Err(error @ BrokerError::UnknownSubject { .. }) => Err(error),
                Err(error) => {
                    // The application is in a thread this instance cannot own, so its binding
                    // cannot be verified. Section 12: suspend rich mutations until it is.
                    let reason =
                        format!("the application selected a thread this host refused: {error}");
                    suspend(instance_of(state, application_instance_id)?, reason.clone());
                    Ok(ThreadChange::Refused(reason))
                }
            }
        }
    }
}

/// Applies a report of one thread ending, under the lock the caller holds.
fn ended(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    thread: &AgentThreadId,
    order: ReportOrder,
    now: TimestampMs,
) -> Result<ThreadChange> {
    let instance = instance_of(state, application_instance_id)?;
    let current = instance.thread_id.as_ref() == Some(thread);
    let in_force = instance.bridge.in_force;
    let reports = instance.bridge.reports(thread);
    reports.ended = reports.ended.max(Some(order));
    if !current {
        // Kept above, so a report of this thread starting that arrives later and is older is
        // overruled by it.
        return Ok(ThreadChange::Unchanged);
    }
    match against(in_force, order) {
        std::cmp::Ordering::Less => Ok(ThreadChange::Stale),
        std::cmp::Ordering::Equal => Ok(unordered(state, application_instance_id)),
        std::cmp::Ordering::Greater => {
            let revision = state.advance_binding(application_instance_id, None, now)?;
            let instance = instance_of(state, application_instance_id)?;
            instance.bridge.in_force = Some(order);
            settle(instance);
            Ok(ThreadChange::Ended(revision))
        }
    }
}

/// Leaves the binding where it is and suspends rich mutations, because the report cannot be
/// ordered against the one it would overrule.
fn unordered(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
) -> ThreadChange {
    if let Ok(instance) = instance_of(state, application_instance_id) {
        suspend(instance, UNORDERED.to_owned());
    }
    ThreadChange::Unordered
}

/// Suspends rich mutations for a reason of this bridge's, unless something else already has.
fn suspend(instance: &mut crate::broker::Instance, reason: String) {
    if instance.rich_suspension.is_none() {
        instance.rich_suspension = Some(reason.clone());
    }
    instance.bridge.suspended = Some(reason);
}

/// Lifts the suspension this bridge placed, now that a report has settled the thread. A
/// suspension something else placed is not this bridge's to lift.
fn settle(instance: &mut crate::broker::Instance) {
    if let Some(reason) = instance.bridge.suspended.take()
        && instance.rich_suspension.as_deref() == Some(reason.as_str())
    {
        instance.rich_suspension = None;
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

    fn observed(event: ObservedEvent, thread: &str, started: u64) -> Observation {
        Observation {
            event,
            thread: AgentThreadId::new(thread).expect("valid"),
            started,
            detail: None,
            text: None,
            contact_request: None,
        }
    }

    fn start(thread: &str, started: u64) -> Observation {
        observed(ObservedEvent::ThreadStarted, thread, started)
    }

    fn end(thread: &str, started: u64) -> Observation {
        observed(ObservedEvent::ThreadEnded, thread, started)
    }

    fn asked(thread: &str, request: &str) -> Observation {
        Observation {
            contact_request: Some(request.to_owned()),
            ..observed(ObservedEvent::ToolFinished, thread, 1)
        }
    }

    /// A bridge process whose start the kernel reports as `kernel`.
    fn reporter(kernel: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            4_000 + kernel,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            kernel,
        )
    }

    fn broker_with(instances: &[ApplicationInstanceId]) -> crate::broker::Broker {
        let broker = crate::broker::Broker::open(
            None,
            kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        )
        .expect("a broker");
        for instance in instances {
            broker
                .register_instance(
                    *instance,
                    kr_protocol::broker::IntegrationMode::NativeBridge,
                    None,
                    None,
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
            .observe_bridge(id, &reporter(kernel), observation, TimestampMs::new(1))
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

    fn revision(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> AgentBindingRevision {
        broker.binding_state(id).expect("known").binding_revision
    }

    /// KR-REQ-11.62: a hook that reports a thread selects it and advances the binding, a hook that
    /// reports it ending leaves no thread selected, and a report from a hook process that started
    /// before the one in force cannot undo it, whatever order the reports arrive in. A thread's own
    /// end overrules an older report of it starting, even when the end arrived first; a later
    /// start of the same thread, as a resume makes, is a new selection.
    #[test]
    fn kr_req_11_62_the_newest_report_decides_the_thread() {
        let id = instance(2);
        let broker = broker_with(&[id]);
        let first = revision(&broker, id);

        assert_eq!(
            apply(&broker, id, 10, &start("t1", 1)),
            ThreadChange::Selected(AgentBindingRevision::new(first.get() + 1))
        );
        assert_eq!(
            apply(&broker, id, 11, &start("t1", 2)),
            ThreadChange::Unchanged
        );
        assert!(matches!(
            apply(&broker, id, 30, &start("t2", 3)),
            ThreadChange::Selected(_)
        ));
        // An older process's report of the first thread arrives late, and changes nothing.
        assert_eq!(apply(&broker, id, 20, &start("t1", 4)), ThreadChange::Stale);
        // Nor does an older report of the current thread ending.
        assert_eq!(apply(&broker, id, 25, &end("t2", 5)), ThreadChange::Stale);
        assert_eq!(selected(&broker, id).as_deref(), Some("t2"));

        // A thread that is not selected ending is kept: its older start arriving afterwards is
        // overruled by it, and a newer start of it is a resume.
        assert_eq!(
            apply(&broker, id, 40, &end("t3", 6)),
            ThreadChange::Unchanged
        );
        assert_eq!(apply(&broker, id, 35, &start("t3", 7)), ThreadChange::Stale);
        assert_eq!(selected(&broker, id).as_deref(), Some("t2"));
        assert!(matches!(
            apply(&broker, id, 45, &start("t3", 8)),
            ThreadChange::Selected(_)
        ));

        // The selected thread ending, reported by a newer process, leaves none selected.
        let before = revision(&broker, id);
        assert_eq!(
            apply(&broker, id, 50, &end("t3", 9)),
            ThreadChange::Ended(AgentBindingRevision::new(before.get() + 1))
        );
        assert_eq!(selected(&broker, id), None);
        // And a tool or a notification never moves the binding.
        let at = revision(&broker, id);
        for event in [
            ObservedEvent::ToolFinished,
            ObservedEvent::ToolFailed,
            ObservedEvent::Notification,
        ] {
            assert_eq!(
                apply(&broker, id, 60, &observed(event, "t4", 10)),
                ThreadChange::Unchanged
            );
        }
        assert_eq!(revision(&broker, id), at);
    }

    /// KR-REQ-11.62: two reports the kernel's clock cannot tell apart are ordered by the boot-clock
    /// reading each forwarder took when it started. Reports equal in both are not ordered at all:
    /// the binding is not moved on a guess, rich mutations are suspended and no selection is
    /// vouched for, until a report the host can order settles it. A suspension something else
    /// placed is not lifted by the bridge.
    #[test]
    fn kr_req_11_62_reports_the_host_cannot_order_move_nothing_and_suspend_rich_mutations() {
        let id = instance(3);
        let broker = broker_with(&[id]);
        assert!(matches!(
            apply(&broker, id, 10, &start("t1", 500)),
            ThreadChange::Selected(_)
        ));
        // The same kernel start value, a later forwarder start: ordered, and it selects.
        assert!(matches!(
            apply(&broker, id, 10, &start("t2", 501)),
            ThreadChange::Selected(_)
        ));
        let at = revision(&broker, id);
        // Equal in both: not ordered.
        assert_eq!(
            apply(&broker, id, 10, &start("t3", 501)),
            ThreadChange::Unordered
        );
        let state = broker.binding_state(id).expect("known");
        assert_eq!(state.binding_revision, at, "the binding did not move");
        assert_eq!(selected(&broker, id).as_deref(), Some("t2"));
        assert!(state.rich_mutations_suspended);
        assert_eq!(broker.verified_selection(id), None);
        // The same for an end the host cannot order against the start in force.
        assert_eq!(
            apply(&broker, id, 10, &end("t2", 501)),
            ThreadChange::Unordered
        );
        // A report the host can order settles it and lifts the bridge's own suspension.
        assert!(matches!(
            apply(&broker, id, 11, &start("t3", 502)),
            ThreadChange::Selected(_)
        ));
        let state = broker.binding_state(id).expect("known");
        assert!(!state.rich_mutations_suspended);
        assert_eq!(
            broker
                .verified_selection(id)
                .map(|(thread, _)| thread.as_str().to_owned())
                .as_deref(),
            Some("t3")
        );

        // A thread's end and a start of it that the host cannot order: not ordered either.
        assert_eq!(
            apply(&broker, id, 20, &end("t9", 7)),
            ThreadChange::Unchanged
        );
        assert_eq!(
            apply(&broker, id, 20, &start("t9", 7)),
            ThreadChange::Unordered
        );

        // A suspension placed by something else stays when a report settles the thread.
        let other = instance(4);
        let broker = broker_with(&[other]);
        broker
            .suspend_rich_mutations(other, "something else")
            .expect("suspended");
        assert!(matches!(
            apply(&broker, other, 10, &start("t1", 5)),
            ThreadChange::Selected(_)
        ));
        assert!(
            broker
                .binding_state(other)
                .expect("known")
                .rich_mutations_suspended
        );
    }

    /// KR-REQ-11.62: a finished contact question's report places its request in the thread that
    /// ran it and selects nothing; a request two reports place in two threads is placed in none;
    /// and a report that says its hook started in the future is refused.
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
        assert_eq!(
            apply(&broker, id, 11, &asked("t1", "r-1")),
            ThreadChange::Unchanged
        );
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

        let future = Observation {
            started: u64::MAX,
            ..start("t1", 0)
        };
        assert!(
            broker
                .observe_bridge(id, &reporter(13), &future, TimestampMs::new(1))
                .is_err()
        );
    }

    /// KR-REQ-11.62: a thread another live execution already owns is not selected; the binding
    /// stays where it was and rich mutations are suspended until it is verified.
    #[test]
    fn kr_req_11_62_a_thread_another_execution_owns_suspends_rich_mutations() {
        let (first, second) = (instance(6), instance(7));
        let broker = broker_with(&[first, second]);
        apply(&broker, first, 10, &start("shared", 1));
        let before = revision(&broker, second);
        let change = apply(&broker, second, 11, &start("shared", 2));
        assert!(matches!(change, ThreadChange::Refused(_)), "{change:?}");
        let state = broker.binding_state(second).expect("known");
        assert_eq!(state.binding_revision, before);
        assert!(state.rich_mutations_suspended);
        assert_eq!(broker.verified_selection(second), None);
    }

    #[test]
    fn an_observation_frame_is_exactly_one_and_bounded() {
        let parsed = Observation::from_frame(
            br#"{"kr_observation":{"event":"tool_finished","thread":"t1","started":7,"detail":"Bash","contact_request":"r-1"}}"#,
        )
        .expect("an observation");
        assert_eq!(parsed.contact_request.as_deref(), Some("r-1"));
        assert_eq!(parsed.started, 7);
        let long_detail = format!(
            r#"{{"kr_observation":{{"event":"notification","thread":"t1","started":1,"detail":"{}"}}}}"#,
            "x".repeat(MAX_OBSERVATION_DETAIL_BYTES + 1)
        );
        for refused in [
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1","started":1,"extra":1}}"#[..],
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1"}}"#[..],
            &br#"{"kr_observation":{"event":"session_started","thread":"t1","started":1}}"#[..],
            &br#"{"kr_observation":{"event":"thread_started","thread":"","started":1}}"#[..],
            &br#"{"kr_observation":{"event":"thread_started","thread":"t1","started":1,"contact_request":"r"}}"#[..],
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1","started":1,"contact_request":"  "}}"#[..],
            &br#"{"kr_observation":{"event":"tool_finished","thread":"t1","started":1},"more":1}"#[..],
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
