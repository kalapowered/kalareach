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

/// How many threads one instance remembers having had selected, with the revision each one had.
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

/// What an instance's native bridge has reported about its threads.
///
/// Hooks are separate processes on separate connections, so their reports can arrive in any order.
/// What orders them is the kernel's start value of the process that made each one, because an
/// application starts the hook for a later event later. A report from a process older than the one
/// whose report is in force cannot undo it.
#[derive(Debug, Default)]
pub(crate) struct BridgeThreads {
    /// The start value of the bridge process whose report decided the selection in force.
    decided_by: Option<u64>,
    /// Threads this instance has had selected, oldest first, with the revision each was selected at.
    selected: std::collections::VecDeque<(AgentThreadId, AgentBindingRevision)>,
    /// Contact requests a bridge placed in a thread, oldest first, with the revision each was made
    /// under.
    attested: std::collections::VecDeque<(String, AgentBindingRevision)>,
}

impl BridgeThreads {
    fn remember_selection(&mut self, thread: AgentThreadId, revision: AgentBindingRevision) {
        self.selected.push_back((thread, revision));
        while self.selected.len() > MAX_REMEMBERED_THREADS {
            self.selected.pop_front();
        }
    }

    fn remember_request(&mut self, request_id: String, revision: AgentBindingRevision) {
        self.attested.push_back((request_id, revision));
        while self.attested.len() > MAX_ATTESTED_REQUESTS {
            self.attested.pop_front();
        }
    }

    fn selected_at(&self, thread: &AgentThreadId) -> Option<AgentBindingRevision> {
        self.selected
            .iter()
            .rev()
            .find(|(selected, _)| selected == thread)
            .map(|(_, revision)| *revision)
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
    /// A short detail: how a thread started, why it ended, which tool, which notification.
    #[serde(default)]
    pub detail: Option<String>,
    /// A notification's text.
    #[serde(default)]
    pub text: Option<String>,
    /// The request identifier of a contact question the finished tool call asked.
    ///
    /// It is what places a question in the thread its request was made in: the application's own
    /// hook reports which thread ran the call, which is the per-request source context section 11
    /// asks of a bridge before a question records a thread binding.
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
    /// The observation came from a bridge process older than the one whose report is in force.
    Stale,
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
    /// The revision the contact request it placed in its thread was recorded under, when it placed
    /// one.
    pub attested: Option<AgentBindingRevision>,
    /// Where it sits in the instance's observed history.
    pub cursor: StreamCursor,
}

impl crate::broker::Broker {
    /// Applies what one of an instance's native bridge hooks observed.
    ///
    /// This is the production caller of the binding's advance. A hook that reports a thread the
    /// binding does not have selects it; a hook that reports the selected thread ending leaves the
    /// instance with none; both advance the binding revision, which is what invalidates the
    /// questions asked under the binding that was left. A report older than the one in force, by
    /// its process's start, is recorded and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn observe_bridge(
        &self,
        application_instance_id: ApplicationInstanceId,
        reporter: &ProcessStartIdentity,
        observation: &Observation,
        now: TimestampMs,
    ) -> Result<(ThreadChange, Option<AgentBindingRevision>, StreamCursor)> {
        let mut state = self.state();
        let reported = reporter.start_value.get();
        let (current, decided_by) = {
            let instance = state
                .instances
                .get(&application_instance_id)
                .ok_or_else(|| crate::broker::unknown_instance(application_instance_id))?;
            (instance.thread_id.clone(), instance.bridge.decided_by)
        };
        let newer = decided_by.is_none_or(|decided| reported > decided);
        let is_current = current.as_ref() == Some(&observation.thread);
        let thread = match observation.event {
            ObservedEvent::ThreadStarted if is_current => {
                if newer {
                    instance_of(&mut state, application_instance_id)?
                        .bridge
                        .decided_by = Some(reported);
                }
                ThreadChange::Unchanged
            }
            ObservedEvent::ThreadStarted if !newer => ThreadChange::Stale,
            ObservedEvent::ThreadStarted => select(
                &mut state,
                application_instance_id,
                &observation.thread,
                reported,
                now,
            )?,
            ObservedEvent::ThreadEnded if is_current && newer => {
                match state.advance_binding(application_instance_id, None, now) {
                    Ok(revision) => {
                        instance_of(&mut state, application_instance_id)?
                            .bridge
                            .decided_by = Some(reported);
                        ThreadChange::Ended(revision)
                    }
                    Err(error) => ThreadChange::Refused(error.to_string()),
                }
            }
            ObservedEvent::ThreadEnded if is_current => ThreadChange::Stale,
            _ => ThreadChange::Unchanged,
        };
        let attested = match (observation.event, &observation.contact_request) {
            (ObservedEvent::ToolFinished, Some(request)) => Some(attest(
                &mut state,
                application_instance_id,
                request,
                &observation.thread,
                reported,
                now,
            )?),
            _ => None,
        };
        let instance = instance_of(&mut state, application_instance_id)?;
        let cursor = instance
            .semantic
            .append(observation.event.kind(), observation.summary(), now);
        Ok((thread, attested, cursor))
    }

    /// Returns the revision a bridge recorded one contact request under, where it recorded one.
    #[must_use]
    pub fn attested_request(
        &self,
        application_instance_id: ApplicationInstanceId,
        request_id: &str,
    ) -> Option<AgentBindingRevision> {
        let state = self.state();
        state
            .instances
            .get(&application_instance_id)?
            .bridge
            .attested
            .iter()
            .rev()
            .find(|(request, _)| request == request_id)
            .map(|(_, revision)| *revision)
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

/// Selects one thread for an instance, as its bridge reported it, under the lock the caller holds.
fn select(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    thread: &AgentThreadId,
    reported: u64,
    now: TimestampMs,
) -> Result<ThreadChange> {
    match state.advance_binding(application_instance_id, Some(thread.clone()), now) {
        Ok(revision) => {
            let instance = instance_of(state, application_instance_id)?;
            instance.bridge.decided_by = Some(reported);
            instance.bridge.remember_selection(thread.clone(), revision);
            Ok(ThreadChange::Selected(revision))
        }
        Err(error @ BrokerError::UnknownSubject { .. }) => Err(error),
        Err(error) => {
            // The application is in a thread this instance cannot own, so its binding cannot be
            // verified. Section 12: suspend rich mutations until it is; the terminal stays.
            let reason = format!("the application selected a thread this host refused: {error}");
            instance_of(state, application_instance_id)?.rich_suspension = Some(reason.clone());
            Ok(ThreadChange::Refused(reason))
        }
    }
}

/// Records the thread one contact request was made in, and returns the revision it was made under.
///
/// A request made in the selected thread was made under the binding in force. One made in a thread
/// that is no longer selected was made under a binding that has already been left, so it is
/// recorded under a revision that is not current, and the question ledger invalidates it. When no
/// thread is selected and the reported one was never left, the report is the first word of the
/// thread in use, and it selects it.
fn attest(
    state: &mut crate::broker::BrokerState,
    application_instance_id: ApplicationInstanceId,
    request_id: &str,
    thread: &AgentThreadId,
    reported: u64,
    now: TimestampMs,
) -> Result<AgentBindingRevision> {
    let (current, revision, known) = {
        let instance = instance_of(state, application_instance_id)?;
        (
            instance.thread_id.clone(),
            instance.binding_revision,
            instance.bridge.selected_at(thread),
        )
    };
    let behind = AgentBindingRevision::new(revision.get().saturating_sub(1));
    let made_under = if current.as_ref() == Some(thread) {
        revision
    } else if current.is_none() && known.is_none() {
        match select(state, application_instance_id, thread, reported, now)? {
            ThreadChange::Selected(selected) => selected,
            _ => behind,
        }
    } else {
        known.unwrap_or(behind)
    };
    instance_of(state, application_instance_id)?
        .bridge
        .remember_request(request_id.to_owned(), made_under);
    Ok(made_under)
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

    fn asked(thread: &str, request: &str) -> Observation {
        Observation {
            contact_request: Some(request.to_owned()),
            ..observed(ObservedEvent::ToolFinished, thread)
        }
    }

    /// A bridge process that started at `start`, as the kernel would report it.
    fn reporter(start: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            4_000 + start,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            start,
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

    fn revision(broker: &crate::broker::Broker, id: ApplicationInstanceId) -> AgentBindingRevision {
        broker.binding_state(id).expect("known").binding_revision
    }

    /// KR-REQ-11.62: a hook that reports a thread selects it and advances the binding, a hook that
    /// reports it ending leaves no thread selected, and a report from a bridge process older than
    /// the one in force cannot undo it, whatever order the reports arrive in.
    #[test]
    fn kr_req_11_62_the_newest_bridge_report_decides_the_thread() {
        let id = instance(2);
        let broker = broker_with(&[id]);
        let now = TimestampMs::new(1);
        let first = revision(&broker, id);

        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(10),
                &observed(ObservedEvent::ThreadStarted, "t1"),
                now,
            )
            .expect("applied");
        let selected = AgentBindingRevision::new(first.get() + 1);
        assert_eq!(change, ThreadChange::Selected(selected));
        assert_eq!(
            broker
                .binding_state(id)
                .expect("known")
                .thread_id
                .as_ref()
                .map(AgentThreadId::as_str),
            Some("t1")
        );

        // The same thread again, from a later process: nothing to change.
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(11),
                &observed(ObservedEvent::ThreadStarted, "t1"),
                now,
            )
            .expect("applied");
        assert_eq!(change, ThreadChange::Unchanged);

        // A later process selects another thread.
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(30),
                &observed(ObservedEvent::ThreadStarted, "t2"),
                now,
            )
            .expect("applied");
        assert_eq!(
            change,
            ThreadChange::Selected(AgentBindingRevision::new(selected.get() + 1))
        );
        // An older process's report of the first thread arrives late, and changes nothing.
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(20),
                &observed(ObservedEvent::ThreadStarted, "t1"),
                now,
            )
            .expect("applied");
        assert_eq!(change, ThreadChange::Stale);
        // Nor does an older report of the current thread ending.
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(25),
                &observed(ObservedEvent::ThreadEnded, "t2"),
                now,
            )
            .expect("applied");
        assert_eq!(change, ThreadChange::Stale);
        // A thread that is not the selected one ending says nothing about the binding.
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(40),
                &observed(ObservedEvent::ThreadEnded, "t1"),
                now,
            )
            .expect("applied");
        assert_eq!(change, ThreadChange::Unchanged);
        // The selected thread ending, reported by a newer process, leaves none selected.
        let before = revision(&broker, id);
        let (change, _, _) = broker
            .observe_bridge(
                id,
                &reporter(50),
                &observed(ObservedEvent::ThreadEnded, "t2"),
                now,
            )
            .expect("applied");
        assert_eq!(
            change,
            ThreadChange::Ended(AgentBindingRevision::new(before.get() + 1))
        );
        assert!(
            broker
                .binding_state(id)
                .expect("known")
                .thread_id
                .as_ref()
                .is_none()
        );
        // And a tool or a notification never moves the binding.
        let at = revision(&broker, id);
        for event in [
            ObservedEvent::ToolFinished,
            ObservedEvent::ToolFailed,
            ObservedEvent::Notification,
        ] {
            let (change, _, _) = broker
                .observe_bridge(id, &reporter(60), &observed(event, "t3"), now)
                .expect("applied");
            assert_eq!(change, ThreadChange::Unchanged);
        }
        assert_eq!(revision(&broker, id), at);
    }

    /// KR-REQ-11.62: a contact request is recorded under the binding of the thread its call ran
    /// in: the current revision when that thread is the selected one, the revision the thread had
    /// when it has been left, and one behind the current revision when a thread this host never
    /// saw selected is not the one in force. With nothing selected and a thread never left, the
    /// report selects the thread in use.
    #[test]
    fn kr_req_11_62_a_contact_request_is_recorded_under_its_threads_binding() {
        let id = instance(3);
        let broker = broker_with(&[id]);
        let now = TimestampMs::new(1);

        // Nothing selected yet: the first word of a thread selects it.
        let (change, attested, _) = broker
            .observe_bridge(id, &reporter(10), &asked("t1", "r-1"), now)
            .expect("applied");
        assert_eq!(change, ThreadChange::Unchanged);
        let t1 = revision(&broker, id);
        assert_eq!(attested, Some(t1));
        assert_eq!(broker.attested_request(id, "r-1"), Some(t1));

        // In the selected thread: the current revision.
        let (_, attested, _) = broker
            .observe_bridge(id, &reporter(11), &asked("t1", "r-2"), now)
            .expect("applied");
        assert_eq!(attested, Some(t1));

        // Another thread is selected; a late report from the first thread records the revision it
        // had, which is no longer current.
        broker
            .observe_bridge(
                id,
                &reporter(20),
                &observed(ObservedEvent::ThreadStarted, "t2"),
                now,
            )
            .expect("applied");
        let t2 = revision(&broker, id);
        assert_ne!(t1, t2);
        let (_, attested, _) = broker
            .observe_bridge(id, &reporter(21), &asked("t1", "r-3"), now)
            .expect("applied");
        assert_eq!(attested, Some(t1));
        // A thread this host never saw selected, while another is: behind the current revision.
        let (_, attested, _) = broker
            .observe_bridge(id, &reporter(22), &asked("t9", "r-4"), now)
            .expect("applied");
        assert_eq!(attested, Some(AgentBindingRevision::new(t2.get() - 1)));
        assert_eq!(
            revision(&broker, id),
            t2,
            "a request report selects nothing here"
        );
        assert_eq!(broker.attested_request(id, "r-5"), None);
    }

    /// KR-REQ-11.62: a thread another live execution already owns is not selected; the binding
    /// stays where it was and rich mutations are suspended until it is verified.
    #[test]
    fn kr_req_11_62_a_thread_another_execution_owns_suspends_rich_mutations() {
        let (first, second) = (instance(4), instance(5));
        let broker = broker_with(&[first, second]);
        let now = TimestampMs::new(1);
        broker
            .observe_bridge(
                first,
                &reporter(10),
                &observed(ObservedEvent::ThreadStarted, "shared"),
                now,
            )
            .expect("applied");
        let before = revision(&broker, second);
        let (change, _, _) = broker
            .observe_bridge(
                second,
                &reporter(11),
                &observed(ObservedEvent::ThreadStarted, "shared"),
                now,
            )
            .expect("applied");
        assert!(matches!(change, ThreadChange::Refused(_)), "{change:?}");
        let state = broker.binding_state(second).expect("known");
        assert_eq!(state.binding_revision, before);
        assert!(state.rich_mutations_suspended);
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
