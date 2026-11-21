//! The reference bridge: the client half of the endpoint, driven step by step.
//!
//! A managed package's reader is native code inside a patched shell. The bytes it puts on the
//! endpoint are not: they are this contract's frames, and what a package has to get right is the
//! order it sends them in and the answers it gives. This module is that half written once, in
//! Rust, so the worker can be exercised over a real socket, with a real handshake and real peer
//! credentials, before any shell package exists, and so a package's own tests have something exact
//! to compare against.
//!
//! It is a reference rather than a simulation: it computes the same proof, refuses the same
//! directions and carries the same identifiers. What it does not do is decide anything. Every
//! event it sends and every answer it gives is supplied by its caller, because a bridge that
//! decided for itself would be testing its own opinion instead of the worker's rules.

use kr_crypto::secret::SymmetricKey;
use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::Endpoint;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, FenceAcknowledgement,
    FencePublication, KeyQueueSnapshot, PendingReaderInput, PromptGeneration, QueueDrainReport,
    ReaderContext, ReaderRevision, RootCommandBlockParams, RootEditorEnterParams,
    RootEditorFenceResult,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::contract::events::BridgeEvent;
use crate::contract::qualification::{BridgeAbi, ShellKind};
use crate::contract::requests::{
    BridgeAnswer, LaunchAccepted, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason,
    LaunchTransactionId, WorkerRequest,
};
use crate::contract::transport::{
    BRIDGE_PROTOCOL, BRIDGE_STREAM_KIND, BridgeEndpoint, BridgeFrame, BridgeHello, EventOutcome,
    HandshakeOutcome, ModuleEntry, PatchRevision, ShellIdentity,
};
use crate::host::error::{HostError, Result};
use crate::host::handshake::proof_bytes;

/// The integration version this build of the reference bridge declares.
pub const REFERENCE_INTEGRATION_VERSION: &str = "1";

/// What the worker sent the bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToBridge {
    /// The answer to one event.
    EventResult {
        /// The event being answered.
        id: RequestId,
        /// The answer.
        result: Box<EventOutcome>,
    },
    /// Something the reader thread must decide.
    Request {
        /// The worker's identifier for this request.
        id: RequestId,
        /// What to decide.
        request: Box<WorkerRequest>,
    },
    /// Whether a fence was published.
    FencePublished(FencePublication),
    /// A launch transaction is over.
    LaunchRevoked {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// Why it ended.
        reason: LaunchRejectionReason,
    },
}

/// Returns the endpoint a client opens for a published bridge address.
///
/// kr-ipc takes the namespaced name on Windows and supplies the pipe prefix itself, while the
/// bootstrap transcript is taken over the full address the shell was given. Stripping it here
/// keeps both true. On Unix the address is already the socket's path and nothing is stripped.
///
/// # Errors
///
/// Returns [`HostError::Ipc`] when the name does not fit an endpoint address.
fn client_endpoint(address: &BridgeEndpoint) -> Result<Endpoint> {
    Ok(Endpoint::from_path(
        address
            .path
            .strip_prefix(crate::contract::transport::WINDOWS_PIPE_PREFIX)
            .unwrap_or(&address.path),
    )?)
}

/// The client half of one bridge connection.
#[derive(Debug)]
pub struct ScriptedBridge {
    reader: FrameReader,
    writer: FrameWriter,
    next_event: u64,
    live: bool,
}

impl ScriptedBridge {
    /// Connects to the worker's endpoint and presents a hello.
    ///
    /// Returns the connection and the worker's answer, accepted or refused. A refusal is a result
    /// rather than an error: what a scenario checks is which named reason came back.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the endpoint cannot be reached or the answer cannot be read,
    /// and [`HostError::WrongDirection`] when the first frame back is not the handshake.
    pub async fn connect(
        address: &BridgeEndpoint,
        hello: &BridgeHello,
    ) -> Result<(Self, HandshakeOutcome)> {
        let endpoint = client_endpoint(address)?;
        let connection = Connection::connect(&endpoint).await?;
        let (reader, writer) = split(connection, BRIDGE_STREAM_KIND);
        let mut bridge = Self {
            reader,
            writer,
            next_event: 0,
            live: true,
        };
        bridge
            .writer
            .write_message(&BridgeFrame::Hello(hello.clone()))
            .await?;
        let frame: BridgeFrame = bridge.reader.read_message_without_schema().await?;
        let BridgeFrame::Handshake(outcome) = frame else {
            bridge.live = false;
            return Err(HostError::WrongDirection {
                frame: "something other than the handshake",
            });
        };
        Ok((bridge, outcome))
    }

    /// Presents a hello and closes the connection without waiting for the answer: a shell that has
    /// gone by the time the worker replies.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the endpoint cannot be reached or the hello cannot be
    /// written.
    pub async fn hello_and_hang_up(address: &BridgeEndpoint, hello: &BridgeHello) -> Result<()> {
        let endpoint = client_endpoint(address)?;
        let connection = Connection::connect(&endpoint).await?;
        let (reader, mut writer) = split(connection, BRIDGE_STREAM_KIND);
        writer
            .write_message(&BridgeFrame::Hello(hello.clone()))
            .await?;
        drop(reader);
        drop(writer);
        Ok(())
    }

    /// Reports something the reader did, and returns the identifier the answer will carry.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn send_event(&mut self, event: BridgeEvent) -> Result<RequestId> {
        self.check()?;
        self.next_event += 1;
        let id = RequestId::new(self.next_event);
        self.send(&BridgeFrame::Event { id, event }).await?;
        Ok(id)
    }

    /// Answers one worker request from the reader thread.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Ipc`] when the frame cannot be written.
    pub async fn answer(&mut self, id: RequestId, answer: BridgeAnswer) -> Result<()> {
        self.send(&BridgeFrame::Answer { id, answer }).await
    }

    /// Returns true while this connection is still usable.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.live
    }

    const fn check(&self) -> Result<()> {
        if self.live {
            return Ok(());
        }
        Err(HostError::ConnectionFinished)
    }

    async fn send(&mut self, frame: &BridgeFrame) -> Result<()> {
        self.check()?;
        match self.writer.write_message(frame).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.live = false;
                Err(error.into())
            }
        }
    }

    /// Reads the next frame the worker may send.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::WrongDirection`] for a frame only a bridge sends, and
    /// [`HostError::Ipc`] when the connection ends.
    pub async fn recv(&mut self) -> Result<ToBridge> {
        self.check()?;
        let frame: BridgeFrame = match self.reader.read_message_without_schema().await {
            Ok(frame) => frame,
            Err(error) => {
                self.live = false;
                return Err(error.into());
            }
        };
        let wrong = |frame: &'static str| HostError::WrongDirection { frame };
        match frame {
            BridgeFrame::EventResult { id, result } => Ok(ToBridge::EventResult {
                id,
                result: Box::new(result),
            }),
            BridgeFrame::Request { id, request } => Ok(ToBridge::Request {
                id,
                request: Box::new(request),
            }),
            BridgeFrame::FencePublished(publication) => Ok(ToBridge::FencePublished(publication)),
            BridgeFrame::LaunchRevoked {
                transaction,
                reason,
            } => Ok(ToBridge::LaunchRevoked {
                transaction,
                reason,
            }),
            BridgeFrame::Hello(_) => {
                self.live = false;
                Err(wrong("hello"))
            }
            BridgeFrame::Handshake(_) => {
                self.live = false;
                Err(wrong("a second handshake"))
            }
            BridgeFrame::Event { .. } => {
                self.live = false;
                Err(wrong("event"))
            }
            BridgeFrame::Answer { .. } => {
                self.live = false;
                Err(wrong("answer"))
            }
        }
    }
}

/// The numbers a scripted reader reports. The caller supplies every one, so a scenario can move
/// them (a prompt that advances, a buffer that changes) and the reader decides none of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderNumbers {
    /// The prompt generation the reader reports in every event and answer.
    pub prompt_generation: u64,
    /// The reader's own revision.
    pub reader_revision: u64,
    /// The buffer revision the reader enters the prompt with.
    pub entered_buffer_revision: u64,
    /// The buffer revision the reader proves a fence at; an accepted launch moves it by one.
    pub buffer_revision: u64,
    /// The working-directory revision.
    pub cwd_revision: u64,
}

/// A scripted bridge that speaks as a root shell's reader at a primary prompt with an empty buffer.
///
/// Each step sends what the contract has the reader send and reads what the worker sends back; no
/// step waits for a time, so a caller bounds a step with its own timeout.
#[derive(Debug)]
pub struct ScriptedReader {
    /// The connection the steps use, for a frame a scenario sends itself.
    pub bridge: ScriptedBridge,
    /// The session the reader is the root shell of.
    pub session_id: SessionId,
    /// The root shell's process, which the worker expects on its endpoint.
    pub root_process: ProcessStartIdentity,
    /// What the reader reports; a scenario may change it between steps.
    pub numbers: ReaderNumbers,
}

impl ScriptedReader {
    /// A reader that reports `numbers` over `bridge`.
    #[must_use]
    pub const fn new(
        bridge: ScriptedBridge,
        session_id: SessionId,
        root_process: ProcessStartIdentity,
        numbers: ReaderNumbers,
    ) -> Self {
        Self {
            bridge,
            session_id,
            root_process,
            numbers,
        }
    }

    /// The editor the reader reports: an empty buffer, the emacs keymap, nothing pending.
    #[must_use]
    pub const fn editor_state(buffer_revision: u64) -> EditorState {
        EditorState {
            buffer_empty: true,
            buffer_revision: EditorBufferRevision::new(buffer_revision),
            keymap: EditorKeymap::Emacs,
            pending: PendingReaderInput::NONE,
        }
    }

    /// Reads the next frame the worker sends the reader.
    ///
    /// # Errors
    ///
    /// As [`ScriptedBridge::recv`].
    pub async fn next(&mut self) -> Result<ToBridge> {
        self.bridge.recv().await
    }

    /// The reader enters the primary prompt with an empty buffer, and the worker has handled it
    /// when this returns.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when a frame cannot be sent or read.
    pub async fn enters_the_prompt(&mut self) -> Result<()> {
        self.enters().await?;
        self.settled().await
    }

    /// The reader enters the primary prompt with an empty buffer and goes no further: a request
    /// the worker makes of it in answer, such as a fence, is still to be read.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when the event cannot be sent.
    pub async fn enters(&mut self) -> Result<()> {
        let numbers = self.numbers;
        self.bridge
            .send_event(BridgeEvent::EditorEnter(RootEditorEnterParams {
                session_id: self.session_id,
                root_process: self.root_process.clone(),
                prompt_generation: PromptGeneration::new(numbers.prompt_generation),
                reader_revision: ReaderRevision::new(numbers.reader_revision),
                reader_context: ReaderContext::Primary,
                editor: Self::editor_state(numbers.entered_buffer_revision),
                cwd_revision: CwdRevision::new(numbers.cwd_revision),
            }))
            .await?;
        Ok(())
    }

    /// Returns once the worker has handled every event sent before this call.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when a frame cannot be sent or read.
    pub async fn settled(&mut self) -> Result<()> {
        self.settled_seeing().await.map(|_| ())
    }

    /// As [`Self::settled`], and returns every other frame the worker sent before it had handled
    /// the events: a request the worker made of the reader in the meantime is among them.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when a frame cannot be sent or read.
    pub async fn settled_seeing(&mut self) -> Result<Vec<ToBridge>> {
        self.bridge
            .send_event(BridgeEvent::CommandBlock(Box::new(
                RootCommandBlockParams {
                    session_id: self.session_id,
                    prompt_generation: PromptGeneration::new(self.numbers.prompt_generation),
                    command: "true".to_owned(),
                    started_at_ms: TimestampMs::new(1_700_000_000_000),
                    duration_ms: Nullable::null(),
                    exit_status: Nullable::null(),
                    cwd: "/tmp".to_owned(),
                    cwd_revision: CwdRevision::new(self.numbers.cwd_revision),
                },
            )))
            .await?;
        let mut seen = Vec::new();
        loop {
            let frame = self.next().await?;
            if let ToBridge::EventResult { result, .. } = &frame
                && matches!(**result, EventOutcome::CommandBlockRecorded(_))
            {
                return Ok(seen);
            }
            seen.push(frame);
        }
    }

    /// The reader answers the worker's request for a fence, and returns what the worker published.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when a frame cannot be sent or read.
    pub async fn proves_a_fence(&mut self) -> Result<FencePublication> {
        let fence_id = loop {
            if let ToBridge::Request { request, .. } = self.next().await?
                && let WorkerRequest::Fence(params) = *request
            {
                break params.fence_id;
            }
        };
        let numbers = self.numbers;
        self.bridge
            .answer(
                RequestId::new(0),
                BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
                    fence_id,
                    prompt_generation: PromptGeneration::new(numbers.prompt_generation),
                    reader_revision: ReaderRevision::new(numbers.reader_revision),
                    reader_context: ReaderContext::Primary,
                    queues: QueueDrainReport::CLEAR,
                    snapshot: KeyQueueSnapshot::drained(),
                    editor: Self::editor_state(numbers.buffer_revision),
                    cwd_revision: CwdRevision::new(numbers.cwd_revision),
                })),
            )
            .await?;
        loop {
            if let ToBridge::FencePublished(published) = self.next().await? {
                return Ok(published);
            }
        }
    }

    /// The next install the worker asks the reader for.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when a frame cannot be read.
    pub async fn install_asked(&mut self) -> Result<LaunchMailboxRequest> {
        loop {
            if let ToBridge::Request { request, .. } = self.next().await?
                && let WorkerRequest::Launch(request) = *request
            {
                return Ok(request);
            }
        }
    }

    /// The reader installs what it was asked to, at the prompt it stands at.
    ///
    /// # Errors
    ///
    /// Returns the bridge's error when the answer cannot be sent.
    pub async fn installs(&mut self, asked: &LaunchMailboxRequest) -> Result<()> {
        let numbers = self.numbers;
        self.bridge
            .answer(
                RequestId::new(0),
                BridgeAnswer::Launch(LaunchDecision::Accepted(LaunchAccepted {
                    transaction: asked.transaction,
                    installed: asked.command.clone(),
                    fence_id: asked.fence_id,
                    prompt_generation: PromptGeneration::new(numbers.prompt_generation),
                    buffer_revision: EditorBufferRevision::new(numbers.buffer_revision + 1),
                    reader_revision: ReaderRevision::new(numbers.reader_revision),
                })),
            )
            .await
    }
}

/// What a reference package says it is.
///
/// The three strings are what a real package reads out of its own build: the binary it was started
/// as, the upstream release it was built from and the editor ABI its reader patch was compiled
/// against. They are carried rather than invented, because a handshake that could not name them
/// would be a qualification claim with nothing behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceShell {
    /// Which managed shell this is.
    pub kind: ShellKind,
    /// The executable the worker started.
    pub executable: String,
    /// The upstream shell version.
    pub upstream_version: String,
    /// The editor ABI revision the reader patch was built against.
    pub editor_abi: String,
}

impl ReferenceShell {
    /// Names one reference package.
    #[must_use]
    pub fn new(
        kind: ShellKind,
        executable: impl Into<String>,
        upstream_version: impl Into<String>,
        editor_abi: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            executable: executable.into(),
            upstream_version: upstream_version.into(),
            editor_abi: editor_abi.into(),
        }
    }

    /// Returns the identity a hello carries.
    #[must_use]
    pub fn identity(&self) -> ShellIdentity {
        ShellIdentity {
            kind: self.kind,
            executable: self.executable.clone(),
            upstream_version: self.upstream_version.clone(),
            editor_abi: self.editor_abi.clone(),
            integration_version: REFERENCE_INTEGRATION_VERSION.to_owned(),
            patches: vec![PatchRevision {
                name: format!("{}-reader-mailbox", self.kind),
                upstream_revision: self.upstream_version.clone(),
                revision: REFERENCE_INTEGRATION_VERSION.to_owned(),
            }],
            modules: vec![ModuleEntry {
                name: format!("{}/kr-bridge", self.kind),
                search_path: format!("{}.modules", self.executable),
                editor_abi: self.editor_abi.clone(),
            }],
        }
    }
}

/// Builds the hello a qualified package of this shell sends.
///
/// The proof is computed exactly as the worker recomputes it, over the session, the endpoint, the
/// connecting process and the integration version. A caller that wants to be refused changes one
/// of those and gets the named refusal rather than a different failure.
///
/// # Errors
///
/// Returns [`HostError::Frame`] when the transcript cannot be encoded canonically.
pub fn qualified_hello(
    shell: &ReferenceShell,
    session_id: SessionId,
    address: &BridgeEndpoint,
    shell_process: ProcessStartIdentity,
    secret: &SymmetricKey,
) -> Result<BridgeHello> {
    let proof = proof_bytes(
        secret,
        session_id,
        address,
        &shell_process,
        REFERENCE_INTEGRATION_VERSION,
    )?;
    Ok(BridgeHello {
        protocol: BRIDGE_PROTOCOL.to_owned(),
        session_id,
        shell_process,
        shell: shell.identity(),
        abi: BridgeAbi::qualified(shell.kind),
        proof,
    })
}

#[cfg(test)]
mod tests {
    use kr_protocol::root::{PromptGeneration, RootEditorEnterResult};
    use kr_protocol::scalars::{Nullable, Uuid};

    use super::*;
    use crate::contract::events::{EofGesture, HooksActivated};
    use crate::contract::qualification::QualificationReason;
    use crate::contract::transport::{
        BridgeFrame, BridgeRefused, HandshakeOutcome, SecretLocation, WorkerExpectation,
    };
    use crate::host::endpoint::HostEndpoint;
    use crate::host::handshake::admit;
    use crate::host::link::{BridgeReader, BridgeWriter, FromBridge, accept as accept_bridge};

    fn zsh() -> ReferenceShell {
        ReferenceShell::new(
            ShellKind::Zsh,
            "/opt/kalareach/shells/zsh-5.9/bin/zsh",
            "5.9",
            "zle-5.9",
        )
    }

    fn owner_only_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("a temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            use kr_ipc::paths::OWNER_ONLY_DIRECTORY_MODE;

            std::fs::set_permissions(
                directory.path(),
                std::fs::Permissions::from_mode(OWNER_ONLY_DIRECTORY_MODE),
            )
            .expect("owner-only");
        }
        directory
    }

    fn expectation(session_id: SessionId, root: ProcessStartIdentity) -> WorkerExpectation {
        WorkerExpectation {
            session_id,
            root_process: root,
            supported_editor_abis: vec!["zle-5.9".to_owned()],
            supported_integration_versions: vec![REFERENCE_INTEGRATION_VERSION.to_owned()],
            launched_package: None,
            already_registered: false,
            gesture: EofGesture::default(),
        }
    }

    /// How long a test waits for the client it started to reach the listener.
    ///
    /// Generous, because these tests share a machine with compilation, and bounded, because the
    /// failure worth reporting is the client's: an unbounded `accept()` turns a client that could
    /// not open the endpoint into a run that never ends and says nothing about why.
    const CONNECTS_WITHIN: std::time::Duration = std::time::Duration::from_secs(20);

    /// Takes the one connection a test's own client makes, or says the client never arrived.
    async fn accept_one(endpoint: &HostEndpoint) -> (Connection, kr_ipc::peer::PeerIdentity) {
        tokio::time::timeout(CONNECTS_WITHIN, endpoint.listener().accept())
            .await
            .expect("the client this test started reaches the listener")
            .expect("accepts")
    }

    /// Accepts one bridge on the real endpoint and answers its hello.
    async fn accept(
        endpoint: &HostEndpoint,
        expectation: &WorkerExpectation,
    ) -> (BridgeReader, BridgeWriter, HandshakeOutcome) {
        let (connection, peer) = accept_one(endpoint).await;
        let (mut reader, mut writer) = accept_bridge(connection);
        let FromBridge::Hello(hello) = reader.recv().await.expect("a hello") else {
            panic!("the opening frame is a hello");
        };
        let outcome = admit(
            endpoint.secret(),
            expectation,
            endpoint.address(),
            &peer,
            &hello,
        )
        .expect("decides");
        writer.send_handshake(&outcome).await.expect("answers");
        (reader, writer, outcome)
    }

    #[tokio::test]
    async fn a_qualified_bridge_registers_over_the_real_endpoint() {
        let directory = owner_only_directory();
        let session_id = SessionId::new(Uuid::from_bytes([0x61; 16]));
        let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
        // The bridge runs in this process, so this process is the root shell the worker expects.
        let root = kr_ipc::identity::current_process_start_identity().expect("this process");
        let expectation = expectation(session_id, root.clone());
        let hello = qualified_hello(
            &zsh(),
            session_id,
            endpoint.address(),
            root,
            endpoint.secret(),
        )
        .expect("a hello");
        let address = endpoint.address().clone();
        let connecting =
            tokio::spawn(async move { ScriptedBridge::connect(&address, &hello).await });
        let (mut reader, mut writer, outcome) = accept(&endpoint, &expectation).await;
        let (mut bridge, answer) = connecting.await.expect("joins").expect("connects");
        assert_eq!(outcome.refusal(), None);
        let HandshakeOutcome::Accepted(accepted) = answer else {
            panic!("a qualified bridge registers");
        };
        assert_eq!(accepted.session_id, session_id);
        assert_eq!(accepted.hold_ms.get(), 250);
        assert_eq!(
            accepted.secret_location,
            SecretLocation::PrivateIntegrationState
        );
        assert_eq!(accepted.hint, kr_protocol::root::DETACH_HINT);

        // One event, one answer, both over the socket the shell was given.
        let id = bridge
            .send_event(BridgeEvent::HooksActivated(HooksActivated {
                session_id,
                prompt_generation: PromptGeneration::new(1),
                modules: Vec::new(),
            }))
            .await
            .expect("reports");
        let FromBridge::Event { id: seen, .. } = reader.recv().await.expect("an event") else {
            panic!("an event");
        };
        assert_eq!(seen, id);
        writer
            .send_event_result(seen, EventOutcome::Received)
            .await
            .expect("answers");
        let ToBridge::EventResult {
            id: answered,
            result,
        } = bridge.recv().await.expect("an answer")
        else {
            panic!("the answer to the event");
        };
        assert_eq!(answered, id);
        assert_eq!(*result, EventOutcome::Received);
    }

    #[tokio::test]
    async fn a_bridge_whose_secret_is_wrong_is_refused_by_name() {
        let directory = owner_only_directory();
        let session_id = SessionId::new(Uuid::from_bytes([0x62; 16]));
        let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
        let root = kr_ipc::identity::current_process_start_identity().expect("this process");
        let expectation = expectation(session_id, root.clone());
        let guessed = kr_crypto::secret::Secret::random().expect("a secret");
        let hello = qualified_hello(
            &ReferenceShell::new(
                ShellKind::Bash,
                "/opt/kalareach/shells/bash-5.2/bin/bash",
                "5.2",
                "readline-8.2",
            ),
            session_id,
            endpoint.address(),
            root,
            &guessed,
        )
        .expect("a hello");
        let address = endpoint.address().clone();
        let connecting =
            tokio::spawn(async move { ScriptedBridge::connect(&address, &hello).await });
        let (_reader, _writer, outcome) = accept(&endpoint, &expectation).await;
        let (_bridge, answer) = connecting.await.expect("joins").expect("connects");
        assert_eq!(outcome.refusal(), Some(QualificationReason::ProofMismatch));
        assert_eq!(answer.refusal(), Some(QualificationReason::ProofMismatch));
    }

    #[tokio::test]
    async fn a_frame_the_bridge_does_not_send_ends_the_connection() {
        let directory = owner_only_directory();
        let session_id = SessionId::new(Uuid::from_bytes([0x63; 16]));
        let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
        // The address the client opens, not the address the shell is given: on Windows the
        // published form carries the pipe prefix and kr-ipc adds it again.
        let address = client_endpoint(endpoint.address()).expect("an endpoint");
        let connecting = tokio::spawn(async move {
            let connection = Connection::connect(&address).await.expect("connects");
            let (_reader, mut writer) = split(connection, BRIDGE_STREAM_KIND);
            // A worker's own frame, sent by a bridge. The direction is part of the contract.
            writer
                .write_message(&BridgeFrame::EventResult {
                    id: RequestId::new(1),
                    result: EventOutcome::EditorEntered(RootEditorEnterResult {
                        state: kr_protocol::root::FenceState::Unfenced,
                        fence_exchange: Nullable::null(),
                    }),
                })
                .await
                .expect("writes");
            // Held open until the worker has read it, so the failure is the direction rather than
            // a closed socket.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (connection, _peer) = accept_one(&endpoint).await;
        let (mut reader, mut writer) = accept_bridge(connection);
        let error = reader.recv().await.expect_err("refused");
        assert!(
            matches!(
                error,
                HostError::WrongDirection {
                    frame: "event_result"
                }
            ),
            "{error}"
        );
        // Both halves are finished: a peer that misunderstood the direction is not one to carry on
        // a conversation with, in either direction.
        assert!(!writer.is_live());
        assert!(matches!(
            reader.recv().await.expect_err("finished"),
            HostError::ConnectionFinished
        ));
        assert!(matches!(
            writer
                .send_handshake(&HandshakeOutcome::Refused(BridgeRefused::new(
                    QualificationReason::ProtocolMismatch,
                    "finished",
                )))
                .await
                .expect_err("finished"),
            HostError::ConnectionFinished
        ));
        connecting.await.expect("joins");
    }

    #[tokio::test]
    async fn a_fence_publication_and_a_revocation_reach_the_bridge() {
        let directory = owner_only_directory();
        let session_id = SessionId::new(Uuid::from_bytes([0x64; 16]));
        let endpoint = HostEndpoint::open(session_id, directory.path()).expect("binds");
        let root = kr_ipc::identity::current_process_start_identity().expect("this process");
        let expectation = expectation(session_id, root.clone());
        let hello = qualified_hello(
            &zsh(),
            session_id,
            endpoint.address(),
            root,
            endpoint.secret(),
        )
        .expect("a hello");
        let address = endpoint.address().clone();
        let connecting =
            tokio::spawn(async move { ScriptedBridge::connect(&address, &hello).await });
        let (_reader, mut writer, _) = accept(&endpoint, &expectation).await;
        let (mut bridge, _) = connecting.await.expect("joins").expect("connects");
        let withheld = FencePublication::Withheld {
            reason: kr_protocol::root::WithheldReason::ExchangeTimedOut,
            state: kr_protocol::root::FenceState::Unfenced,
        };
        writer
            .send_publication(withheld.clone())
            .await
            .expect("sends");
        assert_eq!(
            bridge.recv().await.expect("a publication"),
            ToBridge::FencePublished(withheld)
        );
        let transaction = LaunchTransactionId::new(Uuid::from_bytes([0x65; 16]));
        writer
            .send_revocation(transaction, LaunchRejectionReason::Timeout)
            .await
            .expect("sends");
        assert_eq!(
            bridge.recv().await.expect("a revocation"),
            ToBridge::LaunchRevoked {
                transaction,
                reason: LaunchRejectionReason::Timeout,
            }
        );
        // The worker allocates request identifiers on its own side of the connection.
        assert_eq!(writer.next_request_id(), RequestId::new(1));
        assert_eq!(writer.next_request_id(), RequestId::new(2));
    }
}
