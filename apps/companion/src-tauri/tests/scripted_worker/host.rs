//! A paired host the test scripts, reached the way a view of a paired host reaches a real one: over a
//! real connection between two loopback endpoints, whose control stream carries the same frames as a
//! worker's socket and whose data streams carry the terminal input.
//!
//! The control stream is a [`Link`] like the scripted worker's, so a case answers `session.open`, the
//! attach, the subscription and every call after them the way it does for a worker. The input stream
//! is the client library's own scripted host ([`lane_host`]): it takes `terminal_input` streams,
//! records every frame it reads and the stream's end, and writes the words that the case gives it.
//! What this does not run is the device's dial (`Dial::transport`): the view is handed the connection
//! that the dial would have made.

#![allow(dead_code, reason = "each suite uses the part of the script it needs")]

use std::sync::Arc;

use kr_client::transport::{ControlTransport, NetworkTransport};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::testing::TempHost;
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ConnectionId, EnvironmentId, GrantId, SessionId};
use kr_protocol::input::InputWindow;
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::session::{
    Dimensions, DisplayNumber, OpenedVia, SessionOpenResult, SessionState, SessionSummary,
    ShellMode,
};
use kr_protocol::transfer::TransferStreamsResult;
use kr_transport::scheduler::SendLimits;

use super::{Link, Wire};

#[path = "../../../../../crates/kr-client/tests/lane_host/mod.rs"]
pub mod lane_host;

use lane_host::Script;

/// What the host answers to the client's question whether it takes a stream of its own for typing.
pub enum Takes {
    /// It lists the terminal-input stream.
    Input,
    /// It answers, and lists no such stream.
    NoInput,
    /// It does not serve the method, as a host of an earlier build answers.
    NotServed,
    /// It refuses the question with `code` and `message`.
    Refuses(ErrorCode, &'static str),
}

/// One paired host's scripted end of one connection.
pub struct ScriptedHost {
    /// What the input stream's side of the host saw, and what it writes next.
    pub script: Arc<Script>,
    pub session_id: SessionId,
    pub environment_id: EnvironmentId,
    pub connection_id: ConnectionId,
    links: tokio::sync::mpsc::UnboundedReceiver<Wire>,
    transport: Option<Arc<dyn ControlTransport>>,
    host: lane_host::Side,
    _client: lane_host::Side,
    serving: tokio::task::JoinHandle<()>,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: TempHost,
}

impl Drop for ScriptedHost {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

impl ScriptedHost {
    /// A host that gives the input stream `window` and lists the terminal-input stream, with a
    /// connection of a client already made to it.
    pub async fn start(window: InputWindow) -> Self {
        let temp = TempHost::create();
        let script = Script::new(window, vec![StreamKind::TerminalInput]);
        let host = lane_host::side(1, true).await;
        let client = lane_host::side(2, false).await;
        let (handing, links) = tokio::sync::mpsc::unbounded_channel();
        let serving = lane_host::spawn_host(
            &host,
            client.record,
            Arc::clone(&script),
            move |_script, reader, writer| {
                let handing = handing.clone();
                async move {
                    let _ = handing.send(Wire::quic(reader, writer));
                }
            },
        );
        let transport: Arc<dyn ControlTransport> = Arc::new(
            NetworkTransport::connect(
                &client.endpoint,
                lane_host::direct_addr(&host),
                &client.identity,
                &host.record,
                SendLimits::default(),
            )
            .await
            .expect("an authorised connection"),
        );
        Self {
            script,
            session_id: SessionId::new(kr_ipc::new_uuid()),
            environment_id: temp.environment_id(),
            connection_id: transport.connection_id(),
            links,
            transport: Some(transport),
            host,
            _client: client,
            serving,
            temp,
        }
    }

    /// The host tree's environment, which the application's registry reads, though a paired view reads
    /// nothing from it.
    pub fn paths(&self) -> EnvironmentPaths {
        self.temp.environment()
    }

    /// The view's connection, which the registry hands the next view that opens. Taken once.
    pub fn transport(&mut self) -> Arc<dyn ControlTransport> {
        self.transport.take().expect("the connection is taken once")
    }

    /// The control stream of the view's connection, once the view has opened the session on it: the
    /// host answers `session.open` as it does a paired device's. The next call is the attach.
    pub async fn link(&mut self) -> Link {
        let wire = tokio::time::timeout(super::WATCHDOG, self.links.recv())
            .await
            .expect("the control stream was handed over within the watchdog")
            .expect("the host is still serving");
        let mut link = Link {
            wire,
            sequence: 0,
            session_id: self.session_id,
            connection_id: self.connection_id,
        };
        let open = link.expect(Method::SessionOpen).await;
        link.answer(
            &open,
            &SessionOpenResult::InForce {
                session: Box::new(Nullable::some(self.summary())),
                environment_id: self.environment_id,
                grant_id: GrantId::new(kr_ipc::new_uuid()),
                via: OpenedVia::Pairing,
                actions: CanonicalSet::new(),
                includes_live_screen: true,
                history_from_ms: Nullable::null(),
                ends_at_ms: Nullable::null(),
            },
        )
        .await;
        link
    }

    fn summary(&self) -> SessionSummary {
        SessionSummary {
            session_id: self.session_id,
            session_epoch: kr_protocol::ids::SessionEpoch::new(1),
            environment_id: self.environment_id,
            display_number: DisplayNumber::new(1),
            state: SessionState::Live,
            shell_mode: ShellMode::Managed,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/tmp".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: Dimensions::new(80, 24),
            attachment_count: U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
            root: None,
            application: None,
        }
    }

    /// Answers the client's question whether the host takes a stream of its own for typing, which the
    /// view asks as it opens its lane, right after the attach.
    pub async fn takes(&self, link: &mut Link, takes: Takes) {
        let asked = link.expect(Method::TransferStreams).await;
        match takes {
            Takes::Input => {
                link.answer(
                    &asked,
                    &TransferStreamsResult {
                        accepted_streams: vec![StreamKind::TerminalInput],
                    },
                )
                .await;
            }
            Takes::NoInput => {
                link.answer(
                    &asked,
                    &TransferStreamsResult {
                        accepted_streams: Vec::new(),
                    },
                )
                .await;
            }
            Takes::NotServed => {
                link.refuse_with(
                    &asked,
                    ErrorCode::PermissionDenied,
                    kr_transport::actor::METHOD_NOT_AVAILABLE,
                )
                .await;
            }
            Takes::Refuses(code, message) => link.refuse_with(&asked, code, message).await,
        }
    }

    /// Ends the host's endpoint, as a network that is lost does: every connection to it ends with no
    /// word, the control stream and the input stream both.
    pub async fn lose_the_network(&self) {
        self.host.endpoint.close().await;
    }
}
