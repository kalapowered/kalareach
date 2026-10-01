//! One conversation with a control daemon or a worker, wherever it is.
//!
//! A terminal attached to a session on this host talks to the session's worker over a local
//! socket. One attached to a session in a WSL distribution or a container talks to the same
//! worker through a helper running there, which carries the same frames over its standard
//! streams. The attachment is the same either way, so everything it needs of the connection is one
//! small trait, and the two connections implement it: [`LocalClient`] for a socket here, and
//! [`BridgedLink`] for a bridge.
//!
//! What the trait asks is what the attach loop uses and nothing more: a read, a mutation, the next
//! frame the peer pushed, a frame written without waiting for its answer, the window a mutation
//! quotes, and the build the peer states.

use std::future::Future;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::bridge::invoke::{
    BridgeStream, Diagnostics, MUTATION_LIMIT, Refusal, SILENCE_LIMIT,
};
use kr_controller::bridge::launch::LaunchError;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActionWindowId, RequestId};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};

use crate::error::{CliError, Result};

/// What a host said to one call: the answer, or its refusal.
pub type Answer = std::result::Result<ParamsValue, ProtocolError>;

/// One connection to a control daemon or a worker, over which a terminal is attached.
pub trait Link {
    /// The build of the process at the other end, as it stated it, or none when it states none.
    fn build(&self) -> Option<&LocalBuild>;

    /// The identifier of the action window a mutation built now would quote.
    fn action_window_id(&self) -> ActionWindowId;

    /// Calls a read method.
    ///
    /// # Errors
    ///
    /// Returns a transport failure. The host's own refusal is the answer.
    fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> impl Future<Output = Result<Answer>>;

    /// Calls a mutation.
    ///
    /// # Errors
    ///
    /// Returns a transport failure. The host's own refusal is the answer.
    fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        target: ActionTarget,
        params: &T,
    ) -> impl Future<Output = Result<Answer>>;

    /// Takes the next frame the peer pushed, waiting for one. Dropping this loses nothing.
    ///
    /// # Errors
    ///
    /// Returns what ended the connection.
    fn recv(&mut self) -> impl Future<Output = Result<ControlFrame>>;

    /// Writes one frame without waiting for its answer, which comes back through [`Self::recv`].
    ///
    /// # Errors
    ///
    /// Returns a transport failure.
    fn send(&mut self, frame: ControlFrame) -> impl Future<Output = Result<()>>;

    /// Ends the connection, and says what it has to say about how it ended.
    ///
    /// Called once the terminal is the person's again, because anything said while a terminal
    /// shows a projection of a session damages the screen it is describing.
    fn finish(self) -> impl Future<Output = ()>
    where
        Self: Sized;
}

impl Link for LocalClient {
    fn build(&self) -> Option<&LocalBuild> {
        self.acknowledgement().build.as_ref()
    }

    fn action_window_id(&self) -> ActionWindowId {
        self.action_window().action_window_id.clone()
    }

    async fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<Answer> {
        Self::request(self, method, params)
            .await
            .map_err(CliError::from)
    }

    async fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        target: ActionTarget,
        params: &T,
    ) -> Result<Answer> {
        Self::mutate(self, method, action_id, target, params)
            .await
            .map_err(CliError::from)
    }

    async fn recv(&mut self) -> Result<ControlFrame> {
        Self::recv(self).await.map_err(CliError::from)
    }

    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        self.writer()
            .write_message(&frame)
            .await
            .map_err(CliError::from)
    }

    async fn finish(self) {
        // A socket has nothing left to say, and closes when it is dropped.
        drop(self);
    }
}

/// A connection to a control daemon or a worker in another environment, through a bridge helper.
pub struct BridgedLink {
    stream: BridgeStream,
    /// The last request number this link used. They are this connection's own.
    last_request: u64,
}

kr_client::debug_as_name!(BridgedLink);

impl BridgedLink {
    /// Takes an open bridge as a connection.
    #[must_use]
    pub const fn new(stream: BridgeStream) -> Self {
        Self {
            stream,
            last_request: 0,
        }
    }

    /// What the destination acknowledged.
    #[must_use]
    pub const fn acknowledgement(&self) -> &kr_protocol::identity::BridgeHelloAck {
        self.stream.acknowledgement()
    }

    /// What the helper has written to its standard error so far.
    #[must_use]
    pub fn diagnostics(&self) -> Diagnostics {
        self.stream.diagnostics().clone()
    }

    /// Ends the connection and the helper with it.
    ///
    /// # Errors
    ///
    /// Returns the refusal that names a helper that did not end on its own or at the kill.
    pub async fn close(self) -> std::result::Result<(), Refusal> {
        self.stream.close().await
    }

    fn next_id(&mut self) -> RequestId {
        self.last_request += 1;
        RequestId::new(self.last_request)
    }
}

impl Link for BridgedLink {
    fn build(&self) -> Option<&LocalBuild> {
        self.stream.acknowledgement().build.as_ref()
    }

    fn action_window_id(&self) -> ActionWindowId {
        self.stream.action_window().action_window_id
    }

    fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> impl Future<Output = Result<Answer>> {
        let request_id = self.next_id();
        let params = ParamsValue::from_typed(params);
        async move {
            let params = params.map_err(|error| encoding(&error))?;
            self.stream
                .send(ControlFrame::Request(Request {
                    request_id,
                    method: method.into(),
                    method_version: MethodVersion::V1,
                    params,
                }))
                .await
                .map_err(failed)?;
            let response = self
                .stream
                .response(request_id, SILENCE_LIMIT)
                .await
                .map_err(failed)?;
            Ok(answer(response.outcome))
        }
    }

    fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        target: ActionTarget,
        params: &T,
    ) -> impl Future<Output = Result<Answer>> {
        let request_id = self.next_id();
        let params = ParamsValue::from_typed(params);
        async move {
            let params = params.map_err(|error| encoding(&error))?;
            // The window this mutation quotes is the one the destination last issued, which the
            // stream has already applied if the destination renewed it while this was idle.
            let mutation = MutationRequest {
                request_id,
                method: method.into(),
                method_version: MethodVersion::V1,
                action_id,
                grant_id: Nullable::null(),
                target,
                expected: ParamsValue::empty(),
                action_window_id: self.stream.action_window().action_window_id,
                requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
                params,
            };
            self.stream
                .send(ControlFrame::Mutation(Box::new(mutation)))
                .await
                .map_err(failed)?;
            let response = self
                .stream
                .response(request_id, MUTATION_LIMIT)
                .await
                .map_err(failed)?;
            Ok(answer(response.outcome))
        }
    }

    async fn recv(&mut self) -> Result<ControlFrame> {
        self.stream.recv().await.map_err(failed)
    }

    async fn send(&mut self, frame: ControlFrame) -> Result<()> {
        self.stream.send(frame).await.map_err(failed)
    }

    async fn finish(self) {
        let diagnostics = self.diagnostics();
        let ended = self.close().await;
        // What the helper wrote to its standard error is the destination's to write, so it is
        // counted and not repeated.
        let written = diagnostics.written();
        if written > 0 {
            crate::report::say(&shown!(
                "kr: the bridge helper wrote {} bytes to its standard error",
                written
            ));
        }
        // The attachment has ended already; a helper that would not end is a process this command
        // names, and no longer waits for.
        if let Err(refusal) = ended {
            crate::report::say(&kr_client::shown::Said::said(&failed(refusal)));
        }
    }
}

fn answer(outcome: Outcome) -> Answer {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Error(error) => Err(error),
    }
}

fn encoding(error: &kr_cbor::CborError) -> CliError {
    CliError::Other(shown!(
        "a parameter could not be encoded for the bridge: {}",
        Shown::cbor(error)
    ))
}

/// What a person is told of a bridge that stopped, in this command's own words.
///
/// What the destination's helper said in its own words is shown as the refusal it is. Everything
/// else is a sentence of ours: a decoder's message, an operating system's and the names of the
/// builds at the other end are the destination's to write, and are not repeated.
pub fn failed(refusal: Refusal) -> CliError {
    match refusal {
        Refusal::Destination(error) => CliError::Refused(error),
        Refusal::SessionClosed => CliError::Refused(kr_client::error::refusal(
            ErrorCode::SessionClosed,
            Shown::said("that session is closed"),
        )),
        Refusal::Launch(LaunchError::NotAProcessBridge { .. }) => CliError::Usage(Shown::said(
            "that environment is not reached by a process bridge: run kr on it after logging in \
             to it, or reach it through its own pairing",
        )),
        Refusal::Launch(LaunchError::Incomplete(_)) => CliError::Usage(Shown::said(
            "this environment's enrolment is incomplete; enrol it again with its distribution or \
             container, its user and the absolute path of its helper",
        )),
        Refusal::NotStarted { .. } => CliError::HostUnavailable(Shown::said(
            "the program that opens a bridge to that environment could not be started; is it \
             installed on this host?",
        )),
        Refusal::Level { destination } => CliError::Unfinished {
            code: ErrorCode::UnsupportedSchema,
            message: match destination {
                Some(build) => shown!(
                    "the environment runs {} with protocol {}.{}.{}, and this kr is {} with \
                     protocol {}.{}.{}: update kr in one of them so both are of one release",
                    crate::shown::build_name(&build.build_id),
                    build.protocol_version.major,
                    build.protocol_version.minor,
                    build.protocol_version.patch,
                    crate::shown::build_name(&crate::build_id()),
                    kr_protocol::hello::PACKAGE_VERSION.major,
                    kr_protocol::hello::PACKAGE_VERSION.minor,
                    kr_protocol::hello::PACKAGE_VERSION.patch,
                ),
                None => shown!(
                    "the environment runs a kr that states no protocol version, and this kr is \
                     {} with protocol {}.{}.{}: update kr there",
                    crate::shown::build_name(&crate::build_id()),
                    kr_protocol::hello::PACKAGE_VERSION.major,
                    kr_protocol::hello::PACKAGE_VERSION.minor,
                    kr_protocol::hello::PACKAGE_VERSION.patch,
                ),
            },
        },
        Refusal::Unreadable { .. } => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "the helper in the environment wrote something this kr cannot read: it may be of \
                 another release, or the login it runs under may write to standard output",
            ),
        },
        Refusal::Silent { waited } => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "the environment said nothing for {} seconds, so the bridge was ended",
                waited.as_secs()
            ),
        },
        Refusal::Unkillable { .. } => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "the process that opened the bridge could not be ended and may still be running; \
                 this kr no longer waits for it",
            ),
        },
        Refusal::IdentityMismatch { .. } => CliError::Refused(kr_client::error::refusal(
            ErrorCode::PermissionDenied,
            Shown::said(
                "a different environment answered than the one that was enrolled; enrol the \
                 environment that is installed there",
            ),
        )),
        Refusal::Backlog { .. } => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "the environment sent more than this kr could hold, so the bridge was ended",
            ),
        },
        Refusal::NetworkActor { .. }
        | Refusal::AlreadyBridged
        | Refusal::Stream { .. }
        | Refusal::NotAnAcknowledgement
        | Refusal::ProtocolMajor { .. }
        | Refusal::WrongRole { .. } => CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said("the bridge to the environment failed"),
        },
    }
}
