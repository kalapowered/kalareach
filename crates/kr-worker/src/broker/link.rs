//! The worker-owned transport that drives the gateway.
//!
//! [`gateway`](crate::broker::gateway) decides what one frame means. This is what reads frames off
//! a connection, hands each one to the broker, writes what the broker admitted and executes what
//! the upstream asked this host for. It is core code throughout: nothing here calls a component,
//! which is why a component fault cannot stall native traffic.
//!
//! The worker sits between two ends of one native connection.
//!
//! * The **upstream** is the process this host launched. Its frames are requests it wants answered
//!   and responses to what this host sent it.
//! * The **client** is the native terminal the person is looking at, which reached this host
//!   through the bound endpoint and the `kr-hook` forwarder.
//!
//! One frame at a time, the loop does what section 11 requires in the order it requires it.
//!
//! 1. A request from the upstream is **recorded before it is forwarded**, classified by the
//!    connection's own qualified table, and then written to the client.
//! 2. A response from the client **takes the resource's one transmission admission** before its
//!    bytes go. A rich answer that already holds that admission makes this a refusal rather than a
//!    second answer, and the refusal happens here, before anything is written.
//! 3. A reverse request runs **in the agent's own host environment**, and its answer goes back on
//!    the same connection with the identifier it came in with.
//! 4. Everything the broker resolves is delivered to every attached observer, so a person watching
//!    from a second device sees the same resolution.
//!
//! Encoding an operation this host prepared is the other half. An approval's answer was prepared
//! by the core at admission, so this writes the bytes it was given. The other mutations are
//! encoded here from the connection's rich table, which names the upstream method for each right,
//! and the table's own parameter member. A connector whose upstream wants a different body shape
//! supplies an adapter: section 12 makes the bundled adapters the plugins repository's, and this
//! is the host side they drive.

use std::sync::Arc;

use kr_protocol::broker::ActionProvenance;
use kr_protocol::gateway::{NativeFraming, ReverseOperation};
use kr_protocol::ids::{GatewayConnectionId, UpstreamRequestId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::TimestampMs;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::broker::Broker;
use crate::broker::error::{BrokerError, Result};
use crate::broker::gateway::MAX_NATIVE_FRAME_BYTES;
use crate::broker::methods::{
    UpstreamBody, UpstreamDispatch, UpstreamOperation, UpstreamOutcome, UpstreamRequest,
};

/// How many frames wait to be written to one end before the link reports the connection unusable.
///
/// A writer that is not draining is a connection that cannot safely continue, and section 11 makes
/// that `UPSTREAM_UNAVAILABLE` rather than an unbounded queue or a hidden second backend.
pub const MAX_QUEUED_FRAMES: usize = 256;

/// Reads and writes one connector's frames, as its qualified table describes them.
#[derive(Clone, Copy, Debug)]
pub struct Framing(NativeFraming);

impl Framing {
    /// Frames as this connector does.
    #[must_use]
    pub const fn new(framing: NativeFraming) -> Self {
        Self(framing)
    }

    /// Wraps one body in the framing this connector uses.
    #[must_use]
    pub fn encode(self, body: &[u8]) -> Vec<u8> {
        match self.0 {
            NativeFraming::JsonLines => {
                let mut framed = Vec::with_capacity(body.len() + 1);
                framed.extend_from_slice(body);
                framed.push(b'\n');
                framed
            }
            NativeFraming::LengthPrefixed => {
                let mut framed = format!("{}\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
            NativeFraming::ContentLength => {
                let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
        }
    }

    /// Takes one whole body out of the buffer, or says there is not one yet.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the buffer holds something this framing
    /// cannot be reading: a declared length that is not a number, or one past the frame bound.
    pub fn decode(self, buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        match self.0 {
            NativeFraming::JsonLines => {
                let Some(end) = buffer.iter().position(|byte| *byte == b'\n') else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let body = buffer.drain(..=end).take(end).collect();
                Ok(Some(body))
            }
            NativeFraming::LengthPrefixed => {
                let Some(end) = buffer.iter().position(|byte| *byte == b'\n') else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let declared = std::str::from_utf8(&buffer[..end])
                    .ok()
                    .and_then(|text| text.trim().parse::<usize>().ok())
                    .ok_or_else(|| {
                        BrokerError::invalid("this frame declares no readable length")
                    })?;
                Self::check_declared(declared)?;
                if buffer.len() < end + 1 + declared {
                    return Ok(None);
                }
                buffer.drain(..=end);
                Ok(Some(buffer.drain(..declared).collect()))
            }
            NativeFraming::ContentLength => {
                let Some(end) = find(buffer, b"\r\n\r\n") else {
                    Self::check_partial(buffer.len())?;
                    return Ok(None);
                };
                let headers = std::str::from_utf8(&buffer[..end])
                    .map_err(|_| BrokerError::invalid("this frame's headers are not text"))?;
                let declared = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .ok_or_else(|| {
                        BrokerError::invalid("this frame declares no readable content length")
                    })?;
                Self::check_declared(declared)?;
                if buffer.len() < end + 4 + declared {
                    return Ok(None);
                }
                buffer.drain(..end + 4);
                Ok(Some(buffer.drain(..declared).collect()))
            }
        }
    }

    fn check_partial(held: usize) -> Result<()> {
        if held > MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "a native frame is at most {MAX_NATIVE_FRAME_BYTES} bytes and this one has not \
                 ended after {held}"
            )));
        }
        Ok(())
    }

    fn check_declared(declared: usize) -> Result<()> {
        if declared > MAX_NATIVE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "this frame declares {declared} bytes and a native frame is at most \
                 {MAX_NATIVE_FRAME_BYTES}"
            )));
        }
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// One end of a link, as something that can be written to.
#[derive(Clone, Debug)]
pub struct Writer {
    frames: tokio::sync::mpsc::Sender<Vec<u8>>,
    framing: Framing,
}

impl Writer {
    /// Queues one body for writing, framed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when the other end is gone or is not draining.
    /// Section 11: if the framing connection cannot safely continue, say so; do not open a hidden
    /// second backend.
    pub fn send(&self, body: &[u8]) -> Result<()> {
        self.frames
            .try_send(self.framing.encode(body))
            .map_err(|error| BrokerError::UpstreamUnavailable {
                detail: format!("the framing connection cannot carry this frame: {error}"),
            })
    }
}

/// What the worker-owned transport carries prepared operations over.
///
/// This is the production [`UpstreamDispatch`]: it encodes what the core prepared and queues it on
/// the connection the broker admitted the operation against.
#[derive(Debug)]
pub struct LinkDispatch {
    connection: GatewayConnectionId,
    upstream: Writer,
    next: std::sync::atomic::AtomicU64,
    rich: kr_protocol::gateway::RichMethodTable,
    params_field: String,
    request_id_field: String,
    method_field: String,
}

impl LinkDispatch {
    /// Returns the connection this dispatch writes to.
    #[must_use]
    pub const fn connection(&self) -> GatewayConnectionId {
        self.connection
    }

    fn allocate(&self) -> Result<UpstreamRequestId> {
        let next = self
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        // The identifier is allocated here and written in its own JSON form, so a number stays a
        // number: an upstream that answers `"7"` is not answering `7`.
        UpstreamRequestId::new(next.to_string())
            .map_err(|error| BrokerError::invalid(format!("upstream request identifier: {error}")))
    }

    /// Returns the upstream method this connection's closed rich table names for one operation.
    ///
    /// A prompt, a steer and a cancellation are named by the right they need, because that is what
    /// the rich table records beside each method. A plugin action is named by the action the
    /// package declared, which is what "declared action" means: the table still has to list it, so
    /// an unknown rich mutation is rejected rather than guessed at.
    fn method_for(&self, request: &UpstreamRequest) -> Result<kr_protocol::ids::UpstreamMethod> {
        if let UpstreamBody::PluginAction { action, .. } = &request.body {
            let method =
                kr_protocol::ids::UpstreamMethod::new(action.as_str()).map_err(|error| {
                    BrokerError::invalid(format!("this action is not a method name: {error}"))
                })?;
            self.rich.admit(&method)?;
            return Ok(method);
        }
        let right = match request.operation {
            UpstreamOperation::PromptSubmit
            | UpstreamOperation::PromptQueue
            | UpstreamOperation::TurnSteer => ActionRight::AgentPrompt,
            UpstreamOperation::TurnCancel => ActionRight::AgentCancel,
            UpstreamOperation::ApprovalRespond | UpstreamOperation::PluginAction => {
                ActionRight::AgentApprovalRespond
            }
        };
        self.rich
            .entries
            .iter()
            .find(|entry| entry.required_right == right)
            .map(|entry| entry.method.clone())
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!(
                    "this upstream's rich table names no method for {}, so the core has nothing \
                     to encode it as",
                    request.operation
                ),
            })
    }

    fn parameters(body: &UpstreamBody) -> Result<serde_json::Value> {
        Ok(match body {
            UpstreamBody::Prompt { draft_id, text } => serde_json::json!({
                "draft_id": draft_id.as_ref().map(ToString::to_string),
                "text": text,
            }),
            UpstreamBody::Steer { text } => serde_json::json!({ "text": text }),
            UpstreamBody::Cancel => serde_json::json!({}),
            UpstreamBody::Approval { option_id, .. } => {
                serde_json::json!({ "option_id": option_id })
            }
            UpstreamBody::PluginAction {
                plugin_id,
                action,
                draft_id,
                parameters,
                token,
            } => serde_json::json!({
                "plugin_id": plugin_id.as_str(),
                "action": action.as_str(),
                "draft_id": draft_id.as_ref().map(ToString::to_string),
                "parameters": serde_json::from_slice::<serde_json::Value>(parameters)
                    .unwrap_or(serde_json::Value::Null),
                // Section 11: the effect plan may use only what this invocation permits, and the
                // token is what says which invocation that is.
                "action_token": token.as_ref().map(|token| token.token_id.as_str()),
            }),
        })
    }
}

impl UpstreamDispatch for LinkDispatch {
    fn submit(&self, request: &UpstreamRequest) -> Result<UpstreamOutcome> {
        // An approval's answer was prepared by the core at admission, from this connection's own
        // table. Writing anything else here would send bytes nobody admitted.
        if let UpstreamBody::Approval { response, .. } = &request.body {
            self.upstream.send(&response.frame)?;
            return Ok(UpstreamOutcome {
                upstream_request_id: Some(response.upstream_request_id.clone()),
                turn_id: request.turn_id.clone(),
                provenance: ActionProvenance::UpstreamTypedRpc,
            });
        }
        let upstream_request_id = self.allocate()?;
        let method = self.method_for(request)?;
        let identifier: serde_json::Value = serde_json::from_str(upstream_request_id.as_str())
            .map_err(|error| {
                BrokerError::invalid(format!("this identifier will not encode: {error}"))
            })?;
        let mut frame = serde_json::Map::new();
        frame.insert(self.request_id_field.clone(), identifier);
        frame.insert(
            self.method_field.clone(),
            serde_json::Value::String(method.as_str().to_owned()),
        );
        frame.insert(self.params_field.clone(), Self::parameters(&request.body)?);
        let body = serde_json::to_vec(&serde_json::Value::Object(frame)).map_err(|error| {
            BrokerError::invalid(format!("this operation will not encode: {error}"))
        })?;
        self.upstream.send(&body)?;
        Ok(UpstreamOutcome {
            upstream_request_id: Some(upstream_request_id),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        })
    }
}

/// What the link did with one frame, for a caller that watches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Carried {
    /// A request the upstream sent, recorded and forwarded to the client.
    UpstreamRequest {
        /// The method it named.
        method: kr_protocol::ids::UpstreamMethod,
        /// The resource it created, when it expects a response.
        resource_id: Option<kr_protocol::ids::PendingResourceId>,
    },
    /// A reverse request this host performed in the agent's own environment.
    Reverse {
        /// What was asked for.
        operation: ReverseOperation,
        /// Whether this host could do it.
        performed: bool,
    },
    /// The client's own answer, admitted and forwarded to the upstream.
    ClientAnswer {
        /// The resource it resolved.
        resource_id: kr_protocol::ids::PendingResourceId,
    },
    /// A response the upstream sent for something this host asked it.
    UpstreamResponse,
}

/// One live native connection, driven by the worker.
#[derive(Debug)]
pub struct Link {
    broker: Arc<Broker>,
    connection: GatewayConnectionId,
    framing: Framing,
    upstream: Writer,
    client: Writer,
    site: kr_protocol::ids::EnvironmentId,
    os_user: String,
}

impl Link {
    /// Returns what carries prepared operations to this connection's upstream.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the connection is not one the broker holds.
    pub fn dispatch(&self) -> Result<Arc<LinkDispatch>> {
        let connection = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        Ok(Arc::new(LinkDispatch {
            connection: self.connection,
            upstream: self.upstream.clone(),
            next: std::sync::atomic::AtomicU64::new(0),
            rich: connection.rich.clone(),
            params_field: connection.table.params_field.clone(),
            request_id_field: connection.table.request_id_field.clone(),
            method_field: connection.table.method_field.clone(),
        }))
    }

    /// Carries one frame the upstream sent.
    ///
    /// # Errors
    ///
    /// Returns whatever the broker refuses, and [`BrokerError::UpstreamUnavailable`] when the
    /// client end cannot take the frame.
    pub fn from_upstream(&self, frame: &[u8], now: TimestampMs) -> Result<Carried> {
        // A request names a method and a response does not, which is the one distinction the
        // qualified table guarantees. Asking the broker to correlate a request would resolve a
        // resource on the strength of a matching identifier alone.
        let (forwarded, resource) = match self.broker.forward_native(self.connection, frame, now) {
            Ok(carried) => carried,
            Err(_) => {
                // Not a request this table describes. It is a response to something this host
                // sent, and the arbitration is what says whether anything was waiting for it.
                self.broker.upstream_response(self.connection, frame, now)?;
                return Ok(Carried::UpstreamResponse);
            }
        };
        // What the upstream asks this host to do runs here, in the agent's own environment, and
        // its answer goes back on the connection it came in on.
        if let Some(operation) = self
            .broker
            .connection(self.connection)
            .and_then(|connection| connection.table.reverse_of(&forwarded.method))
        {
            let performed = self.perform_reverse(operation, frame, now)?;
            return Ok(Carried::Reverse {
                operation,
                performed,
            });
        }
        // Recorded first, forwarded second. Section 11 puts the record before the forwarding so
        // that a crash in between leaves a request this host knows about rather than one it does
        // not.
        self.client.send(frame)?;
        Ok(Carried::UpstreamRequest {
            method: forwarded.method,
            resource_id: resource.map(|resource| resource.resource_id),
        })
    }

    /// Carries one frame the native client sent.
    ///
    /// # Errors
    ///
    /// Returns whatever the broker refuses, including the refusal of a second answer to one
    /// request.
    pub fn from_client(&self, frame: &[u8], now: TimestampMs) -> Result<Carried> {
        let resolved = self
            .broker
            .native_answer_through(self.connection, frame, now, |bytes| {
                self.upstream.send(bytes)
            })?;
        // Every attached observer is told, because a person watching from a second device is
        // watching the same resource.
        for observer in self.broker.observers(resolved.application_instance_id) {
            if observer != self.connection {
                let _ = self.client.send(frame);
                let _ = observer;
                break;
            }
        }
        Ok(Carried::ClientAnswer {
            resource_id: resolved.resource_id,
        })
    }

    /// Performs one reverse request in the agent's own host environment, and answers it.
    fn perform_reverse(
        &self,
        operation: ReverseOperation,
        frame: &[u8],
        now: TimestampMs,
    ) -> Result<bool> {
        let body: serde_json::Value = serde_json::from_slice(frame).map_err(|error| {
            BrokerError::invalid(format!("this frame is not readable: {error}"))
        })?;
        let connection = self.broker.connection(self.connection).ok_or_else(|| {
            BrokerError::unknown(format!("no gateway connection {}", self.connection))
        })?;
        let upstream_request_id = body
            .get(&connection.table.request_id_field)
            .and_then(|member| serde_json::to_string(member).ok())
            .and_then(|text| UpstreamRequestId::new(text).ok())
            .ok_or_else(|| {
                BrokerError::invalid("a reverse request carries the identifier it is answered on")
            })?;
        // The site is the gateway's, derived from the connection rather than taken from the
        // request: section 12 runs these in the agent's own environment with its own user, and
        // that is true only if the request does not get to say where.
        let reverse = self.broker.reverse_request(
            self.connection,
            upstream_request_id.clone(),
            operation,
            self.site,
            &self.os_user,
        )?;
        let parameters = body.get(&connection.table.params_field);
        let outcome = perform(operation, parameters);
        let mut answer = serde_json::Map::new();
        answer.insert(
            connection.table.response_id_field.clone(),
            serde_json::from_str(upstream_request_id.as_str()).unwrap_or(serde_json::Value::Null),
        );
        let performed = outcome.is_ok();
        match outcome {
            Ok(result) => {
                answer.insert(connection.table.result_field.clone(), result);
            }
            Err(detail) => {
                answer.insert(
                    connection.table.error_field.clone(),
                    serde_json::json!({ "code": -32_603, "message": detail }),
                );
            }
        }
        let body = serde_json::to_vec(&serde_json::Value::Object(answer)).map_err(|error| {
            BrokerError::invalid(format!("this answer will not encode: {error}"))
        })?;
        self.upstream.send(&body)?;
        let _ = (reverse, now);
        Ok(performed)
    }
}

/// Performs one reverse operation, or says why this host would not.
fn perform(
    operation: ReverseOperation,
    parameters: Option<&serde_json::Value>,
) -> std::result::Result<serde_json::Value, String> {
    let path = parameters
        .and_then(|parameters| parameters.get("path"))
        .and_then(serde_json::Value::as_str);
    match operation {
        ReverseOperation::FilesystemRead => {
            let path = path.ok_or_else(|| "this request names no path".to_owned())?;
            let content = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
            Ok(serde_json::json!({ "content": content }))
        }
        ReverseOperation::FilesystemWrite => {
            let path = path.ok_or_else(|| "this request names no path".to_owned())?;
            let content = parameters
                .and_then(|parameters| parameters.get("content"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "this request names no content".to_owned())?;
            std::fs::write(path, content).map_err(|error| error.to_string())?;
            Ok(serde_json::json!({ "written": content.len() }))
        }
        // The terminal belongs to the session's own input path, which holds the lease and records
        // what it wrote. A reverse request does not get a second way in.
        ReverseOperation::Terminal => Err(
            "terminal input reaches this session through its own lease, and a reverse request is \
             not one"
                .to_owned(),
        ),
    }
}

/// Builds the two writers of one link and the task that drains them.
///
/// The writers are queues rather than handles, so nothing that holds a broker lock ever waits on a
/// socket: [`Writer::send`] queues and returns, and this is what empties the queue.
pub fn writers<U, C>(
    framing: Framing,
    upstream: U,
    client: C,
) -> (Writer, Writer, impl std::future::Future<Output = ()> + Send)
where
    U: AsyncWrite + Unpin + Send + 'static,
    C: AsyncWrite + Unpin + Send + 'static,
{
    let (to_upstream, upstream_frames) = tokio::sync::mpsc::channel(MAX_QUEUED_FRAMES);
    let (to_client, client_frames) = tokio::sync::mpsc::channel(MAX_QUEUED_FRAMES);
    let drain = async move {
        tokio::join!(
            drain_into(upstream, upstream_frames),
            drain_into(client, client_frames)
        );
    };
    (
        Writer {
            frames: to_upstream,
            framing,
        },
        Writer {
            frames: to_client,
            framing,
        },
        drain,
    )
}

async fn drain_into<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    while let Some(frame) = frames.recv().await {
        if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
            break;
        }
    }
}

impl Link {
    /// Builds one link over an already-opened gateway connection.
    #[must_use]
    pub fn new(
        broker: Arc<Broker>,
        connection: GatewayConnectionId,
        framing: Framing,
        upstream: Writer,
        client: Writer,
        site: kr_protocol::ids::EnvironmentId,
        os_user: impl Into<String>,
    ) -> Self {
        Self {
            broker,
            connection,
            framing,
            upstream,
            client,
            site,
            os_user: os_user.into(),
        }
    }

    /// Reads one end for as long as it has frames, carrying each one.
    ///
    /// `upstream` says which end this is. The loop ends when the end closes or sends something
    /// this framing cannot be reading; a refusal of one frame does not end the connection, because
    /// one malformed or unanswerable frame is not a reason to take a working terminal away.
    pub async fn serve<R: AsyncRead + Unpin>(&self, mut reader: R, upstream: bool) {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            loop {
                match self.framing.decode(&mut buffer) {
                    Ok(Some(frame)) => {
                        let now = kr_ipc::now_ms();
                        let _ = if upstream {
                            self.from_upstream(&frame, now)
                        } else {
                            self.from_client(&frame, now)
                        };
                    }
                    Ok(None) => break,
                    // The stream is no longer one this framing can read, so this end is done.
                    Err(_) => return,
                }
            }
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_framing_reads_back_exactly_what_it_wrote() {
        for framing in NativeFraming::ALL {
            let framing = Framing::new(*framing);
            let mut buffer = framing.encode(br#"{"id":1}"#);
            buffer.extend_from_slice(&framing.encode(br#"{"id":2}"#));
            let first = framing
                .decode(&mut buffer)
                .expect("readable")
                .expect("a whole frame");
            let second = framing
                .decode(&mut buffer)
                .expect("readable")
                .expect("a whole frame");
            assert_eq!(first, br#"{"id":1}"#);
            assert_eq!(second, br#"{"id":2}"#);
            assert!(
                framing.decode(&mut buffer).expect("readable").is_none(),
                "and nothing is left over"
            );
        }
    }

    #[test]
    fn a_partial_frame_waits_and_an_unbounded_one_does_not() {
        for framing in NativeFraming::ALL {
            let framing = Framing::new(*framing);
            let whole = framing.encode(br#"{"id":1}"#);
            let mut buffer = whole[..whole.len() - 1].to_vec();
            assert!(
                framing.decode(&mut buffer).expect("readable").is_none(),
                "half a frame is not a frame"
            );
        }
        // A declared length past the bound is refused before anything is allocated for it.
        let framing = Framing::new(NativeFraming::LengthPrefixed);
        let mut buffer = format!("{}\n", MAX_NATIVE_FRAME_BYTES + 1).into_bytes();
        assert!(framing.decode(&mut buffer).is_err());
    }
}
