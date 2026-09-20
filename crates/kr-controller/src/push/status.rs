//! Asking the gateway what became of a notification it was already given.
//!
//! One route, one identifier, no content. `POST <origin>/api/push/deliver/status` with
//! `Authorization: Bearer <credential secret>` and a body that carries the notification identifier
//! alone; the answer is the standard envelope around the [`PushDeliveryAck`] the gateway recorded,
//! or an envelope with no decision when it holds nothing under that identifier.
//!
//! # Why this is not the delivery request again
//!
//! The delivery route takes a request and may dispatch it. Reading an outcome by presenting that
//! request again therefore rests on the gateway recognising the identifier and answering from what
//! it recorded - and on the one case where it does not, an identifier it never claimed, the repeat
//! *is* a dispatch. A host cannot tell those apart from the outside, so asking the question that
//! way means every unresolved notification carries a chance of being delivered by the act of
//! asking about it. This route carries no request to dispatch.
//!
//! # What an unanswered question means
//!
//! Nothing. Section 24 reports completion only once in-flight work is reconciled, and a question
//! nobody answered has reconciled nothing: the record keeps its unknown outcome, keeps counting as
//! outstanding, and stays in the retained artifacts a person is shown. It is never settled by
//! assuming what the silence meant.

use std::sync::Arc;

use kr_client::services::{ServiceHttp, ServiceHttpAnswer};
use kr_delivery::push::{DeliveryStatus, StatusAnswer};
use kr_protocol::ids::NotificationId;
use kr_protocol::push::{PushDeliveryAck, PushDeliveryCredential};
use kr_protocol::service::GatewayOrigin;

use super::client::bearer;

/// The route a delivery's recorded outcome is read from.
pub const STATUS_ROUTE: &str = "/api/push/deliver/status";

/// The most bytes this client reads from an answer.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The gateway this host asks about its own deliveries.
///
/// The HTTP exchange is the embedder's, as it is everywhere else a managed service is reached: a
/// desktop build, a mobile build and a test each reach the network differently, and the
/// composition root attaches the one this host runs with.
#[derive(Clone, Debug)]
pub struct GatewayStatus {
    origin: GatewayOrigin,
    http: Arc<dyn ServiceHttp>,
    runtime: tokio::runtime::Handle,
}

impl GatewayStatus {
    /// Builds a status client for one gateway origin.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            origin,
            http,
            runtime,
        }
    }

    /// The origin this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    fn exchange(&self, body: &[u8], bearer: &str) -> Result<ServiceHttpAnswer, String> {
        let url = format!("{}{STATUS_ROUTE}", self.origin.as_str());
        let header = format!("Bearer {bearer}");
        // The delivery pass is synchronous and runs on a blocking thread, and the transport is
        // asynchronous because every other managed-service client is. The handle is the one the
        // daemon runs on, so the exchange is driven by the daemon's own reactor rather than by a
        // second runtime built for one request.
        self.runtime
            .block_on(async {
                self.http
                    .post_json(&url, body, &[("authorization", header.as_str())])
                    .await
            })
            .map_err(|error| error.to_string())
    }
}

impl DeliveryStatus for GatewayStatus {
    fn status(
        &self,
        credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> StatusAnswer {
        let body = match serde_json::to_vec(&StatusRequest { notification_id }) {
            Ok(body) => body,
            Err(error) => {
                return StatusAnswer::Unanswered {
                    detail: format!("the question could not be encoded: {error}"),
                };
            }
        };
        let answer = match self.exchange(&body, &bearer(credential.secret.expose())) {
            Ok(answer) => answer,
            Err(detail) => {
                return StatusAnswer::Unanswered {
                    detail: format!("the gateway did not answer: {detail}"),
                };
            }
        };
        if answer.body.len() > MAX_ANSWER_BYTES {
            return StatusAnswer::Unanswered {
                detail: format!(
                    "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host \
                     reads",
                    answer.body.len()
                ),
            };
        }
        match answer.status {
            200 => match serde_json::from_slice::<Envelope>(&answer.body) {
                Ok(Envelope {
                    ok: true,
                    data: Some(ack),
                }) => StatusAnswer::Recorded(Box::new(ack)),
                // The gateway answered and holds nothing. That is a fact about its records, and
                // this host draws no conclusion about the notification from it.
                Ok(Envelope { ok: true, data: _ }) => StatusAnswer::NoRecord {
                    detail: "the gateway holds no outcome under that identifier".to_owned(),
                },
                Ok(_) => StatusAnswer::Unanswered {
                    detail: "the gateway refused the question".to_owned(),
                },
                Err(error) => StatusAnswer::Unanswered {
                    detail: format!("the gateway's answer could not be read: {error}"),
                },
            },
            404 => StatusAnswer::NoRecord {
                detail: "the gateway holds no outcome under that identifier".to_owned(),
            },
            // A refused credential is renewed rather than retried, and a question this host may
            // not ask resolves nothing. Both leave the record where it is.
            status => StatusAnswer::Unanswered {
                detail: format!("the gateway answered {status} to the question"),
            },
        }
    }
}

/// The question, which carries an identifier and nothing else.
#[derive(serde::Serialize)]
struct StatusRequest {
    notification_id: NotificationId,
}

/// The standard envelope the gateway answers with.
#[derive(serde::Deserialize)]
struct Envelope {
    ok: bool,
    data: Option<PushDeliveryAck>,
}
