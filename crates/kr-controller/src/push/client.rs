//! The client that presents a notification to the gateway that issued its credential.
//!
//! One route, one body, one header. `POST <gateway>/api/push/deliver` with
//! `Authorization: Bearer <credential secret>` and a [`PushDeliveryRequest`] as JSON; the answer is
//! the standard envelope around a [`PushDeliveryAck`]. The wire shapes are the protocol's own
//! types, so the host and the gateway agree by construction rather than by two descriptions of one
//! document. The gateway is the one the credential names, which is the only one that can read it.
//!
//! Reading what became of a delivery is [`super::status`], on a route of its own. This client
//! sends; it has no read.
//!
//! # Which failure is which
//!
//! Section 23 lets a request be retried automatically only when its receipt proves no dispatch.
//! This client is therefore conservative about which failures it calls
//! [`SendOutcome::NotDispatched`]: only the ones the managed transport reports before a byte of the
//! request was written (see [`super::transport::nothing_was_sent`]). A connection that failed after
//! the body went out, a deadline, and an answer this build cannot read are all
//! [`SendOutcome::Unknown`], which is the answer that stops the automatic retry. Being wrong in
//! that direction costs a notification a person can still see on the host; being wrong in the
//! other direction sends it twice.

use std::sync::Arc;

use kr_client::services::ServiceHttpAnswer;
use kr_delivery::external::ExternalMessage;
use kr_delivery::push::{PushSender, SendOutcome};
use kr_protocol::ids::NotificationId;
use kr_protocol::push::{PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest};
use kr_protocol::scalars::TimestampMs;

use super::transport::{DeliveryTransports, nothing_was_sent};
use crate::error::{ControllerError, Result};

/// The route a delivery is presented on.
pub const DELIVER_ROUTE: &str = "/api/push/deliver";

/// The most bytes this client reads from an answer.
///
/// An acknowledgement is a few hundred bytes. An answer past this reached the host, so whatever
/// the gateway did is done, and what this client lacks is an answer it can trust.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The gateway client a pass presents notifications through.
#[derive(Clone, Debug)]
pub struct GatewayClient {
    transports: Arc<dyn DeliveryTransports>,
    runtime: tokio::runtime::Handle,
}

impl GatewayClient {
    /// Builds a client over the transports this host reaches its gateways through.
    ///
    /// `runtime` is the daemon's own: a pass is synchronous and runs on a blocking thread, the
    /// transport is asynchronous, and the exchange is driven by the daemon's reactor rather than
    /// by a second runtime built for one request.
    #[must_use]
    pub fn new(transports: Arc<dyn DeliveryTransports>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            transports,
            runtime,
        }
    }

    fn present(
        &self,
        credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        let body = match serde_json::to_vec(request) {
            Ok(body) => body,
            Err(error) => {
                return SendOutcome::NotDispatched {
                    detail: format!("the request could not be encoded: {error}"),
                };
            }
        };
        let transport = match self.transports.to(&credential.gateway_origin) {
            Ok(transport) => transport,
            Err(detail) => return SendOutcome::NotDispatched { detail },
        };
        let url = format!("{}{DELIVER_ROUTE}", credential.gateway_origin.as_str());
        let header = format!("Bearer {}", bearer(credential.secret.expose()));
        let answer = self.runtime.block_on(async {
            transport
                .post_json(&url, &body, &[("authorization", header.as_str())])
                .await
        });
        match answer {
            Ok(answer) => Self::answered(&answer, request.notification_id),
            Err(error) if nothing_was_sent(&error) => SendOutcome::NotDispatched {
                detail: format!("the gateway could not be reached: {error}"),
            },
            Err(error) => SendOutcome::Unknown {
                detail: format!("the gateway did not answer: {error}"),
            },
        }
    }

    /// What one answer from the gateway means for the request that received it.
    fn answered(answer: &ServiceHttpAnswer, notification_id: NotificationId) -> SendOutcome {
        if answer.body.len() > MAX_ANSWER_BYTES {
            return SendOutcome::Unknown {
                detail: format!(
                    "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host \
                     reads",
                    answer.body.len()
                ),
            };
        }
        let text = String::from_utf8_lossy(&answer.body);
        match answer.status {
            200 => match serde_json::from_slice::<Envelope>(&answer.body) {
                Ok(Envelope {
                    ok: true,
                    data: Some(ack),
                }) => SendOutcome::Decided(Box::new(ack)),
                Ok(_) => SendOutcome::Unknown {
                    detail: "the gateway answered without a decision".to_owned(),
                },
                Err(error) => SendOutcome::Unknown {
                    detail: format!("the gateway's answer could not be read: {error}"),
                },
            },
            // Section 16: a refused credential is renewed, not retried. The gateway answers 401
            // for a credential it cannot read or match and 403 for one aimed at another
            // authorisation; both mean the same thing to this host.
            401 | 403 => SendOutcome::Forbidden {
                detail: format!("the gateway refused the credential: {text}"),
            },
            // A 429 is the gateway asking for later, and it claims the identifier before it
            // sends anything, so nothing was dispatched.
            429 => SendOutcome::NotDispatched {
                detail: format!("the gateway asked for later: {text}"),
            },
            // Any other 4xx is a request this host has to change: a schema failure or an
            // authorisation the gateway does not hold. Section 23 says a configuration or software
            // change fixes those, so they are refused rather than presented again, and the refusal
            // is recorded against the notification that was refused.
            400..=499 => SendOutcome::Decided(Box::new(PushDeliveryAck {
                decided_at_ms: TimestampMs::new(0),
                notification_id,
                state: kr_protocol::push::PushDeliveryState::Refused,
                suppression: kr_protocol::scalars::Nullable::null(),
            })),
            status => SendOutcome::Unknown {
                detail: format!("the gateway answered {status}: {text}"),
            },
        }
    }
}

impl PushSender for GatewayClient {
    fn send(
        &self,
        credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        self.present(credential, request)
    }
}

/// The standard envelope the gateway answers with.
#[derive(serde::Deserialize)]
struct Envelope {
    ok: bool,
    data: Option<PushDeliveryAck>,
}

/// Reads a composed external message back out of the journal.
///
/// # Errors
///
/// Returns [`ControllerError::Storage`] when the stored document is not one this build wrote.
pub fn message_from(content: &[u8]) -> Result<ExternalMessage> {
    let stored: StoredMessage =
        serde_json::from_slice(content).map_err(|error| ControllerError::Storage {
            operation: "read a queued external message",
            detail: error.to_string(),
        })?;
    let alert = kr_protocol::push::PushAlert::ALL
        .into_iter()
        .find(|alert| alert.as_str() == stored.alert)
        .ok_or(ControllerError::Storage {
            operation: "read a queued external message",
            detail: "a stored alert is not one this build writes".to_owned(),
        })?;
    let from_ms =
        stored
            .interval
            .from_ms
            .parse::<u64>()
            .map_err(|error| ControllerError::Storage {
                operation: "read a queued external message",
                detail: format!("invalid interval from_ms: {error}"),
            })?;
    let to_ms = stored
        .interval
        .to_ms
        .parse::<u64>()
        .map_err(|error| ControllerError::Storage {
            operation: "read a queued external message",
            detail: format!("invalid interval to_ms: {error}"),
        })?;
    let mut withheld = Vec::with_capacity(stored.withheld.len());
    for [reason_str, count_str] in stored.withheld {
        let reason =
            kr_delivery::external::Withheld::from_stored(&reason_str).ok_or_else(|| {
                ControllerError::Storage {
                    operation: "read a queued external message",
                    detail: format!("unknown withheld reason: {reason_str}"),
                }
            })?;
        let count = count_str
            .parse::<u64>()
            .map_err(|error| ControllerError::Storage {
                operation: "read a queued external message",
                detail: format!("invalid withheld count: {error}"),
            })?;
        withheld.push((reason, count));
    }
    Ok(ExternalMessage {
        delivery_id: stored.delivery_id,
        alert,
        body: stored.body,
        provenance: kr_worker::history_filter::Provenance {
            interval: kr_worker::history_filter::SourceInterval::new(from_ms, to_ms),
            resources: stored.resources,
        },
        withheld,
    })
}

#[derive(serde::Deserialize)]
struct StoredMessage {
    alert: String,
    body: String,
    delivery_id: Option<String>,
    interval: StoredInterval,
    resources: Vec<String>,
    #[serde(default)]
    withheld: Vec<[String; 2]>,
}

#[derive(serde::Deserialize)]
struct StoredInterval {
    from_ms: String,
    to_ms: String,
}

/// Renders a credential's bearer as the gateway reads it: 32 bytes, unpadded base64url.
///
/// It is used once, in the header of one request, and never written anywhere. The secret's own
/// debug rendering is a redaction, which is why this is spelled out here rather than formatted.
pub(super) fn bearer(bytes: &[u8]) -> String {
    use base64::Engine as _;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
