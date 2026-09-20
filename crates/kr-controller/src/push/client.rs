//! The HTTP client that speaks the deployed gateway's delivery API.
//!
//! One route, one body, one header. `POST <origin>/api/push/deliver` with
//! `Authorization: Bearer <credential secret>` and a [`PushDeliveryRequest`] as JSON; the answer is
//! the standard envelope around a [`PushDeliveryAck`]. The wire shapes are the protocol's own
//! types, so the host and the gateway agree by construction rather than by two descriptions of one
//! document.
//!
//! # Which failure is which
//!
//! Section 23 lets a request be retried automatically only when its receipt proves no dispatch.
//! This client is therefore conservative about which failures it calls
//! [`SendOutcome::NotDispatched`]: only one where the request was never written. A connection that
//! failed after the body went out, a timeout, and an answer this build cannot read are all
//! [`SendOutcome::Unknown`], which is the answer that stops the automatic retry. Being wrong in
//! that direction costs a notification a person can still see on the host; being wrong in the
//! other direction sends it twice.

use std::time::Duration;

use kr_delivery::external::ExternalMessage;
use kr_delivery::push::{PushSender, SendOutcome};
use kr_protocol::push::{PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest};
use kr_protocol::service::GatewayOrigin;

use crate::error::{ControllerError, Result};

/// The route a delivery is presented on.
pub const DELIVER_ROUTE: &str = "/api/push/deliver";

/// How long one call to the gateway may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// The most bytes this client reads from an answer.
pub const MAX_ANSWER_BYTES: u64 = 16 * 1024;

/// The gateway this host delivers through.
#[derive(Debug)]
pub struct GatewayClient {
    origin: GatewayOrigin,
    agent: ureq::Agent,
}

impl GatewayClient {
    /// Builds a client for one gateway origin.
    #[must_use]
    pub fn new(origin: GatewayOrigin) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(CALL_TIMEOUT))
            // A delivery carries a bearer credential. A redirect is a different address, and a
            // bearer that followed one would be a bearer handed to whoever answered.
            .max_redirects(0)
            .https_only(!origin.as_str().starts_with("http://"))
            .user_agent("KalaReach")
            .build();
        Self {
            origin,
            agent: config.into(),
        }
    }

    /// The origin this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
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
        let url = format!("{}{DELIVER_ROUTE}", self.origin.as_str());
        let call = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                &format!("Bearer {}", hex(credential.secret.expose())),
            )
            .send(&body[..]);
        let mut response = match call {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(status)) => return Self::status(status, String::new()),
            Err(ureq::Error::ConnectionFailed | ureq::Error::HostNotFound) => {
                // The request was never written, so presenting it again cannot be a second
                // notification. This is the one failure that is retried automatically.
                return SendOutcome::NotDispatched {
                    detail: "the gateway could not be reached".to_owned(),
                };
            }
            Err(error) => {
                return SendOutcome::Unknown {
                    detail: format!("the gateway did not answer: {error}"),
                };
            }
        };
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_string()
            .unwrap_or_default();
        if status != 200 {
            return Self::status(status, text);
        }
        match serde_json::from_str::<Envelope>(&text) {
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
        }
    }

    fn status(status: u16, detail: String) -> SendOutcome {
        match status {
            // Section 16: a 403 means the credential is expired, revoked or aimed at another
            // authorisation. It is renewed, not retried.
            403 => SendOutcome::Forbidden {
                detail: if detail.is_empty() {
                    "the gateway refused the credential".to_owned()
                } else {
                    detail
                },
            },
            // The gateway claims the notification identifier before anything reaches a provider,
            // so a refusal it answers with a status cannot have dispatched one. It is still not
            // retried blindly: a 4xx other than 403 is a request this host has to change.
            400..=499 => SendOutcome::NotDispatched {
                detail: format!("the gateway refused the request with {status}: {detail}"),
            },
            _ => SendOutcome::Unknown {
                detail: format!("the gateway answered {status}: {detail}"),
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

    fn receipt(
        &self,
        credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        // The identical request again. The gateway claimed the identifier before it sent anything
        // and answers a repeat from the outcome it recorded, so this reads a decision rather than
        // making a second one.
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
    Ok(ExternalMessage {
        delivery_id: stored.delivery_id,
        alert,
        body: stored.body,
        provenance: kr_worker::history_filter::Provenance {
            interval: kr_worker::history_filter::SourceInterval::new(
                stored.interval.from_ms.parse().unwrap_or(0),
                stored.interval.to_ms.parse().unwrap_or(0),
            ),
            resources: stored.resources,
        },
        // The reasons a line was withheld are in the body the recipient reads; the record here is
        // what the host shows locally, and it is rebuilt as a count rather than re-derived.
        withheld: Vec::new(),
    })
}

#[derive(serde::Deserialize)]
struct StoredMessage {
    alert: String,
    body: String,
    delivery_id: Option<String>,
    interval: StoredInterval,
    resources: Vec<String>,
}

#[derive(serde::Deserialize)]
struct StoredInterval {
    from_ms: String,
    to_ms: String,
}

/// Renders a credential's bearer as the gateway expects it.
///
/// It is used once, in the header of one request, and never written anywhere. The secret's own
/// debug rendering is a redaction, which is why this is spelled out here rather than formatted.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
