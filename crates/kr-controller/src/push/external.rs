//! Delivering an external message to a webhook its owner configured.
//!
//! One request per attempt: `POST <endpoint>` with the composed message as JSON, the document the
//! journal holds, and, when the destination deduplicates by a delivery identifier, that identifier
//! in the header the destination names. The recipients of a webhook read what arrives, and every
//! message says so in its own body: section 19's rule is part of the content rather than of this
//! transport.
//!
//! # Which answer is which
//!
//! | Answer | Outcome |
//! | --- | --- |
//! | A 2xx | Delivered |
//! | A 409 from a destination that deduplicates by identifier | It already had this delivery |
//! | 408, 425 or 429 | Nothing was taken: the destination asked for later |
//! | Any other 4xx | Refused, and a retry cannot change that |
//! | A 5xx, an unreadable answer, a failure after the request left | Nobody knows |
//! | A failure before a byte was written | Nothing was sent |
//!
//! What a retry is allowed to do with each is section 25's rule and not this adapter's:
//! [`kr_delivery::external::decide_external`] retries only a destination that deduplicates by the
//! identifier, and marks the duplicate-delivery uncertainty otherwise.
//!
//! # Which kinds
//!
//! Webhooks alone. Slack, Discord, Telegram and email each need a credential from this host's
//! secret store - a Slack or Discord webhook address is itself a bearer secret, and a destination's
//! endpoint is never a credential - and nothing can put one there yet, so a destination of any of
//! those kinds is refused where it is configured (see [`super::DeliveryModule::configure`]).

use std::sync::Arc;

use kr_delivery::destination::{DestinationKind, ExternalDestination, Idempotency};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, ExternalSender};
use kr_protocol::service::GatewayOrigin;

use super::transport::{DeliveryTransports, nothing_was_sent};

/// The most bytes this adapter reads from a destination's answer.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The webhook adapter a pass sends external messages through.
#[derive(Clone, Debug)]
pub struct WebhookSender {
    transports: Arc<dyn DeliveryTransports>,
    runtime: tokio::runtime::Handle,
}

impl WebhookSender {
    /// Builds the adapter over the transports this host reaches destinations through.
    #[must_use]
    pub fn new(transports: Arc<dyn DeliveryTransports>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            transports,
            runtime,
        }
    }
}

impl ExternalSender for WebhookSender {
    fn send(
        &self,
        destination: &ExternalDestination,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        if destination.kind != DestinationKind::Webhook {
            return ExternalOutcome::NotDispatched {
                detail: format!(
                    "this host has no credential to deliver to a {} destination",
                    destination.kind
                ),
            };
        }
        let origin = match webhook_origin(&destination.endpoint) {
            Ok(origin) => origin,
            Err(detail) => return ExternalOutcome::NotDispatched { detail },
        };
        let body = match serde_json::to_vec(&kr_delivery::producer::message_json(message)) {
            Ok(body) => body,
            Err(error) => {
                return ExternalOutcome::NotDispatched {
                    detail: format!("the message could not be encoded: {error}"),
                };
            }
        };
        let transport = match self.transports.to(&origin) {
            Ok(transport) => transport,
            Err(detail) => return ExternalOutcome::NotDispatched { detail },
        };
        // The identifier travels only to a destination that said it deduplicates by one, under
        // the header it named. Anything else would be a promise this host cannot keep.
        let header = match (&destination.idempotency, &message.delivery_id) {
            (Idempotency::Supported { field }, Some(delivery_id)) => {
                Some((field.to_ascii_lowercase(), delivery_id.clone()))
            }
            _ => None,
        };
        let headers: Vec<(&str, &str)> = header
            .as_ref()
            .map(|(name, value)| vec![(name.as_str(), value.as_str())])
            .unwrap_or_default();
        let answer = self.runtime.block_on(async {
            transport
                .post_json(&destination.endpoint, &body, &headers)
                .await
        });
        let answer = match answer {
            Ok(answer) => answer,
            Err(error) if nothing_was_sent(&error) => {
                return ExternalOutcome::NotDispatched {
                    detail: format!("the destination could not be reached: {error}"),
                };
            }
            Err(error) => {
                return ExternalOutcome::Unknown {
                    detail: format!("the destination did not answer: {error}"),
                };
            }
        };
        if answer.body.len() > MAX_ANSWER_BYTES {
            return ExternalOutcome::Unknown {
                detail: format!(
                    "the destination's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host \
                     reads",
                    answer.body.len()
                ),
            };
        }
        match answer.status {
            200..=299 => ExternalOutcome::Delivered,
            409 if destination.idempotency.supports_retry() => ExternalOutcome::Duplicate,
            408 | 425 | 429 => ExternalOutcome::NotDispatched {
                detail: format!(
                    "the destination asked for later ({}) without taking the message",
                    answer.status
                ),
            },
            400..=499 => ExternalOutcome::Refused {
                detail: format!("the destination answered {}", answer.status),
            },
            status => ExternalOutcome::Unknown {
                detail: format!("the destination answered {status}"),
            },
        }
    }
}

/// Why this host holds no way to deliver to a destination of `kind`, or `None` when it does.
///
/// A paired device and a webhook need nothing beyond their own configuration. Each of the other
/// four needs a credential from this host's secret store, and a destination's endpoint is never a
/// credential. Configuration refuses those kinds with this reason, and a pass settles anything of
/// those kinds with it rather than calling an adapter.
#[must_use]
pub const fn credential_needed(kind: DestinationKind) -> Option<&'static str> {
    match kind {
        DestinationKind::Push | DestinationKind::Webhook => None,
        DestinationKind::Slack | DestinationKind::Discord => {
            Some("its webhook address is itself a bearer secret")
        }
        DestinationKind::Telegram => Some("it sends through a bot token"),
        DestinationKind::Email => Some("it sends through a mail account"),
    }
}

/// The origin a webhook's address belongs to, or why this host will not deliver there.
///
/// HTTPS, or plain HTTP on loopback alone, and no credentials in the address: the managed
/// transport keeps the same rules, and a destination that breaks them is refused where it is
/// configured rather than on its first delivery.
///
/// # Errors
///
/// Returns why the address is not one this host delivers to.
pub fn webhook_origin(endpoint: &str) -> Result<GatewayOrigin, String> {
    let address = url::Url::parse(endpoint)
        .map_err(|_| "a webhook endpoint is an absolute address".to_owned())?;
    if !address.username().is_empty() || address.password().is_some() {
        return Err("a webhook endpoint carries no credentials in its address".to_owned());
    }
    GatewayOrigin::new(address.origin().ascii_serialization())
        .map_err(|error| format!("a webhook endpoint is not an address this host reaches: {error}"))
}
