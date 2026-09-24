//! Delivering an external message: the one sender a pass hands every external destination to, and
//! the webhook adapter it hands a webhook to.
//!
//! [`ExternalSenders`] reads a destination's kind and passes it on: a webhook to [`WebhookSender`],
//! Slack, Discord and Telegram to [`super::chat::ChatSender`], and email to
//! [`super::mail::MailSender`]. Each of the last four is handed the credential the pass read from
//! this host's secret store for this attempt, after checking it is the one the destination was
//! configured with.
//!
//! # Webhooks
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
//! | 408, 425 or 429 | Nothing was taken: the destination asked for later |
//! | Any other 4xx, a 409 included | Refused, and a retry cannot change that |
//! | A 5xx, an unreadable answer, a failure after the request left | Nobody knows |
//! | A failure before a byte was written | Nothing was sent |
//!
//! No status code says "I already had this". A webhook that deduplicates by the identifier this
//! host sends says what it does with a repeat, not how it answers one, and a 409 is as likely to be
//! a conflict in the receiver's own records on the first delivery; reading it as a duplicate would
//! record a delivery nobody confirmed. So a webhook is never reported as a duplicate from its
//! status code.
//!
//! What a retry is allowed to do with each answer is section 25's rule and not this adapter's:
//! [`kr_delivery::external::decide_external`] retries only a destination that deduplicates by the
//! identifier, and marks the duplicate-delivery uncertainty otherwise.
//!
//! # The other four kinds
//!
//! Slack, Discord, Telegram and email each send with a credential - a Slack or Discord webhook
//! address is itself a bearer secret, a Telegram bot sends through its token and email through a
//! mail submission account - and a destination's endpoint is never a credential. The owner hands
//! one over through `delivery.destination.secret.set`, [`check_secret`] checks it for the shape its
//! service issues, and this host keeps it in its secret store. A destination of one of those kinds
//! is configured only once its credential is kept, and [`check_destination`] checks what the
//! endpoint names: the channel a webhook posts to, a Telegram chat, or an email recipient. None of
//! the four deduplicates by an identifier this host could choose, so none is configured with one.

use std::sync::Arc;

use kr_delivery::destination::{DestinationKind, ExternalDestination, Idempotency};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, ExternalSender};
use kr_protocol::delivery::DestinationSecret;
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
        _credential: Option<&DestinationSecret>,
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

/// Checks a credential for the shape its service issues, before it is kept.
///
/// A credential is refused rather than kept when it could send content anywhere but the service
/// its kind names, and every refusal names the rule it broke and never the credential.
///
/// # Errors
///
/// Returns the rule the credential broke.
pub fn check_secret(secret: &DestinationSecret) -> Result<(), String> {
    match secret {
        DestinationSecret::Slack { webhook_url } => {
            super::chat::check_slack_webhook(webhook_url.expose()).map(drop)
        }
        DestinationSecret::Discord { webhook_url } => {
            super::chat::check_discord_webhook(webhook_url.expose()).map(drop)
        }
        DestinationSecret::Telegram { bot_token } => {
            super::chat::check_telegram_token(bot_token.expose())
        }
        DestinationSecret::Email { account } => super::mail::check_account(account),
    }
}

/// Checks what an external destination of a credentialed kind names, and how it may be retried.
///
/// The endpoint is never the credential: for Slack and Discord it names the channel the webhook
/// posts to, for Telegram it is the chat, and for email the recipient's address. None of the four
/// services recognises a repeat by an identifier this host chooses, so a destination of those kinds
/// that claims one is refused: section 25 retries only where the destination deduplicates, and a
/// claim the service does not keep would turn an unknown outcome into a second message.
///
/// # Errors
///
/// Returns the rule the destination broke.
pub fn check_destination(destination: &ExternalDestination) -> Result<(), String> {
    match destination.kind {
        DestinationKind::Push | DestinationKind::Webhook => return Ok(()),
        DestinationKind::Slack | DestinationKind::Discord => {
            super::chat::check_channel_label(&destination.endpoint)?;
        }
        DestinationKind::Telegram => super::chat::check_telegram_chat(&destination.endpoint)?,
        DestinationKind::Email => super::mail::check_address(&destination.endpoint)
            .map_err(|rule| format!("an email destination's recipient: {rule}"))?,
    }
    if destination.idempotency.supports_retry() {
        return Err(format!(
            "a {} destination takes no identifier it would recognise a repeat by, so it is \
             configured without one",
            destination.kind
        ));
    }
    Ok(())
}

/// The sender a pass hands every external destination to.
#[derive(Clone, Debug)]
pub struct ExternalSenders {
    webhook: WebhookSender,
    chat: super::chat::ChatSender,
    mail: super::mail::MailSender,
}

impl ExternalSenders {
    /// Builds every adapter over the transports this host reaches destinations through, with mail
    /// submitted under `mail`.
    #[must_use]
    pub fn new(
        transports: Arc<dyn DeliveryTransports>,
        runtime: tokio::runtime::Handle,
        mail: super::mail::MailSubmission,
    ) -> Self {
        Self {
            webhook: WebhookSender::new(Arc::clone(&transports), runtime.clone()),
            chat: super::chat::ChatSender::new(transports, runtime.clone()),
            mail: super::mail::MailSender::new(mail, runtime),
        }
    }
}

impl ExternalSender for ExternalSenders {
    fn send(
        &self,
        destination: &ExternalDestination,
        credential: Option<&DestinationSecret>,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        match (destination.kind, credential) {
            (DestinationKind::Webhook, _) => self.webhook.send(destination, None, message),
            (
                DestinationKind::Slack | DestinationKind::Discord | DestinationKind::Telegram,
                Some(secret),
            ) => self.chat.send(destination, secret, message),
            (DestinationKind::Email, Some(DestinationSecret::Email { account })) => {
                self.mail.send(destination, account, message)
            }
            (kind, _) => ExternalOutcome::Unsendable {
                detail: format!(
                    "a {kind} destination was handed to the external senders without the \
                     credential it sends with"
                ),
            },
        }
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
