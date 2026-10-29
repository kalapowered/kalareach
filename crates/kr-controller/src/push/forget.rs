//! Asking the gateway to delete what it still holds for a notification this host gave it.
//!
//! One route, one identifier. `POST <gateway>/api/push/deliver/forget` with
//! `Authorization: Bearer <credential secret>` and a body that names the notification; the answer is
//! the standard envelope around what the gateway held for it and whether a copy had already begun
//! to go to a provider. The gateway is the one the credential names.
//!
//! # What the answer is worth
//!
//! Deleting at the gateway removes the record it kept: a notification still queued is not sent, and
//! a decision it recorded is gone. It recalls nothing a provider already accepted, and it does not
//! reach a device. So the answer is an account of what the gateway held and not a claim that the
//! notification never left; the person is shown the copy as one that may have left either way.
//! `none` covers a notification the gateway never saw, one of another authorisation, and one
//! already removed or swept, and this host does not tell them apart because the gateway does not.
//!
//! # What an unanswered request means
//!
//! Nothing was deleted that this host can say, and nothing is recorded about the attempt: the copy
//! stays listed as it was and the person asks again. A refused credential is not retried here. The
//! credential store renews a credential that ran out, and the person asks again once it has.

use std::sync::Arc;

use kr_client::services::ServiceHttpAnswer;
use kr_protocol::ids::NotificationId;
use kr_protocol::push::PushDeliveryCredential;

use super::client::bearer;
use super::transport::DeliveryTransports;

/// The route a host asks the gateway to delete what it holds for a notification on.
pub const FORGET_ROUTE: &str = "/api/push/deliver/forget";

/// The most bytes this client reads from an answer.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// What the gateway was holding for the notification when the deletion reached it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// The notification was still queued and is not sent now.
    Queued,
    /// The gateway had decided and held the record of that decision.
    Settled,
    /// Nothing under that identifier, so nothing was removed.
    Nothing,
}

/// What the gateway answered to a request to delete what it holds for one notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForgetAnswer {
    /// The gateway answered for the notification. `dispatched` is read with `held`: it says a copy
    /// may already have gone to the provider, and means nothing where `held` is
    /// [`Held::Nothing`].
    Answered {
        /// What the gateway held.
        held: Held,
        /// Whether a copy may already have gone to the provider.
        dispatched: bool,
    },
    /// The gateway does not take the credential: it is revoked, expired or not the gateway's.
    CredentialRefused,
    /// The gateway refused the request in its own words' code, such as a rate limit.
    Refused {
        /// The code of the refusal.
        code: String,
    },
    /// No answer this host can read, and the detail of why.
    Unanswered {
        /// Why, never repeating what the answer held.
        detail: String,
    },
}

/// The gateway this host asks to delete what it holds.
///
/// The HTTP exchange is the embedder's, as it is everywhere else a managed service is reached: the
/// daemon attaches the managed transport, and a test attaches a recorder.
#[derive(Clone, Debug)]
pub struct GatewayForget {
    transports: Arc<dyn DeliveryTransports>,
    runtime: tokio::runtime::Handle,
}

impl GatewayForget {
    /// Builds a client over the transports this host reaches its gateways through.
    #[must_use]
    pub fn new(transports: Arc<dyn DeliveryTransports>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            transports,
            runtime,
        }
    }

    /// Asks the gateway the credential names to delete what it holds for `notification_id`.
    ///
    /// Blocks on the daemon's reactor, so a caller runs it on a blocking thread.
    #[must_use]
    pub fn forget(
        &self,
        credential: &PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> ForgetAnswer {
        let body = match serde_json::to_vec(&ForgetRequest {
            notification_ids: [notification_id],
        }) {
            Ok(body) => body,
            Err(error) => {
                return ForgetAnswer::Unanswered {
                    detail: format!("the request could not be encoded: {error}"),
                };
            }
        };
        let transport = match self.transports.to(&credential.gateway_origin) {
            Ok(transport) => transport,
            Err(detail) => {
                return ForgetAnswer::Unanswered {
                    detail: format!("no transport reaches the gateway: {detail}"),
                };
            }
        };
        let url = format!("{}{FORGET_ROUTE}", credential.gateway_origin.as_str());
        let header = format!("Bearer {}", bearer(credential.secret.expose()));
        let answered = self.runtime.block_on(async {
            transport
                .post_json(&url, &body, &[("authorization", header.as_str())])
                .await
        });
        match answered {
            Ok(answer) => read_answer(&answer, notification_id),
            Err(error) => ForgetAnswer::Unanswered {
                detail: format!("the gateway did not answer: {error}"),
            },
        }
    }
}

/// What one answer says.
///
/// The answer is read through the client's one reader, so a text that names a member twice answers
/// nothing, and what a failure says is where the text failed, never what it held. An answer that
/// names another notification, or more than the one asked about, is not an answer to this request.
fn read_answer(answer: &ServiceHttpAnswer, asked: NotificationId) -> ForgetAnswer {
    if answer.body.len() > MAX_ANSWER_BYTES {
        return ForgetAnswer::Unanswered {
            detail: format!(
                "the gateway's answer was {} bytes, past the {MAX_ANSWER_BYTES} this host reads",
                answer.body.len()
            ),
        };
    }
    let envelope = match kr_client::services::json::read::<Envelope>(&answer.body) {
        Ok(envelope) => envelope,
        Err(fault) => {
            return ForgetAnswer::Unanswered {
                detail: format!(
                    "the gateway's answer ({}) could not be read: {fault}",
                    answer.status
                ),
            };
        }
    };
    match (answer.status, envelope) {
        (
            200,
            Envelope {
                ok: true,
                data: Some(Account { removed }),
                ..
            },
        ) => match removed.as_slice() {
            [outcome] if outcome.notification_id == asked => ForgetAnswer::Answered {
                held: outcome.held,
                dispatched: outcome.dispatched,
            },
            _ => ForgetAnswer::Unanswered {
                detail: "the gateway's answer is not about the one notification asked about"
                    .to_owned(),
            },
        },
        (
            401,
            Envelope {
                ok: false,
                error: Some(Refusal { code }),
                ..
            },
        ) if code == "UNAUTHENTICATED" => ForgetAnswer::CredentialRefused,
        (
            _,
            Envelope {
                ok: false,
                error: Some(Refusal { code }),
                ..
            },
        ) => ForgetAnswer::Refused { code },
        (status, _) => ForgetAnswer::Unanswered {
            detail: format!("the gateway answered {status} without a deletion's account"),
        },
    }
}

/// The request, which names the one notification and nothing else.
#[derive(serde::Serialize)]
struct ForgetRequest {
    notification_ids: [NotificationId; 1],
}

/// The standard envelope the gateway answers with.
#[derive(serde::Deserialize)]
struct Envelope {
    ok: bool,
    #[serde(default)]
    data: Option<Account>,
    #[serde(default)]
    error: Option<Refusal>,
}

/// The gateway's account of a deletion, one outcome for each identifier named.
#[derive(serde::Deserialize)]
struct Account {
    removed: Vec<Outcome>,
}

/// What the gateway held for one notification, and whether a copy had begun to go to a provider.
#[derive(serde::Deserialize)]
struct Outcome {
    notification_id: NotificationId,
    #[serde(deserialize_with = "held")]
    held: Held,
    dispatched: bool,
}

/// The code of the gateway's refusal, the only word of it this host reads.
#[derive(serde::Deserialize)]
struct Refusal {
    code: String,
}

/// Reads what the gateway held, in the words the contract gives it.
fn held<'de, D>(deserializer: D) -> Result<Held, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let word = <String as serde::Deserialize>::deserialize(deserializer)?;
    match word.as_str() {
        "queued" => Ok(Held::Queued),
        "settled" => Ok(Held::Settled),
        "none" => Ok(Held::Nothing),
        _ => Err(serde::de::Error::custom(
            "a deletion's account held something this host does not know",
        )),
    }
}
