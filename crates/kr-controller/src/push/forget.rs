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
    /// The gateway refused the request. The code is one of the gateway's published codes, as this
    /// host's own constant, and none when the gateway named any other: its words are the
    /// gateway's, and one that repeats what it was sent repeats the bearer credential.
    Refused {
        /// The published code the refusal names, when it names one.
        code: Option<&'static str>,
    },
    /// No answer this host can read, and the detail of why.
    Unanswered {
        /// Why, never repeating what the answer held.
        detail: String,
    },
}

/// A request to delete what the gateway holds for one notification, ready to be put.
///
/// It holds the credential, the notification and the transport that reaches the gateway, and
/// nothing is sent until [`Self::send`], which only encodes the request and puts it. So a caller
/// can check the authority it acts under once more immediately before the request leaves, with
/// nothing between the check and the request that waits.
#[derive(Debug)]
pub struct PreparedForget {
    runtime: tokio::runtime::Handle,
    transport: Arc<dyn kr_client::services::ServiceHttp>,
    credential: PushDeliveryCredential,
    notification_id: NotificationId,
}

impl PreparedForget {
    /// Puts the request and reads the gateway's answer.
    ///
    /// Blocks on the daemon's reactor, so a caller runs it on a blocking thread.
    #[must_use]
    pub fn send(self) -> ForgetAnswer {
        let body = match serde_json::to_vec(&ForgetRequest {
            notification_ids: [self.notification_id],
        }) {
            Ok(body) => body,
            Err(error) => {
                return ForgetAnswer::Unanswered {
                    detail: format!("the request could not be encoded: {error}"),
                };
            }
        };
        let url = format!("{}{FORGET_ROUTE}", self.credential.gateway_origin.as_str());
        let header = format!("Bearer {}", bearer(self.credential.secret.expose()));
        let answered = self.runtime.block_on(async {
            self.transport
                .post_json(&url, &body, &[("authorization", header.as_str())])
                .await
        });
        match answered {
            Ok(answer) => read_answer(&answer, self.notification_id),
            Err(error) => ForgetAnswer::Unanswered {
                detail: format!("the gateway did not answer: {error}"),
            },
        }
    }
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

    /// Readies the request to the gateway `credential` names for `notification_id`, with the
    /// transport that reaches it.
    ///
    /// # Errors
    ///
    /// Returns why no transport reaches the gateway. Nothing has been sent when this fails.
    pub fn prepare(
        &self,
        credential: PushDeliveryCredential,
        notification_id: NotificationId,
    ) -> Result<PreparedForget, String> {
        let transport = self
            .transports
            .to(&credential.gateway_origin)
            .map_err(|detail| format!("no transport reaches the gateway: {detail}"))?;
        Ok(PreparedForget {
            runtime: self.runtime.clone(),
            transport,
            credential,
            notification_id,
        })
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
                error: None,
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
        ) => ForgetAnswer::Refused {
            code: super::sender::known_code(&code),
        },
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

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn asked() -> NotificationId {
        NotificationId::new(Uuid::from_bytes([7; 16]))
    }

    fn answer(status: u16, body: &serde_json::Value) -> ServiceHttpAnswer {
        ServiceHttpAnswer {
            status,
            body: body.to_string().into_bytes(),
        }
    }

    fn removed(held: &str, dispatched: bool, id: NotificationId) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "data": {
                "removed": [{ "notification_id": id, "held": held, "dispatched": dispatched }],
                "note": "Deletion removes what the gateway still holds.",
            },
        })
    }

    /// The gateway's account for each thing it can have held is read as what it says, and a
    /// success that also names an error, one that names another notification and one that names
    /// more than were asked about are not an answer to this request.
    #[test]
    fn the_gateways_account_is_read_for_the_one_notification_asked_about() {
        for (word, held) in [
            ("queued", Held::Queued),
            ("settled", Held::Settled),
            ("none", Held::Nothing),
        ] {
            assert_eq!(
                read_answer(&answer(200, &removed(word, true, asked())), asked()),
                ForgetAnswer::Answered {
                    held,
                    dispatched: true
                },
                "{word}"
            );
        }

        let other = NotificationId::new(Uuid::from_bytes([8; 16]));
        let mut with_error = removed("settled", false, asked());
        with_error["error"] = serde_json::json!({ "code": "INTERNAL" });
        let mut two = removed("settled", false, asked());
        two["data"]["removed"]
            .as_array_mut()
            .expect("a list")
            .push(serde_json::json!({
                "notification_id": other, "held": "none", "dispatched": false
            }));
        for (why, body) in [
            ("another notification", removed("settled", false, other)),
            ("a word it does not know", removed("sent", false, asked())),
            ("a success naming an error", with_error),
            ("two outcomes", two),
        ] {
            assert!(
                matches!(
                    read_answer(&answer(200, &body), asked()),
                    ForgetAnswer::Unanswered { .. }
                ),
                "{why}"
            );
        }
    }

    /// A refusal is told by its published code, as this host's own constant. A code the gateway
    /// published only by that name is repeated; any other text, which may be what the request
    /// carried, is not.
    #[test]
    fn a_refusal_is_told_by_a_published_code_and_never_by_the_gateways_own_words() {
        let refused = |status: u16, code: &str| {
            read_answer(
                &answer(
                    status,
                    &serde_json::json!({
                        "ok": false,
                        "error": { "code": code, "message": "a-marker-nobody-should-see" },
                    }),
                ),
                asked(),
            )
        };
        assert_eq!(
            refused(401, "UNAUTHENTICATED"),
            ForgetAnswer::CredentialRefused
        );
        assert_eq!(
            refused(429, "RATE_LIMITED"),
            ForgetAnswer::Refused {
                code: Some("RATE_LIMITED")
            }
        );
        assert_eq!(
            refused(400, "a-marker-nobody-should-see"),
            ForgetAnswer::Refused { code: None }
        );
        // An answer the reader cannot take says where it failed and never what it held.
        let ForgetAnswer::Unanswered { detail } = read_answer(
            &answer(
                500,
                &serde_json::json!({ "ok": "a-marker-nobody-should-see" }),
            ),
            asked(),
        ) else {
            panic!("nothing answered");
        };
        assert!(!detail.contains("a-marker-nobody-should-see"), "{detail}");
    }
}
