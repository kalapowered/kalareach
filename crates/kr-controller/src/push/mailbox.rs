//! Putting the encrypted object a notification's preview refers to where its device reads it.
//!
//! A notification whose detail does not fit in a push moves the detail into an object sealed to the
//! paired device's stored-envelope key, and the preview carries only the object's identifier. The
//! device reads the object from its mailbox, so the object has to be there before the device is
//! told about it. This host places it with `mailbox.deliver`, at the mailbox service its
//! configuration document selects (`mailbox.origin`), as part of the notification's own attempt:
//! after every check that decides whether the notification may be presented, and before the push
//! that refers to the object is. The privacy generation, the recipient's authority, the
//! notification's expiry and its retry schedule therefore govern the object as they govern the
//! push, with no second set of rules to keep in step.
//!
//! # What the mailbox service is told
//!
//! One sealed envelope and the key it is addressed to. The service sees the envelope's routing
//! record, its size and when it was placed, as section 20 allows, and nothing of what is inside.
//! The object's identifier is derived from the notification's with a secret only this host holds,
//! so the service cannot tell which push an object belongs to.
//!
//! # Which failure is which
//!
//! Placing an object is safe to repeat: the service answers a second delivery of the same envelope
//! as the first, and refuses a different item under that identifier. So a delivery whose answer is
//! lost, or whose service cannot be reached or asks for later, is [`Placement::Later`]: the
//! notification is not presented, and its next attempt is due when its retry schedule says, or
//! when the service said it would take requests again, whichever is later. A service that will not
//! take this object, because the device's mailbox is full or the item is not one it keeps, is
//! [`Placement::Refused`]: waiting would not change the answer, and the notification is a person's
//! alert, so it is presented without its detail and its record says why.

use std::sync::Arc;
use std::time::Duration;

use kr_client::ClientError;
use kr_client::services::ServiceSigner;
use kr_client::services::mailbox::{MailboxClient, MailboxDeliveryState};
use kr_protocol::error::ErrorCode;
use kr_protocol::mailbox::SealedEnvelope;
use kr_protocol::scalars::StoredEnvelopeKey;
use kr_protocol::service::GatewayOrigin;

use super::transport::DeliveryTransports;

/// What came of placing one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    /// The object is in the device's mailbox: stored now, stored by an earlier delivery of the same
    /// envelope, or folded into an unread item of its thread.
    Placed,
    /// Nothing is known to be in the mailbox, and a later delivery may succeed.
    Later {
        /// What happened, for the notification's record.
        detail: String,
        /// How long the service asked to be left alone, when it said.
        after: Option<Duration>,
    },
    /// The service will not take this object, and asking again would not change that.
    Refused {
        /// What the service said, for the notification's record.
        detail: String,
    },
}

/// What places the objects a delivery owes a device's mailbox.
///
/// A trait so that the delivery module, which is synchronous and runs on a blocking thread, holds
/// no network client of its own, and a test can see exactly what was asked of the mailbox service.
pub trait ObjectPlacer: std::fmt::Debug + Send + Sync {
    /// Places one sealed envelope in the mailbox of the device whose stored-envelope key is
    /// `recipient`. May cause a delivery.
    fn place(&self, recipient: &StoredEnvelopeKey, envelope: &SealedEnvelope) -> Placement;
}

/// The mailbox service this host's configuration document selects, as the delivery module places
/// objects in it.
#[derive(Clone)]
pub struct MailboxPlacer {
    origin: GatewayOrigin,
    transports: Arc<dyn DeliveryTransports>,
    signer: Arc<dyn ServiceSigner>,
    runtime: tokio::runtime::Handle,
}

impl std::fmt::Debug for MailboxPlacer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailboxPlacer")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl MailboxPlacer {
    /// Builds the placer for the service at `origin`, reached through `transports` and signed for
    /// as this host. `runtime` is the daemon's own reactor, which drives every exchange.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        transports: Arc<dyn DeliveryTransports>,
        signer: Arc<dyn ServiceSigner>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            origin,
            transports,
            signer,
            runtime,
        }
    }
}

impl ObjectPlacer for MailboxPlacer {
    fn place(&self, recipient: &StoredEnvelopeKey, envelope: &SealedEnvelope) -> Placement {
        let transport = match self.transports.to(&self.origin) {
            Ok(transport) => transport,
            Err(detail) => {
                return Placement::Later {
                    detail,
                    after: None,
                };
            }
        };
        let client = MailboxClient::new(self.origin.clone(), transport, Arc::clone(&self.signer))
            .leaving_delays_to_the_caller();
        match self.runtime.block_on(client.deliver(recipient, envelope)) {
            Ok(delivery) => match delivery.state {
                MailboxDeliveryState::Stored
                | MailboxDeliveryState::Duplicate
                | MailboxDeliveryState::Coalesced => Placement::Placed,
            },
            Err(error) => placement_of(&error),
        }
    }
}

/// What a failed delivery means for the object.
///
/// Whether the service may yet take the object turns on whether it refused it or could not answer.
/// A rate limit, a service with no room for the request now, a service or a connection that did
/// not answer, a clock the service does not trust and an answer this host could not read all pass.
/// Everything else is the service saying no to this object: a mailbox that is full, an item it does
/// not keep, an identifier that carried another item, a signature it does not accept.
fn placement_of(error: &ClientError) -> Placement {
    let after = match error {
        ClientError::Refused {
            retry_after_seconds,
            ..
        } => retry_after_seconds.map(Duration::from_secs),
        _ => None,
    };
    match error.code() {
        ErrorCode::RateLimited
        | ErrorCode::ServiceCapacity
        | ErrorCode::UpstreamUnavailable
        | ErrorCode::OutcomeUnknown
        | ErrorCode::ClockUntrusted
        | ErrorCode::ResourceUnavailable => Placement::Later {
            detail: format!("the mailbox service did not take it yet: {error}"),
            after,
        },
        _ => Placement::Refused {
            detail: format!("the mailbox service would not take it: {error}"),
        },
    }
}
