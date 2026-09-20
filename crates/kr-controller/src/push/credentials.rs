//! The bearer this host delivers under, and the two methods that manage it.
//!
//! Section 16 gives the host two of the four `Services` push methods: `push.sender.renew` and
//! `push.sender.revoke`, both proven by the **host** key over a fresh gateway nonce. The other
//! two, registering a token and issuing a sender authorisation, are the installation's and reach
//! the gateway from the device; the credential they produce arrives here through the paired
//! encrypted channel.
//!
//! D-018 puts one signature on every managed-service method: a [`ServiceRequestSignature`] over
//! the gateway origin, the method, a fresh nonce, the time and the digest of the body. Building it
//! is [`sign_request`], and it is the same five facts for both methods because inventing a second
//! scheme is what that decision exists to prevent.
//!
//! # Where the secret lives
//!
//! In memory, in [`HeldCredentials`], and nowhere else. It is never written to the delivery
//! journal, never logged and never put in an error message: what the journal holds is the
//! `sender_record_id`, which names the authorisation and proves nothing.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_delivery::push::SenderCredentials;
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::method::Method;
use kr_protocol::push::PushDeliveryCredential;
use kr_protocol::scalars::{Nonce256, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, ServiceRequestSigner,
    body_digest,
};

/// What this host holds for each authorisation it delivers under.
///
/// The map is the whole of it: a credential is a bearer with an expiry, and a host that lost one
/// renews rather than asking for the same one again.
#[derive(Debug, Default)]
pub struct HeldCredentials {
    held: Mutex<BTreeMap<PushSenderRecordId, PushDeliveryCredential>>,
    renewals: Mutex<Vec<PushSenderRecordId>>,
}

impl HeldCredentials {
    /// Builds an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the credential one authorisation produced.
    pub fn hold(&self, credential: PushDeliveryCredential) {
        if let Ok(mut held) = self.held.lock() {
            held.insert(credential.sender_record_id, credential);
        }
    }

    /// Forgets one authorisation's credential, which is what unpairing does.
    pub fn forget(&self, sender_record_id: PushSenderRecordId) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(&sender_record_id);
        }
    }

    /// Returns which authorisations this host has asked to renew, in order.
    ///
    /// A renewal is a call to the gateway, which this store does not make: it records the need and
    /// the caller performs it. That keeps the credential store free of a socket.
    #[must_use]
    pub fn renewals_requested(&self) -> Vec<PushSenderRecordId> {
        self.renewals
            .lock()
            .map(|renewals| renewals.clone())
            .unwrap_or_default()
    }
}

impl SenderCredentials for HeldCredentials {
    fn current(&self, sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        self.held
            .lock()
            .ok()
            .and_then(|held| held.get(&sender_record_id).cloned())
    }

    fn renew(
        &self,
        sender_record_id: PushSenderRecordId,
    ) -> kr_delivery::Result<PushDeliveryCredential> {
        if let Ok(mut renewals) = self.renewals.lock() {
            renewals.push(sender_record_id);
        }
        self.current(sender_record_id).ok_or_else(|| {
            kr_delivery::DeliveryError::Source(
                "this host holds no credential for that authorisation, so a renewal needs a \
                     fresh authorisation from the device"
                    .to_owned(),
            )
        })
    }
}

/// Builds the signature one managed-service request is authenticated by.
///
/// Five facts, and every one of them load bearing: the origin, so a signature made for one
/// deployment is refused by another; the method, so a signature for a renewal is not the
/// authorisation for a revocation; a fresh nonce, so the same signed request is not accepted
/// twice; the time, so a captured request cannot be held and presented later; and the digest of
/// the body, so the body cannot be swapped under a signature that still verifies.
///
/// The signer is [`ServiceRequestSigner::Host`], which is a different domain from an
/// installation's, so relabelling one cannot turn it into the other.
#[must_use]
pub fn sign_request(
    origin: &GatewayOrigin,
    method: Method,
    body: &[u8],
    nonce: Nonce256,
    now_ms: u64,
    sign: &dyn Fn(&[u8]) -> kr_protocol::scalars::Signature64,
    public_key: kr_protocol::scalars::AuthorisationKey,
) -> Option<ServiceRequestSignature> {
    let payload = ServiceRequestPayload {
        body_digest: body_digest(body),
        gateway_origin: origin.clone(),
        method,
        nonce,
        signed_at_ms: TimestampMs::new(now_ms),
    };
    if !payload.names_a_service_method() {
        return None;
    }
    let input = payload.signing_input(ServiceRequestSigner::Host).ok()?;
    Some(ServiceRequestSignature {
        payload,
        signer: ServiceRequestSigner::Host,
        public_key,
        signature: sign(&input),
    })
}

/// The route a renewal is presented on.
pub const RENEW_ROUTE: &str = "/api/push/sender/renew";

/// The route a revocation is presented on.
pub const REVOKE_ROUTE: &str = "/api/push/sender/revoke";
