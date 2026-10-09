//! A running daemon delivers notifications to the destinations it was given.
//!
//! One real daemon on the loopback network, a real worker it adopts, and real pairing: a device is
//! paired through the owner's confirmation and then speaks to the daemon over its own paired
//! connection. Nothing here configures a destination by calling the delivery module. A paired
//! device registers its push credential with `device.push.register`, and the daemon's own pass
//! takes what the attention store announces and delivers it.
//!
//! The only stand-ins are the ones the product has no way to run in a test: the phone's side of the
//! exchange (the device hands over what its installation was issued) and the push gateway, which
//! answers renewals and revocations the way the Worker does, checking the host's signature under
//! the key the authorisation names, and delivers to nobody.
//!
//! Everything is on the internal disk: the environment is a temporary host tree.

mod net_support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::{ServiceFuture, ServiceHttp, ServiceHttpAnswer};
use kr_controller::service::Controller;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AuthorityRevision, BuildId, ConnectionId, ControllerGeneration, EnvironmentId,
    InstallationId, PushSenderRecordId, PushSenderRevision, SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::push::{
    DevicePushRegisterParams, DevicePushRegisterResult, PUSH_SENDER_RENEWAL_DOMAIN,
    PUSH_SENDER_REVOCATION_DOMAIN, PushAlert, PushDeliveryAck, PushDeliveryCredential,
    PushDeliveryRequest, PushDeliveryState, PushRatePolicy, PushRequest, PushSenderBinding,
    PushSenderRecord, PushSenderRenewRequest, PushSenderRevokeRequest, PushSenderState,
};
use kr_protocol::question::{QuestionCreateParams, QuestionKind};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, EndpointKey, Nonce256, Nullable, SecretBytes32, TimestampMs, Uuid,
};
use kr_protocol::service::{ServiceRequestSignature, ServiceRequestSigner};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::broker::channel_fixture::{Channel, Package, launched, register};
use kr_worker::broker::connectors::fixture;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use net_support::{Device, Host, RawDevice, pair_with, proposal};

/// How long a test waits for something the daemon's own tick or the worker has to do.
const PATIENCE: Duration = Duration::from_secs(60);

/// The gateway the product delivers through.
const GATEWAY: &str = "https://reach.kala.to";

/// How long a credential the stand-in gateway issues lasts.
const LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000 - 1_000;

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn now() -> u64 {
    kr_ipc::now_ms().get()
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

/// Waits until `holds` says it does, or the patience runs out.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !holds() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// The push gateway
// ---------------------------------------------------------------------------------------------

/// What the gateway holds for one authorisation an installation issued.
#[derive(Clone, Debug)]
struct Authorisation {
    installation_id: InstallationId,
    host_signing_key: AuthorisationKey,
    state: PushSenderState,
    revision: u64,
    secret: [u8; 32],
    expires_at_ms: u64,
    /// When the credential was last renewed; nought for one never renewed.
    renewed_at_ms: u64,
}

/// How long before a credential expires the gateway renews it, and how long after a renewal it
/// renews once more for a host that lost the answer: the Worker's own rules.
const RENEWAL_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const RENEWAL_RECOVERY_MS: u64 = 60 * 60 * 1000;

#[derive(Debug, Default)]
struct GatewayState {
    authorisations: BTreeMap<PushSenderRecordId, Authorisation>,
    /// The nonces handed out and not yet answered, with the purpose each was asked for.
    nonces: BTreeSet<(&'static str, [u8; 32])>,
    /// Every delivery taken, with the authorisation its bearer matched.
    delivered: Vec<(PushSenderRecordId, PushDeliveryRequest)>,
    /// The routes asked, in order, with the status each was answered with.
    asked: Vec<(String, u16)>,
    /// Deliveries refused because the bearer was not the latest one issued.
    bearers_refused: usize,
    /// Every post to an address that is not one of the gateway's routes: an external destination.
    posted: Vec<Posted>,
}

/// One post an external destination received.
#[derive(Clone, Debug)]
struct Posted {
    url: String,
    /// The JSON the adapter sent.
    body: serde_json::Value,
    /// The headers it sent, names in lower case.
    headers: Vec<(String, String)>,
}

impl Posted {
    /// The text of the message the post carries, whichever service it went to.
    fn text(&self) -> String {
        ["body", "text", "content"]
            .into_iter()
            .find_map(|member| self.body.get(member).and_then(serde_json::Value::as_str))
            .unwrap_or_default()
            .to_owned()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(held, _)| held.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The Worker's push gateway, for what a host asks of it: renewals and revocations proven under
/// the host key the authorisation names, and deliveries under the latest bearer it issued.
#[derive(Debug, Default)]
struct Gateway {
    state: Mutex<GatewayState>,
    /// Answers nothing: a gateway nobody can reach.
    down: AtomicBool,
    /// How long the credentials it issues last, in milliseconds; a month when nothing says.
    lifetime_ms: std::sync::atomic::AtomicU64,
    /// Answers a revocation with a refusal that may pass: a gateway having a bad hour.
    refuses_revocations: AtomicBool,
    /// What a route answers with whatever it is asked, for a deployment, a proxy or a fault that
    /// does not answer as the Worker does.
    replies: Mutex<BTreeMap<&'static str, ServiceHttpAnswer>>,
    /// Requests, or answers, held back until the test lets them go.
    gates: Mutex<Vec<Gate>>,
    /// The last time the gateway stamped a credential with, so that two credentials never carry
    /// one time.
    stamped_ms: std::sync::atomic::AtomicU64,
}

/// An exchange the gateway holds back until the test lets it go: either the request, before the
/// gateway has acted on it, or the answer, after it has and before the caller has heard.
#[derive(Debug)]
struct Gate {
    route: &'static str,
    /// How many requests to the route pass before the one that is held.
    skip: usize,
    /// Whether the request is held before the gateway acts on it.
    before: bool,
    held: Arc<Held>,
}

/// The two ends of a held answer.
#[derive(Debug, Default)]
struct Held {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// The test's end of a held answer. A test that fails while an answer is held lets it go, or the
/// caller waiting for it would keep the test from ending.
struct Hold(Arc<Held>);

impl Hold {
    /// Waits until the gateway holds the answer.
    async fn reached(&self) {
        self.0.reached.notified().await;
    }

    /// Gives the caller the answer it waits for.
    fn release(&self) {
        self.0.release.notify_one();
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

impl Gateway {
    /// What an installation does with the gateway: creates an authorisation for the host whose
    /// signing key it names, and returns the credential it passes to the host.
    fn issue(
        &self,
        sender_record_id: PushSenderRecordId,
        installation_id: InstallationId,
        host_signing_key: AuthorisationKey,
    ) -> PushDeliveryCredential {
        let mut secret = [0_u8; 32];
        kr_crypto::random_bytes(&mut secret).expect("a secret");
        let issued = self.stamp();
        let mut state = self.state();
        // An identifier the gateway already holds is issued again as the Worker does: the next
        // revision, a new bearer that retires the last, and the hour after a renewal opened.
        let earlier = state
            .authorisations
            .get(&sender_record_id)
            .map(|held| held.revision);
        let authorisation = Authorisation {
            installation_id,
            host_signing_key,
            state: PushSenderState::Active,
            revision: earlier.map_or(1, |revision| revision + 1),
            secret,
            expires_at_ms: issued + self.lifetime(),
            renewed_at_ms: if earlier.is_some() { issued } else { 0 },
        };
        let credential = Self::credential_of(sender_record_id, &authorisation, issued);
        state.authorisations.insert(sender_record_id, authorisation);
        credential
    }

    fn credential_of(
        sender_record_id: PushSenderRecordId,
        authorisation: &Authorisation,
        issued_at_ms: u64,
    ) -> PushDeliveryCredential {
        PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(authorisation.expires_at_ms),
            gateway_origin: kr_protocol::service::GatewayOrigin::new(GATEWAY).expect("an origin"),
            installation_id: authorisation.installation_id,
            issued_at_ms: TimestampMs::new(issued_at_ms),
            revision: PushSenderRevision::new(authorisation.revision),
            secret: SecretBytes32::from_bytes(authorisation.secret),
            sender_record_id,
        }
    }

    /// The time the gateway stamps a credential with: its clock, never the same twice.
    fn stamp(&self) -> u64 {
        let mut last = self.stamped_ms.load(Ordering::SeqCst);
        loop {
            let next = now().max(last + 1);
            match self
                .stamped_ms
                .compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return next,
                Err(seen) => last = seen,
            }
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, GatewayState> {
        self.state.lock().expect("the gateway is not poisoned")
    }

    fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    fn refuse_revocations(&self, refuse: bool) {
        self.refuses_revocations.store(refuse, Ordering::SeqCst);
    }

    /// Makes the route answer `status` and `body` to everything, or as the Worker does again.
    fn answer_route_with(&self, route: &'static str, answer: Option<(u16, &str)>) {
        let mut replies = self.replies.lock().expect("the gateway is not poisoned");
        match answer {
            Some((status, body)) => {
                replies.insert(
                    route,
                    ServiceHttpAnswer {
                        status,
                        body: body.as_bytes().to_vec(),
                    },
                );
            }
            None => {
                replies.remove(route);
            }
        }
    }

    /// Holds back the answer to the request to `route` after `skip` others, once the gateway has
    /// acted on it. The request is not answered until [`Held::release`].
    fn hold(&self, route: &'static str, skip: usize) -> Hold {
        self.gate(route, skip, false)
    }

    /// Holds back the request to `route` after `skip` others before the gateway acts on it, so
    /// that what else happens meanwhile happens first.
    fn hold_before(&self, route: &'static str, skip: usize) -> Hold {
        self.gate(route, skip, true)
    }

    fn gate(&self, route: &'static str, skip: usize, before: bool) -> Hold {
        let held = Arc::new(Held::default());
        self.gates
            .lock()
            .expect("the gateway is not poisoned")
            .push(Gate {
                route,
                skip,
                before,
                held: Arc::clone(&held),
            });
        Hold(held)
    }

    /// The gate the request meets, if it is one a test holds. A request counts against the first
    /// gate for its route that it does not pass.
    fn met(&self, url: &str) -> Option<(Arc<Held>, bool)> {
        let mut gates = self.gates.lock().expect("the gateway is not poisoned");
        let index = gates.iter().position(|gate| url.ends_with(gate.route))?;
        if gates[index].skip > 0 {
            gates[index].skip -= 1;
            return None;
        }
        let gate = gates.remove(index);
        Some((gate.held, gate.before))
    }

    /// Makes the credentials it issues from now on last `lifetime_ms`.
    fn issue_for(&self, lifetime_ms: u64) {
        self.lifetime_ms.store(lifetime_ms, Ordering::SeqCst);
    }

    fn lifetime(&self) -> u64 {
        match self.lifetime_ms.load(Ordering::SeqCst) {
            0 => LIFETIME_MS,
            set => set,
        }
    }

    /// The revision of the credential the gateway last issued for one authorisation.
    fn revision_of(&self, id: PushSenderRecordId) -> u64 {
        self.authorisation(id).map_or(0, |held| held.revision)
    }

    /// The notifications delivered, in order.
    fn delivered(&self) -> Vec<PushDeliveryRequest> {
        self.state()
            .delivered
            .iter()
            .map(|(_, request)| request.clone())
            .collect()
    }

    /// The posts external destinations received, in order.
    fn posted(&self) -> Vec<Posted> {
        self.state().posted.clone()
    }

    /// The statuses the routes named were answered with, in order.
    fn answers_on(&self, route: &str) -> Vec<u16> {
        self.state()
            .asked
            .iter()
            .filter(|(url, _)| url.ends_with(route))
            .map(|(_, status)| *status)
            .collect()
    }

    fn authorisation(&self, id: PushSenderRecordId) -> Option<Authorisation> {
        self.state().authorisations.get(&id).cloned()
    }

    fn answer(status: u16, body: &serde_json::Value) -> ServiceHttpAnswer {
        ServiceHttpAnswer {
            status,
            body: serde_json::to_vec(body).expect("an answer"),
        }
    }

    fn refusal(status: u16, code: &str) -> ServiceHttpAnswer {
        Self::answer(
            status,
            &serde_json::json!({ "ok": false, "error": { "code": code, "message": "no" } }),
        )
    }

    /// Verifies a signature the way the Worker does: over the exact transcript, under the domain
    /// it claims, with the key given.
    fn verifies(
        key: &AuthorisationKey,
        domain: &str,
        input: Vec<u8>,
        signature: &kr_protocol::scalars::Signature64,
    ) -> bool {
        kr_crypto::sign::SigningTranscript::from_canonical_bytes(domain, input)
            .and_then(|transcript| kr_crypto::sign::verify(key, &transcript, signature))
            .is_ok()
    }

    /// A status question about a notification: the bearer is authenticated first, and the
    /// gateway holds nothing under an identifier it was never given.
    fn status(&self, headers: &[(&str, &str)]) -> ServiceHttpAnswer {
        let state = self.state();
        let presented = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| *value);
        let known = state.authorisations.values().any(|held| {
            let expected = {
                use base64::Engine as _;
                format!(
                    "Bearer {}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(held.secret)
                )
            };
            presented == Some(expected.as_str())
                && held.state == PushSenderState::Active
                && held.expires_at_ms > now()
        });
        if known {
            Self::answer(200, &serde_json::json!({ "ok": true, "data": null }))
        } else {
            Self::refusal(401, "UNAUTHENTICATED")
        }
    }

    /// Lets the credential the gateway last issued for one authorisation lapse, as it does for a
    /// host that was away for a month.
    fn lapse(&self, id: PushSenderRecordId) {
        if let Some(held) = self.state().authorisations.get_mut(&id) {
            held.expires_at_ms = now().saturating_sub(1_000);
            held.renewed_at_ms = 0;
        }
    }

    fn deliver(&self, body: &[u8], headers: &[(&str, &str)]) -> ServiceHttpAnswer {
        let Ok(request) = serde_json::from_slice::<PushDeliveryRequest>(body) else {
            return Self::refusal(400, "INVALID_REQUEST");
        };
        let mut state = self.state();
        let Some(authorisation) = state.authorisations.get(&request.sender_record_id).cloned()
        else {
            return Self::refusal(403, "FORBIDDEN");
        };
        let expected = {
            use base64::Engine as _;
            format!(
                "Bearer {}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authorisation.secret)
            )
        };
        let presented = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| *value);
        if presented != Some(expected.as_str()) {
            state.bearers_refused += 1;
            return Self::refusal(401, "UNAUTHENTICATED");
        }
        if authorisation.state != PushSenderState::Active {
            return Self::refusal(403, "FORBIDDEN");
        }
        let ack = PushDeliveryAck {
            decided_at_ms: TimestampMs::new(now()),
            notification_id: request.notification_id,
            state: PushDeliveryState::Queued,
            suppression: Nullable::null(),
        };
        state
            .delivered
            .push((request.sender_record_id, request.clone()));
        Self::answer(200, &serde_json::json!({ "ok": true, "data": ack }))
    }

    /// One signed request to the renewal or the revocation route.
    fn sender(&self, route: &str, body: &[u8]) -> ServiceHttpAnswer {
        #[derive(serde::Deserialize)]
        struct Signed {
            body: PushRequest,
            signature: ServiceRequestSignature,
        }
        let Ok(signed) = serde_json::from_slice::<Signed>(body) else {
            return Self::refusal(400, "INVALID_REQUEST");
        };
        // The signature covers this body and this method, under the host's domain.
        let covers = signed.signature.payload.method == signed.body.method()
            && signed.body.digest().ok() == Some(signed.signature.payload.body_digest)
            && signed
                .signature
                .payload
                .signing_input(ServiceRequestSigner::Host)
                .is_ok_and(|input| {
                    Self::verifies(
                        &signed.signature.public_key,
                        ServiceRequestSigner::Host.domain(),
                        input,
                        &signed.signature.signature,
                    )
                });
        if !covers {
            // The Worker refuses a request whose signature does not hold with 401, before it
            // looks at what the request is about.
            return Self::refusal(401, "UNAUTHENTICATED");
        }
        let key = signed.signature.public_key;
        let mut state = self.state();
        let nonce_for = |state: &mut GatewayState,
                         purpose: &'static str,
                         id: PushSenderRecordId|
         -> ServiceHttpAnswer {
            match state.authorisations.get(&id) {
                Some(held) if held.host_signing_key == key => {}
                _ => return Self::refusal(403, "FORBIDDEN"),
            }
            let mut nonce = [0_u8; 32];
            kr_crypto::random_bytes(&mut nonce).expect("a nonce");
            state.nonces.insert((purpose, nonce));
            Self::answer(
                200,
                &serde_json::json!({
                    "ok": true,
                    "data": {
                        "gateway_nonce": Nonce256::from_bytes(nonce),
                        "expires_at_ms": TimestampMs::new(now() + 60_000),
                    },
                }),
            )
        };
        match signed.body {
            PushRequest::SenderRenew {
                request: PushSenderRenewRequest::Begin { request },
            } if route.ends_with("/renew") => {
                nonce_for(&mut state, "renew", request.sender_record_id)
            }
            PushRequest::SenderRevoke {
                request: PushSenderRevokeRequest::Begin { request },
            } if route.ends_with("/revoke") => {
                if self.refuses_revocations.load(Ordering::SeqCst) {
                    return Self::refusal(503, "SERVICE_UNAVAILABLE");
                }
                nonce_for(&mut state, "revoke", request.sender_record_id)
            }
            PushRequest::SenderRenew {
                request: PushSenderRenewRequest::Complete { renewal },
            } if route.ends_with("/renew") => {
                let id = renewal.payload.sender_record_id;
                let spent = state
                    .nonces
                    .remove(&("renew", *renewal.payload.gateway_nonce.as_bytes()));
                let proven = renewal.payload.signing_input().is_ok_and(|input| {
                    Self::verifies(&key, PUSH_SENDER_RENEWAL_DOMAIN, input, &renewal.signature)
                });
                let Some(held) = state.authorisations.get_mut(&id) else {
                    return Self::refusal(403, "FORBIDDEN");
                };
                if !spent || !proven || held.host_signing_key != key {
                    return Self::refusal(403, "FORBIDDEN");
                }
                // A revoked authorisation never renews.
                if held.state != PushSenderState::Active {
                    return Self::refusal(403, "FORBIDDEN");
                }
                // And an active one renews in the last week of its credential's life, or within
                // an hour of a renewal whose answer was lost: never on the day it was issued.
                let issued = self.stamp();
                let due = held.expires_at_ms.saturating_sub(RENEWAL_WINDOW_MS) <= issued;
                let recovering = held.renewed_at_ms > 0
                    && issued.saturating_sub(held.renewed_at_ms) <= RENEWAL_RECOVERY_MS;
                if !due && !recovering {
                    return Self::refusal(403, "FORBIDDEN");
                }
                held.revision += 1;
                kr_crypto::random_bytes(&mut held.secret).expect("a secret");
                held.renewed_at_ms = issued;
                held.expires_at_ms = issued + self.lifetime();
                let credential = Self::credential_of(id, held, issued);
                let record = PushSenderRecord {
                    binding: PushSenderBinding {
                        gateway_origin: credential.gateway_origin.clone(),
                        host_endpoint_key: EndpointKey::from_bytes([4; 32]),
                        host_signing_key: held.host_signing_key,
                        installation_id: held.installation_id,
                        rate_policy: PushRatePolicy::FREE,
                        sender_record_id: id,
                    },
                    credential_expires_at_ms: credential.expires_at_ms,
                    issued_at_ms: credential.issued_at_ms,
                    revision: credential.revision,
                    state: held.state,
                };
                Self::answer(
                    200,
                    &serde_json::json!({
                        "ok": true,
                        "data": { "record": record, "credential": credential },
                    }),
                )
            }
            PushRequest::SenderRevoke {
                request: PushSenderRevokeRequest::Complete { revocation },
            } if route.ends_with("/revoke") => {
                let id = revocation.payload.sender_record_id;
                let spent = state
                    .nonces
                    .remove(&("revoke", *revocation.payload.gateway_nonce.as_bytes()));
                let proven = revocation.payload.signing_input().is_ok_and(|input| {
                    Self::verifies(
                        &key,
                        PUSH_SENDER_REVOCATION_DOMAIN,
                        input,
                        &revocation.signature,
                    )
                });
                let Some(held) = state.authorisations.get_mut(&id) else {
                    return Self::refusal(403, "FORBIDDEN");
                };
                if !spent || !proven || held.host_signing_key != key {
                    return Self::refusal(403, "FORBIDDEN");
                }
                held.state = PushSenderState::Revoked;
                let credential = Self::credential_of(id, held, now());
                let record = PushSenderRecord {
                    binding: PushSenderBinding {
                        gateway_origin: credential.gateway_origin.clone(),
                        host_endpoint_key: EndpointKey::from_bytes([4; 32]),
                        host_signing_key: held.host_signing_key,
                        installation_id: held.installation_id,
                        rate_policy: PushRatePolicy::FREE,
                        sender_record_id: id,
                    },
                    credential_expires_at_ms: credential.expires_at_ms,
                    issued_at_ms: credential.issued_at_ms,
                    revision: credential.revision,
                    state: held.state,
                };
                Self::answer(
                    200,
                    &serde_json::json!({ "ok": true, "data": { "record": record } }),
                )
            }
            _ => Self::refusal(400, "INVALID_REQUEST"),
        }
    }
}

impl Gateway {
    /// What the gateway answers, and the record that it was asked.
    fn respond(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<ServiceHttpAnswer, kr_client::ClientError> {
        let replied = self
            .replies
            .lock()
            .expect("the gateway is not poisoned")
            .iter()
            .find(|(route, _)| url.ends_with(**route))
            .map(|(_, answer)| answer.clone());
        // Anything that is not one of the gateway's routes is an address an external destination
        // was configured with, and what it was sent is kept whatever it is answered with.
        if !url.contains("/api/push/") {
            self.state().posted.push(Posted {
                url: url.to_owned(),
                body: serde_json::from_slice(body).unwrap_or(serde_json::Value::Null),
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
                    .collect(),
            });
        }
        let answer = if self.down.load(Ordering::SeqCst) {
            Err(kr_client::ClientError::ConnectionEnded)
        } else if let Some(replied) = replied {
            Ok(replied)
        } else if url.ends_with("/api/push/deliver") {
            Ok(self.deliver(body, headers))
        } else if url.ends_with("/api/push/deliver/status") {
            Ok(self.status(headers))
        } else if url.ends_with("/api/push/sender/renew")
            || url.ends_with("/api/push/sender/revoke")
        {
            Ok(self.sender(url, body))
        } else if url.contains("/api/push/") {
            Ok(Self::refusal(404, "NOT_FOUND"))
        } else {
            Ok(Self::answer(200, &serde_json::json!({ "ok": true })))
        };
        if let Ok(answered) = &answer {
            self.state().asked.push((url.to_owned(), answered.status));
        }
        answer
    }
}

impl ServiceHttp for Gateway {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        match self.met(url) {
            // Held before the gateway acts: what happens meanwhile happens first.
            Some((held, true)) => Box::pin(async move {
                held.reached.notify_one();
                held.release.notified().await;
                self.respond(url, body, headers)
            }),
            // Held after: the gateway has acted, and the caller has not heard.
            Some((held, false)) => {
                let answer = self.respond(url, body, headers);
                Box::pin(async move {
                    held.reached.notify_one();
                    held.release.notified().await;
                    answer
                })
            }
            None => {
                let answer = self.respond(url, body, headers);
                Box::pin(async move { answer })
            }
        }
    }
}

/// Every origin reached through the one gateway.
#[derive(Debug)]
struct Through(Arc<Gateway>);

impl kr_controller::push::transport::DeliveryTransports for Through {
    fn to(
        &self,
        _origin: &kr_protocol::service::GatewayOrigin,
    ) -> Result<Arc<dyn ServiceHttp>, String> {
        Ok(Arc::clone(&self.0) as Arc<dyn ServiceHttp>)
    }
}

// ---------------------------------------------------------------------------------------------
// A daemon, a worker it adopts, and a paired device
// ---------------------------------------------------------------------------------------------

/// A worker for one session, in this process, on an environment tree a daemon of it serves.
struct Worker {
    service: Arc<WorkerService>,
    session_id: SessionId,
    _runtime: Arc<SessionRuntime>,
}

impl Worker {
    /// Starts a worker for one session and records it the way a daemon records one it adopts. No
    /// daemon may be running on the tree while this runs.
    async fn start(tree: &kr_ipc::testing::TempHost, display: u64) -> Self {
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller_key = {
            let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
            *ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                .expect("the daemon's identity")
                .public_key()
        };
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let display_number = DisplayNumber::new(display);
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process.clone(),
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let project: PathBuf = tree.root().join("delivery-project");
        std::fs::create_dir_all(&project).expect("the project directory");
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number,
            shell: kr_worker::pty::ShellCommand {
                cwd: project.display().to_string(),
                ..kr_worker::testing::posix_script("sleep 600")
            },
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(display_number)
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let public_key = *identity.public_key();
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint.clone(),
                ServiceBinding {
                    environment_id,
                    boot_identity: boot.clone(),
                    controller_public_key: controller_key,
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: build(),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        let mut registry = kr_controller::registry::Registry::open(
            environment.registry_database(),
            environment_id,
        )
        .expect("the registry");
        registry
            .adopt_worker(
                &kr_controller::registry::WorkerRecord {
                    session_id,
                    display_number,
                    public_key,
                    process_identity: process.clone(),
                    endpoint: endpoint.as_text(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                Some(&DesktopBinding::none()),
            )
            .expect("the worker is recorded");
        drop(registry);
        kr_ipc::descriptor::publish(
            &environment,
            &WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number,
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: public_key,
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: kr_ipc::now_ms(),
            },
        )
        .expect("the worker's descriptor is published");
        Self {
            service,
            session_id,
            _runtime: runtime,
        }
    }

    /// Opens a Claude Code channel on this worker's own broker for the application instance
    /// `number`, as the command backend hands one over once it has admitted it. With `bound` the
    /// connector's package is bound to the instance, so what the channel relays is interpreted as
    /// an approval a person can answer; without it a relayed request is recorded and has no
    /// meaning here, and the application's own dialog answers it.
    fn open_channel(&self, number: u8, bound: bool) -> OpenChannel {
        let broker = self.service.broker();
        register(broker, number);
        let package = Package::laid_out();
        if bound {
            package.bind(broker, number);
        }
        let channel = Channel::open(
            package.launch(broker, number, Some(fixture::QUALIFIED_VERSION)),
            number,
            launched(number),
        );
        OpenChannel {
            channel,
            number,
            _package: package,
        }
    }

    /// Waits until the broker holds the request one channel relayed, and, when `interpreted`,
    /// until it has interpreted it.
    async fn until_relayed(&self, channel: &OpenChannel, request_id: &str, interpreted: bool) {
        let broker = Arc::clone(self.service.broker());
        let number = channel.number;
        let quoted = format!("\"{request_id}\"");
        until("the broker holding the relayed request", move || {
            broker.pending_resources().iter().any(|resource| {
                resource.application_instance_id
                    == kr_worker::broker::channel_fixture::instance(number)
                    && resource.request.upstream.as_str() == quoted
                    && (!interpreted || resource.interpretation_verified)
            })
        })
        .await;
    }

    /// Asks a question from inside the session, as a verified source bound to it does.
    fn ask(&self, request: &str, question: &str) {
        self.service
            .questions()
            .create(
                &kr_worker::questions::VerifiedSource {
                    process: kr_ipc::identity::current_process_start_identity()
                        .expect("a process identity"),
                    executable: Some("/bin/agent".to_owned()),
                    session_member: true,
                    ancestry: true,
                    launch_channel: true,
                    connection_id: ConnectionId::new(kr_ipc::new_uuid()),
                },
                &QuestionCreateParams {
                    session_id: self.session_id,
                    request_id: request.to_owned(),
                    agent_name: Nullable::some("an agent".to_owned()),
                    context: "the release is tagged".to_owned(),
                    question: question.to_owned(),
                    kind: QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: Nullable::null(),
                    wait_ms: Nullable::null(),
                },
                kr_worker::questions::Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: kr_ipc::clock::boot_elapsed_ms(),
                },
            )
            .expect("a verified source asks");
    }
}

/// One channel of the worker's application, and what keeps its package.
struct OpenChannel {
    channel: Channel,
    number: u8,
    _package: Package,
}

/// A daemon on the network with one adopted worker, and the keys of the environment's owner.
struct Environment {
    host: Host,
    owner: DeviceKeys,
    _worker: Worker,
    worker_session: SessionId,
    gateway: Arc<Gateway>,
}

/// A device paired with the daemon, connected, with the keys it declared at pairing.
struct Phone {
    device: Device,
    record: kr_controller::service::net::devices::DeviceRecord,
    connection: RawDevice,
}

impl Environment {
    /// Starts a daemon on a fresh environment, bootstraps its owner, stops it, starts a worker on
    /// the tree, and starts the daemon again, which adopts the worker. The daemon delivers through
    /// the stand-in gateway.
    async fn start() -> Self {
        Self::start_attached(true).await
    }

    /// Starts as [`Self::start`] does, with the daemon delivering through the gateway only when
    /// `attached` says so: a daemon with no transport asks no gateway anything.
    async fn start_attached(attached: bool) -> Self {
        Self::start_on(attached, None).await
    }

    /// Starts as [`Self::start`] does, on clocks the test moves by hand.
    async fn start_on_clocks(clocks: kr_controller::service::Clocks) -> Self {
        Self::start_on(true, Some(clocks)).await
    }

    async fn start_on(attached: bool, clocks: Option<kr_controller::service::Clocks>) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = match clocks {
            Some(clocks) => Host::start_on_clocks(&owner, clocks).await,
            None => Host::start(&owner).await,
        };
        let stopped = host.shut_down().await;
        let worker = Worker::start(stopped.tree(), 1).await;
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let environment = Self {
            host,
            owner,
            worker_session: worker.session_id,
            _worker: worker,
            gateway: Arc::new(Gateway::default()),
        };
        environment.until_adopted().await;
        if attached {
            environment.attach_gateway();
        }
        environment
    }

    /// Stops the daemon and starts another on the same tree, which finds the worker still running.
    async fn restart(self) -> Self {
        self.restart_attached(true).await
    }

    /// Restarts as [`Self::restart`] does, attaching the gateway only when `attached` says so.
    async fn restart_attached(self, attached: bool) -> Self {
        let Self {
            host,
            owner,
            _worker,
            worker_session,
            gateway,
        } = self;
        let host = host.restart().await;
        let environment = Self {
            host,
            owner,
            _worker,
            worker_session,
            gateway,
        };
        environment.until_adopted().await;
        if attached {
            environment.attach_gateway();
        }
        environment
    }

    /// The daemon delivers through the stand-in gateway, as a shipped daemon delivers through the
    /// managed transport.
    fn attach_gateway(&self) {
        assert!(
            self.controller()
                .attach_delivery_transport(Arc::new(Through(Arc::clone(&self.gateway))))
        );
    }

    fn controller(&self) -> &Arc<Controller> {
        self.host.controller()
    }

    fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    /// The signing key the daemon proves its renewals and revocations with: the authorisation key
    /// of the host's own device keys, which it keeps in its secret store.
    fn host_signing_key(&self) -> AuthorisationKey {
        let store = open_store_in(&self.host.tree().environment().secrets_dir())
            .expect("the daemon's secret store");
        kr_crypto::store::load_device_keys(
            store.store.as_ref(),
            &kr_controller::service::net::device_key_scope(self.environment_id()),
        )
        .expect("the host's keys are readable")
        .expect("the daemon made its keys when it started")
        .public_keys()
        .authorisation
    }

    /// Waits until the daemon serves the worker's session.
    async fn until_adopted(&self) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read = client
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams {
                        session_id: self.worker_session,
                    },
                )
                .await
                .expect("the call reaches the daemon");
            if read.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon never reached the worker: {read:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Pairs a device that may see sessions, and connects it.
    async fn phone(&self) -> Phone {
        self.phone_with(DeviceKeys::generate().expect("device keys"))
            .await
    }

    /// Pairs a device whose grant reaches only `sessions`, and connects it.
    async fn phone_for_sessions(&self, sessions: kr_protocol::grant::SessionSelector) -> Phone {
        let keys = DeviceKeys::generate().expect("device keys");
        let device = Device::with_keys(keys).await;
        let mut grant = proposal(&[ActionRight::SessionView]);
        grant.session_selector = sessions;
        grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(1));
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Phone {
            device,
            record,
            connection,
        }
    }

    /// The same device, connected again after the daemon restarted: its keys and its pairing.
    async fn phone_with_keys_of(&self, phone: &Phone) -> Phone {
        let device = Device::with_keys(phone.device.keys().clone()).await;
        let record = phone.record.clone();
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Phone {
            device,
            record,
            connection,
        }
    }

    /// Pairs a device whose grant carries no history bound, with or without the live screen, as
    /// the sharing screen and `kr pair --view` give them, and connects it.
    async fn phone_with_no_history_bound(&self, include_live_screen: bool) -> Phone {
        let device = Device::with_keys(DeviceKeys::generate().expect("device keys")).await;
        let mut grant = proposal(&[ActionRight::SessionView]);
        assert!(grant.history.lower_bound_ms.0.is_none());
        grant.history.include_live_screen = include_live_screen;
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Phone {
            device,
            record,
            connection,
        }
    }

    /// Pairs a device that holds `keys`, and connects it.
    async fn phone_with(&self, keys: DeviceKeys) -> Phone {
        let device = Device::with_keys(keys).await;
        let mut grant = proposal(&[ActionRight::SessionView]);
        grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(1));
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Phone {
            device,
            record,
            connection,
        }
    }

    /// What the daemon's journal holds for notifications.
    fn deliveries(&self) -> usize {
        self.controller()
            .delivery()
            .with(|producer| Ok(producer.journal().deliveries().expect("a read").len()))
            .expect("a read")
    }

    /// The owner configures an external destination at the daemon's local socket.
    async fn configure(
        &self,
        params: &kr_protocol::delivery::DeliveryDestinationConfigureParams,
    ) -> Result<
        kr_protocol::delivery::DeliveryDestinationConfigureResult,
        kr_protocol::error::ProtocolError,
    > {
        let mut client = self.host.client().await;
        net_support::pairing::mutate(
            self.environment_id(),
            &mut client,
            Method::DeliveryDestinationConfigure,
            params,
        )
        .await
    }

    /// The destinations the daemon lists, as the owner reads them at its local socket.
    async fn listed(&self) -> Vec<kr_protocol::delivery::DeliveryDestinationSummary> {
        let mut client = self.host.client().await;
        let answer = client
            .request(
                Method::DeliveryDestinationList,
                &kr_protocol::delivery::DeliveryDestinationListParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner reads the list");
        answer
            .to_typed::<kr_protocol::delivery::DeliveryDestinationListResult>()
            .expect("a list")
            .destinations
    }

    /// The owner removes a destination at the daemon's local socket.
    async fn remove(
        &self,
        destination_id: &str,
    ) -> Result<
        kr_protocol::delivery::DeliveryDestinationRemoveResult,
        kr_protocol::error::ProtocolError,
    > {
        let mut client = self.host.client().await;
        net_support::pairing::mutate(
            self.environment_id(),
            &mut client,
            Method::DeliveryDestinationRemove,
            &kr_protocol::delivery::DeliveryDestinationRemoveParams {
                destination_id: destination_id.to_owned(),
            },
        )
        .await
    }

    /// The owner hands the daemon a destination's credential at its local socket.
    async fn keep_secret(
        &self,
        destination_id: &str,
        secret: kr_protocol::delivery::DestinationSecret,
    ) {
        let mut client = self.host.client().await;
        let _: kr_protocol::delivery::DeliveryDestinationSecretSetResult =
            net_support::pairing::mutate(
                self.environment_id(),
                &mut client,
                Method::DeliveryDestinationSecretSet,
                &kr_protocol::delivery::DeliveryDestinationSecretSetParams {
                    destination_id: destination_id.to_owned(),
                    secret,
                },
            )
            .await
            .expect("the owner keeps the credential");
    }

    /// The destination the daemon holds under an identifier, if any.
    fn destination_named(
        &self,
        destination_id: &str,
    ) -> Option<kr_delivery::destination::DestinationRecord> {
        let id =
            kr_delivery::destination::DestinationId::new(destination_id).expect("an identifier");
        self.controller()
            .delivery()
            .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
            .expect("a read")
    }

    /// The notifications written for a destination, in the order they were admitted.
    fn deliveries_to(&self, destination_id: &str) -> Vec<kr_delivery::journal::DeliveryRecord> {
        self.controller()
            .delivery()
            .with(|producer| {
                Ok(producer
                    .journal()
                    .deliveries()
                    .expect("a read")
                    .into_iter()
                    .filter(|record| record.destination_id.as_str() == destination_id)
                    .collect())
            })
            .expect("a read")
    }

    /// The destination the daemon holds for a device, if any.
    fn destination(
        &self,
        device_id: kr_protocol::ids::DeviceId,
    ) -> Option<kr_delivery::destination::DestinationRecord> {
        let id = kr_delivery::destination::DestinationId::new(device_id.to_string())
            .expect("an identifier");
        self.controller()
            .delivery()
            .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
            .expect("a read")
    }
}

impl Phone {
    fn device_id(&self) -> kr_protocol::ids::DeviceId {
        self.record.device_id
    }

    /// The installation this device's authorisation key names, which is what its installation
    /// authenticates the gateway's exchanges with.
    fn installation(&self) -> InstallationId {
        kr_protocol::service::installation_id(&self.device.keys().public_keys().authorisation)
    }

    /// The device hands the daemon the credential its installation was issued.
    async fn register(
        &self,
        environment: &Environment,
        credential: &PushDeliveryCredential,
    ) -> Result<DevicePushRegisterResult, kr_protocol::error::ProtocolError> {
        self.connection
            .mutate(
                Method::DevicePushRegister,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment.environment_id()),
                &DevicePushRegisterParams {
                    credential: credential.clone(),
                    previews_enabled: true,
                },
            )
            .await
            .map(|value| value.to_typed().expect("a registration result"))
    }
}

/// The owner unpairs a device at the daemon's local socket.
async fn unpair(environment: &Environment, device_id: kr_protocol::ids::DeviceId) {
    let mut client = environment.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        environment.environment_id(),
        &mut client,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams { device_id },
    )
    .await
    .expect("the owner unpairs the device");
}

/// The revocations the daemon owes a gateway.
fn owed(environment: &Environment) -> Vec<kr_delivery::journal::OwedRevocation> {
    environment
        .controller()
        .delivery()
        .with(|producer| {
            Ok(producer
                .journal()
                .revocations_due(u64::MAX, 64)
                .expect("a read"))
        })
        .expect("a read")
}

/// Waits until the attention store holds `questions` pending questions and the daemon has decided
/// what to tell, and whom: the delivery journal has taken everything the store announced and has
/// produced from every event it took.
async fn until_the_questions_are_settled(environment: &Environment, questions: usize) {
    until(
        "the store settling its questions with the delivery journal",
        || {
            let taken = environment
                .controller()
                .attention()
                .take_for_delivery(|store, _| {
                    let raised = store
                        .engine()
                        .map(|engine| {
                            engine
                                .items()
                                .filter(|item| {
                                    item.rule == kr_protocol::attention::AttentionRule::PendingInput
                                })
                                .count()
                        })
                        .unwrap_or(0);
                    raised >= questions && store.awaiting_delivery().ok() == Some(0)
                })
                .unwrap_or(false);
            taken
                && environment
                    .controller()
                    .delivery()
                    .with(|producer| {
                        Ok(producer
                            .journal()
                            .pending_events(0, 1)
                            .is_ok_and(|p| p.is_empty()))
                    })
                    .unwrap_or(false)
        },
    )
    .await;
}

/// How many pending approvals the attention store holds.
fn pending_approvals(environment: &Environment) -> usize {
    environment
        .controller()
        .attention()
        .take_for_delivery(|store, _| {
            store
                .engine()
                .map(|engine| {
                    engine
                        .items()
                        .filter(|item| {
                            item.rule == kr_protocol::attention::AttentionRule::PendingApproval
                        })
                        .count()
                })
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

/// Waits until the attention store has read every transition the worker's broker has announced,
/// holds nothing it has not given the delivery journal, and the journal has produced from
/// everything it took.
async fn until_the_approvals_are_settled(environment: &Environment) {
    let announced = environment
        ._worker
        .service
        .broker()
        .resource_snapshot()
        .cursor
        .sequence;
    let origin = kr_attention::Origin::Session(environment.worker_session);
    until(
        "the store settling the broker's transitions with the delivery journal",
        || {
            let read = environment
                .controller()
                .attention()
                .take_for_delivery(|store, _| {
                    let consumed = store
                        .engine()
                        .map(|engine| {
                            engine
                                .consumed(
                                    origin,
                                    kr_protocol::attention::AttentionSource::Approvals,
                                )
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    consumed >= announced && store.awaiting_delivery().ok() == Some(0)
                })
                .unwrap_or(false);
            read && environment
                .controller()
                .delivery()
                .with(|producer| {
                    Ok(producer
                        .journal()
                        .pending_events(0, 1)
                        .is_ok_and(|pending| pending.is_empty()))
                })
                .unwrap_or(false)
        },
    )
    .await;
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// KR-REQ-16.08, KR-REQ-16.09, KR-REQ-16.12, KR-REQ-16.13: a paired device registers the
/// credential its installation was issued, over its own paired connection, and the daemon then
/// delivers the next question a worker raises to it, through the gateway, under that credential:
/// the sealed preview opens with the device's own key, the
/// plaintext alert is the generic one, and nothing of the session is in the clear. Before the
/// registration the same question reaches nobody. After the daemon restarts, the next question is
/// delivered with the phone saying nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_paired_device_that_registers_is_told_of_the_next_question_and_still_is_after_a_restart()
{
    const WORDS: &str = "Deploy the release to production?";
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x51));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());

    // The control: a question raised before the device registers reaches nobody. The daemon has
    // taken it, decided it, and has no destination to send it to.
    environment._worker.ask("deploy-0", WORDS);
    until_the_questions_are_settled(&environment, 1).await;
    assert_eq!(environment.deliveries(), 0, "no notification was written");
    assert!(environment.gateway.delivered().is_empty());
    assert!(environment.destination(phone.device_id()).is_none());

    let registered = phone
        .register(&environment, &credential)
        .await
        .expect("the daemon registers a credential its gateway confirms");
    assert_eq!(registered.device_id, phone.device_id());
    assert_eq!(registered.sender_record_id, sender);
    assert_eq!(
        environment.gateway.answers_on("/api/push/sender/renew"),
        vec![200],
        "the daemon asked the gateway for a nonce under its own key, which only an authorisation \
         that names that key is given, and renewed nothing"
    );
    assert_eq!(
        environment.gateway.answers_on("/api/push/deliver/status"),
        vec![200],
        "and asked whether the bearer it was handed works"
    );
    let destination = environment
        .destination(phone.device_id())
        .expect("the device is a destination now");
    let push = destination.as_push().expect("a push destination");
    assert_eq!(push.sender_record_id, sender);
    assert_eq!(
        push.preview_keys.current,
        *phone.device.keys().notification_preview.public(),
        "the preview key is the one the pairing recorded"
    );
    assert_eq!(
        destination.rule.as_ref().and_then(|rule| rule.grant_id),
        Some(phone.record.grant.grant_id),
        "and the rule is the device's own grant"
    );

    environment._worker.ask("deploy-1", WORDS);
    until("the question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    let request = environment.gateway.delivered().remove(0);
    assert_eq!(request.sender_record_id, sender);
    assert_eq!(request.hints.alert, PushAlert::QuestionWaiting);
    let host_preview = environment
        .controller()
        .delivery()
        .with(|producer| Ok(*producer.preview_public()))
        .expect("the host's preview key");
    let opened = kr_delivery::preview::open_preview(
        &phone.device.keys().notification_preview,
        &host_preview,
        request.preview.as_ref().expect("a preview"),
        now(),
    )
    .expect("the device opens its own preview");
    assert!(!format!("{opened:?}").contains(WORDS));
    let wire = serde_json::to_string(&request).expect("the request");
    for private in [WORDS, "deploy-1", &environment.worker_session.to_string()] {
        assert!(!wire.contains(private), "the gateway is given {private}");
    }
    assert_eq!(
        environment.gateway.state().bearers_refused,
        0,
        "every delivery was under the latest bearer the gateway issued"
    );

    // The daemon restarts. The bearer the gateway last issued is the one it finds, and the next
    // question is delivered with the device saying nothing.
    let environment = environment.restart().await;
    let before = environment.gateway.delivered().len();
    environment._worker.ask("deploy-2", WORDS);
    until("the question after the restart being delivered", || {
        environment.gateway.delivered().len() > before
    })
    .await;
    assert_eq!(environment.gateway.state().bearers_refused, 0);
}

// ---------------------------------------------------------------------------------------------
// Approvals a worker's application raises
// ---------------------------------------------------------------------------------------------

/// KR-REQ-25.01, KR-REQ-16.13: an approval an application raises through its channel reaches a
/// registered device. The worker's broker records the relayed request and its interpretation, the
/// attention store reads the broker's transitions and raises a pending approval, and the daemon
/// delivers it through the gateway under the device's credential as the generic approval alert, with
/// nothing of the request in the clear. The control is a request nothing gives a meaning (the
/// connector's package is not bound to its application): it is relayed first and recorded by the
/// broker, and raises nothing. Exactly one notification is written for the approval, though the
/// broker records several transitions of it and a transition of the other request before them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_approval_a_worker_relays_through_its_channel_is_delivered_as_an_approval_alert() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x91));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");

    // The control: recorded by the broker, and no approval to deliver.
    let mut unbound = environment._worker.open_channel(3, false);
    unbound.channel.relay("fghij").await;
    environment
        ._worker
        .until_relayed(&unbound, "fghij", false)
        .await;

    let mut bound = environment._worker.open_channel(2, true);
    bound.channel.relay("abcde").await;
    environment
        ._worker
        .until_relayed(&bound, "abcde", true)
        .await;
    until("the approval being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    let request = environment.gateway.delivered().remove(0);
    assert_eq!(request.sender_record_id, sender);
    assert_eq!(request.hints.alert, PushAlert::ApprovalWaiting);
    let wire = serde_json::to_string(&request).expect("the request");
    for private in [
        "Bash",
        "List the files here",
        "ls -la",
        "abcde",
        &environment.worker_session.to_string(),
    ] {
        assert!(!wire.contains(private), "the gateway is given {private}");
    }
    until_the_approvals_are_settled(&environment).await;
    assert_eq!(
        environment
            .deliveries_to(&phone.device_id().to_string())
            .len(),
        1,
        "one notification for the approval, whatever the broker recorded of it"
    );
    assert_eq!(
        environment.deliveries(),
        1,
        "and none for the request nothing interprets"
    );
    assert_eq!(environment.gateway.delivered().len(), 1);

    // The approval is pending in the inbox until it ends, and ends with its channel: the item
    // leaves, and the end is no new notification.
    assert_eq!(
        pending_approvals(&environment),
        1,
        "the control: it is pending"
    );
    bound.channel.close().await;
    until("the approval's item leaving the inbox", || {
        pending_approvals(&environment) == 0
    })
    .await;
    until_the_approvals_are_settled(&environment).await;
    assert_eq!(
        environment
            .deliveries_to(&phone.device_id().to_string())
            .len(),
        1,
        "the end of an approval raises nothing"
    );
}

/// KR-REQ-16.17, KR-REQ-25.01: twenty-two distinct approvals relayed at once are all retained by
/// the host, and the gateway is given no more than the free limit allows. The daemon's passes read a
/// time the test holds still, so the allowance has no time to refill and the figures are exact on
/// any machine: the first twenty are sent as approval alerts; the twenty-first opens the one
/// attention update the five-minute window lets through, which is sent in their place; the
/// twenty-second is collapsed into it, recorded and never sent, with the suppression the host shows
/// locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn twenty_two_approvals_at_once_are_all_retained_and_sent_within_the_burst_limit() {
    use kr_delivery::journal::DeliveryState;

    const RELAYED: usize = 22;
    const BURST: usize = 20;
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x92));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    environment
        .controller()
        .delivery_runtime()
        .hold_time_at(now());

    // Distinct request identifiers of the five-letter form Claude Code uses.
    let requests: Vec<String> = ('a'..='z')
        .filter(|letter| *letter != 'l')
        .take(RELAYED)
        .map(|letter| format!("abcd{letter}"))
        .collect();
    let mut bound = environment._worker.open_channel(2, true);
    for request in &requests {
        bound.channel.relay(request).await;
    }
    environment
        ._worker
        .until_relayed(&bound, requests.last().expect("a last request"), true)
        .await;
    until_the_approvals_are_settled(&environment).await;

    let records = environment.deliveries_to(&phone.device_id().to_string());
    assert_eq!(records.len(), RELAYED, "the host retains every request");
    let collapsed: Vec<_> = records
        .iter()
        .filter(|record| record.state == DeliveryState::Collapsed)
        .collect();
    let updates: Vec<_> = records
        .iter()
        .filter(|record| record.state != DeliveryState::Collapsed && record.suppression.is_some())
        .collect();
    let alerts = records.len() - collapsed.len() - updates.len();
    assert_eq!(
        (alerts, updates.len(), collapsed.len()),
        (BURST, 1, RELAYED - BURST - 1),
        "twenty alerts, the attention update, and what it took the place of: {records:?}"
    );
    for record in &collapsed {
        assert!(record.content.is_none() && !record.dispatched, "never sent");
        assert!(
            record
                .suppression
                .as_ref()
                .is_some_and(|suppression| suppression.collapsed_into == updates[0].notification_id),
            "what was collapsed names the update that took its place"
        );
    }

    // The gateway is given the alerts and the update, and nothing else.
    until("the sends reaching the gateway", || {
        environment.gateway.delivered().len() == alerts + updates.len()
    })
    .await;
    let sent = environment.gateway.delivered();
    assert_eq!(
        sent.iter()
            .filter(|request| request.hints.alert == PushAlert::ApprovalWaiting)
            .count(),
        BURST
    );
    assert_eq!(
        sent.iter()
            .filter(|request| request.hints.alert == PushAlert::AttentionUpdate)
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------------------------
// What a registration has to establish, and what it leaves alone
// ---------------------------------------------------------------------------------------------

/// Every file under `directory` that holds `needle`.
fn files_holding(directory: &std::path::Path, needle: &[u8]) -> Vec<PathBuf> {
    fn walk(directory: &std::path::Path, needle: &[u8], found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, needle, found);
            } else if std::fs::read(&path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(directory, needle, &mut found);
    found
}

/// The two spellings a bearer takes on a wire and in a file.
fn spellings(secret: [u8; 32]) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    vec![
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(secret)
            .into_bytes(),
        secret.to_vec(),
    ]
}

fn bytes_of(credential: &PushDeliveryCredential) -> [u8; 32] {
    credential
        .secret
        .expose()
        .to_vec()
        .try_into()
        .expect("thirty-two bytes")
}

/// The credential the secret store holds for one authorisation, read the way a daemon that starts
/// next would read it.
fn stored_credential(
    environment: &Environment,
    sender: PushSenderRecordId,
) -> Option<PushDeliveryCredential> {
    let store = open_store_in(&environment.host.tree().environment().secrets_dir())
        .expect("the daemon's secret store");
    match kr_controller::push::secrets::DestinationSecrets::new(
        Arc::from(store.store),
        environment.environment_id(),
    )
    .push_credential(sender)
    .expect("a read")
    {
        kr_controller::push::secrets::StoredCredential::Held(credential) => Some(credential),
        _ => None,
    }
}

/// Whether the secret store the daemon keeps its secrets in holds this bearer.
fn secret_store_holds(environment: &Environment, secret: [u8; 32]) -> bool {
    let secrets = environment.host.tree().environment().secrets_dir();
    spellings(secret)
        .iter()
        .any(|spelling| !files_holding(&secrets, spelling).is_empty())
}

/// Whether any file the daemon keeps outside its secret store holds this bearer.
fn state_holds(environment: &Environment, secret: [u8; 32]) -> Vec<PathBuf> {
    let paths = environment.host.tree().environment();
    let secrets = paths.secrets_dir();
    spellings(secret)
        .iter()
        .flat_map(|spelling| files_holding(paths.state_dir(), spelling))
        .filter(|path| !path.starts_with(&secrets))
        .collect()
}

/// KR-REQ-16.08, KR-REQ-16.09: what a device's word does not establish, the gateway does, and
/// nothing is kept until it has. Each refusal leaves no destination and no held credential, and
/// the bearer a refused device offered is in no file the daemon keeps; the control is the same
/// device registering a credential the gateway confirms to this host's key. A device cannot make
/// the daemon deliver through another origin, register an installation its own authorisation key
/// does not name, take an authorisation another device's destination holds, or register a
/// credential the gateway does not take; and a gateway nobody can reach changes nothing that was
/// already working.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_registration_is_kept_only_when_the_gateway_confirms_it_to_the_hosts_own_key() {
    let environment = Environment::start().await;
    let host_key = environment.host_signing_key();
    let phone = environment.phone().await;
    let other_phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x61));
    let credentials = environment.controller().delivery_runtime().credentials();
    let renewals = || {
        environment
            .gateway
            .answers_on("/api/push/sender/renew")
            .len()
    };
    let probes = || {
        environment
            .gateway
            .answers_on("/api/push/deliver/status")
            .len()
    };
    let invalid = kr_protocol::error::ErrorCode::InvalidArgument;
    let mut refused_bearers = Vec::new();

    // Not the gateway this host delivers through.
    let mut elsewhere = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    elsewhere.gateway_origin =
        kr_protocol::service::GatewayOrigin::new("https://gateway.elsewhere.example")
            .expect("an origin");
    refused_bearers.push(bytes_of(&elsewhere));
    let refused = phone
        .register(&environment, &elsewhere)
        .await
        .expect_err("another gateway's credential is refused");
    assert_eq!(refused.code, invalid);

    // An installation this device's own authorisation key does not name: another device's, and
    // one nobody's.
    let theirs = environment
        .gateway
        .issue(sender, other_phone.installation(), host_key);
    let nobodys = environment
        .gateway
        .issue(sender, InstallationId::new(uuid(0x62)), host_key);
    for unfit in [&theirs, &nobodys] {
        refused_bearers.push(bytes_of(unfit));
        let refused = phone
            .register(&environment, unfit)
            .await
            .expect_err("an installation that is not this device's own is refused");
        assert_eq!(refused.code, invalid);
    }

    // Already expired, lasting longer than thirty days, and issued in the future.
    let mut expired = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    expired.issued_at_ms = TimestampMs::new(now() - 60_000);
    expired.expires_at_ms = TimestampMs::new(now() - 1_000);
    let mut forever = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    forever.expires_at_ms = TimestampMs::new(forever.issued_at_ms.get() + 31 * 24 * 60 * 60 * 1000);
    // Issued an hour from now, by a clock that is not this host's.
    let mut early = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    early.issued_at_ms = TimestampMs::new(now() + 60 * 60 * 1000);
    early.expires_at_ms = TimestampMs::new(early.issued_at_ms.get() + 29 * 24 * 60 * 60 * 1000);
    for unfit in [&expired, &forever, &early] {
        refused_bearers.push(bytes_of(unfit));
        let refused = phone
            .register(&environment, unfit)
            .await
            .expect_err("a credential section 16 does not allow is refused");
        assert_eq!(refused.code, invalid);
    }
    assert_eq!(
        (renewals(), probes()),
        (0, 0),
        "none of them reached the gateway"
    );

    // An authorisation the gateway holds for another host's key.
    let someone_elses = AuthorisationKey::from_bytes([9; 32]);
    let foreign = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0x63)),
        phone.installation(),
        someone_elses,
    );
    refused_bearers.push(bytes_of(&foreign));
    let refused = phone
        .register(&environment, &foreign)
        .await
        .expect_err("the gateway does not name this host for it");
    assert_eq!(
        refused.code, invalid,
        "a refusal that asking again does not change"
    );
    assert_eq!(
        environment.gateway.answers_on("/api/push/sender/renew"),
        vec![403],
        "the gateway was asked for a nonce under the host's key and refused it"
    );
    assert_eq!(
        environment.gateway.answers_on("/api/push/deliver/status"),
        vec![200],
        "after the bearer was put to it, which it takes"
    );

    // A bearer the gateway does not take: the authorisation is this host's, the secret is not.
    let mut wrong = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    wrong.secret = SecretBytes32::from_bytes([0xab; 32]);
    refused_bearers.push(bytes_of(&wrong));
    let refused = phone
        .register(&environment, &wrong)
        .await
        .expect_err("a bearer the gateway does not take is refused");
    assert_eq!(refused.code, invalid);
    assert_eq!(
        environment.gateway.answers_on("/api/push/deliver/status"),
        vec![200, 401]
    );
    assert_eq!(
        renewals(),
        1,
        "and the nonce was not asked for, which costs the host's allowance for renewing"
    );
    assert!(environment.destination(phone.device_id()).is_none());
    assert!(credentials.held(sender).is_none());
    assert!(credentials.held(foreign.sender_record_id).is_none());

    // The control: the credential the gateway does take is kept, as the device gave it.
    let credential = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    phone
        .register(&environment, &credential)
        .await
        .expect("a confirmed credential is registered");
    assert!(environment.destination(phone.device_id()).is_some());
    assert_eq!(
        credentials.held(sender).expect("held").secret,
        credential.secret
    );

    // Another device cannot take the authorisation this device's destination holds, even under an
    // installation of its own.
    let mut taken = credential.clone();
    taken.installation_id = other_phone.installation();
    let before = (renewals(), probes());
    let refused = other_phone
        .register(&environment, &taken)
        .await
        .expect_err("an authorisation one destination holds is not another's");
    assert_eq!(refused.code, invalid);
    assert!(environment.destination(other_phone.device_id()).is_none());
    assert_eq!(
        (renewals(), probes()),
        before,
        "and the gateway was not asked about it"
    );

    // A gateway nobody can reach, or one with no answer that says either way, confirms nothing and
    // changes nothing that was already working. A bare 404 from a deployment without the status
    // route is no evidence that a bearer works.
    let held = credentials.held(sender).expect("held");
    let unasked = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0x65)),
        other_phone.installation(),
        host_key,
    );
    refused_bearers.push(bytes_of(&unasked));
    environment.gateway.set_down(true);
    let refused = other_phone
        .register(&environment, &unasked)
        .await
        .expect_err("a registration the gateway cannot confirm");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::UpstreamUnavailable,
        "a failure asking again may mend"
    );
    environment.gateway.set_down(false);
    environment
        .gateway
        .answer_route_with("/api/push/deliver/status", Some((404, "not found")));
    let refused = other_phone
        .register(&environment, &unasked)
        .await
        .expect_err("a status route that answers 404 confirms nothing");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    environment
        .gateway
        .answer_route_with("/api/push/deliver/status", None);
    assert!(environment.destination(other_phone.device_id()).is_none());
    assert!(credentials.held(unasked.sender_record_id).is_none());
    assert_eq!(
        credentials.held(sender).expect("still held").secret,
        held.secret
    );
    assert_eq!(
        environment
            .destination(phone.device_id())
            .and_then(|record| record.as_push().map(|push| push.sender_record_id)),
        Some(sender),
        "and the destination still names the authorisation it named"
    );

    // The bearer is where the secret store keeps it, and no bearer a refused device offered is
    // anywhere the daemon writes.
    assert!(
        secret_store_holds(&environment, bytes_of(&held)),
        "the control: the secret store holds the bearer"
    );
    assert!(
        state_holds(&environment, bytes_of(&held)).is_empty(),
        "no journal or directory holds it"
    );
    for refused in refused_bearers {
        assert!(!secret_store_holds(&environment, refused));
        assert!(state_holds(&environment, refused).is_empty());
    }
}

/// KR-REQ-16.10: unpairing a device ends its destination, forgets the credential held for it, in
/// memory and in the secret store, and asks the gateway to revoke the authorisation, proven under
/// the host's key. Nothing more is delivered to the device.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unpairing_a_device_ends_its_destination_and_the_gateway_revokes_the_authorisation() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x71));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let credentials = environment.controller().delivery_runtime().credentials();
    let bearer = bytes_of(&credential);
    assert!(
        secret_store_holds(&environment, bearer),
        "the control: the secret store holds the bearer while the device is paired"
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered to the paired device", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;

    unpair(&environment, phone.device_id()).await;

    // The destination is out of service: gone, or kept without a rule as the name of the
    // notification already sent to it.
    assert!(
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    );
    assert!(credentials.held(sender).is_none());
    assert!(
        !secret_store_holds(&environment, bearer),
        "the secret store gave the bearer up"
    );
    until(
        "the gateway being asked to revoke the authorisation",
        || {
            environment
                .gateway
                .authorisation(sender)
                .is_some_and(|held| held.state == PushSenderState::Revoked)
        },
    )
    .await;
    assert_eq!(
        environment.gateway.answers_on("/api/push/sender/revoke"),
        vec![200, 200],
        "a nonce, and then the revocation under the host key"
    );
    until("the revocation no longer being owed", || {
        owed(&environment).is_empty()
    })
    .await;

    // Nothing more is delivered to it: the daemon decided the next question reaches nobody, which
    // is its journal writing no notification, not the gateway merely not having been asked yet.
    let (written, delivered) = (
        environment.deliveries(),
        environment.gateway.delivered().len(),
    );
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");
    until_the_questions_are_settled(&environment, 2).await;
    assert_eq!(environment.deliveries(), written);
    assert_eq!(environment.gateway.delivered().len(), delivered);
}

/// KR-REQ-16.10: unpairing ends the device's destination before it answers, even when the device's
/// record cannot be marked revoked. The grants are withdrawn by then and the destination sends
/// under the device's own pairing grant, which the unmarked record still holds, so a host that
/// answered the error and left the destination would go on delivering to a device it was told to
/// unpair. The authorisation is owed to the gateway, and the unpairing, asked again once the record
/// can be written, completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unpairing_ends_the_destination_even_when_the_device_record_cannot_be_written() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x72));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    assert!(environment.destination(phone.device_id()).is_some());

    // The registry refuses to mark any device revoked, as a full disk or a locked file would.
    let registry = rusqlite::Connection::open(environment.host.registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_to_mark_a_device_revoked
                 BEFORE UPDATE OF revoked_at_ms ON network_devices
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("plants the fault");
    let mut client = environment.host.client().await;
    let refused = net_support::pairing::mutate::<_, kr_protocol::sharing::RevocationResult>(
        environment.environment_id(),
        &mut client,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: phone.device_id(),
        },
    )
    .await
    .expect_err("the record cannot be marked revoked");
    drop(refused);

    assert!(
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none()),
        "the destination is out of service"
    );
    assert!(
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_none()
    );
    until("the authorisation being revoked at the gateway", || {
        environment
            .gateway
            .authorisation(sender)
            .is_some_and(|held| held.state == PushSenderState::Revoked)
    })
    .await;

    // Asked again once the record can be written, the unpairing completes.
    registry
        .execute_batch("DROP TRIGGER refuse_to_mark_a_device_revoked;")
        .expect("removes the fault");
    unpair(&environment, phone.device_id()).await;
    let mut client = environment.host.client().await;
    let listed: kr_protocol::sharing::DeviceListResult = net_support::pairing::read(
        &mut client,
        Method::DeviceList,
        &kr_protocol::sharing::DeviceListParams {
            include_revoked: false,
        },
    )
    .await
    .expect("the list");
    assert!(
        listed
            .devices
            .iter()
            .all(|device| device.device_id != phone.device_id()),
        "the device is unpaired"
    );
}

/// KR-REQ-16.10: a device whose grant runs out while the daemon runs is no longer paired, and its
/// destination, the credential held for it and the authorisation behind it end with that, as they do
/// at its unpairing. The daemon runs on clocks the test moves by hand, so the grant runs out when
/// the test says and not when the machine's clock does. The control is the same device before its
/// grant runs out: its destination is in service and the question is delivered to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_devices_destination_ends_when_its_grant_runs_out_while_the_daemon_runs() {
    let (moved, clocks) = Moved::new();
    let environment = Environment::start_on_clocks(clocks).await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x73));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let credentials = environment.controller().delivery_runtime().credentials();
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the control question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert!(
        environment
            .destination(phone.device_id())
            .is_some_and(|record| record.enabled)
    );
    assert!(credentials.held(sender).is_some());

    moved.past_the_grant();
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");

    until("the device's destination ending", || {
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    })
    .await;
    until("the credential being given up", || {
        credentials.held(sender).is_none()
    })
    .await;
    assert!(
        !secret_store_holds(&environment, bytes_of(&credential)),
        "the secret store gave the bearer up"
    );
    // The stand-in gateway reads the real time and the daemon's clock is two days ahead of it, so
    // the revocation is not made here; that it is owed, durably, is what ending the destination
    // leaves behind.
    assert!(
        owed(&environment)
            .iter()
            .any(|debt| debt.sender_record_id == sender),
        "the authorisation is owed a revocation"
    );
}

/// The clocks of a daemon the test takes forward by hand, and a way to take both past a day.
///
/// Both run with the machine's own, as a running host's do: a daemon that restarts finds the wall
/// clock where the boot clock says it must be, and a wall clock that stood still while the machine
/// ran would be one that went backwards. The test adds what it moves them by.
struct Moved {
    wall_ahead_ms: Arc<std::sync::atomic::AtomicU64>,
    continuous_ahead_ns: Arc<std::sync::atomic::AtomicU64>,
}

/// The machine's continuous clock, taken forward by what a test adds to it.
#[derive(Debug)]
struct ContinuousAhead {
    machine: kr_transport::clock::SystemContinuousClock,
    ahead_ns: Arc<std::sync::atomic::AtomicU64>,
}

impl kr_transport::clock::ContinuousClock for ContinuousAhead {
    fn now(&self) -> kr_transport::clock::ContinuousInstant {
        let now = self.machine.now();
        let ahead = Duration::from_nanos(self.ahead_ns.load(std::sync::atomic::Ordering::Acquire));
        now.checked_add(ahead).unwrap_or(now)
    }
}

impl Moved {
    fn new() -> (Self, kr_controller::service::Clocks) {
        let wall_ahead_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let continuous_ahead_ns = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = kr_controller::service::Clocks {
            continuous: Arc::new(ContinuousAhead {
                machine: kr_transport::clock::SystemContinuousClock::new(),
                ahead_ns: Arc::clone(&continuous_ahead_ns),
            }),
            wall: kr_controller::service::WallClock::from_fn({
                let wall_ahead_ms = Arc::clone(&wall_ahead_ms);
                move || now() + wall_ahead_ms.load(std::sync::atomic::Ordering::SeqCst)
            }),
        };
        (
            Self {
                wall_ahead_ms,
                continuous_ahead_ns,
            },
            clocks,
        )
    }

    /// Takes the wall clock two days on and leaves the continuous clock where it is: the grant
    /// `proposal` gives a session invitation has run out by UTC, and the deadlines a request was
    /// admitted under, which are counted on the continuous clock, have not.
    fn past_the_grant_by_utc(&self) {
        let days = Duration::from_secs(2 * 24 * 60 * 60);
        self.wall_ahead_ms.fetch_add(
            u64::try_from(days.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Takes both clocks two days on, past the day the grant `proposal` gives a session invitation
    /// lasts.
    ///
    /// The wall clock goes first. A daemon that reads between the two steps anchors the new wall
    /// reading at the old continuous instant, and its first reading after the continuous step
    /// finds the wall clock two days behind that anchor and distrusts it. A grant with no anchor
    /// in this boot would then be refused; the three cases that use this anchored theirs at the
    /// connection, and the grant ends on its continuous deadline whatever the host trusts.
    fn past_the_grant(&self) {
        let days = Duration::from_secs(2 * 24 * 60 * 60);
        self.past_the_grant_by_utc();
        self.continuous_ahead_ns.fetch_add(
            u64::try_from(days.as_nanos()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Release,
        );
    }
}

/// The daemon's watch over paired devices looks every fifty milliseconds, and the test waits until
/// it has looked `looks` more times.
async fn until_the_watch_has_looked(environment: &Environment, looks: u64) {
    let controller = Arc::clone(environment.controller());
    let first = controller.device_watch_looks();
    until("the watch over paired devices looking again", || {
        controller.device_watch_looks() >= first + looks
    })
    .await;
}

/// KR-REQ-16.10: a device nothing is delivered to is still found when its grant runs out. A
/// destination the provider rejected the token of is out of service and keeps its rule, its
/// credential and the authorisation behind it, and the daemon's own watch over the paired devices,
/// on its timer, asks where its device's grant stands. Nothing here calls the watch: the control
/// is the same destination while the grant stands, which the watch has looked at twice and left
/// as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_watch_over_paired_devices_ends_the_destination_nothing_is_delivered_to() {
    let (moved, clocks) = Moved::new();
    let environment = Environment::start_on_clocks(clocks).await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x74));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let credentials = environment.controller().delivery_runtime().credentials();
    let rejected = environment
        .destination(phone.device_id())
        .expect("the destination");
    environment
        .controller()
        .delivery()
        .disable(&rejected)
        .expect("the provider rejects the token");

    environment
        .controller()
        .watch_devices_every(Duration::from_millis(50));
    until_the_watch_has_looked(&environment, 2).await;
    assert!(
        environment
            .destination(phone.device_id())
            .is_some_and(|record| !record.enabled && record.rule.is_some()),
        "the control: out of service, with its rule, while the grant stands"
    );
    assert!(credentials.held(sender).is_some());

    moved.past_the_grant();
    until("the watch ending the destination", || {
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    })
    .await;
    until("the credential being given up", || {
        credentials.held(sender).is_none()
    })
    .await;
    assert!(
        owed(&environment)
            .iter()
            .any(|debt| debt.sender_record_id == sender),
        "the authorisation is owed a revocation"
    );
}

/// KR-REQ-16.10: an ending that failed is tried again by the daemon's own watch. The expiry is on
/// record by then, so nothing writes it a second time to start the ending. Here the delivery
/// journal refuses the revocation the host owes the gateway, so the ending stops before anything is
/// removed and the watch looks again, several times, and leaves the destination as it was; once the
/// journal takes the debt the watch ends the destination on its next look. Nothing here calls the
/// watch.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_ending_that_failed_when_the_grant_ran_out_is_tried_again() {
    let (moved, clocks) = Moved::new();
    let environment = Environment::start_on_clocks(clocks).await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x75));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let credentials = environment.controller().delivery_runtime().credentials();

    let journal = rusqlite::Connection::open(
        environment
            .host
            .tree()
            .environment()
            .state_dir()
            .join(kr_controller::push::DELIVERY_JOURNAL),
    )
    .expect("opens the delivery journal");
    journal
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    journal
        .execute_batch(
            "CREATE TRIGGER refuse_the_debt BEFORE INSERT ON delivery_revocations
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("plants the fault");

    environment
        .controller()
        .watch_devices_every(Duration::from_millis(50));
    moved.past_the_grant();
    // The watch finds the expiry and writes it down, which starts the ending, which the journal
    // refuses.
    until("the expiry being on record", || {
        environment
            .controller()
            .devices()
            .record_for_device(phone.device_id())
            .ok()
            .flatten()
            .is_some_and(|record| record.expired_at_ms.is_some())
    })
    .await;
    // The watch looks again while the journal refuses the debt: nothing is removed and nothing is
    // ended, however often it tries.
    until_the_watch_has_looked(&environment, 3).await;
    assert!(
        environment
            .destination(phone.device_id())
            .is_some_and(|record| record.rule.is_some()),
        "the destination is still there"
    );
    assert!(credentials.held(sender).is_some());

    journal
        .execute_batch("DROP TRIGGER refuse_the_debt;")
        .expect("removes the fault");
    until("the watch ending the destination", || {
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    })
    .await;
    until("the credential being given up", || {
        credentials.held(sender).is_none()
    })
    .await;
    assert!(
        owed(&environment)
            .iter()
            .any(|debt| debt.sender_record_id == sender)
    );
}

/// KR-REQ-16.10: a revocation the gateway has not taken is owed, and is still owed after the
/// daemon restarts. Here the daemon has no way to reach any gateway when the device is unpaired:
/// the destination and its credential go at once, the debt is written down, and the revocation is
/// made when a gateway can be reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_owed_when_no_gateway_can_be_reached_is_made_when_one_can() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x81));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");

    // The daemon restarts and reaches no gateway, and the device is unpaired.
    let environment = environment.restart_attached(false).await;
    unpair(&environment, phone.device_id()).await;
    assert!(
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled)
    );
    let owing = owed(&environment);
    assert_eq!(owing.len(), 1, "one revocation is owed");
    assert_eq!(owing[0].sender_record_id, sender);
    assert_eq!(owing[0].gateway_origin, GATEWAY);
    assert_eq!(
        environment
            .gateway
            .authorisation(sender)
            .expect("held")
            .state,
        PushSenderState::Active,
        "and the gateway still holds the authorisation"
    );

    // A stop between ending the destination and deleting its item leaves the item behind. It is
    // put back here, and the next start removes it: nothing renews it for a device that is gone.
    {
        let store = open_store_in(&environment.host.tree().environment().secrets_dir())
            .expect("the daemon's secret store");
        kr_controller::push::secrets::DestinationSecrets::new(
            Arc::from(store.store),
            environment.environment_id(),
        )
        .put_push_credential(&credential)
        .expect("the item is left behind");
    }
    assert!(secret_store_holds(&environment, bytes_of(&credential)));

    // It is owed across another restart too.
    let environment = environment.restart_attached(false).await;
    assert_eq!(owed(&environment).len(), 1);
    assert!(
        !secret_store_holds(&environment, bytes_of(&credential)),
        "and the start removed what was left of the authorisation"
    );
    assert!(
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_none()
    );

    // A gateway that can be reached is asked, and the debt is paid.
    environment.attach_gateway();
    until("the gateway being asked to revoke", || {
        environment
            .gateway
            .authorisation(sender)
            .is_some_and(|held| held.state == PushSenderState::Revoked)
    })
    .await;
    until("the debt being settled", || owed(&environment).is_empty()).await;
}

/// KR-REQ-16.09: the daemon keeps the credential current with no phone awake or connected. One
/// the gateway issued for two days, inside the renewal window, is renewed when the daemon starts;
/// one found past its expiry in the secret store is renewed too, because the authorisation behind
/// it has not lapsed. Each renewal is kept, so a daemon that starts again delivers under the
/// bearer the gateway issued last, and the gateway never refuses one. An older copy of the
/// credential, handed over again, is refused. The gateway renews only in the last week of a
/// credential's life, as the Worker does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_daemon_renews_what_it_holds_with_the_phone_away_and_remembers_the_renewal() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x91));
    // A credential with two days left: inside the seven days section 16 renews ahead of expiry.
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    environment.gateway.issue_for(0);
    let registered = environment.gateway.revision_of(sender);

    // The daemon starts again, with the phone away. It renews at once, and the renewal is kept.
    let environment = environment.restart().await;
    until("the daemon renewing a credential in its window", || {
        environment.gateway.revision_of(sender) > registered
    })
    .await;
    let renewed = environment.gateway.revision_of(sender);
    let credentials = environment.controller().delivery_runtime().credentials();
    until(
        "the daemon holding the credential the gateway issued",
        || {
            credentials
                .held(sender)
                .is_some_and(|held| held.revision.get() == renewed)
        },
    )
    .await;

    // And the renewal is in the secret store, where a daemon that starts next reads it from: the
    // gateway renews again only in the last week of the new credential's life, or within an hour.
    assert_eq!(
        stored_credential(&environment, sender).map(|stored| stored.revision.get()),
        Some(renewed),
        "the renewed bearer was written before it was used"
    );

    // The copy the device kept is older than what the daemon holds, and is refused.
    let reconnected = environment.phone_with_keys_of(&phone).await;
    let refused = reconnected
        .register(&environment, &credential)
        .await
        .expect_err("an older copy of a credential is refused");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::InvalidArgument);

    // The copy in the secret store is found past its expiry, as it is by a daemon that was off for
    // a month, and the gateway's record has lapsed with it. The daemon renews that too.
    environment.gateway.lapse(sender);
    {
        let store = open_store_in(&environment.host.tree().environment().secrets_dir())
            .expect("the daemon's secret store");
        let vault = kr_controller::push::secrets::DestinationSecrets::new(
            Arc::from(store.store),
            environment.environment_id(),
        );
        let mut lapsed = stored_credential(&environment, sender).expect("the credential is kept");
        lapsed.issued_at_ms = TimestampMs::new(now() - 31 * 24 * 60 * 60 * 1000);
        lapsed.expires_at_ms = TimestampMs::new(now() - 1_000);
        vault.put_push_credential(&lapsed).expect("a write");
    }
    let environment = environment.restart().await;
    until("the daemon renewing a credential past its expiry", || {
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_some_and(|held| held.revision.get() > renewed)
    })
    .await;

    let latest = environment
        .controller()
        .delivery_runtime()
        .credentials()
        .held(sender)
        .expect("held");
    assert_eq!(
        stored_credential(&environment, sender),
        Some(latest),
        "and so is the renewal of a credential found past its expiry"
    );

    // And what it delivers under afterwards is the bearer the gateway issued last.
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(environment.gateway.state().bearers_refused, 0);
    let environment = environment.restart().await;
    let before = environment.gateway.delivered().len();
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");
    until("the question after another restart being delivered", || {
        environment.gateway.delivered().len() > before
    })
    .await;
    assert_eq!(
        environment.gateway.state().bearers_refused,
        0,
        "the daemon remembered every renewal"
    );
}

/// KR-REQ-16.10: a device that registers a new authorisation for its installation leaves the
/// earlier one behind. The earlier credential goes from the secret store, the gateway is asked to
/// revoke the authorisation, a question is delivered under the new one, and the preview-key
/// rotation the device made in between is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_new_authorisation_replaces_the_earlier_one_and_the_gateway_revokes_it() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let host_key = environment.host_signing_key();
    let old = PushSenderRecordId::new(uuid(0xb1));
    let new = PushSenderRecordId::new(uuid(0xb2));
    let first = environment
        .gateway
        .issue(old, phone.installation(), host_key);
    phone
        .register(&environment, &first)
        .await
        .expect("the first credential is registered");
    assert!(secret_store_holds(&environment, bytes_of(&first)));

    // The device rotates its preview key between the two registrations, and keeps the rotation.
    let rotated = kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair");
    phone
        .connection
        .mutate(
            Method::DevicePreviewKeyUpdate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment.environment_id()),
            &kr_protocol::sharing::DevicePreviewKeyUpdateParams {
                device_id: phone.device_id(),
                notification_preview: *rotated.public(),
                revision: kr_protocol::ids::DeviceKeyRevision::new(2),
            },
        )
        .await
        .expect("the preview key rotates");

    let second = environment
        .gateway
        .issue(new, phone.installation(), host_key);
    phone
        .register(&environment, &second)
        .await
        .expect("the second credential is registered");
    let kept = environment
        .destination(phone.device_id())
        .expect("a destination");
    let keys = &kept.as_push().expect("a push destination").preview_keys;
    assert_eq!(
        (keys.current, keys.revision),
        (*rotated.public(), 2),
        "registering again keeps the rotation the device made"
    );
    let credentials = environment.controller().delivery_runtime().credentials();
    assert!(credentials.held(old).is_none());
    assert!(
        !secret_store_holds(&environment, bytes_of(&first)),
        "the earlier bearer is gone from the secret store"
    );
    assert!(secret_store_holds(&environment, bytes_of(&second)));
    until("the earlier authorisation being revoked", || {
        environment
            .gateway
            .authorisation(old)
            .is_some_and(|held| held.state == PushSenderState::Revoked)
    })
    .await;
    until("the debt being paid", || owed(&environment).is_empty()).await;
    assert_eq!(
        environment.gateway.authorisation(new).expect("held").state,
        PushSenderState::Active
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(
        environment
            .gateway
            .state()
            .delivered
            .last()
            .map(|(sender, _)| *sender),
        Some(new)
    );
}

/// KR-REQ-16.10: while the host owes the gateway a revocation of an authorisation, a device cannot
/// register it again: the sweep would revoke the one in use. Nothing changes, the gateway is not
/// asked, and a question is delivered under the authorisation in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_authorisation_the_host_is_revoking_cannot_be_registered_again() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let host_key = environment.host_signing_key();
    let old = PushSenderRecordId::new(uuid(0xb1));
    let new = PushSenderRecordId::new(uuid(0xb2));
    let first = environment
        .gateway
        .issue(old, phone.installation(), host_key);
    phone
        .register(&environment, &first)
        .await
        .expect("the first credential is registered");
    assert!(secret_store_holds(&environment, bytes_of(&first)));

    // The gateway is having a bad hour: the revocation of the earlier authorisation stays owed.
    environment.gateway.refuse_revocations(true);
    let second = environment
        .gateway
        .issue(new, phone.installation(), host_key);
    phone
        .register(&environment, &second)
        .await
        .expect("the second credential is registered");
    let credentials = environment.controller().delivery_runtime().credentials();
    assert!(credentials.held(old).is_none());
    assert!(
        !secret_store_holds(&environment, bytes_of(&first)),
        "the earlier bearer is gone from the secret store"
    );
    assert!(secret_store_holds(&environment, bytes_of(&second)));
    until(
        "the revocation of the earlier authorisation being owed",
        || {
            owed(&environment)
                .iter()
                .any(|owing| owing.sender_record_id == old)
        },
    )
    .await;

    // While it is owed, the earlier authorisation cannot be registered again: the sweep would
    // revoke the one in use. Nothing changes and the gateway is not asked.
    let (renewals, probes) = (
        environment
            .gateway
            .answers_on("/api/push/sender/renew")
            .len(),
        environment
            .gateway
            .answers_on("/api/push/deliver/status")
            .len(),
    );
    let refused = phone
        .register(&environment, &first)
        .await
        .expect_err("an authorisation being revoked is refused");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::InvalidArgument);
    assert_eq!(
        (
            environment
                .gateway
                .answers_on("/api/push/sender/renew")
                .len(),
            environment
                .gateway
                .answers_on("/api/push/deliver/status")
                .len()
        ),
        (renewals, probes),
        "and the gateway was not asked"
    );
    assert!(credentials.held(old).is_none());
    assert_eq!(
        environment
            .destination(phone.device_id())
            .and_then(|record| record.as_push().map(|push| push.sender_record_id)),
        Some(new)
    );

    assert_eq!(
        environment.gateway.authorisation(old).expect("held").state,
        PushSenderState::Active,
        "the gateway has not revoked it yet, and the host still owes it"
    );
    assert_eq!(
        environment.gateway.authorisation(new).expect("held").state,
        PushSenderState::Active
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(
        environment
            .gateway
            .state()
            .delivered
            .last()
            .map(|(sender, _)| *sender),
        Some(new)
    );
}

/// A daemon with no way to reach a gateway cannot confirm a credential, and keeps none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_daemon_that_cannot_reach_a_gateway_registers_nothing() {
    let environment = Environment::start_attached(false).await;
    let phone = environment.phone().await;
    let credential = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0xc1)),
        phone.installation(),
        environment.host_signing_key(),
    );
    let refused = phone
        .register(&environment, &credential)
        .await
        .expect_err("no gateway can be asked");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    assert!(environment.destination(phone.device_id()).is_none());
    assert!(!secret_store_holds(&environment, bytes_of(&credential)));
}

/// KR-REQ-16.10: a device revoked while the daemon was not serving it leaves a destination and a
/// credential behind. The daemon that starts next ends them and asks the gateway to revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_revoked_while_the_daemon_was_down_is_ended_at_the_next_start() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0xd1));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    // The device directory records the revocation and the daemon stops before it does the rest.
    environment
        .controller()
        .devices()
        .revoke(phone.device_id(), TimestampMs::new(now()))
        .expect("the device is revoked in the directory");
    assert!(environment.destination(phone.device_id()).is_some());

    let environment = environment.restart().await;
    assert!(
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    );
    assert!(
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_none()
    );
    assert!(!secret_store_holds(&environment, bytes_of(&credential)));
    until("the gateway being asked to revoke", || {
        environment
            .gateway
            .authorisation(sender)
            .is_some_and(|held| held.state == PushSenderState::Revoked)
    })
    .await;
}

/// A destination in service with no credential kept for it, which is what a stop between writing a
/// registration's destination and its credential leaves, delivers nothing: its notifications
/// settle as revoked. The device registers again, and the next question is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_destination_with_no_credential_delivers_nothing_until_the_device_registers_again() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0xe1));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    // The item is gone from the secret store, as it is when a stop came between the two writes.
    {
        let store = open_store_in(&environment.host.tree().environment().secrets_dir())
            .expect("the daemon's secret store");
        kr_controller::push::secrets::DestinationSecrets::new(
            Arc::from(store.store),
            environment.environment_id(),
        )
        .remove_push_credential(sender)
        .expect("the item is removed");
    }

    let environment = environment.restart().await;
    assert!(environment.destination(phone.device_id()).is_some());
    assert!(
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_none()
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until_the_questions_are_settled(&environment, 1).await;
    until("the notification being settled", || {
        environment
            .controller()
            .delivery()
            .with(|producer| {
                Ok(producer
                    .journal()
                    .deliveries()
                    .expect("a read")
                    .iter()
                    .any(|record| record.state == kr_delivery::journal::DeliveryState::Revoked))
            })
            .expect("a read")
    })
    .await;
    assert!(
        environment.gateway.delivered().is_empty(),
        "nothing reached the gateway"
    );

    // The device registers again, and what comes next is delivered.
    let reconnected = environment.phone_with_keys_of(&phone).await;
    reconnected
        .register(&environment, &credential)
        .await
        .expect("the credential is registered again");
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");
    until("the next question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
}

/// A device that registers over and over has the gateway asked only a few times an hour: the
/// questions come out of the gateway's allowances for this host, and a device must not be able to
/// spend the renewals and revocations of every other. The fourth in a row is refused without the
/// gateway being asked, and another device is not affected.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_that_registers_over_and_over_is_not_confirmed_with_the_gateway_each_time() {
    let environment = Environment::start().await;
    let host_key = environment.host_signing_key();
    let phone = environment.phone().await;
    let other_phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0xf1));
    let mut wrong = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    wrong.secret = SecretBytes32::from_bytes([0xab; 32]);
    let probes = || {
        environment
            .gateway
            .answers_on("/api/push/deliver/status")
            .len()
    };
    for attempt in 1..=3 {
        let refused = phone
            .register(&environment, &wrong)
            .await
            .expect_err("a bearer the gateway does not take");
        assert_eq!(
            refused.code,
            kr_protocol::error::ErrorCode::InvalidArgument,
            "attempt {attempt}"
        );
    }
    assert_eq!(probes(), 3);
    let good = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    let refused = phone
        .register(&environment, &good)
        .await
        .expect_err("the fourth in a row is not put to the gateway");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::RateLimited,
        "a refusal that says to wait"
    );
    assert_eq!(probes(), 3, "and the gateway was not asked");
    assert!(environment.destination(phone.device_id()).is_none());

    // Another device has its own allowance.
    let theirs = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0xf2)),
        other_phone.installation(),
        host_key,
    );
    other_phone
        .register(&environment, &theirs)
        .await
        .expect("another device is confirmed");
}

// ---------------------------------------------------------------------------------------------
// What the gateway's answers have to be to count
// ---------------------------------------------------------------------------------------------

const STATUS_ROUTE: &str = "/api/push/deliver/status";
const RENEW_ROUTE: &str = "/api/push/sender/renew";
const REVOKE_ROUTE: &str = "/api/push/sender/revoke";

/// KR-REQ-16.08: only the gateway's own success confirms a bearer. A success with no `data`, one
/// whose `data` is not an acknowledgement, a success that also carries an error, a refusal under a
/// success status, and a refusal with no envelope, from something in front of the gateway, confirm
/// nothing and keep nothing. None of them is taken for the gateway refusing the bearer, because
/// asking again may mend them, and none reaches the question that costs the host's allowance for
/// renewing. The gateway's own refusal of the bearer is the control, and so is its success.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn only_the_gateways_own_success_confirms_a_bearer() {
    use kr_protocol::error::ErrorCode::{InvalidArgument, UpstreamUnavailable};

    let environment = Environment::start().await;
    let host_key = environment.host_signing_key();
    let phones = [
        environment.phone().await,
        environment.phone().await,
        environment.phone().await,
        environment.phone().await,
    ];
    let unauthenticated = r#"{"ok":false,"error":{"code":"UNAUTHENTICATED","message":"no"}}"#;
    // An acknowledgement of a notification, which a refusal does not carry.
    let acknowledgement = PushDeliveryAck {
        decided_at_ms: TimestampMs::new(now()),
        notification_id: kr_protocol::ids::NotificationId::new(uuid(0x55)),
        state: PushDeliveryState::Queued,
        suppression: Nullable::null(),
    };
    let refusal_with = |data: serde_json::Value| {
        serde_json::json!({
            "ok": false,
            "data": data,
            "error": { "code": "UNAUTHENTICATED", "message": "no" },
        })
        .to_string()
    };
    let cases: [(u16, String, kr_protocol::error::ErrorCode); 9] = [
        (200, r#"{"ok":true}"#.to_owned(), UpstreamUnavailable),
        (
            200,
            r#"{"ok":true,"data":{}}"#.to_owned(),
            UpstreamUnavailable,
        ),
        (
            200,
            r#"{"ok":true,"data":null,"error":{"code":"UNAUTHENTICATED","message":"no"}}"#
                .to_owned(),
            UpstreamUnavailable,
        ),
        (200, unauthenticated.to_owned(), UpstreamUnavailable),
        // A refusal whose `data` is not nothing is not the gateway's refusal either.
        (
            401,
            refusal_with(serde_json::to_value(&acknowledgement).expect("an acknowledgement")),
            UpstreamUnavailable,
        ),
        (401, "unauthorised".to_owned(), UpstreamUnavailable),
        (403, "<html>blocked</html>".to_owned(), UpstreamUnavailable),
        (
            401,
            r#"{"ok":false,"error":{"code":"RATE_LIMITED","message":"no"}}"#.to_owned(),
            UpstreamUnavailable,
        ),
        // The control: the gateway refusing the bearer is its answer about this credential.
        (401, unauthenticated.to_owned(), InvalidArgument),
    ];
    for (index, (status, body, code)) in cases.iter().enumerate() {
        let phone = &phones[index / 3];
        let credential = environment.gateway.issue(
            PushSenderRecordId::new(uuid(0x70 + u8::try_from(index).expect("a few cases"))),
            phone.installation(),
            host_key,
        );
        environment
            .gateway
            .answer_route_with(STATUS_ROUTE, Some((*status, body)));
        let refused = phone
            .register(&environment, &credential)
            .await
            .expect_err("an answer that is not the gateway's success confirms nothing");
        assert_eq!(refused.code, *code, "{status} {body}");
        assert!(environment.destination(phone.device_id()).is_none());
        assert!(
            environment
                .controller()
                .delivery_runtime()
                .credentials()
                .held(credential.sender_record_id)
                .is_none()
        );
        assert!(!secret_store_holds(&environment, bytes_of(&credential)));
    }
    assert!(
        environment.gateway.answers_on(RENEW_ROUTE).is_empty(),
        "none of them reached the question that spends the host's allowance for renewing"
    );

    // The control: the gateway's success, with the nothing it says of a notification that does not
    // exist, confirms the bearer.
    environment.gateway.answer_route_with(STATUS_ROUTE, None);
    let credential = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0x7f)),
        phones[3].installation(),
        host_key,
    );
    phones[3]
        .register(&environment, &credential)
        .await
        .expect("the gateway's success confirms the bearer");
    assert_eq!(environment.gateway.answers_on(RENEW_ROUTE), vec![200]);
}

/// KR-REQ-16.08: the nonce a registration asks for is the gateway's to give or to refuse, and only
/// its own refusal says the authorisation is not this host's. A 403 or a 401 with no envelope comes
/// from something in front of the gateway: it confirms nothing, is not blamed on the credential,
/// and may be asked again. The gateway's own `FORBIDDEN` is the control.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_refusal_of_the_nonce_that_is_not_the_gateways_blames_nobody() {
    use kr_protocol::error::ErrorCode::{InvalidArgument, UpstreamUnavailable};

    let environment = Environment::start().await;
    let host_key = environment.host_signing_key();
    let phones = [
        environment.phone().await,
        environment.phone().await,
        environment.phone().await,
    ];
    // A nonce with an error beside it is not the gateway's success, and is not its refusal.
    let contradictory = serde_json::json!({
        "ok": true,
        "data": {
            "gateway_nonce": Nonce256::from_bytes([1; 32]),
            "expires_at_ms": TimestampMs::new(now() + 60_000),
        },
        "error": { "code": "FORBIDDEN", "message": "no" },
    })
    .to_string();
    let cases: [(u16, String, kr_protocol::error::ErrorCode); 4] = [
        (403, "forbidden".to_owned(), UpstreamUnavailable),
        (401, "<html>sign in</html>".to_owned(), UpstreamUnavailable),
        (200, contradictory, UpstreamUnavailable),
        (
            403,
            r#"{"ok":false,"error":{"code":"FORBIDDEN","message":"no"}}"#.to_owned(),
            InvalidArgument,
        ),
    ];
    for (index, (status, body, code)) in cases.iter().enumerate() {
        let phone = &phones[index % 3];
        let credential = environment.gateway.issue(
            PushSenderRecordId::new(uuid(0x80 + u8::try_from(index).expect("a few cases"))),
            phone.installation(),
            host_key,
        );
        environment
            .gateway
            .answer_route_with(RENEW_ROUTE, Some((*status, body)));
        let refused = phone
            .register(&environment, &credential)
            .await
            .expect_err("a nonce nobody gave confirms nothing");
        assert_eq!(refused.code, *code, "{status} {body}");
        assert!(environment.destination(phone.device_id()).is_none());
    }
    environment.gateway.answer_route_with(RENEW_ROUTE, None);
    let credential = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0x8f)),
        phones[1].installation(),
        host_key,
    );
    phones[1]
        .register(&environment, &credential)
        .await
        .expect("the gateway's nonce confirms the authorisation");
}

// ---------------------------------------------------------------------------------------------
// The gateway's allowance for the host
// ---------------------------------------------------------------------------------------------

/// KR-REQ-16.09: the gateway counts the host's renewals and revocations together, and a
/// registration that asks for a nonce spends from the same allowance. So the host allows itself a
/// few registrations an hour whichever devices make them, and says to wait: the third device's
/// seventh registration, with a bearer the gateway takes, is not put to the question that spends
/// the allowance, while a bearer that fails the first question costs it nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn devices_registering_cannot_spend_the_gateways_allowance_for_renewing_and_revoking() {
    let environment = Environment::start().await;
    let host_key = environment.host_signing_key();
    let phones = [
        environment.phone().await,
        environment.phone().await,
        environment.phone().await,
    ];
    let mut next = 0xa0_u8;
    // Two devices register three times each: each is within its own allowance.
    for phone in &phones[..2] {
        for _ in 0..3 {
            next += 1;
            let credential = environment.gateway.issue(
                PushSenderRecordId::new(uuid(next)),
                phone.installation(),
                host_key,
            );
            phone
                .register(&environment, &credential)
                .await
                .expect("a device within its own allowance is confirmed");
        }
    }
    assert_eq!(environment.gateway.answers_on(RENEW_ROUTE).len(), 6);

    // The third device has an allowance of its own and a bearer the gateway takes.
    next += 1;
    let credential = environment.gateway.issue(
        PushSenderRecordId::new(uuid(next)),
        phones[2].installation(),
        host_key,
    );
    let refused = phones[2]
        .register(&environment, &credential)
        .await
        .expect_err("the host has asked the gateway for as many nonces as it allows itself");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::RateLimited);
    assert_eq!(
        environment.gateway.answers_on(RENEW_ROUTE).len(),
        6,
        "the gateway was not asked for another nonce"
    );
    assert_eq!(
        environment.gateway.answers_on(STATUS_ROUTE).len(),
        7,
        "its bearer was put to the first question, which spends a larger allowance"
    );
    assert!(environment.destination(phones[2].device_id()).is_none());
}

// ---------------------------------------------------------------------------------------------
// Which bearer the host keeps when two things change it at once
// ---------------------------------------------------------------------------------------------

/// KR-REQ-16.09: a registration whose bearer the gateway has confirmed does not put that bearer
/// back over the one a renewal stored while the gateway was answering. The renewal retired it, so
/// the host would hold a bearer the gateway no longer takes, and nothing but the gateway's recovery
/// hour would mend it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_registration_leaves_the_bearer_a_renewal_stored_while_the_gateway_was_answering() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x67));
    // Two days left: inside the last week, where the gateway renews.
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    let first =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &first)
        .await
        .expect("the first credential is registered");
    let credentials = Arc::clone(environment.controller().delivery_runtime().credentials());

    // The device is issued another bearer for the authorisation and hands it over. The gateway
    // takes it, and its answer is held while the host renews.
    let second =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    let held = environment.gateway.hold(STATUS_ROUTE, 0);
    let renewing = async {
        held.reached().await;
        let current = credentials.held(sender).expect("held");
        let credentials = Arc::clone(&credentials);
        let renewed = tokio::task::spawn_blocking(move || {
            kr_delivery::push::SenderCredentials::renew(credentials.as_ref(), &current)
        })
        .await
        .expect("a thread")
        .expect("the host renews");
        held.release();
        renewed
    };
    let (registered, renewed) = tokio::join!(phone.register(&environment, &second), renewing);
    registered.expect("the registration is accepted");

    assert_ne!(
        renewed.secret, second.secret,
        "the renewal retired the bearer"
    );
    assert_eq!(
        credentials.held(sender).expect("held").secret,
        renewed.secret,
        "the host holds the bearer the gateway issued last"
    );
    assert_eq!(
        stored_credential(&environment, sender).map(|stored| stored.secret),
        Some(renewed.secret),
        "and so does the secret store"
    );
    assert!(
        environment.destination(phone.device_id()).is_some(),
        "the destination was written all the same"
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(environment.gateway.state().bearers_refused, 0);
}

/// KR-REQ-16.09: a renewal whose answer comes late does not put its bearer over the one the device
/// was issued and registered while it waited. The gateway issued the device's bearer later, so the
/// renewed one is the retired one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_renewal_leaves_the_bearer_a_device_registered_while_the_gateway_was_answering() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x68));
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    let first =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &first)
        .await
        .expect("the first credential is registered");
    let credentials = Arc::clone(environment.controller().delivery_runtime().credentials());

    // The renewal's nonce is answered, and the gateway renews; the answer to the renewal is held.
    let current = credentials.held(sender).expect("held");
    let held = environment.gateway.hold(RENEW_ROUTE, 1);
    let renewing = tokio::task::spawn_blocking({
        let credentials = Arc::clone(&credentials);
        move || kr_delivery::push::SenderCredentials::renew(credentials.as_ref(), &current)
    });
    held.reached().await;

    // The device is issued a bearer after that renewal, which retires the renewed one, and
    // registers it.
    let second =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &second)
        .await
        .expect("the second credential is registered");
    held.release();
    let answered = renewing
        .await
        .expect("a thread")
        .expect("the renewal is answered");

    assert_eq!(
        credentials.held(sender).expect("held").secret,
        second.secret,
        "the host holds the bearer the device registered, not the renewal that came after it"
    );
    assert_eq!(
        answered.secret, second.secret,
        "and the caller that renewed is given it"
    );
    assert_eq!(
        stored_credential(&environment, sender).map(|stored| stored.secret),
        Some(second.secret)
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(environment.gateway.state().bearers_refused, 0);
}

// ---------------------------------------------------------------------------------------------
// One sweep of owed revocations at a time
// ---------------------------------------------------------------------------------------------

/// KR-REQ-16.10: a sweep that finds another still asking leaves the debts to it, and the one that
/// is asking goes round again before it lets go. Two sweeps that asked about one debt would each
/// ask the gateway for a nonce and for the revocation, and the gateway counts all four against the
/// host's allowance for renewing and revoking; and a debt written after the running sweep read
/// its list would otherwise wait for the next round of questions.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_second_sweep_does_not_ask_about_a_debt_the_first_is_asking_about() {
    let environment = Environment::start().await;
    let phones = [environment.phone().await, environment.phone().await];
    let senders = [
        PushSenderRecordId::new(uuid(0x69)),
        PushSenderRecordId::new(uuid(0x6b)),
    ];
    // Two days left, so that the daemon's first round of questions renews both and shows it ran.
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    for (phone, sender) in phones.iter().zip(senders) {
        let credential =
            environment
                .gateway
                .issue(sender, phone.installation(), environment.host_signing_key());
        phone
            .register(&environment, &credential)
            .await
            .expect("the credential is registered");
    }
    // The first round of questions is the one other thing that sweeps, and it comes once, a moment
    // after the daemon has a transport and then every five minutes. Let it come before the
    // sweeps are looked at.
    let renewals = environment.gateway.answers_on(RENEW_ROUTE).len();
    let environment = environment.restart().await;
    until("the first round of questions", || {
        environment.gateway.answers_on(RENEW_ROUTE).len() >= renewals + 4
    })
    .await;

    // The first unpairing starts a sweep, whose first question is held at the gateway.
    let held = environment.gateway.hold(REVOKE_ROUTE, 0);
    unpair(&environment, phones[0].device_id()).await;
    held.reached().await;
    let runtime = Arc::clone(environment.controller().delivery_runtime());
    tokio::task::spawn_blocking(move || runtime.sweep_revocations())
        .await
        .expect("a sweep");
    assert_eq!(
        environment.gateway.answers_on(REVOKE_ROUTE),
        vec![200],
        "the second sweep asked nothing while the first was asking"
    );

    // Another device is unpaired meanwhile. Its debt was written after the first sweep read its
    // list, and is asked about as soon as that sweep is done, not at the next round of questions.
    unpair(&environment, phones[1].device_id()).await;
    assert_eq!(owed(&environment).len(), 2, "both debts are owed");
    assert_eq!(
        environment.gateway.answers_on(REVOKE_ROUTE),
        vec![200],
        "and nothing was asked for the second debt either"
    );
    held.release();
    until("both debts being paid", || owed(&environment).is_empty()).await;
    assert_eq!(
        environment.gateway.answers_on(REVOKE_ROUTE),
        vec![200; 4],
        "a nonce and the revocation, once for each"
    );
    for sender in senders {
        assert_eq!(
            environment
                .gateway
                .authorisation(sender)
                .expect("held")
                .state,
            PushSenderState::Revoked
        );
    }
}

// ---------------------------------------------------------------------------------------------
// A renewal that fails ahead of need, and one that comes back late
// ---------------------------------------------------------------------------------------------

/// KR-REQ-16.09, KR-REQ-16.12: a bearer the gateway has not refused works until its expiry, so a
/// renewal ahead of need that fails does not hold a notification back. The gateway cannot be
/// reached for a renewal, or refuses it because the expiry the device wrote is earlier than the
/// gateway's; the question is delivered under the bearer held all the same, and the host goes on
/// asking for the renewal after a wait, not at every attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_renewal_ahead_of_need_that_fails_does_not_hold_a_notification_back() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x6c));
    // Two days left: inside the last week, where the host renews ahead of need.
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let renewals = environment.gateway.answers_on(RENEW_ROUTE).len();

    environment
        .gateway
        .answer_route_with(RENEW_ROUTE, Some((503, "unavailable")));
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert!(
        environment.gateway.answers_on(RENEW_ROUTE).len() > renewals,
        "the renewal was asked for and failed"
    );
    assert_eq!(
        environment.gateway.state().bearers_refused,
        0,
        "and the bearer held was the one that works"
    );

    // The next question is delivered in the wait without the gateway being asked again.
    let asked = environment.gateway.answers_on(RENEW_ROUTE).len();
    let before = environment.gateway.delivered().len();
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");
    until("the next question being delivered", || {
        environment.gateway.delivered().len() > before
    })
    .await;
    assert_eq!(
        environment.gateway.answers_on(RENEW_ROUTE).len(),
        asked,
        "the host waits before it asks for the renewal again"
    );
}

/// KR-REQ-16.09: the gateway renews a credential, and the device's installation issues another,
/// and the host hears of the two in whichever order the answers arrive. The device's bearer is
/// confirmed while a renewal is on its way, the gateway then renews and retires it, and the host
/// keeps the device's bearer before the renewal's answer reaches it. The renewal is the later
/// issue, so it is the one kept; the gateway issued the bearer the device handed over earlier.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_bearer_confirmed_before_a_renewal_that_retired_it_does_not_outlast_the_renewal() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x6a));
    let host_key = environment.host_signing_key();
    environment.gateway.issue_for(2 * 24 * 60 * 60 * 1000);
    let first = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    phone
        .register(&environment, &first)
        .await
        .expect("the first credential is registered");
    let credentials = Arc::clone(environment.controller().delivery_runtime().credentials());

    // The device is issued another bearer, which retires the first, and hands it over. Its
    // registration is held at the nonce, after the gateway took the bearer; the renewal then goes
    // through, retires that bearer too, and its answer is held.
    let second = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    let registering = environment.gateway.hold_before(RENEW_ROUTE, 0);
    let renewal_answer = environment.gateway.hold(RENEW_ROUTE, 1);
    let driver = async {
        registering.reached().await;
        let current = credentials.held(sender).expect("held");
        let renewing = tokio::task::spawn_blocking({
            let credentials = Arc::clone(&credentials);
            move || kr_delivery::push::SenderCredentials::renew(credentials.as_ref(), &current)
        });
        renewal_answer.reached().await;
        registering.release();
        until("the host keeping the device's bearer", || {
            credentials
                .held(sender)
                .is_some_and(|held| held.secret == second.secret)
        })
        .await;
        renewal_answer.release();
        renewing
            .await
            .expect("a thread")
            .expect("the renewal is answered")
    };
    let (registered, renewed) = tokio::join!(phone.register(&environment, &second), driver);
    registered.expect("the second credential is registered");

    assert_ne!(
        renewed.secret, second.secret,
        "the renewal retired the bearer"
    );
    assert_eq!(
        credentials.held(sender).expect("held").secret,
        renewed.secret,
        "the host holds the bearer the gateway issued last"
    );
    assert_eq!(
        stored_credential(&environment, sender).map(|stored| stored.secret),
        Some(renewed.secret)
    );
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("a question being delivered", || {
        !environment.gateway.delivered().is_empty()
    })
    .await;
    assert_eq!(environment.gateway.state().bearers_refused, 0);
}

// ---------------------------------------------------------------------------------------------
// External destinations the owner configures
// ---------------------------------------------------------------------------------------------

/// The owner's configuration of a webhook.
fn webhook(
    destination_id: &str,
    endpoint: &str,
    idempotency_header: Option<&str>,
    grant_id: kr_protocol::ids::GrantId,
) -> kr_protocol::delivery::DeliveryDestinationConfigureParams {
    configuration(
        kr_protocol::delivery::ExternalDestinationKind::Webhook,
        destination_id,
        endpoint,
        idempotency_header,
        grant_id,
    )
}

fn configuration(
    kind: kr_protocol::delivery::ExternalDestinationKind,
    destination_id: &str,
    endpoint: &str,
    idempotency_header: Option<&str>,
    grant_id: kr_protocol::ids::GrantId,
) -> kr_protocol::delivery::DeliveryDestinationConfigureParams {
    kr_protocol::delivery::DeliveryDestinationConfigureParams {
        destination_id: destination_id.to_owned(),
        kind,
        endpoint: endpoint.to_owned(),
        idempotency_header: Nullable::from(idempotency_header.map(str::to_owned)),
        rule_name: "tell the team".to_owned(),
        grant_id,
        secret: Nullable::null(),
    }
}

/// `params` carrying the credential the destination sends with.
fn with_secret(
    mut params: kr_protocol::delivery::DeliveryDestinationConfigureParams,
    secret: kr_protocol::delivery::DestinationSecret,
) -> kr_protocol::delivery::DeliveryDestinationConfigureParams {
    params.secret = Nullable::some(secret);
    params
}

/// KR-REQ-18.08, KR-REQ-25.23: the owner creates a webhook with `delivery.destination.configure`,
/// and the next question a worker raises is posted to it, by the daemon, under the rule and the
/// grant it was created with. The message is the host's generic alert and the sentence that says
/// its recipients can read it; the question's own words are in neither. Nothing is posted before the
/// destination exists, and nothing after it is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_webhook_the_owner_creates_is_told_of_the_next_question_and_not_after_it_is_removed() {
    const WORDS: &str = "Deploy the release to production?";
    const ENDPOINT: &str = "https://hooks.example.test/in/ops";
    // A token in the address's query, which the daemon sends to and never lists.
    const ENDPOINT_WITH_TOKEN: &str =
        "https://hooks.example.test/in/ops?token=not-a-real-token#top";
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let grant = phone.record.grant.grant_id;

    // The control: a question raised before there is a destination reaches nobody.
    environment._worker.ask("deploy-0", WORDS);
    until_the_questions_are_settled(&environment, 1).await;
    assert!(environment.gateway.posted().is_empty());

    let created = environment
        .configure(&webhook(
            "ops",
            ENDPOINT_WITH_TOKEN,
            Some("Idempotency-Key"),
            grant,
        ))
        .await
        .expect("the owner creates a webhook");
    assert!(created.in_force);
    assert_eq!(
        created.kind,
        kr_protocol::delivery::ExternalDestinationKind::Webhook
    );
    assert!(
        created.recipients_can_read.contains("Whoever runs"),
        "{}",
        created.recipients_can_read
    );
    let record = environment.destination_named("ops").expect("configured");
    assert!(record.enabled);
    assert_eq!(
        record.rule.as_ref().and_then(|rule| rule.grant_id),
        Some(grant)
    );
    // The list names the address without the query and the fragment, which can carry a token.
    let ops = environment
        .listed()
        .await
        .into_iter()
        .find(|listed| listed.destination_id == "ops")
        .expect("the webhook is listed");
    assert_eq!(ops.endpoint.0.as_deref(), Some(ENDPOINT));

    environment._worker.ask("deploy-1", WORDS);
    until("the webhook being posted to", || {
        !environment.gateway.posted().is_empty()
    })
    .await;
    // And the daemon posts to the address as it was given.
    let posted = environment.gateway.posted().remove(0);
    assert_eq!(posted.url, ENDPOINT_WITH_TOKEN);
    let text = posted.text();
    assert!(text.contains("waiting for an answer"), "{text}");
    assert!(
        text.contains(&format!(
            "A question is waiting in session {}.",
            environment.worker_session
        )),
        "the host's own words name the session the grant reaches: {text}"
    );
    assert!(
        text.contains(kr_delivery::external::RECIPIENTS_CAN_READ),
        "{text}"
    );
    for private in [WORDS, "deploy-1"] {
        assert!(!text.contains(private), "the destination is told {private}");
    }
    assert_eq!(
        posted.header("idempotency-key"),
        posted.body["delivery_id"].as_str(),
        "the identifier the destination deduplicates by is the message's own"
    );

    // Removed, it is told nothing more, and what it was told stays in the journal as history.
    let removed = environment
        .remove("ops")
        .await
        .expect("the owner removes it");
    assert!(removed.found);
    let (posts, records) = (
        environment.gateway.posted().len(),
        environment.deliveries_to("ops").len(),
    );
    environment._worker.ask("deploy-2", WORDS);
    until_the_questions_are_settled(&environment, 3).await;
    // Nothing is written for it, so there is nothing for a later pass to send.
    assert_eq!(environment.deliveries_to("ops").len(), records);
    assert_eq!(environment.gateway.posted().len(), posts);
    assert!(
        environment
            .destination_named("ops")
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    );
    environment
        .remove("ops")
        .await
        .expect("removing twice is removing once");
}

/// KR-REQ-25.23: the grant a destination is made under is asked again where the row is written, after
/// every wait the write could have had, and not only before. The daemon runs on clocks the test
/// moves by hand, and the configuration is held after it has read everything and before the
/// journal's write asks its admission; the grant runs out in that wait, and nothing is configured.
/// The control is the same configuration with the grant left standing, which is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_grant_that_runs_out_while_a_configuration_waits_to_be_written_configures_nothing() {
    for runs_out in [false, true] {
        let (moved, clocks) = Moved::new();
        let environment = Environment::start_on_clocks(clocks).await;
        let phone = environment.phone().await;
        let grant = phone.record.grant.grant_id;
        let (arrived, go) = environment
            .controller()
            .delivery()
            .pause_before_destination_write();
        let params = webhook("ops", "https://hooks.example.test/in/ops", None, grant);
        let configuring = environment.configure(&params);
        tokio::pin!(configuring);
        let arrival = tokio::task::spawn_blocking(move || arrived.recv_timeout(PATIENCE));
        // The write has to reach the pause before the configuration answers: one that is refused
        // first fails here with its answer, and a write that never arrives fails at the deadline.
        tokio::select! {
            answer = &mut configuring => {
                panic!("the configuration answered before its write reached the pause: {answer:?}")
            }
            arrived = arrival => {
                arrived
                    .expect("the pause reports its arrival")
                    .expect("the write arrives");
            }
        }
        if runs_out {
            moved.past_the_grant_by_utc();
        }
        go.send(()).expect("the write is waiting");
        let configured = configuring.await;
        if runs_out {
            configured.expect_err("the grant ran out before the row was written");
            assert!(environment.destination_named("ops").is_none());
        } else {
            configured.expect("the control is made");
            assert!(environment.destination_named("ops").is_some());
        }
    }
}

/// KR-REQ-25.23: a destination is made only where the owner may make it and only under authority
/// that stands. Each refusal leaves no destination: a paired device's identifier, a grant that is
/// not found or that has been revoked, a service that sends with a credential none is kept for, an
/// address the host would not send to, a header that is not a header name, a retry claim a service
/// cannot keep, and a rule with no name. The control is the same webhook, accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_destination_is_refused_unless_the_owner_may_make_it_under_a_grant_that_stands() {
    use kr_protocol::delivery::ExternalDestinationKind::{Slack, Telegram};
    use kr_protocol::error::ErrorCode::InvalidArgument;

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let leaving = environment.phone().await;
    let grant = phone.record.grant.grant_id;
    let endpoint = "https://hooks.example.test/in/ops";
    unpair(&environment, leaving.device_id()).await;

    let device_named = phone.device_id().to_string();
    let mut refusals = vec![
        (
            "a paired device's identifier",
            webhook(&device_named, endpoint, None, grant),
        ),
        (
            "a grant that was never made",
            webhook(
                "ops",
                endpoint,
                None,
                kr_protocol::ids::GrantId::new(uuid(0x99)),
            ),
        ),
        (
            "a grant that was revoked",
            webhook("ops", endpoint, None, leaving.record.grant.grant_id),
        ),
        (
            "a service that sends with a credential, with none kept",
            configuration(Slack, "chat", "ops-channel", None, grant),
        ),
        (
            "an address that is not HTTPS",
            webhook("ops", "http://hooks.example.test/in", None, grant),
        ),
        (
            "an address with a password in it",
            webhook(
                "ops",
                "https://someone:secret@hooks.example.test/in",
                None,
                grant,
            ),
        ),
        (
            "a header that is not a header name",
            webhook("ops", endpoint, Some("not a header"), grant),
        ),
        (
            "a retry claim for a service that cannot keep it",
            configuration(
                Telegram,
                "chat",
                "@ops_team",
                Some("Idempotency-Key"),
                grant,
            ),
        ),
    ];
    let mut unnamed = webhook("ops", endpoint, None, grant);
    unnamed.rule_name = String::new();
    refusals.push(("a rule with no name", unnamed));
    // The headers a request is framed with are the transport's, and a value of the owner's would
    // break every request to the destination.
    for framing in [
        "Content-Length",
        "host",
        "Transfer-Encoding",
        "Expect",
        "Connection",
    ] {
        refusals.push((
            "a header the request is framed with",
            webhook("ops", endpoint, Some(framing), grant),
        ));
    }
    for (what, params) in &refusals {
        let refused = environment
            .configure(params)
            .await
            .expect_err("the owner's configuration is refused");
        assert_eq!(refused.code, InvalidArgument, "{what}");
        assert!(
            environment
                .destination_named(&params.destination_id)
                .is_none(),
            "{what} left a destination"
        );
    }

    environment
        .configure(&webhook("ops", endpoint, None, grant))
        .await
        .expect("the control: the same webhook, under a grant that stands, is made");
    assert!(environment.destination_named("ops").is_some());
}

/// KR-REQ-18.08, KR-REQ-25.23: what an external message names is checked against the grant of the
/// rule that sends it. Two webhooks under two paired devices' grants: one reaches every session,
/// and its message names the session a worker's question was asked in; the other reaches one other
/// session, and is told nothing of this one, neither a message nor a record of one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_external_message_names_only_the_sessions_its_grant_reaches() {
    const WORDS: &str = "Deploy the release to production?";
    let environment = Environment::start().await;
    let everywhere = environment.phone().await;
    let other_session = SessionId::new(kr_ipc::new_uuid());
    let elsewhere = environment
        .phone_for_sessions(kr_protocol::grant::SessionSelector::These {
            session_ids: [other_session].into_iter().collect(),
        })
        .await;
    for (name, grant) in [
        ("everywhere", everywhere.record.grant.grant_id),
        ("elsewhere", elsewhere.record.grant.grant_id),
    ] {
        environment
            .configure(&webhook(
                name,
                &format!("https://hooks.example.test/in/{name}"),
                None,
                grant,
            ))
            .await
            .expect("the owner creates a webhook");
    }

    environment._worker.ask("deploy-1", WORDS);
    until(
        "the webhook that reaches the session being posted to",
        || !environment.gateway.posted().is_empty(),
    )
    .await;
    until_the_questions_are_settled(&environment, 1).await;
    let posted = environment.gateway.posted();
    assert_eq!(posted.len(), 1, "one message, to one webhook");
    assert_eq!(posted[0].url, "https://hooks.example.test/in/everywhere");
    let text = posted[0].text();
    assert!(
        text.contains(&environment.worker_session.to_string()),
        "the message names the session the grant reaches: {text}"
    );
    assert!(
        !text.contains(&other_session.to_string()),
        "and no other session: {text}"
    );
    assert!(
        environment.deliveries_to("elsewhere").is_empty(),
        "nothing was written for the webhook whose grant does not reach the session"
    );
}

/// KR-REQ-25.23: a grant with no history bound reaches what was first seen at or after its own
/// start, as the audience decides, whether or not it includes the live screen, and the message
/// composed for it says the same: it names the session and does not say that anything was left
/// out. The two grants are the ones `kr pair --view` and the sharing screen give.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_external_message_under_a_grant_with_no_history_bound_leaves_nothing_out() {
    let environment = Environment::start().await;
    for (name, live_screen) in [("with-screen", true), ("without-screen", false)] {
        let phone = environment.phone_with_no_history_bound(live_screen).await;
        environment
            .configure(&webhook(
                name,
                &format!("https://hooks.example.test/in/{name}"),
                None,
                phone.record.grant.grant_id,
            ))
            .await
            .expect("the owner creates a webhook");
    }

    environment._worker.ask("deploy-1", "Deploy the release?");
    for name in ["with-screen", "without-screen"] {
        let url = format!("https://hooks.example.test/in/{name}");
        until("the webhook being posted to", || {
            environment
                .gateway
                .posted()
                .iter()
                .any(|posted| posted.url == url)
        })
        .await;
        let text = environment
            .gateway
            .posted()
            .into_iter()
            .find(|posted| posted.url == url)
            .expect("posted")
            .text();
        assert!(
            text.contains(&environment.worker_session.to_string()),
            "{name}: the message names the session the grant reaches: {text}"
        );
        assert!(
            !text.contains("left out"),
            "{name}: and nothing the grant reaches is said to be left out: {text}"
        );
    }
}

/// KR-REQ-25.23: the credentialed kinds are configured through the same method, with their
/// credential in the request or kept before with `delivery.destination.secret.set`, and each sends
/// from the host to the service it names: Slack and Discord to the webhook address the owner
/// handed over, Telegram to the Bot API under the bot's token. The credential is in none of the messages, and removing a
/// destination takes its credential away. An email destination is made the same way; its sending
/// is the mail adapter's own suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn each_credentialed_kind_is_made_after_its_credential_and_sends_to_its_own_service() {
    use kr_protocol::delivery::DestinationSecret;
    use kr_protocol::delivery::ExternalDestinationKind::{Discord, Email, Slack, Telegram};

    const SLACK: &str = "https://hooks.slack.com/services/T0000/B0000/abcdefghijkl";
    const DISCORD: &str = "https://discord.com/api/webhooks/123456789/abcdefghijkl_token";
    const TELEGRAM_TOKEN: &str = "123456:ABCdefGHIjklMNOpqrSTUvwxYZ0123456789";
    let secret_text =
        |text: &str| kr_protocol::delivery::SecretText::new(text).expect("a credential");

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let grant = phone.record.grant.grant_id;

    // Discord is made after its credential is kept on its own; Slack and Telegram are made with
    // theirs in one request.
    environment
        .keep_secret(
            "discord",
            DestinationSecret::Discord {
                webhook_url: secret_text(DISCORD),
            },
        )
        .await;
    for params in [
        with_secret(
            configuration(Slack, "slack", "ops-channel", None, grant),
            DestinationSecret::Slack {
                webhook_url: secret_text(SLACK),
            },
        ),
        configuration(Discord, "discord", "ops-channel", None, grant),
        with_secret(
            configuration(Telegram, "telegram", "@ops_team", None, grant),
            DestinationSecret::Telegram {
                bot_token: secret_text(TELEGRAM_TOKEN),
            },
        ),
    ] {
        let made = environment
            .configure(&params)
            .await
            .expect("the owner makes it with its credential kept");
        assert!(made.in_force);
    }

    environment._worker.ask("deploy-1", "Deploy the release?");
    until("each service being posted to", || {
        environment.gateway.posted().len() >= 3
    })
    .await;
    let posts = environment.gateway.posted();
    let to = |prefix: &str| {
        posts
            .iter()
            .find(|posted| posted.url.starts_with(prefix))
            .unwrap_or_else(|| panic!("nothing was posted to {prefix}"))
    };
    for posted in [
        to(SLACK),
        to("https://discord.com/api/webhooks/123456789/"),
        to(&format!(
            "https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        )),
    ] {
        let text = posted.text();
        assert!(text.contains("waiting for an answer"), "{text}");
        assert!(
            text.contains(&environment.worker_session.to_string()),
            "the message names the session: {text}"
        );
        assert!(text.contains("can read"), "{text}");
        for private in [SLACK, DISCORD, TELEGRAM_TOKEN, "Deploy the release?"] {
            assert!(!text.contains(private), "a message carries {private}");
        }
    }

    // A credentialed destination goes with its credential. The email destination is made and
    // removed here, with no question in between.
    let secrets = environment.host.tree().environment().secrets_dir();
    let vault = |text: &str| !files_holding(&secrets, text.as_bytes()).is_empty();
    assert!(
        vault(TELEGRAM_TOKEN),
        "the control: the credential is in the secret store"
    );
    environment.remove("telegram").await.expect("removed");
    assert!(
        !vault(TELEGRAM_TOKEN),
        "removing the destination took its credential away"
    );
    environment
        .keep_secret(
            "mail",
            DestinationSecret::Email {
                account: kr_protocol::delivery::MailAccount {
                    server: "smtp.example.test".to_owned(),
                    port: kr_protocol::scalars::U64::new(465),
                    security: kr_protocol::delivery::MailSecurity::ImplicitTls,
                    username: secret_text("ops@example.test"),
                    password: secret_text("a-password-for-the-account"),
                    from_address: "ops@example.test".to_owned(),
                },
            },
        )
        .await;
    environment
        .configure(&configuration(
            Email,
            "mail",
            "team@example.test",
            None,
            grant,
        ))
        .await
        .expect("an email destination is made the same way");
    environment.remove("mail").await.expect("removed");
}

/// KR-REQ-25.23: a configuration the host refuses changes nothing, the credential in it included. A
/// Slack destination replaced under a grant that does not stand goes on sending to the channel it
/// was made for, under the credential it was made with and the rule it had; a destination refused
/// at its first configuration leaves no credential kept. A refused replacement never leaves the new
/// credential at work under the old grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_refused_configuration_leaves_the_destination_and_its_credential_as_they_were() {
    use kr_protocol::delivery::DestinationSecret;
    use kr_protocol::delivery::ExternalDestinationKind::Slack;

    const FIRST: &str = "https://hooks.slack.com/services/T0000/B0000/first-credential";
    const SECOND: &str = "https://hooks.slack.com/services/T0000/B0000/second-credential";
    let slack = |text: &str| DestinationSecret::Slack {
        webhook_url: kr_protocol::delivery::SecretText::new(text).expect("a credential"),
    };
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let grant = phone.record.grant.grant_id;
    let nobody = kr_protocol::ids::GrantId::new(uuid(0xee));

    environment
        .configure(&with_secret(
            configuration(Slack, "chat", "first-channel", None, grant),
            slack(FIRST),
        ))
        .await
        .expect("the owner makes it");
    let original = environment.destination_named("chat").expect("configured");
    let stamp_of = |record: &kr_delivery::destination::DestinationRecord| match &record.destination
    {
        kr_delivery::destination::Destination::External(external) => external.credential.clone(),
        kr_delivery::destination::Destination::Push(_) => None,
    };
    assert!(stamp_of(&original).is_some());

    // The replacement is refused: the grant it names was never issued.
    environment
        .configure(&with_secret(
            configuration(Slack, "chat", "second-channel", None, nobody),
            slack(SECOND),
        ))
        .await
        .expect_err("a grant that does not stand is refused");
    // And so is a first configuration.
    environment
        .configure(&with_secret(
            configuration(Slack, "fresh", "second-channel", None, nobody),
            slack(SECOND),
        ))
        .await
        .expect_err("a grant that does not stand is refused");

    assert_eq!(
        environment.destination_named("chat"),
        Some(original),
        "the destination is as it was"
    );
    assert!(environment.destination_named("fresh").is_none());
    let secrets = environment.host.tree().environment().secrets_dir();
    let vault = |text: &str| !files_holding(&secrets, text.as_bytes()).is_empty();
    assert!(vault(FIRST), "the credential it sends with is still kept");
    assert!(
        !vault(SECOND),
        "the credential of a refused configuration is kept nowhere"
    );

    // It still sends where it was made to send, with what it was made with.
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the first channel being posted to", || {
        environment
            .gateway
            .posted()
            .iter()
            .any(|posted| posted.url == FIRST)
    })
    .await;
    assert!(
        environment
            .gateway
            .posted()
            .iter()
            .all(|posted| posted.url != SECOND)
    );
}

/// KR-REQ-24.12, KR-REQ-25.24: after an attempt whose outcome nobody knows, a destination that said
/// it deduplicates by an identifier is sent the same message under the same identifier, and one
/// that said nothing is not sent it again: the record says it may have arrived, and may have
/// arrived twice. Both are webhooks the owner created, and both are answered with a failure after
/// the request left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_webhook_that_deduplicates_is_retried_after_an_unknown_outcome_and_one_that_does_not_is_not()
 {
    use kr_delivery::journal::DeliveryState;

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let grant = phone.record.grant.grant_id;
    environment
        .gateway
        .answer_route_with("/in/claimed", Some((500, "the receiver failed")));
    environment
        .gateway
        .answer_route_with("/in/bare", Some((500, "the receiver failed")));
    environment
        .configure(&webhook(
            "claimed",
            "https://hooks.example.test/in/claimed",
            Some("Idempotency-Key"),
            grant,
        ))
        .await
        .expect("a webhook that deduplicates");
    environment
        .configure(&webhook(
            "bare",
            "https://hooks.example.test/in/bare",
            None,
            grant,
        ))
        .await
        .expect("a webhook that does not");

    environment._worker.ask("deploy-1", "Deploy the release?");
    let posted_to = |suffix: &str| {
        environment
            .gateway
            .posted()
            .into_iter()
            .filter(|posted| posted.url.ends_with(suffix))
            .collect::<Vec<_>>()
    };
    until("both webhooks being posted to once", || {
        !posted_to("/in/claimed").is_empty() && !posted_to("/in/bare").is_empty()
    })
    .await;
    // The receiver recovers. Only the destination that deduplicates is sent the message again.
    environment.gateway.answer_route_with("/in/claimed", None);
    environment.gateway.answer_route_with("/in/bare", None);
    let state_of = |destination: &str| {
        environment
            .deliveries_to(destination)
            .first()
            .map(|record| record.state)
    };
    until("the repeat being accepted", || {
        state_of("claimed") == Some(DeliveryState::Accepted)
    })
    .await;
    until("the other being marked", || {
        state_of("bare") == Some(DeliveryState::DuplicateUncertain)
    })
    .await;
    let claimed = posted_to("/in/claimed");
    assert_eq!(claimed.len(), 2, "the message was sent again");
    assert_eq!(
        claimed[0].header("idempotency-key"),
        claimed[1].header("idempotency-key"),
        "under the identifier the first attempt carried"
    );
    assert!(claimed[0].header("idempotency-key").is_some());
    assert_eq!(
        posted_to("/in/bare").len(),
        1,
        "and the one that deduplicates by nothing was not sent it again"
    );
}

/// KR-REQ-24.12: privacy mode turned on while an external message waits to be sent takes it back,
/// and nothing is sent to the destination after it. The destination had asked for later, so
/// nothing of the message had left when privacy mode began.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn privacy_mode_turned_on_while_an_external_message_waits_cancels_it() {
    use kr_delivery::journal::DeliveryState;

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    environment
        .gateway
        .answer_route_with("/in/waiting", Some((429, "later")));
    environment
        .configure(&webhook(
            "waiting",
            "https://hooks.example.test/in/waiting",
            Some("Idempotency-Key"),
            phone.record.grant.grant_id,
        ))
        .await
        .expect("a webhook");
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the destination asking for later", || {
        environment
            .deliveries_to("waiting")
            .first()
            .is_some_and(|record| record.state == DeliveryState::Retrying)
    })
    .await;

    let mut client = environment.host.client().await;
    let _: kr_protocol::privacy::PrivacyReport = net_support::pairing::mutate(
        environment.environment_id(),
        &mut client,
        Method::PrivacySet,
        &kr_protocol::privacy::PrivacySetParams { enabled: true },
    )
    .await
    .expect("privacy mode turns on");
    assert_eq!(
        environment
            .deliveries_to("waiting")
            .first()
            .map(|record| record.state),
        Some(DeliveryState::Cancelled),
        "privacy mode took the message back"
    );

    // The destination would take it now, and is not told.
    environment.gateway.answer_route_with("/in/waiting", None);
    let posts = environment.gateway.posted().len();
    until_the_questions_are_settled(&environment, 1).await;
    assert_eq!(environment.gateway.posted().len(), posts);
}

/// KR-REQ-16.10: removing a paired device's destination ends its delivery and owes the gateway a
/// revocation of the authorisation behind it, as unpairing does, and leaves the device paired. The
/// authorisation cannot be registered again; another can.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn removing_a_paired_devices_destination_ends_its_delivery_and_leaves_it_paired() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let host_key = environment.host_signing_key();
    let sender = PushSenderRecordId::new(uuid(0x6d));
    let credential = environment
        .gateway
        .issue(sender, phone.installation(), host_key);
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    let device = phone.device_id().to_string();

    let removed = environment
        .remove(&device)
        .await
        .expect("the owner removes it");
    assert!(removed.found);
    assert!(
        environment
            .destination(phone.device_id())
            .is_none_or(|record| !record.enabled && record.rule.is_none())
    );
    assert!(
        environment
            .controller()
            .delivery_runtime()
            .credentials()
            .held(sender)
            .is_none()
    );
    assert!(!secret_store_holds(&environment, bytes_of(&credential)));
    until("the authorisation being revoked", || {
        environment
            .gateway
            .authorisation(sender)
            .is_some_and(|held| held.state == PushSenderState::Revoked)
    })
    .await;
    assert!(
        environment
            .controller()
            .devices()
            .record_for_device(phone.device_id())
            .expect("a read")
            .is_some_and(|record| record.is_paired()),
        "the device is still paired"
    );

    until("the debt being paid", || owed(&environment).is_empty()).await;

    // Nothing reaches the device now, and the authorisation that was revoked is not registered
    // again.
    environment._worker.ask("deploy-1", "Deploy the release?");
    until_the_questions_are_settled(&environment, 1).await;
    assert!(
        environment
            .deliveries_to(&phone.device_id().to_string())
            .is_empty(),
        "nothing was produced for the device"
    );
    assert!(environment.gateway.delivered().is_empty());
    let refused = phone
        .register(&environment, &credential)
        .await
        .expect_err("a revoked authorisation is not registered again");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::InvalidArgument);

    let again = environment.gateway.issue(
        PushSenderRecordId::new(uuid(0x6e)),
        phone.installation(),
        host_key,
    );
    phone
        .register(&environment, &again)
        .await
        .expect("another authorisation registers");
    assert!(environment.destination(phone.device_id()).is_some());
    // The destination the removal ended stays in the journal as history, and registering again
    // does not owe the gateway the revocation it already took.
    assert!(owed(&environment).is_empty());
}

/// KR-REQ-16.12: a bearer past its expiry is not presented because a renewal failed, and the
/// notification that waits for the renewal keeps its attempts. The daemon holds a bearer that has
/// expired (the held credential is replaced by one that says so, the way a bearer that went unused
/// for its thirty days does), the gateway refuses the renewal, and the notification stays pending:
/// the one ask is its one attempt, and no look since has asked the gateway again or presented the
/// bearer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_renewal_that_fails_leaves_a_bearer_past_its_expiry_unpresented() {
    use kr_delivery::journal::DeliveryState;

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let sender = PushSenderRecordId::new(uuid(0x6f));
    let credential =
        environment
            .gateway
            .issue(sender, phone.installation(), environment.host_signing_key());
    phone
        .register(&environment, &credential)
        .await
        .expect("the credential is registered");
    // The registration's own confirmation opened a renewal at the gateway. The gateway refuses
    // from here on, before the bearer expires, so no round of questions can renew it meanwhile.
    let before = environment.gateway.answers_on(RENEW_ROUTE).len();
    environment
        .gateway
        .answer_route_with(RENEW_ROUTE, Some((503, "unavailable")));
    environment
        .controller()
        .delivery_runtime()
        .credentials()
        .hold(PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(now() - 1_000),
            ..credential.clone()
        });
    environment._worker.ask("deploy-1", "Deploy the release?");
    let waiting = |wait: &str| {
        environment
            .deliveries_to(&phone.device_id().to_string())
            .first()
            .is_some_and(|record| {
                record.state == DeliveryState::Retrying
                    && record
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains(wait))
            })
    };
    until("the notification waiting for a renewal", || {
        waiting("has to be renewed")
    })
    .await;
    // A look since the refusal found the wait and asked nothing.
    until("a look at the wait", || waiting("asks again in")).await;
    let record = environment
        .deliveries_to(&phone.device_id().to_string())
        .remove(0);
    // The gateway was asked once, by the notification or by the daemon's own round of questions,
    // whichever came first; the wait then held against the other and against every later look. An
    // ask the notification made is its one attempt, and a look that found the wait used none.
    assert!(
        record.attempts <= 1,
        "the looks spent attempts: {:?} {:?}",
        record.state,
        record.detail
    );
    assert!(
        environment.gateway.delivered().is_empty(),
        "the expired bearer was not presented"
    );
    assert_eq!(environment.gateway.state().bearers_refused, 0);
    let asked = environment.gateway.answers_on(RENEW_ROUTE).len() - before;
    assert_eq!(
        asked, 1,
        "the gateway was asked to renew once and not again while the wait holds"
    );
}

/// KR-REQ-24.12: removing a destination takes back what waits for it, unsent, and says how much.
/// The destination had asked for later, so nothing of the message had left; and what is queued for
/// a destination that is removed is not sent when it asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn removing_a_destination_takes_back_what_waits_for_it_and_says_so() {
    use kr_delivery::journal::DeliveryState;

    let environment = Environment::start().await;
    let phone = environment.phone().await;
    environment
        .gateway
        .answer_route_with("/in/slow", Some((429, "later")));
    environment
        .configure(&webhook(
            "slow",
            "https://hooks.example.test/in/slow",
            Some("Idempotency-Key"),
            phone.record.grant.grant_id,
        ))
        .await
        .expect("a webhook");
    environment._worker.ask("deploy-1", "Deploy the release?");
    until("the destination asking for later", || {
        environment
            .deliveries_to("slow")
            .first()
            .is_some_and(|record| record.state == DeliveryState::Retrying)
    })
    .await;

    let removed = environment.remove("slow").await.expect("removed");
    assert!(removed.found);
    assert_eq!(removed.revoked.get(), 1, "the message that waited");
    assert_eq!(removed.unresolved.get() + removed.fenced.get(), 0);
    assert_eq!(
        environment
            .deliveries_to("slow")
            .first()
            .map(|record| record.state),
        Some(DeliveryState::Revoked)
    );
    environment.gateway.answer_route_with("/in/slow", None);
    let (posts, records) = (
        environment.gateway.posted().len(),
        environment.deliveries_to("slow").len(),
    );
    environment
        ._worker
        .ask("deploy-2", "Deploy the release again?");
    until_the_questions_are_settled(&environment, 2).await;
    assert_eq!(environment.deliveries_to("slow").len(), records);
    assert_eq!(environment.gateway.posted().len(), posts);
}

/// KR-REQ-24.12: removing a destination while a message is on the wire says so. The attempt is
/// held at the destination's end, the destination is removed, and the answer counts the attempt:
/// it finishes and reports its answer, can never be followed by another, and the destination may
/// still receive it. The control is the count of the same removal with nothing on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn removing_a_destination_with_a_message_on_the_wire_counts_the_attempt() {
    let environment = Environment::start().await;
    let phone = environment.phone().await;
    let grant = phone.record.grant.grant_id;
    environment
        .configure(&webhook(
            "quiet",
            "https://hooks.example.test/in/quiet",
            None,
            grant,
        ))
        .await
        .expect("a webhook");
    let idle = environment.remove("quiet").await.expect("removed");
    assert_eq!(
        (idle.revoked.get(), idle.unresolved.get(), idle.fenced.get()),
        (0, 0, 0),
        "the control: nothing was on the wire"
    );

    let held = environment.gateway.hold_before("/in/busy", 0);
    environment
        .configure(&webhook(
            "busy",
            "https://hooks.example.test/in/busy",
            None,
            grant,
        ))
        .await
        .expect("a webhook");
    environment._worker.ask("deploy-1", "Deploy the release?");
    held.reached().await;
    let removed = environment.remove("busy").await.expect("removed");
    assert!(removed.found);
    assert_eq!(removed.fenced.get(), 1, "the attempt on the wire");
    held.release();
}
