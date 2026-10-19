//! The relay control plane's lease routes, answering as the Worker's relay does.
//!
//! A relay carries nothing for a pair of endpoints until it holds a lease the service signed, so a
//! host asks the service for one: `relay.lease.issue` opens a lease for a pair or refills the one
//! the pair holds, and `relay.lease.revoke` ends it. The stand-in keeps what the service keeps for
//! that: the authorisations an account gave a caller, each lease with its reservation, ceiling and
//! deadline, and the credentials it has accepted.
//!
//! The source is the web repository's `workers/api/src/relay/{index,credential,lease}.ts` and the
//! contract in `packages/service-contracts/src/relay.ts`; each rule below is one of theirs, and the
//! fidelity table in the crate's documentation names the line. The credential is the one every
//! managed-service method uses, over the five facts that make a request, but the two relay methods
//! are not entries in the protocol's method registry yet, so it is read here field by field and not
//! through the registry's type.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use kr_client::services::ServiceHttpAnswer;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::RelayLeaseId;
use kr_protocol::relay::{RELAY_LEASE_DOMAIN, RelayDirection, RelayLease};
use kr_protocol::scalars::{
    AuthorisationKey, Digest256, EndpointKey, Nonce256, Nullable, Signature64, TimestampMs, U64,
};
use kr_protocol::service::ServiceRequestSigner;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::web::{answered, refusal};

/// The domain a lease request's body digest covers.
const LEASE_REQUEST_DOMAIN: &str = "kr-relay-lease-request/1";

/// The domain an admission request's body digest covers.
const ADMISSION_REQUEST_DOMAIN: &str = "kr-relay-admission-request/1";

/// The bytes one pairing admission allows, and how long it lasts, as the Worker issues one.
pub const ADMISSION_BYTES: u64 = 512 * 1024;
const ADMISSION_SECONDS: u64 = 600;

/// The domain a revocation request's body digest covers.
const LEASE_REVOKE_DOMAIN: &str = "kr-relay-lease-revoke/1";

/// The domain a payer sign-in request's body digest covers.
const PAYER_SIGN_IN_DOMAIN: &str = "kr-relay-payer-sign-in/1";

/// How long the authorisation a sign-in opens lasts from each renewal, and how little of it must
/// remain for the next sign-in to renew it in place.
const SIGN_IN_AUTHORISATION_MS: u64 = 3600 * 1000;
const SIGN_IN_RENEW_BELOW_MS: u64 = 1800 * 1000;

/// The scope an account token needs before the host that holds it can make the account its payer.
pub(crate) const RELAY_LEASE_SCOPE: &str = "relay.lease";

/// How far a credential's time may be from the service's, either way.
const FRESHNESS_MS: u64 = 5 * 60 * 1000;

/// The most one principal holds outstanding across its leases (section 17).
const OUTSTANDING_CEILING_BYTES: u64 = 8 * 1024 * 1024;

/// The monthly allowance of an account, which the recording's local deployment gives.
const ALLOWANCE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// The shortest and the longest a lease may last.
const LEASE_SECONDS: std::ops::RangeInclusive<u32> = 30..=900;

/// The fewest bytes a lease reserves.
const MIN_LEASE_BYTES: u64 = 64 * 1024;

/// The most a number the service's language holds exactly.
const MAX_COUNTER: u64 = (1 << 53) - 1;

/// What an account gave one caller leave to spend.
#[derive(Clone, Debug)]
struct Authorisation {
    account_id: String,
    /// The host key it was given to, as unpadded base64url.
    subject: String,
    /// The most one lease may hold outstanding under it.
    byte_ceiling: u64,
    withdrawn: bool,
    /// When it came into force, in UTC milliseconds on the service's clock.
    valid_from_ms: u64,
    /// When it stops being in force, on the service's clock. No lease under it lasts past this.
    valid_until_ms: u64,
    /// The sign-in grant that opened it: a grant opens at most one.
    grant: String,
    /// When the caller made it its default, when it did.
    selected_at_ms: Option<u64>,
}

impl Authorisation {
    /// Whether it is in force at `service_now`.
    const fn in_force(&self, service_now: u64) -> bool {
        !self.withdrawn && service_now < self.valid_until_ms
    }
}

/// What became of a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseState {
    Installed,
    Revoked,
}

/// One lease the service issued.
#[derive(Clone, Debug)]
struct Lease {
    lease_id: String,
    reservation_id: String,
    revision: u64,
    source: String,
    destination: String,
    direction: RelayDirection,
    /// The relay instance the lease was installed on when it was issued. A refill keeps it: only a
    /// new lease goes to the instance the service selects now.
    relay_url: String,
    /// The key that asked for it, which is the only one that may change it.
    requested_by: String,
    /// `account:<id>` or `installation:<id>`.
    payer: String,
    authorisation_id: Option<String>,
    /// Whether the authorisation was not the caller's default when the lease was issued, so
    /// that the account sponsors the lease. It is a fact of the lease and every revision keeps it,
    /// whatever has happened to the authorisation since.
    sponsored: bool,
    ceiling: u64,
    expires_at_ms: u64,
    consumed: u64,
    state: LeaseState,
    /// Why it was ended, when it was.
    ended_for: Option<&'static str>,
    /// The relay carrying it is no longer one the service can bill through.
    retired: bool,
}

/// A lease as a test reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayLeaseView {
    /// The lease's identifier.
    pub lease_id: String,
    /// The endpoint that may send.
    pub source: EndpointKey,
    /// The endpoint that may receive.
    pub destination: EndpointKey,
    /// The revision the service holds.
    pub revision: u64,
    /// The cumulative bytes the reservation may reach.
    pub byte_ceiling: u64,
    /// When the lease stops being valid, in UTC milliseconds on the service's clock.
    pub expires_at_ms: u64,
    /// The bytes the relay has counted.
    pub bytes_consumed: u64,
    /// The relay instance it is installed on.
    pub relay_url: String,
    /// The authorisation it was issued under, when an account pays.
    pub authorisation_id: Option<String>,
    /// Whether the account sponsors it: the authorisation was not the caller's default when
    /// the lease was issued.
    pub sponsored: bool,
    /// Whether the lease is installed: the service has not revoked it. Its deadline may have
    /// passed.
    pub live: bool,
    /// Why it was ended, when it was: `unpaired`, `payer_withdrew` or `finished`.
    pub ended_for: Option<&'static str>,
}

/// What the service answers a request for an admission at one relay it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionBehaviour {
    /// It issues and installs one.
    Admit,
    /// It cannot admit now, and says so with the paths that still work.
    Unavailable {
        /// The seconds it asks the caller to wait, when it asks.
        retry_after_seconds: Option<u64>,
    },
}

/// A request for an admission that proved its credential, as a test reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAdmissionView {
    /// The endpoint being paired with.
    pub host: EndpointKey,
    /// The endpoint that is pairing.
    pub candidate: EndpointKey,
    /// The relay the request named, as it was written.
    pub relay_url: String,
}

/// An authorisation a sign-in opened, as a test reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAuthorisationView {
    /// The authorisation record, which a lease request names.
    pub authorisation_id: String,
    /// The account that is billed.
    pub account_id: String,
    /// The sign-in grant that opened it.
    pub grant: String,
    /// When it stops being in force, in UTC milliseconds on the service's clock.
    pub valid_until_ms: u64,
    /// Whether the account withdrew it.
    pub withdrawn: bool,
}

/// Everything the relay control plane keeps.
#[derive(Debug)]
pub(crate) struct Relay {
    authorisations: BTreeMap<String, Authorisation>,
    leases: BTreeMap<String, Lease>,
    /// Credentials spent, by signer and nonce.
    nonces: BTreeSet<(String, String)>,
    /// Added to the machine's clock for the lease deadlines the service writes.
    clock_offset_ms: u64,
    /// The payer's allowance is spent.
    exhausted: bool,
    /// The service has no relay instance to offer.
    no_relay: bool,
    /// A deadline cannot be moved later, as at the end of a month's period.
    frozen_deadlines: bool,
    /// The most a principal holds outstanding across its leases.
    aggregate_limit: u64,
    /// The allowance warning every answer carries, in percent: 80 or 95.
    warning: Option<u32>,
    /// The principal is inside its bounded grace, so every answer carries what is left of it.
    in_grace: bool,
    /// The address of the relay instance new leases are installed on: the one the service selects.
    relay_url: String,
    /// The most one lease may hold outstanding under an authorisation a sign-in opens.
    sign_in_bound: u64,
    /// The time of the request being answered, by the machine's clock.
    seen_ms: u64,
    counter: u64,
    issuer: AuthorisationKeyPair,
    /// What each relay the service carries answers a request for an admission with, by URL.
    /// A relay the lease path installs on is carried too, and admits unless a test says otherwise.
    admission_relays: BTreeMap<String, AdmissionBehaviour>,
    /// The service's free budget for admissions is spent for the day.
    admission_budget_spent: bool,
    /// Every request for an admission that proved its credential.
    admissions: Vec<RelayAdmissionView>,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            authorisations: BTreeMap::new(),
            leases: BTreeMap::new(),
            nonces: BTreeSet::new(),
            clock_offset_ms: 0,
            exhausted: false,
            no_relay: false,
            frozen_deadlines: false,
            aggregate_limit: OUTSTANDING_CEILING_BYTES,
            warning: None,
            in_grace: false,
            relay_url: "https://relay-1.reach.kala.to".to_owned(),
            sign_in_bound: OUTSTANDING_CEILING_BYTES,
            seen_ms: 0,
            counter: 0,
            issuer: AuthorisationKeyPair::generate().expect("an admission key"),
            admission_relays: BTreeMap::new(),
            admission_budget_spent: false,
            admissions: Vec::new(),
        }
    }
}

impl Relay {
    /// The next identifier, as a lower-case hyphenated UUID of the given kind.
    fn identifier(&mut self, kind: u32) -> String {
        self.counter += 1;
        format!("{kind:08x}-0000-4000-8000-{:012x}", self.counter)
    }

    /// The time on the service's clock.
    const fn service_now(&self, now_ms: u64) -> u64 {
        now_ms + self.clock_offset_ms
    }

    /// The account withdraws an authorisation: it is no longer in force, and the leases issued
    /// under it are revoked, as the Worker's withdrawal does.
    pub(crate) fn withdraw(&mut self, authorisation_id: &str) {
        if let Some(held) = self.authorisations.get_mut(authorisation_id) {
            held.withdrawn = true;
        }
        for lease in self.leases.values_mut() {
            if lease.authorisation_id.as_deref() == Some(authorisation_id)
                && lease.state == LeaseState::Installed
            {
                lease.state = LeaseState::Revoked;
                lease.revision += 1;
                lease.ended_for = Some(Reason::PayerWithdrew.as_str());
            }
        }
    }

    /// The authorisation's validity window ends now: it is not in force from now on, and no lease
    /// issued under it outlasts it, as the Worker caps every lease at its authorisation's end.
    pub(crate) fn lapse(&mut self, authorisation_id: &str) {
        let end = self.service_now(self.seen_ms);
        if let Some(held) = self.authorisations.get_mut(authorisation_id) {
            held.valid_until_ms = held.valid_until_ms.min(end);
        }
        for lease in self.leases.values_mut() {
            if lease.authorisation_id.as_deref() == Some(authorisation_id) {
                lease.expires_at_ms = lease.expires_at_ms.min(end);
            }
        }
    }

    /// The authorisations a sign-in opened, as a test reads them.
    pub(crate) fn sign_ins(&self) -> Vec<RelayAuthorisationView> {
        self.authorisations
            .iter()
            .map(|(id, held)| RelayAuthorisationView {
                authorisation_id: id.clone(),
                account_id: held.account_id.clone(),
                grant: held.grant.clone(),
                valid_until_ms: held.valid_until_ms,
                withdrawn: held.withdrawn,
            })
            .collect()
    }

    /// The service ends a lease on its own, as when its record of the lease is lost.
    pub(crate) fn end_by_the_service(&mut self, lease_id: &str) {
        if let Some(lease) = self.leases.get_mut(lease_id)
            && lease.state == LeaseState::Installed
        {
            lease.state = LeaseState::Revoked;
            lease.revision += 1;
            lease.ended_for = Some("service");
        }
    }

    pub(crate) const fn exhaust(&mut self, exhausted: bool) {
        self.exhausted = exhausted;
    }

    pub(crate) const fn withhold_relays(&mut self, withheld: bool) {
        self.no_relay = withheld;
    }

    pub(crate) const fn freeze_deadlines(&mut self, frozen: bool) {
        self.frozen_deadlines = frozen;
    }

    /// The most a principal may hold outstanding across its leases, as a test narrows it to put a
    /// refill past it.
    pub(crate) const fn limit_aggregate(&mut self, bytes: u64) {
        self.aggregate_limit = bytes;
    }

    /// Every answer carries the allowance warning at `percent`, or none.
    pub(crate) const fn warn(&mut self, percent: Option<u32>) {
        self.warning = percent;
    }

    /// The principal is inside its bounded grace, or is not: every answer carries what is left.
    pub(crate) const fn enter_grace(&mut self, in_grace: bool) {
        self.in_grace = in_grace;
    }

    /// The authorisations a sign-in opens from now on bound one lease at `bytes` outstanding. The
    /// Worker bounds them at what a principal may hold; a test narrows it to put a refill past the
    /// bound.
    pub(crate) const fn bound_sign_ins(&mut self, bytes: u64) {
        self.sign_in_bound = bytes;
    }

    /// The relay instance new leases are installed on is at `url`.
    pub(crate) fn name_relay(&mut self, url: &str) {
        url.clone_into(&mut self.relay_url);
    }

    /// The service carries a relay at `url`, and answers a request for an admission there as
    /// `behaviour` says.
    pub(crate) fn carry_relay(&mut self, url: &str, behaviour: AdmissionBehaviour) {
        self.admission_relays.insert(same_relay(url), behaviour);
    }

    /// The service's free budget for admissions is spent, or is not.
    pub(crate) const fn spend_admission_budget(&mut self, spent: bool) {
        self.admission_budget_spent = spent;
    }

    /// Every request for an admission that proved its credential, in order.
    pub(crate) fn admission_requests(&self) -> Vec<RelayAdmissionView> {
        self.admissions.clone()
    }

    /// The warnings an answer carries.
    fn warnings(&self) -> Value {
        self.warning.map_or_else(
            || json!([]),
            |threshold| {
                json!([{ "threshold": threshold, "raised_at": "2026-10-12T12:00:00.000Z" }])
            },
        )
    }

    /// What is left of the principal's grace, as an answer carries it.
    fn grace_remainder(&self) -> Value {
        json!({
            "started_at": "2026-10-12T12:00:00.000Z",
            "ends_at": "2026-10-12T12:15:00.000Z",
            "remaining_ms": "600000",
            "remaining_bytes": "104857600",
        })
    }

    /// The service has no record of a lease any more: it never issued it, as far as it can say.
    pub(crate) fn forget(&mut self, lease_id: &str) {
        self.leases.remove(lease_id);
    }

    pub(crate) const fn advance_clock(&mut self, by_ms: u64) {
        self.clock_offset_ms += by_ms;
    }

    /// The relay counts `bytes` more for a lease's reservation.
    pub(crate) fn consume(&mut self, lease_id: &str, bytes: u64) {
        if let Some(lease) = self.leases.get_mut(lease_id) {
            lease.consumed = (lease.consumed + bytes).min(lease.ceiling);
        }
    }

    pub(crate) fn views(&self) -> Vec<RelayLeaseView> {
        self.leases
            .values()
            .map(|lease| RelayLeaseView {
                lease_id: lease.lease_id.clone(),
                source: key_of(&lease.source),
                destination: key_of(&lease.destination),
                revision: lease.revision,
                byte_ceiling: lease.ceiling,
                expires_at_ms: lease.expires_at_ms,
                bytes_consumed: lease.consumed,
                relay_url: lease.relay_url.clone(),
                authorisation_id: lease.authorisation_id.clone(),
                sponsored: lease.sponsored,
                live: lease.state == LeaseState::Installed,
                ended_for: lease.ended_for,
            })
            .collect()
    }

    /// The bytes an account has outstanding across its live leases: what each holds beyond what
    /// the relay has counted for it, which is what the aggregate bound is measured on. The
    /// reservation of a lease past its deadline has been settled, so it holds nothing.
    fn outstanding(&self, payer: &str) -> u64 {
        let service_now = self.service_now(self.seen_ms);
        self.leases
            .values()
            .filter(|lease| {
                lease.state == LeaseState::Installed
                    && lease.payer == payer
                    && lease.expires_at_ms > service_now
            })
            .map(|lease| lease.ceiling - lease.consumed)
            .sum()
    }

    /// The relay carrying a lease is retired: the service can no longer bill through it.
    pub(crate) fn retire_relay_of(&mut self, lease_id: &str) {
        if let Some(lease) = self.leases.get_mut(lease_id) {
            lease.retired = true;
        }
    }
}

/// A scalar as the text it is written as in JSON.
fn text_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("a scalar")
        .as_str()
        .expect("text")
        .to_owned()
}

/// A relay's URL as the Worker's registry compares it (`normalisedRelayUrl` in
/// `workers/api/src/relay/instances.ts`): the scheme and host in lower case, the default port left
/// out, a path with its case and no trailing slash. A text that is not an http or https URL names
/// no relay, and is kept as written so that it matches nothing but itself.
fn same_relay(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return url.to_owned();
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return url.to_owned();
    }
    let host = parsed.host_str().unwrap_or_default();
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    format!(
        "{}://{host}{port}{}",
        parsed.scheme(),
        parsed.path().trim_end_matches('/')
    )
}

fn key_of(text: &str) -> EndpointKey {
    serde_json::from_value(Value::String(text.to_owned())).expect("an endpoint key")
}

/// The body of a lease request, as the contract reads it and the client writes it. The digest the
/// credential covers is taken over its canonical encoding, so it is rebuilt here from the values
/// that arrived and not from the text they arrived as.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssueBody {
    source_endpoint_key: EndpointKey,
    destination_endpoint_key: EndpointKey,
    direction: RelayDirection,
    byte_ceiling: U64,
    duration_seconds: u32,
    region_preference: Nullable<String>,
    payer: Nullable<Payer>,
    lease_id: Nullable<RelayLeaseId>,
}

/// Who a request says pays.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Payer {
    Installation,
    Account {
        account_id: String,
        authorisation_id: String,
    },
}

/// The body of an admission request, as the contract reads it and the client writes it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmissionBody {
    host_endpoint_key: EndpointKey,
    candidate_endpoint_key: EndpointKey,
    relay_url: String,
}

/// The body of a revocation request.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    lease_id: RelayLeaseId,
    reason: Reason,
}

/// Why a lease is ended.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    Unpaired,
    PayerWithdrew,
    Finished,
}

impl Reason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unpaired => "unpaired",
            Self::PayerWithdrew => "payer_withdrew",
            Self::Finished => "finished",
        }
    }
}

/// The five facts a credential covers, as the client writes them.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    body_digest: Digest256,
    gateway_origin: String,
    method: String,
    nonce: Nonce256,
    signed_at_ms: TimestampMs,
}

/// What a credential proved.
struct Proof {
    key: String,
    signer: ServiceRequestSigner,
}

fn unauthenticated(message: &str) -> ServiceHttpAnswer {
    refusal(401, "UNAUTHENTICATED", message)
}

fn invalid(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_REQUEST", message)
}

/// Reads the credential of a relay request and checks it, in the Worker's order, spending its
/// nonce last.
fn check_credential(
    relay: &mut Relay,
    origin: &str,
    method: &str,
    document: &Value,
    digest_over: &[u8],
    now_ms: u64,
) -> Result<Proof, ServiceHttpAnswer> {
    let signature = &document["signature"];
    let Ok(payload) = serde_json::from_value::<Payload>(signature["payload"].clone()) else {
        return Err(unauthenticated(
            "This request was not signed over anything this service recognises.",
        ));
    };
    if payload.gateway_origin != origin {
        return Err(unauthenticated(
            "This request was signed for another gateway.",
        ));
    }
    if payload.method != method {
        return Err(unauthenticated(
            "The credential names a different method from the one called.",
        ));
    }
    if payload.body_digest != Digest256::from_bytes(kr_cbor::sha256(digest_over)) {
        return Err(unauthenticated(
            "The credential covers a different body from the one sent.",
        ));
    }
    if payload.signed_at_ms.get().abs_diff(now_ms) > FRESHNESS_MS {
        return Err(unauthenticated(
            "A request is signed within five minutes of being made.",
        ));
    }
    let (Ok(signer), Ok(public_key), Ok(presented)) = (
        serde_json::from_value::<ServiceRequestSigner>(signature["signer"].clone()),
        serde_json::from_value::<AuthorisationKey>(signature["public_key"].clone()),
        serde_json::from_value::<Signature64>(signature["signature"].clone()),
    ) else {
        return Err(unauthenticated(
            "This request was not signed by a key this service can check.",
        ));
    };
    let covered = kr_cbor::encode(&kr_cbor::signing_value(
        signer.domain(),
        vec![kr_cbor::to_canonical_value(&payload).expect("a canonical payload")],
    ));
    let Ok(transcript) =
        kr_crypto::sign::SigningTranscript::from_canonical_bytes(signer.domain(), covered)
    else {
        return Err(unauthenticated(
            "This request was not signed over anything this service recognises.",
        ));
    };
    if kr_crypto::sign::verify(&public_key, &transcript, &presented).is_err() {
        return Err(unauthenticated(
            "This request was not signed by the key it presents.",
        ));
    }
    let key = crate::feed::key_text(&public_key);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.nonce.as_bytes());
    if !relay.nonces.insert((key.clone(), nonce)) {
        return Err(unauthenticated("That credential has already been used."));
    }
    Ok(Proof { key, signer })
}

/// `relay.admission.issue`: the admission a device that holds no lease asks for before it pairs.
///
/// The Worker proves the credential, finds the relay the request names among the instances it
/// carries (a URL it does not carry is `not_managed`, and nothing is spent finding that out), takes
/// the free budget's debit, signs the admission and installs it. A relay that is asked to carry
/// the pair of a lease answers that the lease decides it alone. What the relay then does with the
/// admission is the relay's own: this answers what the service says.
pub(crate) fn admit(
    relay: &mut Relay,
    origin: &str,
    document: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    relay.seen_ms = now_ms;
    let Ok(body) = serde_json::from_value::<AdmissionBody>(document["body"].clone()) else {
        return invalid("That admission request is not one this service reads.");
    };
    let canonical = kr_cbor::encode(&kr_cbor::signing_value(
        ADMISSION_REQUEST_DOMAIN,
        vec![kr_cbor::to_canonical_value(&body).expect("a canonical body")],
    ));
    if let Err(refused) = check_credential(
        relay,
        origin,
        "relay.admission.issue",
        document,
        &canonical,
        now_ms,
    ) {
        return refused;
    }
    if body.host_endpoint_key == body.candidate_endpoint_key {
        return invalid("An admission names two different endpoints.");
    }
    relay.admissions.push(RelayAdmissionView {
        host: body.host_endpoint_key,
        candidate: body.candidate_endpoint_key,
        relay_url: body.relay_url.clone(),
    });

    let url = same_relay(&body.relay_url);
    let carried = relay.admission_relays.get(&url).copied().or_else(|| {
        let leased = relay
            .leases
            .values()
            .any(|lease| same_relay(&lease.relay_url) == url);
        (same_relay(&relay.relay_url) == url || leased).then_some(AdmissionBehaviour::Admit)
    });
    let Some(behaviour) = carried else {
        return answered(json!({ "state": "not_managed" }));
    };
    if relay.admission_budget_spent {
        return answered(json!({
            "state": "unavailable",
            "message": "The anonymous budget for today is spent.",
            "alternatives": ALTERNATIVES,
        }));
    }
    let service_now = relay.service_now(now_ms);
    let (host, candidate) = (
        text_of(&body.host_endpoint_key),
        text_of(&body.candidate_endpoint_key),
    );
    let holds_a_lease = relay.leases.values().any(|lease| {
        lease.state == LeaseState::Installed
            && lease.expires_at_ms > service_now
            && same_relay(&lease.relay_url) == url
            && ((lease.source == host && lease.destination == candidate)
                || (lease.source == candidate && lease.destination == host))
    });
    if holds_a_lease {
        return answered(json!({ "state": "not_needed" }));
    }
    match behaviour {
        AdmissionBehaviour::Unavailable {
            retry_after_seconds,
        } => {
            let mut answer = json!({
                "state": "unavailable",
                "message": "The relay would not take that admission.",
                "alternatives": ALTERNATIVES,
            });
            if let Some(seconds) = retry_after_seconds {
                answer["retry_after_seconds"] = json!(seconds);
            }
            answered(answer)
        }
        AdmissionBehaviour::Admit => answered(json!({
            "state": "admitted",
            "relay_url": body.relay_url,
            "relay_instance_id": "44444444-4444-4444-4444-444444444444",
            "expires_in_seconds": ADMISSION_SECONDS,
            "byte_ceiling": ADMISSION_BYTES.to_string(),
        })),
    }
}

/// The paths that still work, as the service names them.
const ALTERNATIVES: [&str; 2] = [
    "A direct connection between the devices, which needs no managed relay.",
    "A self-hosted relay configured in the service settings.",
];

/// `relay.lease.issue`: opens a lease for a pair, or refills the one the pair holds.
pub(crate) fn issue(
    relay: &mut Relay,
    origin: &str,
    document: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    relay.seen_ms = now_ms;
    let Ok(body) = serde_json::from_value::<IssueBody>(document["body"].clone()) else {
        return invalid("That lease request is not one this service reads.");
    };
    let canonical = kr_cbor::encode(&kr_cbor::signing_value(
        LEASE_REQUEST_DOMAIN,
        vec![kr_cbor::to_canonical_value(&body).expect("a canonical body")],
    ));
    let proof = match check_credential(
        relay,
        origin,
        "relay.lease.issue",
        document,
        &canonical,
        now_ms,
    ) {
        Ok(proof) => proof,
        Err(refused) => return refused,
    };
    let mut asked = body.byte_ceiling.get();
    if body.source_endpoint_key == body.destination_endpoint_key {
        return invalid("A lease binds two different endpoints.");
    }
    if !LEASE_SECONDS.contains(&body.duration_seconds) {
        return invalid("A lease lasts between 30 and 900 seconds.");
    }
    if !(MIN_LEASE_BYTES..=MAX_COUNTER).contains(&asked) {
        return invalid(
            "A lease reserves at least 64 KiB and a number this service counts exactly.",
        );
    }

    // Who pays: the account a caller names under an authorisation that account gave it, and when a
    // host names none, the account it selected as its default. A host key draws on no allowance of
    // its own, so a host that names none and has selected none is turned away.
    let service_now = relay.service_now(now_ms);
    let named = match (&body.payer.0, proof.signer) {
        (
            Some(Payer::Account {
                account_id,
                authorisation_id,
            }),
            _,
        ) => Some((account_id.clone(), authorisation_id.clone())),
        (None, ServiceRequestSigner::Host) => relay
            .authorisations
            .iter()
            .find(|(_, held)| {
                held.subject == proof.key
                    && held.selected_at_ms.is_some()
                    && !held.withdrawn
                    && held.in_force(service_now)
            })
            .map(|(id, held)| (held.account_id.clone(), id.clone())),
        _ => None,
    };
    let (payer, authorisation_id, max_bytes, ends_at_ms, sponsored) = match (named, proof.signer) {
        (Some((account_id, authorisation_id)), _) => {
            let Some(held) = relay.authorisations.get(&authorisation_id) else {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That account has not authorised this caller.",
                );
            };
            if held.account_id != account_id || held.subject != proof.key {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That account has not authorised this caller.",
                );
            }
            if held.withdrawn {
                return refusal(403, "FORBIDDEN", "That authorisation has been withdrawn.");
            }
            if !held.in_force(service_now) {
                return refusal(403, "FORBIDDEN", "That authorisation is not in force.");
            }
            (
                format!("account:{account_id}"),
                Some(authorisation_id.clone()),
                held.byte_ceiling.min(OUTSTANDING_CEILING_BYTES),
                held.valid_until_ms,
                held.selected_at_ms.is_none(),
            )
        }
        (None, ServiceRequestSigner::Host) => {
            return refusal(
                403,
                "FORBIDDEN",
                "A host names the account it is spending, because a host key draws on no allowance \
                 of its own.",
            );
        }
        (None, ServiceRequestSigner::Installation) => (
            format!("installation:{}", proof.key),
            None,
            OUTSTANDING_CEILING_BYTES,
            u64::MAX,
            false,
        ),
    };

    let pair = (
        text_of(&body.source_endpoint_key),
        text_of(&body.destination_endpoint_key),
    );
    // The lease this request is about: the one it named, or the one its pair holds.
    let mut found = match &body.lease_id.0 {
        Some(named) => match relay.leases.get(&named.get().to_string()) {
            Some(lease) if lease.state == LeaseState::Installed => Some(lease.clone()),
            _ => {
                return invalid("That lease is not one this service is carrying.");
            }
        },
        None => relay
            .leases
            .values()
            .find(|lease| {
                lease.state == LeaseState::Installed
                    && lease.payer == payer
                    && lease.source == pair.0
                    && lease.destination == pair.1
            })
            .cloned(),
    };
    // A lease at or past its deadline carries nothing, whatever its record says, and nothing wakes
    // at the deadline to close the record. It is read before anything else about the lease: the
    // request that finds it ends it, and is answered as one for a pair that holds none, whoever
    // asks and under whatever authorisation. A reservation that has passed its deadline has been
    // settled, so a fresh one holds everything it is given: what a cumulative total meant to the
    // one that is gone is not what it means to this one, and it is clamped to what the payer
    // authorises, not refused for a figure the caller was right to ask for.
    if let Some(lease) = &found
        && service_now >= lease.expires_at_ms
    {
        let old = lease.lease_id.clone();
        if let Some(expired) = relay.leases.get_mut(&old) {
            expired.state = LeaseState::Revoked;
            expired.revision += 1;
            expired.ended_for = Some("expired");
        }
        found = None;
        asked = asked.min(max_bytes);
    }
    if let Some(lease) = &found {
        if lease.requested_by != proof.key {
            return refusal(
                403,
                "FORBIDDEN",
                "That pair already holds a lease issued to another caller.",
            );
        }
        if lease.payer != payer {
            return refusal(
                403,
                "FORBIDDEN",
                "That lease is billed to another principal.",
            );
        }
        if lease.authorisation_id != authorisation_id {
            return refusal(
                403,
                "FORBIDDEN",
                "That lease was issued under another authorisation. Revoke it, or name the one it \
                 names.",
            );
        }
        if lease.source != pair.0
            || lease.destination != pair.1
            || lease.direction != body.direction
        {
            return invalid("That lease binds another pair, or another direction.");
        }
        if lease.retired || relay.no_relay {
            return refused_answer(
                relay,
                &payer,
                "unavailable",
                "The relay carrying that lease is no longer one this service can bill through. \
                 Revoke the lease and ask for another.",
            );
        }
    }
    let held = found.as_ref().map_or(0, |lease| lease.ceiling);
    // A refill that asks for no more than the reservation holds raises nothing: it is answered as
    // it stands, deadline included, because the ledger moves a deadline only with a raised ceiling,
    // and it is not measured against what the payer authorises.
    let raises = asked > held;
    if let Some(lease) = &found
        && !raises
    {
        return granted(relay, &payer, lease);
    }
    // What the payer authorises is a bound on what a lease holds outstanding: the cumulative
    // ceiling less what the relay has counted.
    let counted = found.as_ref().map_or(0, |lease| lease.consumed);
    if asked.saturating_sub(counted) > max_bytes {
        return invalid(&format!(
            "That payer authorises at most {max_bytes} bytes outstanding for one lease."
        ));
    }
    if found.is_none() && relay.no_relay {
        return refused_answer(
            relay,
            &payer,
            "unavailable",
            "This service has no relay instance to carry that pair right now.",
        );
    }
    // The ledger refuses a hold that would take the principal past its allowance, which is an
    // exhaustion, or past the aggregate it may hold outstanding, which is a refusal of this
    // request.
    let addition = asked - held;
    if relay.exhausted {
        return refused_answer(
            relay,
            &payer,
            "exhausted",
            "The relay allowance for this period is used up.",
        );
    }
    if relay.outstanding(&payer) + addition > relay.aggregate_limit {
        return refused_answer(
            relay,
            &payer,
            "unavailable",
            "That would pass the aggregate outstanding relay-byte ceiling for this principal.",
        );
    }

    // No lease lasts past the authorisation that pays for it.
    let deadline = (service_now + u64::from(body.duration_seconds) * 1000).min(ends_at_ms);
    let frozen = relay.frozen_deadlines;
    let lease = match found {
        Some(mut lease) => {
            lease.revision += 1;
            lease.ceiling = asked;
            if !frozen {
                lease.expires_at_ms = lease.expires_at_ms.max(deadline);
            }
            lease
        }
        None => Lease {
            lease_id: relay.identifier(3),
            reservation_id: relay.identifier(4),
            relay_url: relay.relay_url.clone(),
            revision: 1,
            source: pair.0,
            destination: pair.1,
            direction: body.direction,
            requested_by: proof.key,
            payer: payer.clone(),
            authorisation_id,
            sponsored,
            ceiling: asked,
            expires_at_ms: deadline,
            consumed: 0,
            state: LeaseState::Installed,
            ended_for: None,
            retired: false,
        },
    };
    relay.leases.insert(lease.lease_id.clone(), lease.clone());
    granted(relay, &payer, &lease)
}

/// The answer that a lease is issued, as the lease stands.
fn granted(relay: &Relay, payer: &str, lease: &Lease) -> ServiceHttpAnswer {
    let signed = signed_lease(relay, lease);
    let reserved = relay.outstanding(payer);
    answered(json!({
        "state": "issued",
        "lease": signed,
        "relay_url": lease.relay_url,
        "relay_instance_id": RELAY_INSTANCE,
        "region": "eu-central",
        "issuer_key_revision": "1",
        "installed": ack(lease),
        "payer": payer,
        "reservation_id": lease.reservation_id,
        "allowance": allowance(relay, reserved),
        "warnings": relay.warnings(),
        "grace": if relay.in_grace { relay.grace_remainder() } else { Value::Null },
    }))
}

/// The one relay instance this service offers.
const RELAY_INSTANCE: &str = "00000009-0000-4000-8000-000000000001";

/// The lease as the relay holds it, signed with the admission key.
fn signed_lease(relay: &Relay, lease: &Lease) -> Value {
    let payer = lease.payer.split_once(':').expect("a payer");
    let principal = if payer.0 == "account" {
        json!({ "account": { "account_id": payer.1 } })
    } else {
        json!({ "installation": { "installation_id": "00000007-0000-4000-8000-000000000001" } })
    };
    // An authorisation that was not the caller's default when the lease was issued sponsors
    // it.
    let payer_authorisation = match (&lease.authorisation_id, lease.sponsored) {
        (Some(authorisation_id), true) => {
            json!({ "sponsored": { "authorisation_id": authorisation_id } })
        }
        _ => Value::String("host_selected".to_owned()),
    };
    let value = json!({
        "lease_id": lease.lease_id,
        "revision": lease.revision.to_string(),
        "reservation_id": lease.reservation_id,
        "source_endpoint_key": lease.source,
        "destination_endpoint_key": lease.destination,
        "direction": lease.direction,
        "payer": principal,
        "payer_authorisation": payer_authorisation,
        "byte_ceiling": lease.ceiling.to_string(),
        "expires_at_ms": lease.expires_at_ms.to_string(),
        "relay_scope": {
            "ingress_relay_instance_id": RELAY_INSTANCE,
            "egress_relay_instance_id": RELAY_INSTANCE,
        },
        "metering_relay_instance_id": RELAY_INSTANCE,
        "metering_role": "ingress",
        "grace": Value::Null,
        "issuer_key": crate::feed::key_text(relay.issuer.public()),
    });
    // The protocol's own type reads it, so the stand-in cannot hand out a lease that no relay
    // could read.
    let typed: RelayLease = serde_json::from_value(value.clone()).expect("a lease of the protocol");
    let input = typed.signing_input().expect("canonical bytes");
    let transcript =
        kr_crypto::sign::SigningTranscript::from_canonical_bytes(RELAY_LEASE_DOMAIN, input)
            .expect("a transcript");
    let signature =
        kr_crypto::sign::sign(&relay.issuer, &transcript).expect("an admission signature");
    json!({ "lease": value, "signature": signature })
}

/// What the relay answers when asked to install or to fence a lease.
fn ack(lease: &Lease) -> Value {
    json!({
        "lease_id": lease.lease_id,
        "revision": lease.revision.to_string(),
        "state": if lease.state == LeaseState::Installed { "installed" } else { "revoked" },
        "bytes_consumed": lease.consumed.to_string(),
        "bytes_remaining": (lease.ceiling - lease.consumed).to_string(),
        "grace_remaining_ms": Value::Null,
    })
}

fn allowance(relay: &Relay, reserved: u64) -> Value {
    let used: u64 = relay.leases.values().map(|lease| lease.consumed).sum();
    json!({
        "allowance": ALLOWANCE_BYTES.to_string(),
        "used": if relay.exhausted { ALLOWANCE_BYTES } else { used }.to_string(),
        "reserved": reserved.to_string(),
        "period": "2026-10",
        "exhausted": relay.exhausted,
    })
}

/// The answer about capacity: an allowance that is spent, or a service with no relay to offer.
fn refused_answer(relay: &Relay, payer: &str, state: &str, message: &str) -> ServiceHttpAnswer {
    answered(json!({
        "state": state,
        "payer": payer,
        "message": message,
        "alternatives": [
            "A direct connection between the devices, which needs no managed relay.",
            "A self-hosted relay configured in the service settings."
        ],
        "allowance": allowance(relay, relay.outstanding(payer)),
        "warnings": relay.warnings(),
        "grace": if state == "exhausted" || relay.in_grace {
            relay.grace_remainder()
        } else {
            Value::Null
        },
    }))
}

/// The body of a payer sign-in request.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignInBody {
    account_id: String,
}

/// An instant as the Worker writes it: an ISO 8601 text in UTC with milliseconds.
fn instant(ms: u64) -> String {
    let milliseconds = i64::try_from(ms).expect("a time in range");
    let timestamp = jiff::Timestamp::from_millisecond(milliseconds).expect("a time in range");
    timestamp.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// `relay.payer.sign_in`: makes the account a caller is signed in to the caller's payer, from the
/// sign-in itself.
///
/// The request carries two proofs: the caller's credential, and the bearer token of an account
/// sign-in that was issued the `relay.lease` scope. A grant opens at most one authorisation, for the
/// first caller that presents it. It is renewed in place when fewer than half its hour remains, it
/// lasts an hour from each renewal, and a withdrawal holds for that grant for ever. Every refusal
/// that only signing in again mends is `REAUTHENTICATION_REQUIRED`.
pub(crate) fn sign_in(
    relay: &mut Relay,
    tokens: &BTreeMap<String, crate::web::Token>,
    origin: &str,
    document: &Value,
    bearer: Option<&str>,
    now_ms: u64,
) -> ServiceHttpAnswer {
    relay.seen_ms = now_ms;
    let Ok(body) = serde_json::from_value::<SignInBody>(document["body"].clone()) else {
        return invalid("That sign-in payer request is not one this service reads.");
    };
    let canonical = kr_cbor::encode(&kr_cbor::signing_value(
        PAYER_SIGN_IN_DOMAIN,
        vec![kr_cbor::to_canonical_value(&body).expect("a canonical body")],
    ));
    let proof = match check_credential(
        relay,
        origin,
        "relay.payer.sign_in",
        document,
        &canonical,
        now_ms,
    ) {
        Ok(proof) => proof,
        Err(refused) => return refused,
    };
    // No sign-in, one issued without the scope, one that has ended, or one that records no grant:
    // the person signs the caller in again.
    let sign_in_required = || {
        refusal(
            403,
            "REAUTHENTICATION_REQUIRED",
            "Sign this device in to its account again, and allow it to pay for relay traffic from \
             that account.",
        )
    };
    let Some(token) = bearer.and_then(|bearer| tokens.get(bearer)) else {
        return sign_in_required();
    };
    let Some(grant) = token.grant.as_ref() else {
        return sign_in_required();
    };
    if !token.live || !token.scopes.contains(RELAY_LEASE_SCOPE) {
        return sign_in_required();
    }
    // The two proofs have to be about one pairing.
    if token.account != body.account_id {
        return refusal(
            403,
            "FORBIDDEN",
            "That request names an account other than the one the sign-in belongs to.",
        );
    }
    let service_now = relay.service_now(now_ms);
    let opened = relay
        .authorisations
        .iter()
        .find(|(_, held)| held.grant == *grant)
        .map(|(id, _)| id.clone());
    let authorisation_id = if let Some(id) = opened {
        let held = relay
            .authorisations
            .get_mut(&id)
            .expect("the one just found");
        if held.account_id != body.account_id || held.subject != proof.key {
            return refusal(
                403,
                "REAUTHENTICATION_REQUIRED",
                "That sign-in belongs to a different key than the one this device signs with. \
                 Sign the device in to its account again.",
            );
        }
        if held.withdrawn {
            return refusal(
                403,
                "REAUTHENTICATION_REQUIRED",
                "This account withdrew the relay authorisation it gave this device. Sign the \
                 device in to the account again to authorise it.",
            );
        }
        if held.valid_until_ms.saturating_sub(service_now) < SIGN_IN_RENEW_BELOW_MS {
            held.valid_until_ms = service_now + SIGN_IN_AUTHORISATION_MS;
        }
        id
    } else {
        let id = relay.identifier(2);
        relay.authorisations.insert(
            id.clone(),
            Authorisation {
                account_id: body.account_id.clone(),
                subject: proof.key.clone(),
                byte_ceiling: relay.sign_in_bound,
                withdrawn: false,
                valid_from_ms: service_now,
                valid_until_ms: service_now + SIGN_IN_AUTHORISATION_MS,
                grant: grant.clone(),
                selected_at_ms: None,
            },
        );
        id
    };
    // It is the caller's default, and whatever else the caller had selected is not.
    for (id, held) in &mut relay.authorisations {
        if held.subject == proof.key {
            held.selected_at_ms = if *id == authorisation_id {
                held.selected_at_ms.or(Some(service_now))
            } else {
                None
            };
        }
    }
    let held = &relay.authorisations[&authorisation_id];
    answered(json!({
        "authorisation": {
            "authorisation_id": authorisation_id,
            "account_id": held.account_id,
            "subject_kind": match proof.signer {
                ServiceRequestSigner::Host => "host",
                ServiceRequestSigner::Installation => "installation",
            },
            "subject": held.subject,
            "byte_ceiling": held.byte_ceiling.to_string(),
            "valid_from": instant(held.valid_from_ms),
            "valid_until": instant(held.valid_until_ms),
            "selected_at": held.selected_at_ms.map(instant),
            "withdrawn_at": Value::Null,
        }
    }))
}

/// `relay.lease.revoke`: ends a lease, fences it, and answers with the settlement as it stands. A
/// revocation sent again finishes whatever the first did not and answers the same.
pub(crate) fn revoke(
    relay: &mut Relay,
    origin: &str,
    document: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    relay.seen_ms = now_ms;
    let Ok(body) = serde_json::from_value::<RevokeBody>(document["body"].clone()) else {
        return invalid("That revocation request is not one this service reads.");
    };
    let canonical = kr_cbor::encode(&kr_cbor::signing_value(
        LEASE_REVOKE_DOMAIN,
        vec![kr_cbor::to_canonical_value(&body).expect("a canonical body")],
    ));
    let proof = match check_credential(
        relay,
        origin,
        "relay.lease.revoke",
        document,
        &canonical,
        now_ms,
    ) {
        Ok(proof) => proof,
        Err(refused) => return refused,
    };
    let Some(lease) = relay.leases.get_mut(&body.lease_id.get().to_string()) else {
        return invalid("That lease is not one this service has issued.");
    };
    if lease.requested_by != proof.key {
        return refusal(403, "FORBIDDEN", "That lease was issued to another caller.");
    }
    if lease.state == LeaseState::Installed {
        lease.state = LeaseState::Revoked;
        lease.revision += 1;
        lease.ended_for = Some(body.reason.as_str());
    }
    let lease = lease.clone();
    answered(json!({
        "lease_id": lease.lease_id,
        "revision": lease.revision.to_string(),
        "relay": ack(&lease),
        "settlement": {
            "reservation_id": lease.reservation_id,
            "bytes_receipted": lease.consumed.to_string(),
            "bytes_settled": lease.consumed.to_string(),
            "basis": "receipts",
            "settled_at": "2026-10-12T12:00:00.000Z",
        },
        "grace": Value::Null,
    }))
}
