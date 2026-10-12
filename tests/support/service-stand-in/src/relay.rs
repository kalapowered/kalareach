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

/// The domain a revocation request's body digest covers.
const LEASE_REVOKE_DOMAIN: &str = "kr-relay-lease-revoke/1";

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
    /// The key that asked for it, which is the only one that may change it.
    requested_by: String,
    /// `account:<id>` or `installation:<id>`.
    payer: String,
    authorisation_id: Option<String>,
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
    /// The authorisation it was issued under, when an account pays.
    pub authorisation_id: Option<String>,
    /// Whether the lease still carries traffic.
    pub live: bool,
    /// Why it was ended, when it was: `unpaired`, `payer_withdrew` or `finished`.
    pub ended_for: Option<&'static str>,
}

/// What an account console gives a host: the ids a host names to be paid for by the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayPayerRecord {
    /// The account that pays.
    pub account_id: String,
    /// The authorisation record.
    pub authorisation_id: String,
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
    counter: u64,
    issuer: AuthorisationKeyPair,
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
            counter: 0,
            issuer: AuthorisationKeyPair::generate().expect("an admission key"),
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

    pub(crate) fn authorise(
        &mut self,
        host: &AuthorisationKey,
        byte_ceiling: u64,
    ) -> RelayPayerRecord {
        let account_id = self.identifier(1);
        let authorisation_id = self.identifier(2);
        self.authorisations.insert(
            authorisation_id.clone(),
            Authorisation {
                account_id: account_id.clone(),
                subject: crate::feed::key_text(host),
                byte_ceiling,
                withdrawn: false,
            },
        );
        RelayPayerRecord {
            account_id,
            authorisation_id,
        }
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
                authorisation_id: lease.authorisation_id.clone(),
                live: lease.state == LeaseState::Installed,
                ended_for: lease.ended_for,
            })
            .collect()
    }

    /// The bytes an account has outstanding across its live leases: what each holds beyond what
    /// the relay has counted for it, which is what the aggregate bound is measured on.
    fn outstanding(&self, payer: &str) -> u64 {
        self.leases
            .values()
            .filter(|lease| lease.state == LeaseState::Installed && lease.payer == payer)
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

/// `relay.lease.issue`: opens a lease for a pair, or refills the one the pair holds.
pub(crate) fn issue(
    relay: &mut Relay,
    origin: &str,
    document: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
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
    let asked = body.byte_ceiling.get();
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

    // Who pays: the account a host names under an authorisation that account gave it. A host key
    // draws on no allowance of its own, and this stand-in does not model a host selecting a default
    // account, so a host that names none is turned away.
    let (payer, authorisation_id, max_bytes) = match (&body.payer.0, proof.signer) {
        (
            Some(Payer::Account {
                account_id,
                authorisation_id,
            }),
            _,
        ) => {
            let Some(held) = relay.authorisations.get(authorisation_id) else {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That account has not authorised this caller.",
                );
            };
            if held.account_id != *account_id || held.subject != proof.key {
                return refusal(
                    403,
                    "FORBIDDEN",
                    "That account has not authorised this caller.",
                );
            }
            if held.withdrawn {
                return refusal(403, "FORBIDDEN", "That authorisation is not in force.");
            }
            (
                format!("account:{account_id}"),
                Some(authorisation_id.clone()),
                held.byte_ceiling.min(OUTSTANDING_CEILING_BYTES),
            )
        }
        (_, ServiceRequestSigner::Host) => {
            return refusal(
                403,
                "FORBIDDEN",
                "A host names the account it is spending, because a host key draws on no allowance \
                 of its own.",
            );
        }
        (_, ServiceRequestSigner::Installation) => (
            format!("installation:{}", proof.key),
            None,
            OUTSTANDING_CEILING_BYTES,
        ),
    };

    let pair = (
        text_of(&body.source_endpoint_key),
        text_of(&body.destination_endpoint_key),
    );
    // The lease this request is about: the one it named, or the one its pair holds.
    let service_now = relay.service_now(now_ms);
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
                "That lease was issued under another authorisation. Revoke it, or select the one \
                 it names.",
            );
        }
        if lease.source != pair.0
            || lease.destination != pair.1
            || lease.direction != body.direction
        {
            return invalid("That lease binds another pair, or another direction.");
        }
        if lease.retired {
            return refused_answer(
                relay,
                &payer,
                "unavailable",
                "The relay carrying that lease is no longer one this service can bill through. \
                 Revoke the lease and ask for another.",
            );
        }
        // A reservation that has passed its deadline has been settled, and there is nothing left to
        // raise: the lease is fenced and the pair is given a new one, whose figures are the new
        // reservation's.
        if service_now >= lease.expires_at_ms {
            let old = lease.lease_id.clone();
            if let Some(expired) = relay.leases.get_mut(&old) {
                expired.state = LeaseState::Revoked;
                expired.revision += 1;
                expired.ended_for = Some("expired");
            }
            found = None;
        }
    }
    // What the payer authorises is a bound on what a lease holds outstanding: the cumulative
    // ceiling less what the relay has counted.
    let counted = found.as_ref().map_or(0, |lease| lease.consumed);
    if asked.saturating_sub(counted) > max_bytes {
        return invalid(&format!(
            "That payer authorises at most {max_bytes} bytes outstanding for one lease."
        ));
    }

    let held = found.as_ref().map_or(0, |lease| lease.ceiling);
    // A refill that asks for no more than the reservation holds is answered as it stands, deadline
    // included: the ledger moves a deadline only with a raised ceiling.
    let raises = asked > held;
    if let Some(lease) = &found
        && !raises
    {
        return granted(relay, &payer, lease);
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
    // exhaustion, or past the aggregate it may hold outstanding, which is a refusal of this request.
    let addition = asked - held;
    if relay.exhausted {
        return refused_answer(
            relay,
            &payer,
            "exhausted",
            "The relay allowance for this period is used up.",
        );
    }
    if relay.outstanding(&payer) + addition > OUTSTANDING_CEILING_BYTES {
        return refused_answer(
            relay,
            &payer,
            "unavailable",
            "That would pass the aggregate outstanding relay-byte ceiling for this principal.",
        );
    }

    let deadline = service_now + u64::from(body.duration_seconds) * 1000;
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
            revision: 1,
            source: pair.0,
            destination: pair.1,
            direction: body.direction,
            requested_by: proof.key,
            payer: payer.clone(),
            authorisation_id,
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
        "relay_url": "https://relay-1.reach.kala.to",
        "relay_instance_id": RELAY_INSTANCE,
        "region": "eu-central",
        "issuer_key_revision": "1",
        "installed": ack(lease),
        "payer": payer,
        "reservation_id": lease.reservation_id,
        "allowance": allowance(relay, reserved),
        "warnings": [],
        "grace": Value::Null,
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
    // An authorisation the host named without selecting it as its default sponsors the lease.
    let payer_authorisation = match &lease.authorisation_id {
        Some(authorisation_id) => json!({ "sponsored": { "authorisation_id": authorisation_id } }),
        None => Value::String("host_selected".to_owned()),
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
        "warnings": [],
        "grace": if state == "exhausted" {
            json!({
                "started_at": "2026-10-12T12:00:00.000Z",
                "ends_at": "2026-10-12T12:15:00.000Z",
                "remaining_ms": "600000",
                "remaining_bytes": "104857600",
            })
        } else {
            Value::Null
        },
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
