//! The durable authority feed, answering as the Worker's authority feed does.
//!
//! One feed per host, addressed by the identifier of the host's own authorisation key. A remote
//! owner publishes a signed revocation request; the host issues its own ordered revisions,
//! acknowledges or refuses what it read, names the keys that may remove it, and is removed by itself
//! or by a key it named. Every answer is the whole state of the feed after the call, in the shape the
//! contract states.
//!
//! The source is the web repository's `workers/api/src/authority-feed/{index,feed}.ts`; each rule
//! below is one of its, and the fidelity table in the crate's documentation names the line.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use kr_client::services::ServiceHttpAnswer;
use kr_protocol::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, REVOCATION_DOMAIN,
    RevocationAcknowledgement, RevocationCompletion, RevocationRequest, RevocationTarget,
};
use kr_protocol::scalars::AuthorisationKey;
use kr_protocol::service::{ServiceRequestSignature, ServiceRequestSigner};
use serde_json::{Value, json};

use crate::web::{answered, key_id_of, record_verifies, refusal};

/// How often the contract says a device polls the feed while it is online, in seconds.
const FEED_POLL_INTERVAL_SECONDS: u32 = 30;
/// How long a record the host finished with is kept so its publisher can read the answer.
const ACKNOWLEDGED_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// The most records the host has not finished with that one feed holds.
const MAX_FEED_RECORDS: usize = 1_000;
/// The part of a feed only the keys the host named may use.
const FEED_RECORDS_FOR_NAMED_KEYS: usize = 256;
/// The most records one publisher may have in one feed.
const MAX_FEED_RECORDS_PER_PUBLISHER: usize = 32;
/// How many records one read returns.
const FEED_PAGE: usize = 64;
/// The most identifiers one revocation request names.
const MAX_REVOCATION_TARGETS: usize = 256;
/// The most requests one revision names as applied.
const MAX_APPLIED_REQUESTS: usize = 256;
/// The most keys a host may name as permitted to remove it.
const MAX_REMOVAL_KEYS: usize = 8;

/// The host row of a feed.
#[derive(Debug)]
struct Host {
    host_key_id: String,
    host_device_id: Option<String>,
    authority_revision: Option<u64>,
    revised_at_ms: Option<u64>,
    acknowledged_at_ms: Option<u64>,
    last_acknowledgement: Option<Value>,
    removed_at_ms: Option<u64>,
    next_sequence: u64,
}

/// One revocation request a feed holds.
#[derive(Debug)]
struct Record {
    request_id: String,
    content: Value,
    request: Value,
    published_by: String,
    published_at_ms: u64,
    acknowledgement: Option<Value>,
    rejected: Option<String>,
    settled_at_ms: Option<u64>,
}

/// One host's feed.
#[derive(Debug, Default)]
pub(crate) struct Feed {
    host: Option<Host>,
    records: BTreeMap<u64, Record>,
    revisions: BTreeMap<u64, (Value, Value)>,
    removal_keys: BTreeSet<String>,
}

/// What a feed is asked, once the route has checked the request.
enum Call {
    Publish {
        request: Box<RevocationRequest>,
        value: Value,
    },
    Revise {
        revision: Box<AuthorityRevisionRecord>,
        value: Value,
    },
    Acknowledge {
        acknowledgement: Box<RevocationAcknowledgement>,
        value: Value,
    },
    Reject {
        request_id: String,
        reason: String,
    },
    Delegate {
        owner_key_ids: Vec<String>,
    },
    Read,
    Remove,
}

/// What the caller is, as the feed sees it.
struct Caller {
    /// The public key that signed, as unpadded base64url.
    key: String,
    /// The identifier that key derives.
    key_id: String,
    signer: ServiceRequestSigner,
    after_sequence: Option<u64>,
    summary_only: bool,
    now_ms: u64,
}

type Outcome = Result<Value, ServiceHttpAnswer>;

fn invalid(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_REQUEST", message)
}

fn forbidden(message: &str) -> ServiceHttpAnswer {
    refusal(403, "FORBIDDEN", message)
}

/// One 16-byte identifier in its hyphenated lower-case form.
fn identifier(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let groups: Vec<&str> = text.split('-').collect();
    let sizes = [8, 4, 4, 4, 12];
    (groups.len() == 5
        && groups
            .iter()
            .zip(sizes)
            .all(|(group, size)| group.len() == size && group.bytes().all(is_lower_hex)))
    .then(|| text.to_owned())
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

/// One 32-byte key identifier in its canonical base64url form.
fn key_identifier(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()?;
    (bytes.len() == 32 && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == text)
        .then(|| text.to_owned())
}

/// A counter in its canonical decimal form.
fn counter(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    let parsed: u64 = text.parse().ok()?;
    (parsed.to_string() == text).then_some(parsed)
}

/// The time as an RFC 3339 instant, in UTC, to the millisecond.
fn instant(ms: u64) -> String {
    let days = i64::try_from(ms / 86_400_000).unwrap_or(0);
    let of_day = ms % 86_400_000;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1_000 % 60,
        of_day % 1_000
    )
}

fn key_text(key: &AuthorisationKey) -> String {
    serde_json::to_value(key)
        .expect("a key")
        .as_str()
        .expect("text")
        .to_owned()
}

/// Answers one `authority.sync` request that passed the credential, as the Worker's route and feed
/// do. `feeds` holds every feed this service keeps, by the identifier of the host key.
pub(crate) fn sync(
    feeds: &mut BTreeMap<String, Feed>,
    signature: &ServiceRequestSignature,
    body: &Value,
    now_ms: u64,
) -> ServiceHttpAnswer {
    let members = [
        "publish",
        "revise",
        "acknowledge",
        "reject",
        "delegate",
        "read",
        "remove",
    ];
    let named: Vec<&str> = members
        .into_iter()
        .filter(|member| body.get(member).is_some())
        .collect();
    let [operation] = named.as_slice() else {
        return invalid(
            "An authority-feed request publishes, revises, acknowledges, refuses, delegates, reads or removes, and asks for exactly one of those.",
        );
    };
    let caller = Caller {
        key: key_text(&signature.public_key),
        key_id: key_id_of(&signature.public_key),
        signer: signature.signer,
        after_sequence: None,
        summary_only: false,
        now_ms,
    };
    let own = (caller.signer == ServiceRequestSigner::Host).then(|| caller.key_id.clone());
    let member = body[*operation].as_object().map(|_| &body[*operation]);

    let built = build(operation, member, &caller, own.as_deref(), signature);
    let (host_key_id, call, caller) = match built {
        Ok(built) => built,
        Err(answer) => return answer,
    };
    let feed = feeds.entry(host_key_id.clone()).or_default();
    match feed.run(&host_key_id, &call, &caller) {
        Ok(state) => answered(state),
        Err(answer) => answer,
    }
}

/// What the route checks before the feed decides, and the call it makes of the feed.
fn build(
    operation: &str,
    member: Option<&Value>,
    caller: &Caller,
    own: Option<&str>,
    signature: &ServiceRequestSignature,
) -> Result<(String, Call, Caller), ServiceHttpAnswer> {
    let carried = |after_sequence, summary_only| Caller {
        key: caller.key.clone(),
        key_id: caller.key_id.clone(),
        signer: caller.signer,
        after_sequence,
        summary_only,
        now_ms: caller.now_ms,
    };
    match operation {
        "publish" => {
            let member = member
                .ok_or_else(|| invalid("A publication names the host it is addressed to."))?;
            let host = own
                .map(str::to_owned)
                .or_else(|| key_identifier(&member["host_key_id"]))
                .ok_or_else(|| {
                    invalid("A publication names the host key identifier it is addressed to.")
                })?;
            let value = member["request"].clone();
            let request: RevocationRequest = serde_json::from_value(value.clone())
                .map_err(|_| invalid("A publication carries a signed revocation request."))?;
            let targets = match &request.target {
                RevocationTarget::Grants { grant_ids } => grant_ids.len(),
                RevocationTarget::Devices { device_ids } => device_ids.len(),
            };
            if targets > MAX_REVOCATION_TARGETS {
                return Err(invalid(&format!(
                    "A revocation request names at most {MAX_REVOCATION_TARGETS} identifiers."
                )));
            }
            proven(
                caller,
                signature,
                serde_json::to_value(request.issuer_key_id)
                    .expect("a key id")
                    .as_str()
                    .expect("text"),
                REVOCATION_DOMAIN,
                request.signing_input(),
                &request.signature,
            )?;
            Ok((
                host,
                Call::Publish {
                    request: Box::new(request),
                    value,
                },
                carried(None, false),
            ))
        }
        "revise" => {
            let value = member
                .map(|member| member["revision"].clone())
                .unwrap_or(Value::Null);
            let revision: AuthorityRevisionRecord = serde_json::from_value(value.clone())
                .map_err(|_| invalid("A revision carries a signed authority revision record."))?;
            if revision.applied_requests.len() > MAX_APPLIED_REQUESTS {
                return Err(invalid(&format!(
                    "A revision names at most {MAX_APPLIED_REQUESTS} applied requests."
                )));
            }
            let host = own.ok_or_else(|| forbidden("Only the host issues its own revisions."))?;
            proven(
                caller,
                signature,
                serde_json::to_value(revision.host_key_id)
                    .expect("a key id")
                    .as_str()
                    .expect("text"),
                AUTHORITY_REVISION_DOMAIN,
                revision.signing_input(),
                &revision.signature,
            )?;
            Ok((
                host.to_owned(),
                Call::Revise {
                    revision: Box::new(revision),
                    value,
                },
                carried(None, false),
            ))
        }
        "acknowledge" => {
            let value = member
                .map(|member| member["acknowledgement"].clone())
                .unwrap_or(Value::Null);
            let acknowledgement: RevocationAcknowledgement = serde_json::from_value(value.clone())
                .map_err(|_| {
                    invalid("An acknowledgement names the request, the host and the revision.")
                })?;
            let host =
                own.ok_or_else(|| forbidden("Only the host acknowledges what it applied."))?;
            Ok((
                host.to_owned(),
                Call::Acknowledge {
                    acknowledgement: Box::new(acknowledgement),
                    value,
                },
                carried(None, false),
            ))
        }
        "reject" => {
            let request_id = member.and_then(|member| identifier(&member["request_id"]));
            let reason = member
                .and_then(|member| member["reason"].as_str())
                .filter(|reason| {
                    matches!(
                        *reason,
                        "no_owner_authority" | "unknown_target" | "superseded"
                    )
                });
            let (Some(request_id), Some(reason)) = (request_id, reason) else {
                return Err(invalid(
                    "A refusal names the request and why the host will not apply it.",
                ));
            };
            let host =
                own.ok_or_else(|| forbidden("Only the host refuses a request addressed to it."))?;
            Ok((
                host.to_owned(),
                Call::Reject {
                    request_id,
                    reason: reason.to_owned(),
                },
                carried(None, false),
            ))
        }
        "delegate" => {
            let listed = member.and_then(|member| member["owner_key_ids"].as_array());
            let Some(listed) = listed.filter(|listed| listed.len() <= MAX_REMOVAL_KEYS) else {
                return Err(invalid(&format!(
                    "A delegation names at most {MAX_REMOVAL_KEYS} key identifiers that may remove this host."
                )));
            };
            let keys = listed
                .iter()
                .map(key_identifier)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| invalid("A delegation names key identifiers."))?;
            let host =
                own.ok_or_else(|| forbidden("Only the host names the keys that may remove it."))?;
            Ok((
                host.to_owned(),
                Call::Delegate {
                    owner_key_ids: keys,
                },
                carried(None, false),
            ))
        }
        "remove" => {
            let host = own
                .map(str::to_owned)
                .or_else(|| member.and_then(|member| key_identifier(&member["host_key_id"])))
                .ok_or_else(|| invalid("A removal names the host key identifier."))?;
            Ok((host, Call::Remove, carried(None, false)))
        }
        _ => {
            let host = own
                .map(str::to_owned)
                .or_else(|| member.and_then(|member| key_identifier(&member["host_key_id"])))
                .ok_or_else(|| invalid("A read names the host key identifier."))?;
            let declared = member.map(|member| &member["after_sequence"]);
            let after = match declared {
                Some(declared) if !declared.is_null() => Some(
                    counter(declared)
                        .ok_or_else(|| invalid("A cursor is a position this feed has issued."))?,
                ),
                _ => None,
            };
            let summary_only = member.is_some_and(|member| member["summary_only"] == json!(true));
            Ok((host, Call::Read, carried(after, summary_only)))
        }
    }
}

/// Checks that the record was signed by the key that carried the request.
fn proven(
    caller: &Caller,
    signature: &ServiceRequestSignature,
    named_key_id: &str,
    domain: &str,
    input: Result<Vec<u8>, kr_cbor::CborError>,
    record_signature: &kr_protocol::scalars::Signature64,
) -> Result<(), ServiceHttpAnswer> {
    if caller.key_id != named_key_id {
        return Err(forbidden(
            "That record names a key other than the one that carried the request.",
        ));
    }
    if input.is_err() {
        return Err(invalid("That record is not one this service can check."));
    }
    if record_verifies(&signature.public_key, domain, input, record_signature) {
        Ok(())
    } else {
        Err(forbidden(
            "That record was not signed by the key that carried it.",
        ))
    }
}

impl Feed {
    /// Runs one call: the host record is established, the caller is checked, and the call decides.
    fn run(&mut self, host_key_id: &str, call: &Call, caller: &Caller) -> Outcome {
        self.sweep(caller.now_ms);
        if self.host.is_none() {
            self.host = Some(Host {
                host_key_id: host_key_id.to_owned(),
                host_device_id: None,
                authority_revision: None,
                revised_at_ms: None,
                acknowledged_at_ms: None,
                last_acknowledgement: None,
                removed_at_ms: None,
                next_sequence: 1,
            });
        }
        // A host-proven caller is the host, because the route found this feed by the identifier of
        // the key that signed. A removal is also admitted from a key the host named for it.
        let host_only = !matches!(call, Call::Publish { .. } | Call::Read);
        if caller.signer != ServiceRequestSigner::Host && host_only {
            let removal_by_a_named_key =
                matches!(call, Call::Remove) && self.removal_keys.contains(&caller.key_id);
            if !removal_by_a_named_key {
                return Err(forbidden(
                    "The host issues its own revisions, acknowledgements and refusals, and only the host or a key it named removes it.",
                ));
            }
        }
        match call {
            Call::Publish { request, value } => self.publish(request, value, caller),
            Call::Revise { revision, value } => self.revise(revision, value, caller),
            Call::Acknowledge {
                acknowledgement,
                value,
            } => self.acknowledge(acknowledgement, value, caller),
            Call::Reject { request_id, reason } => self.reject(request_id, reason, caller),
            Call::Delegate { owner_key_ids } => {
                self.removal_keys = owner_key_ids.iter().cloned().collect();
                Ok(self.state(caller))
            }
            Call::Read => Ok(self.state(caller)),
            Call::Remove => {
                self.records.clear();
                self.host_mut().removed_at_ms = Some(caller.now_ms);
                Ok(self.state(caller))
            }
        }
    }

    /// A week passes: the records the host finished with are dropped, as retention drops them.
    pub(crate) fn forget_what_was_finished(&mut self) {
        self.records
            .retain(|_, record| record.settled_at_ms.is_none());
    }

    fn host(&self) -> &Host {
        self.host.as_ref().expect("the host row")
    }

    fn host_mut(&mut self) -> &mut Host {
        self.host.as_mut().expect("the host row")
    }

    /// Drops what has outlived its retention.
    fn sweep(&mut self, now_ms: u64) {
        let horizon = now_ms.saturating_sub(ACKNOWLEDGED_RETENTION_MS);
        self.records
            .retain(|_, record| record.settled_at_ms.is_none_or(|settled| settled > horizon));
    }

    fn outstanding(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.settled_at_ms.is_none())
            .count()
    }

    fn publish(&mut self, request: &RevocationRequest, value: &Value, caller: &Caller) -> Outcome {
        if self.host().removed_at_ms.is_some() {
            return Err(refusal(
                404,
                "NOT_FOUND",
                "That host has been removed from the feed.",
            ));
        }
        let request_id = serde_json::to_value(request.request_id)
            .expect("an identifier")
            .as_str()
            .expect("text")
            .to_owned();
        if let Some(existing) = self
            .records
            .values()
            .find(|record| record.request_id == request_id)
        {
            // The identifier is the whole of the idempotence for a repeat of one publication.
            return if existing.content == *value {
                Ok(self.state(caller))
            } else {
                Err(forbidden(
                    "That request identifier has already carried a different request.",
                ))
            };
        }
        let outstanding = self.outstanding();
        if outstanding >= MAX_FEED_RECORDS {
            return Err(refusal(
                402,
                "QUOTA_EXHAUSTED",
                "This feed holds as many records the host has not finished with as it may.",
            ));
        }
        if !self.removal_keys.contains(&caller.key_id)
            && outstanding >= MAX_FEED_RECORDS - FEED_RECORDS_FOR_NAMED_KEYS
        {
            return Err(refusal(
                402,
                "QUOTA_EXHAUSTED",
                "The part of this feed a publisher the host has not named may use is full. The host settles what is there when it returns.",
            ));
        }
        let mine = self
            .records
            .values()
            .filter(|record| record.published_by == caller.key && record.settled_at_ms.is_none())
            .count();
        if mine >= MAX_FEED_RECORDS_PER_PUBLISHER {
            return Err(refusal(
                402,
                "QUOTA_EXHAUSTED",
                "This publisher holds as much of that feed as one publisher may.",
            ));
        }
        let sequence = self.host().next_sequence;
        self.host_mut().next_sequence = sequence + 1;
        self.records.insert(
            sequence,
            Record {
                request_id,
                content: value.clone(),
                request: value.clone(),
                published_by: caller.key.clone(),
                published_at_ms: caller.now_ms,
                acknowledgement: None,
                rejected: None,
                settled_at_ms: None,
            },
        );
        Ok(self.state(caller))
    }

    fn revise(
        &mut self,
        revision: &AuthorityRevisionRecord,
        value: &Value,
        caller: &Caller,
    ) -> Outcome {
        let number = revision.authority_revision.get();
        let previous = revision.previous_revision.get();
        if number <= previous {
            return Err(invalid("A revision follows the revision it names."));
        }
        if let Some((digest, _)) = self.revisions.get(&number) {
            // The same revision submitted twice is the revision that already stands.
            return if digest == value {
                Ok(self.state(caller))
            } else {
                Err(forbidden(
                    "That revision has already been issued with different content.",
                ))
            };
        }
        let held = self.host().authority_revision;
        if held.is_some_and(|held| number <= held) {
            return Err(forbidden(
                "This feed holds a revision at least as high as that one.",
            ));
        }
        if held.unwrap_or(0) != previous {
            return Err(forbidden(
                "A revision follows the revision this feed holds.",
            ));
        }
        self.revisions
            .insert(number, (value.clone(), value.clone()));
        let device = serde_json::to_value(revision.host_device_id)
            .expect("an identifier")
            .as_str()
            .expect("text")
            .to_owned();
        let host = self.host_mut();
        host.authority_revision = Some(number);
        host.revised_at_ms = Some(caller.now_ms);
        host.host_device_id = Some(device);
        Ok(self.state(caller))
    }

    fn acknowledge(
        &mut self,
        acknowledgement: &RevocationAcknowledgement,
        value: &Value,
        caller: &Caller,
    ) -> Outcome {
        let request_id = serde_json::to_value(acknowledgement.request_id)
            .expect("an identifier")
            .as_str()
            .expect("text")
            .to_owned();
        let Some(sequence) = self
            .records
            .iter()
            .find(|(_, record)| record.request_id == request_id)
            .map(|(sequence, _)| *sequence)
        else {
            return Err(refusal(404, "NOT_FOUND", "No such record."));
        };
        let number = acknowledgement.authority_revision.get();
        let Some((_, issued)) = self.revisions.get(&number) else {
            return Err(invalid(
                "An acknowledgement names a revision this host has issued.",
            ));
        };
        let applied = issued["applied_requests"]
            .as_array()
            .is_some_and(|applied| applied.iter().any(|entry| entry == &json!(request_id)));
        if !applied {
            return Err(invalid(
                "An acknowledgement names the revision that applied that request.",
            ));
        }
        let complete = acknowledgement.completion == RevocationCompletion::Complete;
        let record = &self.records[&sequence];
        if record.rejected.is_some() {
            return Err(invalid(
                "That request has been refused rather than applied.",
            ));
        }
        if record.settled_at_ms.is_some() && !complete {
            return Err(invalid(
                "That request has already been acknowledged as complete.",
            ));
        }
        if let Some(held) = record.acknowledgement.as_ref()
            && acknowledgement.acknowledged_at_ms.get()
                < counter(&held["acknowledged_at_ms"]).unwrap_or(0)
        {
            return Err(invalid(
                "That acknowledgement is older than the one this record holds.",
            ));
        }
        let record = self.records.get_mut(&sequence).expect("the record");
        record.acknowledgement = Some(value.clone());
        record.settled_at_ms = if complete {
            Some(record.settled_at_ms.unwrap_or(caller.now_ms))
        } else {
            None
        };
        let device = serde_json::to_value(acknowledgement.host_device_id)
            .expect("an identifier")
            .as_str()
            .expect("text")
            .to_owned();
        let host = self.host_mut();
        host.acknowledged_at_ms = Some(caller.now_ms);
        host.last_acknowledgement = Some(value.clone());
        host.host_device_id = Some(device);
        Ok(self.state(caller))
    }

    fn reject(&mut self, request_id: &str, reason: &str, caller: &Caller) -> Outcome {
        let Some(sequence) = self
            .records
            .iter()
            .find(|(_, record)| record.request_id == request_id)
            .map(|(sequence, _)| *sequence)
        else {
            return Err(refusal(404, "NOT_FOUND", "No such record."));
        };
        let record = self.records.get_mut(&sequence).expect("the record");
        if record.settled_at_ms.is_none() {
            record.rejected = Some(reason.to_owned());
            record.settled_at_ms = Some(caller.now_ms);
        }
        Ok(self.state(caller))
    }

    /// What a caller sees: the records it may see, and the summary.
    fn state(&self, caller: &Caller) -> Value {
        let host = self.host();
        let summary = self.summary();
        if caller.summary_only {
            return json!({
                "host_key_id": host.host_key_id,
                "host_device_id": host.host_device_id,
                "records": [],
                "next_after_sequence": caller.after_sequence.unwrap_or(0).to_string(),
                "more": false,
                "summary": summary,
            });
        }
        let after = caller.after_sequence.unwrap_or(0);
        let visible: Vec<(&u64, &Record)> = self
            .records
            .iter()
            .filter(|(sequence, record)| {
                **sequence > after
                    && (caller.signer == ServiceRequestSigner::Host
                        || record.published_by == caller.key)
            })
            .take(FEED_PAGE + 1)
            .collect();
        let more = visible.len() > FEED_PAGE;
        let page = &visible[..visible.len().min(FEED_PAGE)];
        let records: Vec<Value> = page
            .iter()
            .map(|(sequence, record)| {
                json!({
                    "sequence": sequence.to_string(),
                    "request": record.request,
                    "published_by": record.published_by,
                    "published_at_ms": record.published_at_ms.to_string(),
                    "acknowledgement": record.acknowledgement,
                    "rejected": record.rejected,
                })
            })
            .collect();
        json!({
            "host_key_id": host.host_key_id,
            "host_device_id": host.host_device_id,
            "records": records,
            "next_after_sequence": page.last().map_or(after, |(sequence, _)| **sequence).to_string(),
            "more": more,
            "summary": summary,
        })
    }

    fn summary(&self) -> Value {
        let host = self.host();
        json!({
            "authority_revision": host.authority_revision.map(|revision| revision.to_string()),
            "revised_at": host.revised_at_ms.map(instant),
            "last_acknowledgement": host.last_acknowledgement,
            "acknowledged_at": host.acknowledged_at_ms.map(instant),
            "outstanding": self.outstanding().to_string(),
            "removed": host.removed_at_ms.is_some(),
            "removal_keys": self.removal_keys.iter().collect::<Vec<_>>(),
            "poll_interval_seconds": FEED_POLL_INTERVAL_SECONDS,
        })
    }
}
