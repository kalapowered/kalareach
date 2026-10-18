//! Settings sync's collections at the sync route, answering as the Worker's sync collection does.
//!
//! A collection holds up to 256 sealed objects, each under its own revision and its own order of
//! writes, and lives in the namespace of the installation that made it, its home. Before a key
//! record has claimed it the collection is its home's alone and carries no key epoch. The first
//! record is the home's claim, taken only while the collection holds no object and no copy; every
//! record after it is offered by a member of the newest one, and from the claim on every object is
//! written under the epoch the collection is at, a write under an older one is refused and kept as
//! its request's receipt, and an installation the newest record does not list is answered as for a
//! collection that does not exist.
//!
//! A write names the revision it replaces. One that names another is refused and its content is
//! kept as a copy for the person to choose between, up to eight copies of one object, past which
//! the write is refused outright because dropping a copy would choose by the clock.
//!
//! Every exchange and every key record offer may name a request identity, and the collection keeps
//! a receipt for it under the installation that sent it: sent again it is answered what it was
//! answered, other content under it is `ID_CONFLICT`, and a fence ends the identity until the
//! receipt would have been swept. The receipt is read before membership, so an installation that
//! was removed after it sent a request can still ask what became of it.
//!
//! A write of an object spends the principal's settings-sync allowance; a test arranges for it to
//! be spent with [`crate::ServiceWeb::refuse_settings_writes`]. A removal stores nothing and is not
//! refused when the allowance is spent.
//!
//! A removal (an exchange that names no object) is a compared write like any other: it takes a place
//! in the object's order, leaves a tombstone so the next write carries on from it, and frees the
//! object's place in the collection; one that loses its comparison keeps nothing.
//!
//! What the Worker does that this does not: a receipt is never swept (a local run lasts far less than 30 days), so the collection keeps no
//! replay cutoff and no sweep mark; the index of memberships is read from the collections at the
//! moment it is asked, where the Worker delivers each change to it afterwards; and a collection is
//! never put back from an export, so every recovery identity is null.
//!
//! The source is the web repository's `workers/api/src/sync/{index,collection,memberships}.ts` and
//! `packages/service-contracts/src/sync.ts`.

use std::collections::{BTreeMap, BTreeSet};

use kr_client::services::ServiceHttpAnswer;
use kr_crypto::envelope::{check_genesis, check_successor, verify_collection_key_record};
use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::scalars::AuthorisationKey;
use kr_protocol::service::installation_id;
use kr_protocol::sync::{
    MAX_SYNC_CONFLICT_COPIES, MAX_SYNC_OBJECTS_PER_COLLECTION, SealedSyncObject, SyncObjectKind,
};
use serde_json::{Map, Value, json};

use crate::sync::{Arrival, Unread, counter, instant, invalid_argument, invalid_request, is_uuid};
use crate::web::{answered, refusal, refusal_with};

/// The members of a settings-sync request, as the contract names the fields each carries.
const EXCHANGE_FIELDS: [&str; 8] = [
    "request_id",
    "collection_id",
    "home",
    "key_epoch",
    "kind",
    "object_id",
    "expected_revision",
    "object",
];
const COMPARE_FIELDS: [&str; 6] = [
    "collection_id",
    "home",
    "kind",
    "known",
    "with_conflicts",
    "conflicts_after_sequence",
];
const RESOLVE_FIELDS: [&str; 3] = ["collection_id", "home", "conflict_ids"];
const STATUS_FIELDS: [&str; 3] = ["collection_id", "home", "request_id"];
const FENCE_FIELDS: [&str; 5] = [
    "collection_id",
    "home",
    "request_id",
    "first_signed_at_ms",
    "last_signed_at_ms",
];
const KEYS_FIELDS: [&str; 3] = ["collection_id", "home", "after_revision"];
const REKEY_FIELDS: [&str; 4] = ["request_id", "collection_id", "home", "record"];
const MEMBERSHIPS_FIELDS: [&str; 1] = ["after"];

/// The most objects, copies or memberships one answer carries.
const PAGE: usize = 64;
/// The most key records one answer carries.
const KEY_RECORDS_PAGE: usize = 16;
/// The most objects a reader may name as held in one comparison.
const MAX_KNOWN: usize = 8 * PAGE;
/// How long a signed request is fresh for, either side of the service's clock.
const FRESHNESS_MS: u64 = 300_000;
/// How long a receipt is kept, and so how far ahead of the clock a fence may name an attempt.
const RECEIPT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The last place in an object's order of writes.
const MAX_WRITE_SEQUENCE: u64 = (1 << 53) - 1;
/// The settings-sync allowance a comparison states for the one principal the service knows: the
/// free tier a local deployment's catalogue gives, which the recording was made against.
const ALLOWANCE_BYTES: &str = "33554432";

/// Who sent a request: the installation its key derives and the key itself.
struct Caller<'a> {
    installation: String,
    key: &'a AuthorisationKey,
}

/// Where a caller stands with one collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// Listed by the newest record, or the home of a collection no record has claimed.
    Member,
    /// Listed by an earlier record and not by the newest: may ask what became of a request.
    Former,
    /// Anybody else, answered as for a collection that does not exist.
    Stranger,
}

/// What a receipt records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Written,
    Removed,
    Conflict,
    Retired,
    Rekeyed,
    RekeyRefused,
    Fenced,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Removed => "removed",
            Self::Conflict => "conflict",
            Self::Retired => "retired",
            Self::Rekeyed => "rekeyed",
            Self::RekeyRefused => "rekey_refused",
            Self::Fenced => "fenced",
        }
    }

    /// The state a status query and a fence answer a recorded outcome with.
    const fn state(self) -> &'static str {
        match self {
            Self::Written | Self::Removed | Self::Rekeyed => "applied",
            Self::Conflict | Self::RekeyRefused => "refused",
            Self::Retired => "retired",
            Self::Fenced => "fenced",
        }
    }
}

/// The newest key record a collection holds: its place in the chain and the epoch it is at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Head {
    revision: u64,
    /// Nothing before a record has claimed the collection.
    epoch: Option<u64>,
}

impl Head {
    /// The members an answer names the head with, beside its own.
    fn members(head: Option<Self>) -> Map<String, Value> {
        let mut members = Map::new();
        if let Some(head) = head {
            if let Some(epoch) = head.epoch {
                members.insert("key_epoch".to_owned(), json!(epoch.to_string()));
            }
            members.insert("key_revision".to_owned(), json!(head.revision.to_string()));
        }
        members
    }
}

/// One object a collection holds.
#[derive(Clone, Debug)]
struct Object {
    kind: SyncObjectKind,
    revision: String,
    write_sequence: u64,
    key_epoch: Option<u64>,
    /// The sealed object as it arrived.
    object: Value,
    stored_bytes: u64,
    updated_at_ms: u64,
}

impl Object {
    fn summary(&self, object_id: &str) -> Value {
        let mut summary = json!({
            "kind": self.kind,
            "object_id": object_id,
            "revision": self.revision,
            "write_sequence": self.write_sequence.to_string(),
            "updated_at": instant(self.updated_at_ms),
            "bytes": self.stored_bytes.to_string(),
        });
        if let Some(epoch) = self.key_epoch {
            summary["key_epoch"] = json!(epoch.to_string());
        }
        summary
    }
}

/// A write the comparison refused, kept for the person to choose between.
#[derive(Clone, Debug)]
struct Copy {
    sequence: u64,
    conflict_id: String,
    object_id: String,
    kind: SyncObjectKind,
    expected_revision: Option<String>,
    current_revision: String,
    current_write_sequence: u64,
    key_epoch: Option<u64>,
    object: Value,
    stored_bytes: u64,
    recorded_at_ms: u64,
}

impl Copy {
    fn summary(&self) -> Value {
        let mut summary = json!({
            "sequence": self.sequence.to_string(),
            "conflict_id": self.conflict_id,
            "object_id": self.object_id,
            "expected_revision": self.expected_revision,
            "current_revision": self.current_revision,
            "current_write_sequence": self.current_write_sequence.to_string(),
            "recorded_at": instant(self.recorded_at_ms),
        });
        if let Some(epoch) = self.key_epoch {
            summary["key_epoch"] = json!(epoch.to_string());
        }
        summary
    }

    fn body(&self) -> Value {
        let mut body = self.summary();
        body["kind"] = json!(self.kind);
        body["object"] = self.object.clone();
        body
    }
}

/// One key record, kept for the life of the collection.
#[derive(Clone, Debug)]
struct Record {
    record: CollectionKeyRecord,
    /// The record as it arrived.
    document: Value,
    bytes: u64,
    /// The installations it lists.
    members: BTreeSet<String>,
}

/// What a collection recorded about one request identity.
#[derive(Clone, Debug)]
struct Receipt {
    /// What the request asked, less its identity; none for a fence.
    digest: Option<Value>,
    outcome: Outcome,
    record: Option<Value>,
    current_revision: Option<String>,
    current_write_sequence: Option<String>,
    conflict: Option<Value>,
    key: Option<Head>,
    /// The collection's figures when the exchange was answered.
    stored: Option<Value>,
    never_ran: bool,
    recorded_at_ms: u64,
}

/// One collection.
#[derive(Debug, Default)]
struct Collection {
    objects: BTreeMap<String, Object>,
    /// Where each removed object's order of writes stands, so that a write after a removal carries
    /// on from it. Dropped when the object is written again.
    tombstones: BTreeMap<String, u64>,
    /// The copies, in the order they were recorded.
    copies: Vec<Copy>,
    next_sequence: u64,
    records: Vec<Record>,
    /// By installation and request identity.
    receipts: BTreeMap<(String, String), Receipt>,
    /// Revisions and copy identifiers given so far, so each is new.
    issued: u64,
}

/// Every settings collection the service keeps, by home and collection.
#[derive(Debug, Default)]
pub(crate) struct Collections {
    collections: BTreeMap<(String, String), Collection>,
}

/* -------------------------------------------------------------------------- */
/* Reading what a caller asks                                                  */
/* -------------------------------------------------------------------------- */

/// A request as its fields, once it is an object carrying no field its member does not name.
fn only<'a>(
    value: &'a Value,
    allowed: &[&str],
    asked: &str,
    noun: &str,
) -> Result<&'a Map<String, Value>, Unread> {
    let Some(fields) = value.as_object() else {
        return Err(invalid_request(&format!("{asked} is an object.")));
    };
    let mut extra: Vec<&str> = fields
        .keys()
        .map(String::as_str)
        .filter(|field| !allowed.contains(field))
        .collect();
    extra.sort_unstable();
    if extra.is_empty() {
        Ok(fields)
    } else {
        Err(invalid_request(&format!(
            "{asked} carries {}, which {noun} does not.",
            extra.join(", ")
        )))
    }
}

fn uuid_of(fields: &Map<String, Value>, name: &str) -> Option<String> {
    fields
        .get(name)
        .filter(|value| is_uuid(value))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The home a request names, or nothing for the caller's own namespace.
fn home_of(fields: &Map<String, Value>, asked: &str) -> Result<Option<String>, Unread> {
    match fields.get("home") {
        None | Some(Value::Null) => Ok(None),
        Some(home) if is_uuid(home) => Ok(home.as_str().map(str::to_owned)),
        Some(_) => Err(invalid_request(&format!(
            "{asked} names the home installation as a canonical lowercase UUID."
        ))),
    }
}

fn request_id_of(fields: &Map<String, Value>, optional: bool) -> Result<Option<String>, Unread> {
    match fields.get("request_id") {
        None | Some(Value::Null) if optional => Ok(None),
        None | Some(Value::Null) => Err(invalid_argument("A request identity is required.")),
        Some(id) if is_uuid(id) => Ok(id.as_str().map(str::to_owned)),
        Some(_) => Err(invalid_argument(
            "A request identity is a canonical lowercase UUID.",
        )),
    }
}

/// A kind a collection holds: settings, a draft or a client's position.
fn kind_of(value: &Value) -> Result<SyncObjectKind, Unread> {
    serde_json::from_value::<SyncObjectKind>(value.clone())
        .ok()
        .filter(|kind| kind.holds_a_sealed_object())
        .ok_or_else(|| invalid_request("An object is one of settings, draft, client_selection."))
}

/// The address every request about a collection carries.
#[derive(Clone, Debug)]
struct Address {
    home: Option<String>,
    collection_id: String,
}

struct Exchange {
    address: Address,
    request_id: Option<String>,
    key_epoch: Option<u64>,
    kind: SyncObjectKind,
    object_id: String,
    expected: Option<String>,
    /// The sealed object and the bytes it is stored as, or none when the write removes the object.
    object: Option<(Value, u64)>,
}

impl Exchange {
    /// What the write asks, less its identity: an exact retry asks the same.
    fn digest(&self) -> Value {
        let mut digest = json!({
            "member": "exchange",
            "collection_id": self.address.collection_id,
            "kind": self.kind,
            "object_id": self.object_id,
            "expected_revision": self.expected,
            "object": self.object.as_ref().map(|object| object.0.clone()),
        });
        if let Some(epoch) = self.key_epoch {
            digest["key_epoch"] = json!(epoch.to_string());
        }
        digest
    }
}

fn read_exchange(value: &Value) -> Result<Exchange, Unread> {
    let fields = only(value, &EXCHANGE_FIELDS, "An exchange", "an exchange")?;
    let (Some(collection_id), Some(object_id)) = (
        uuid_of(fields, "collection_id"),
        uuid_of(fields, "object_id"),
    ) else {
        return Err(invalid_request(
            "An exchange names the collection and the object.",
        ));
    };
    let kind = kind_of(fields.get("kind").unwrap_or(&Value::Null))?;
    let expected = match fields.get("expected_revision") {
        None | Some(Value::Null) => None,
        Some(revision) if is_uuid(revision) => revision.as_str().map(str::to_owned),
        Some(_) => {
            return Err(invalid_request(
                "An expected revision is one this service issued, or null for a new object.",
            ));
        }
    };
    let home = home_of(fields, "A settings-sync request")?;
    let key_epoch = match fields.get("key_epoch") {
        None | Some(Value::Null) => None,
        Some(epoch) => Some(counter(epoch).ok_or_else(|| {
            invalid_argument(
                "A key epoch is a whole number no larger than 9007199254740991, written as a \
                 decimal string.",
            )
        })?),
    };
    let request_id = request_id_of(fields, true)?;
    let object = match fields.get("object") {
        None | Some(Value::Null) => None,
        Some(declared) => {
            let sealed: SealedSyncObject =
                serde_json::from_value(declared.clone()).map_err(|_| {
                    invalid_request("An exchange carries one sealed object, or none to remove it.")
                })?;
            sealed.check_structure().map_err(|_| {
                invalid_request(
                    "A synchronised object is its declared bucket plus the seal, and nothing else.",
                )
            })?;
            Some((declared.clone(), sealed.stored_bytes()))
        }
    };
    Ok(Exchange {
        address: Address {
            home,
            collection_id,
        },
        request_id,
        key_epoch,
        kind,
        object_id,
        expected,
        object,
    })
}

struct Compare {
    address: Address,
    kind: Option<SyncObjectKind>,
    known: Vec<(String, String)>,
    with_conflicts: bool,
    conflicts_after: u64,
}

fn read_compare(value: &Value) -> Result<Compare, Unread> {
    let fields = only(value, &COMPARE_FIELDS, "A comparison", "a comparison")?;
    let Some(collection_id) = uuid_of(fields, "collection_id") else {
        return Err(invalid_request("A comparison names the collection."));
    };
    let kind = match fields.get("kind") {
        None => None,
        Some(kind) => Some(kind_of(kind)?),
    };
    let held = "What a reader holds is a list of object identifiers and revisions.";
    let mut known = Vec::new();
    match fields.get("known") {
        None | Some(Value::Null) => {}
        Some(Value::Array(entries)) if entries.len() <= MAX_KNOWN => {
            for entry in entries {
                let Some(entry) = entry.as_object().filter(|entry| entry.len() == 2) else {
                    return Err(invalid_request(held));
                };
                let (Some(object), Some(revision)) =
                    (uuid_of(entry, "object_id"), uuid_of(entry, "revision"))
                else {
                    return Err(invalid_request(held));
                };
                known.push((object, revision));
            }
        }
        Some(_) => return Err(invalid_request(held)),
    }
    let conflicts_after = match fields.get("conflicts_after_sequence") {
        None => 0,
        Some(cursor) => counter(cursor)
            .ok_or_else(|| invalid_request("A cursor is a position this collection has issued."))?,
    };
    let home = home_of(fields, "A settings-sync request")?;
    let with_conflicts = match fields.get("with_conflicts") {
        None => false,
        Some(Value::Bool(asked)) => *asked,
        Some(_) => {
            return Err(invalid_request(
                "A comparison asks for the copies with true, or leaves them out with false.",
            ));
        }
    };
    Ok(Compare {
        address: Address {
            home,
            collection_id,
        },
        kind,
        known,
        with_conflicts,
        conflicts_after,
    })
}

struct Resolve {
    address: Address,
    conflict_ids: Vec<String>,
}

fn read_resolve(value: &Value) -> Result<Resolve, Unread> {
    let fields = only(value, &RESOLVE_FIELDS, "A resolution", "a resolution")?;
    let Some(collection_id) = uuid_of(fields, "collection_id") else {
        return Err(invalid_request("A resolution names the collection."));
    };
    let copies = "A resolution names the copies to drop.";
    let mut conflict_ids = Vec::new();
    match fields.get("conflict_ids") {
        None | Some(Value::Null) => {}
        Some(Value::Array(entries)) if entries.len() <= PAGE => {
            for entry in entries {
                if !is_uuid(entry) {
                    return Err(invalid_request(copies));
                }
                conflict_ids.extend(entry.as_str().map(str::to_owned));
            }
        }
        Some(_) => return Err(invalid_request(copies)),
    }
    let home = home_of(fields, "A settings-sync request")?;
    Ok(Resolve {
        address: Address {
            home,
            collection_id,
        },
        conflict_ids,
    })
}

struct Status {
    address: Address,
    request_id: String,
}

fn read_identity(fields: &Map<String, Value>, asked: &str) -> Result<(Address, String), Unread> {
    let Some(collection_id) = uuid_of(fields, "collection_id") else {
        return Err(invalid_request(&format!(
            "{asked} names the collection as a UUID."
        )));
    };
    let home = home_of(fields, asked)?;
    let Some(request_id) = uuid_of(fields, "request_id") else {
        return Err(invalid_argument("A request identity is a UUID."));
    };
    Ok((
        Address {
            home,
            collection_id,
        },
        request_id,
    ))
}

fn read_status(value: &Value) -> Result<Status, Unread> {
    let fields = only(value, &STATUS_FIELDS, "A status query", "a status query")?;
    let (address, request_id) = read_identity(fields, "A status query")?;
    Ok(Status {
        address,
        request_id,
    })
}

struct Fence {
    address: Address,
    request_id: String,
    first_signed_at_ms: u64,
    last_signed_at_ms: u64,
}

fn read_fence(value: &Value) -> Result<Fence, Unread> {
    let fields = only(value, &FENCE_FIELDS, "A fence", "a fence")?;
    let (address, request_id) = read_identity(fields, "A fence")?;
    let signed = |name: &str, which: &str| {
        fields.get(name).and_then(counter).ok_or_else(|| {
            invalid_argument(&format!(
                "A fence names when it signed the {which} as a whole number of milliseconds."
            ))
        })
    };
    let first = signed("first_signed_at_ms", "earliest attempt")?;
    let last = signed("last_signed_at_ms", "latest attempt")?;
    if first > last {
        return Err(invalid_argument(
            "A fence names the earliest attempt no later than the latest.",
        ));
    }
    Ok(Fence {
        address,
        request_id,
        first_signed_at_ms: first,
        last_signed_at_ms: last,
    })
}

struct Keys {
    address: Address,
    after_revision: u64,
}

fn read_keys(value: &Value) -> Result<Keys, Unread> {
    let fields = only(
        value,
        &KEYS_FIELDS,
        "A read of key records",
        "a read of key records",
    )?;
    let Some(collection_id) = uuid_of(fields, "collection_id") else {
        return Err(invalid_request(
            "A read of key records names the collection as a UUID.",
        ));
    };
    let home = home_of(fields, "A read of key records")?;
    let after_revision = match fields.get("after_revision") {
        None => 0,
        Some(after) => counter(after).ok_or_else(|| {
            invalid_argument(
                "A read of key records starts after a revision written as a decimal string.",
            )
        })?,
    };
    Ok(Keys {
        address: Address {
            home,
            collection_id,
        },
        after_revision,
    })
}

struct Rekey {
    address: Address,
    request_id: String,
    record: CollectionKeyRecord,
    document: Value,
}

fn read_rekey(value: &Value, caller: &str) -> Result<Rekey, Unread> {
    let fields = only(
        value,
        &REKEY_FIELDS,
        "A key record offer",
        "a key record offer",
    )?;
    let request_id = request_id_of(fields, false)?.unwrap_or_default();
    let Some(collection_id) = uuid_of(fields, "collection_id") else {
        return Err(invalid_request(
            "A key record offer names the collection as a UUID.",
        ));
    };
    let home = home_of(fields, "A key record offer")?;
    let document = fields.get("record").cloned().unwrap_or(Value::Null);
    let record: CollectionKeyRecord = serde_json::from_value(document.clone())
        .map_err(|_| invalid_request("A key record offer carries one record."))?;
    let record_home = record.payload.home.to_string();
    if record.payload.collection_id.to_string() != collection_id
        || record_home != home.as_deref().unwrap_or(caller)
    {
        return Err(invalid_request(
            "A key record belongs to the collection and the home the offer names.",
        ));
    }
    Ok(Rekey {
        address: Address {
            home,
            collection_id,
        },
        request_id,
        record,
        document,
    })
}

struct Memberships {
    after: Option<(String, String)>,
}

fn read_memberships(value: &Value) -> Result<Memberships, Unread> {
    let fields = only(
        value,
        &MEMBERSHIPS_FIELDS,
        "A membership listing",
        "a membership listing",
    )?;
    let after = match fields.get("after") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => {
            let parts: Vec<&str> = cursor.split('/').collect();
            match parts.as_slice() {
                [home, collection] if is_uuid(&json!(home)) && is_uuid(&json!(collection)) => {
                    Some(((*home).to_owned(), (*collection).to_owned()))
                }
                _ => {
                    return Err(invalid_request(
                        "A membership listing continues after a cursor an earlier page returned.",
                    ));
                }
            }
        }
        Some(_) => {
            return Err(invalid_request(
                "A membership listing continues after a cursor an earlier page returned.",
            ));
        }
    };
    Ok(Memberships { after })
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// What the service answers a caller the collection does not admit, and a collection nobody made.
fn absent() -> ServiceHttpAnswer {
    refusal(
        404,
        "COLLECTION_ABSENT",
        "That collection does not exist, or this installation is not one of its members.",
    )
}

fn refused_argument(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_ARGUMENT", message)
}

fn quota_exhausted(message: &str) -> ServiceHttpAnswer {
    refusal(402, "QUOTA_EXHAUSTED", message)
}

/// The refusal of a write under a key epoch the collection has retired.
fn retired(head: Head) -> ServiceHttpAnswer {
    refusal_with(
        409,
        "KEY_EPOCH_RETIRED",
        "That exchange names a key epoch this collection has retired; seal it again under the \
         current one.",
        Value::Object(Head::members(Some(head)))
            .as_object()
            .map_or_else(
                || json!({}),
                |members| {
                    let mut members = members.clone();
                    members.insert("recovery_id".to_owned(), Value::Null);
                    Value::Object(members)
                },
            ),
    )
}

impl Collections {
    /// What the service answers one request that names no locator.
    ///
    /// `funded` is whether the principal's settings-sync allowance admits a write.
    pub(crate) fn handle(
        &mut self,
        arrival: &Arrival<'_>,
        member: &str,
        funded: bool,
    ) -> ServiceHttpAnswer {
        let key = &arrival.signature.public_key;
        let who = Caller {
            installation: installation_id(key).to_string(),
            key,
        };
        let value = &arrival.body[member];
        let now_ms = arrival.now_ms;
        let answer = match member {
            "exchange" => {
                read_exchange(value).map(|asked| self.exchange(&who, &asked, now_ms, funded))
            }
            "compare" => read_compare(value).map(|asked| self.compare(&who, &asked, funded)),
            "resolve" => read_resolve(value).map(|asked| self.resolve(&who, &asked)),
            "status" => read_status(value).map(|asked| self.status(&who, &asked)),
            "fence" => read_fence(value).map(|asked| self.fence(&who, &asked, now_ms)),
            "keys" => read_keys(value).map(|asked| self.keys(&who, &asked)),
            "rekey" => read_rekey(value, &who.installation)
                .and_then(|asked| self.rekey(&who, asked, now_ms, funded)),
            _ => read_memberships(value).map(|asked| self.memberships(&who, &asked)),
        };
        answer.unwrap_or_else(|Unread(answer)| answer)
    }

    /// The collection an address names, and the namespace it lives in.
    fn collection(&mut self, who: &Caller<'_>, address: &Address) -> (String, &mut Collection) {
        let home = address
            .home
            .clone()
            .unwrap_or_else(|| who.installation.clone());
        let collection = self
            .collections
            .entry((home.clone(), address.collection_id.clone()))
            .or_default();
        (home, collection)
    }

    fn exchange(
        &mut self,
        who: &Caller<'_>,
        asked: &Exchange,
        now_ms: u64,
        funded: bool,
    ) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        collection.exchange(who, &home, asked, now_ms, funded)
    }

    fn compare(&mut self, who: &Caller<'_>, asked: &Compare, funded: bool) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        if collection.standing(&who.installation, &home) != Standing::Member {
            return absent();
        }
        collection.compare(asked, funded)
    }

    fn resolve(&mut self, who: &Caller<'_>, asked: &Resolve) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        if collection.standing(&who.installation, &home) != Standing::Member {
            return absent();
        }
        let before = collection.copies.len();
        collection
            .copies
            .retain(|copy| !asked.conflict_ids.contains(&copy.conflict_id));
        let resolved = before - collection.copies.len();
        answered(json!({ "resolved": resolved.to_string(), "stored": collection.usage() }))
    }

    fn status(&mut self, who: &Caller<'_>, asked: &Status) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        if collection.standing(&who.installation, &home) == Standing::Stranger {
            return absent();
        }
        let key = (who.installation.clone(), asked.request_id.clone());
        answered(collection.receipts.get(&key).map_or_else(
            || {
                json!({
                    "request_id": asked.request_id,
                    "state": "unknown",
                    "never_ran": false,
                    "outcome": null,
                    "record": null,
                    "current_revision": null,
                    "current_write_sequence": null,
                    "conflict_id": null,
                    "recovery_id": null,
                    "recorded_at": null,
                })
            },
            |receipt| receipt.status(&asked.request_id),
        ))
    }

    fn fence(&mut self, who: &Caller<'_>, asked: &Fence, now_ms: u64) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        if collection.standing(&who.installation, &home) == Standing::Stranger {
            return absent();
        }
        // An attempt signed further ahead than the whole retention cannot act at this clock, and a
        // row kept until it could would be kept for ever by anybody who asks.
        if asked.last_signed_at_ms > now_ms + RECEIPT_RETENTION_MS {
            return refused_argument(
                "A fence names when it signed within the time this service keeps a refusal for.",
            );
        }
        let key = (who.installation.clone(), asked.request_id.clone());
        if let Some(receipt) = collection.receipts.get(&key) {
            return answered(receipt.status(&asked.request_id));
        }
        // Nothing here is ever swept, so nothing that could have been a receipt for an attempt
        // this fence names has been removed: whether it ran is whether a receipt is held for it.
        let never_ran = asked.first_signed_at_ms > FRESHNESS_MS;
        let receipt = Receipt {
            digest: None,
            outcome: Outcome::Fenced,
            record: None,
            current_revision: None,
            current_write_sequence: None,
            conflict: None,
            key: None,
            stored: None,
            never_ran,
            recorded_at_ms: now_ms,
        };
        let answer = receipt.status(&asked.request_id);
        collection.receipts.insert(key, receipt);
        answered(answer)
    }

    fn keys(&mut self, who: &Caller<'_>, asked: &Keys) -> ServiceHttpAnswer {
        let (home, collection) = self.collection(who, &asked.address);
        if collection.standing(&who.installation, &home) != Standing::Member {
            return absent();
        }
        let Some(head) = collection.head() else {
            return answered(json!({
                "records": [],
                "more": false,
                "key_revision": "0",
                "key_epoch": null,
                "recovery_id": null,
            }));
        };
        let after = usize::try_from(asked.after_revision).unwrap_or(usize::MAX);
        let later: Vec<&Record> = collection.records.iter().skip(after).collect();
        let more = later.len() > KEY_RECORDS_PAGE;
        let page: Vec<Value> = later
            .iter()
            .take(KEY_RECORDS_PAGE)
            .map(|record| record.document.clone())
            .collect();
        answered(json!({
            "records": page,
            "more": more,
            "key_revision": head.revision.to_string(),
            "key_epoch": head.epoch.map(|epoch| epoch.to_string()),
            "recovery_id": null,
        }))
    }

    fn rekey(
        &mut self,
        who: &Caller<'_>,
        asked: Rekey,
        now_ms: u64,
        funded: bool,
    ) -> Result<ServiceHttpAnswer, Unread> {
        // What depends on the request alone: the record's structure, that its issuer is the key
        // that carried the request, and that it is signed by that key.
        if let Err(error) = asked.record.check_structure() {
            return Err(invalid_request(&error.to_string()));
        }
        if verify_collection_key_record(&asked.record, who.key).is_err() {
            let issuer_is_the_caller = kr_protocol::pairing::key_id(
                kr_protocol::pairing::KeyPurpose::Authorisation,
                who.key.as_bytes(),
            ) == asked.record.payload.issuer_key_id;
            return Ok(if issuer_is_the_caller {
                refusal(
                    403,
                    "FORBIDDEN",
                    "That record was not signed by the key that carried it.",
                )
            } else {
                refusal(
                    403,
                    "FORBIDDEN",
                    "That record names an issuer other than the key that carried the request.",
                )
            });
        }
        let (home, collection) = self.collection(who, &asked.address);
        Ok(collection.rekey(who, &home, asked, now_ms, funded))
    }

    fn memberships(&self, who: &Caller<'_>, asked: &Memberships) -> ServiceHttpAnswer {
        let listed: Vec<Value> = self
            .collections
            .iter()
            .filter(|((home, _), collection)| {
                collection.head().is_some()
                    && collection.standing(&who.installation, home) == Standing::Member
            })
            .filter(|((home, id), _)| {
                asked.after.as_ref().is_none_or(|(after_home, after_id)| {
                    (home.as_str(), id.as_str()) > (after_home.as_str(), after_id.as_str())
                })
            })
            .filter_map(|((home, id), collection)| {
                let head = collection.head()?;
                Some(json!({
                    "home": home,
                    "collection_id": id,
                    "key_revision": head.revision.to_string(),
                    "key_epoch": head.epoch.unwrap_or_default().to_string(),
                    "recovery_id": null,
                }))
            })
            .collect();
        let more = listed.len() > PAGE;
        let page: Vec<Value> = listed.into_iter().take(PAGE).collect();
        let next_after = page.last().map(|last| {
            format!(
                "{}/{}",
                last["home"].as_str().unwrap_or_default(),
                last["collection_id"].as_str().unwrap_or_default()
            )
        });
        answered(json!({ "memberships": page, "more": more, "next_after": next_after }))
    }
}

impl Receipt {
    /// What a status query and a fence answer about this receipt.
    fn status(&self, request_id: &str) -> Value {
        let mut status = json!({
            "request_id": request_id,
            "state": self.outcome.state(),
            "never_ran": self.never_ran,
            "outcome": self.outcome.as_str(),
            "record": self.record,
            "current_revision": self.current_revision,
            "current_write_sequence": self.current_write_sequence,
            "conflict_id": self.conflict.as_ref().map(|copy| copy["conflict_id"].clone()),
            "recovery_id": null,
            "recorded_at": instant(self.recorded_at_ms),
        });
        if let (Some(status), head) = (status.as_object_mut(), Head::members(self.key)) {
            status.extend(head);
        }
        status
    }
}

/// The reply to one exchange, before it is made a receipt.
struct Reply {
    outcome: Outcome,
    record: Option<Value>,
    current_revision: Option<String>,
    current_write_sequence: u64,
    conflict: Option<Value>,
}

impl Collection {
    fn head(&self) -> Option<Head> {
        self.records.last().map(|record| Head {
            revision: record.record.payload.revision.get(),
            epoch: Some(record.record.payload.key_epoch.get()),
        })
    }

    /// Where a caller stands: a record that lists it lists it from then on, until a newer one does
    /// not.
    fn standing(&self, caller: &str, home: &str) -> Standing {
        if self.records.is_empty() {
            return if caller == home {
                Standing::Member
            } else {
                Standing::Stranger
            };
        }
        match self
            .records
            .iter()
            .rposition(|record| record.members.contains(caller))
        {
            None => Standing::Stranger,
            Some(at) if at + 1 == self.records.len() => Standing::Member,
            Some(_) => Standing::Former,
        }
    }

    /// Where an object stands in its own order of writes: the live object's, the removal's that
    /// took its place, or nought for one never held.
    fn write_sequence_of(&self, object_id: &str) -> u64 {
        self.objects.get(object_id).map_or_else(
            || self.tombstones.get(object_id).copied().unwrap_or(0),
            |object| object.write_sequence,
        )
    }

    /// What the collection holds, and what the allowance leaves.
    fn usage(&self) -> Value {
        let bytes: u64 = self
            .objects
            .values()
            .map(|object| object.stored_bytes)
            .chain(self.copies.iter().map(|copy| copy.stored_bytes))
            .chain(self.records.iter().map(|record| record.bytes))
            .sum();
        json!({
            "objects": self.objects.len().to_string(),
            "conflicts": self.copies.len().to_string(),
            "bytes": bytes.to_string(),
            "object_limit": MAX_SYNC_OBJECTS_PER_COLLECTION.to_string(),
            "allowance_bytes": null,
        })
    }

    fn mint(&mut self, class: u64) -> String {
        self.issued += 1;
        format!("00000000-0000-4000-{class:04x}-{:012x}", self.issued)
    }

    /// The reply a retry is owed, from the receipt, with the figures of now for a member.
    fn replay(&self, receipt: &Receipt, standing: Standing) -> ServiceHttpAnswer {
        if receipt.outcome == Outcome::Retired {
            return receipt.key.map_or_else(
                || {
                    refusal(
                        500,
                        "INTERNAL",
                        "The collection could not finish that request.",
                    )
                },
                retired,
            );
        }
        if matches!(receipt.outcome, Outcome::Rekeyed | Outcome::RekeyRefused) {
            return answered(rekey_answer(receipt));
        }
        let stored = if standing == Standing::Member {
            self.usage()
        } else {
            receipt.stored.clone().unwrap_or_else(|| self.usage())
        };
        answered(exchange_answer(
            receipt.outcome,
            receipt.record.clone(),
            receipt.current_revision.clone(),
            receipt.current_write_sequence.clone().unwrap_or_default(),
            receipt.conflict.clone(),
            receipt.key,
            stored,
        ))
    }

    /// What a receipt for this request identity decides before anything else is read, or nothing.
    fn recorded(
        &self,
        who: &Caller<'_>,
        request_id: Option<&str>,
        digest: &Value,
        standing: Standing,
    ) -> Option<ServiceHttpAnswer> {
        let receipt = self
            .receipts
            .get(&(who.installation.clone(), request_id?.to_owned()))?;
        if receipt.outcome == Outcome::Fenced {
            return Some(refusal(
                409,
                "REQUEST_FENCED",
                "That settings-sync request identity has been fenced and will not be run.",
            ));
        }
        if receipt.digest.as_ref() != Some(digest) {
            return Some(refusal(
                409,
                "ID_CONFLICT",
                "That request identity was used for a different settings-sync request.",
            ));
        }
        Some(self.replay(receipt, standing))
    }

    fn exchange(
        &mut self,
        who: &Caller<'_>,
        home: &str,
        asked: &Exchange,
        now_ms: u64,
        funded: bool,
    ) -> ServiceHttpAnswer {
        let standing = self.standing(&who.installation, home);
        if standing == Standing::Stranger {
            return absent();
        }
        let digest = asked.digest();
        if let Some(answer) = self.recorded(who, asked.request_id.as_deref(), &digest, standing) {
            return answer;
        }
        if standing != Standing::Member {
            return absent();
        }
        // Whether the epoch it declares is the collection's.
        let head = self.head();
        match (head, asked.key_epoch) {
            (None, None) => {}
            (None, Some(_)) => {
                return refused_argument(
                    "A collection no key record has claimed has no key epoch, so an exchange into \
                     it declares none.",
                );
            }
            (Some(_), None) => {
                return refused_argument(
                    "An exchange into a collection a key record has claimed declares the key epoch \
                     its object is sealed under.",
                );
            }
            (Some(head), Some(epoch)) => {
                let current = head.epoch.unwrap_or_default();
                if epoch > current {
                    return refused_argument(
                        "That key epoch is ahead of the epoch this collection is at.",
                    );
                }
                if epoch < current {
                    // Nothing stored, nothing held, and the refusal is the request's receipt.
                    if let Some(id) = &asked.request_id {
                        self.receipts.insert(
                            (who.installation.clone(), id.clone()),
                            Receipt {
                                digest: Some(digest),
                                outcome: Outcome::Retired,
                                record: None,
                                current_revision: None,
                                current_write_sequence: None,
                                conflict: None,
                                key: Some(head),
                                stored: None,
                                never_ran: false,
                                recorded_at_ms: now_ms,
                            },
                        );
                    }
                    return retired(head);
                }
            }
        }
        // A removal stores nothing, so the Worker takes no hold against the allowance for it and
        // one that is spent does not refuse it.
        if !funded && asked.object.is_some() {
            return quota_exhausted(
                "This principal's settings-sync allowance has no room for that write.",
            );
        }
        self.write(who, asked, digest, now_ms)
    }

    /// The comparison and the write: one step, as the Worker runs them in one transaction.
    fn write(
        &mut self,
        who: &Caller<'_>,
        asked: &Exchange,
        digest: Value,
        now_ms: u64,
    ) -> ServiceHttpAnswer {
        let existing = self.objects.get(&asked.object_id).cloned();
        let current = existing.as_ref().map(|object| object.revision.clone());
        let position = self.write_sequence_of(&asked.object_id);

        if asked.expected != current {
            return self.conflict(who, asked, digest, existing.as_ref(), position, now_ms);
        }
        if position >= MAX_WRITE_SEQUENCE {
            return quota_exhausted("This object has been written as many times as one may be.");
        }
        let Some((object, stored_bytes)) = &asked.object else {
            return self.removal(who, asked, digest, existing.is_some(), position, now_ms);
        };
        if existing.is_none() && self.objects.len() as u64 >= MAX_SYNC_OBJECTS_PER_COLLECTION {
            return quota_exhausted(&format!(
                "A collection holds {MAX_SYNC_OBJECTS_PER_COLLECTION} objects."
            ));
        }
        let revision = self.mint(0x8000);
        let written = Object {
            kind: asked.kind,
            revision: revision.clone(),
            write_sequence: position + 1,
            key_epoch: asked.key_epoch,
            object: object.clone(),
            stored_bytes: *stored_bytes,
            updated_at_ms: now_ms,
        };
        let record = written.summary(&asked.object_id);
        self.tombstones.remove(&asked.object_id);
        self.objects.insert(asked.object_id.clone(), written);
        self.answered(
            who,
            asked,
            digest,
            Reply {
                outcome: Outcome::Written,
                record: Some(record),
                current_revision: Some(revision),
                current_write_sequence: position + 1,
                conflict: None,
            },
            now_ms,
        )
    }

    /// A removal whose comparison held: the object goes, its place in the order is kept, and a
    /// removal of an object that is not there removes nothing and moves nothing.
    fn removal(
        &mut self,
        who: &Caller<'_>,
        asked: &Exchange,
        digest: Value,
        held: bool,
        position: u64,
        now_ms: u64,
    ) -> ServiceHttpAnswer {
        let removed_at = if held { position + 1 } else { position };
        if held {
            self.objects.remove(&asked.object_id);
            self.tombstones.insert(asked.object_id.clone(), removed_at);
        }
        self.answered(
            who,
            asked,
            digest,
            Reply {
                outcome: Outcome::Removed,
                record: None,
                current_revision: None,
                current_write_sequence: removed_at,
                conflict: None,
            },
            now_ms,
        )
    }

    /// Keeps what a refused write carried, so the person can choose.
    fn conflict(
        &mut self,
        who: &Caller<'_>,
        asked: &Exchange,
        digest: Value,
        existing: Option<&Object>,
        position: u64,
        now_ms: u64,
    ) -> ServiceHttpAnswer {
        let record = existing.map(|object| object.summary(&asked.object_id));
        let current_revision = existing.map(|object| object.revision.clone());
        let Some((object, stored_bytes)) = &asked.object else {
            // A removal carries no content, so a refused one keeps nothing.
            return self.answered(
                who,
                asked,
                digest,
                Reply {
                    outcome: Outcome::Conflict,
                    record,
                    current_revision,
                    current_write_sequence: position,
                    conflict: None,
                },
                now_ms,
            );
        };
        let held = self
            .copies
            .iter()
            .filter(|copy| copy.object_id == asked.object_id)
            .count() as u64;
        if held >= MAX_SYNC_CONFLICT_COPIES {
            // Every copy is one somebody still has to choose about; dropping the oldest would
            // choose by the clock.
            return quota_exhausted(&format!(
                "This object holds {MAX_SYNC_CONFLICT_COPIES} copies nobody has chosen between yet."
            ));
        }
        self.next_sequence = self.next_sequence.max(1);
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let copy = Copy {
            sequence,
            conflict_id: self.mint(0x8001),
            object_id: asked.object_id.clone(),
            kind: asked.kind,
            expected_revision: asked.expected.clone(),
            current_revision: current_revision.clone().unwrap_or_default(),
            current_write_sequence: position,
            key_epoch: asked.key_epoch,
            object: object.clone(),
            stored_bytes: *stored_bytes,
            recorded_at_ms: now_ms,
        };
        let kept = copy.summary();
        self.copies.push(copy);
        self.answered(
            who,
            asked,
            digest,
            Reply {
                outcome: Outcome::Conflict,
                record,
                current_revision,
                current_write_sequence: position,
                conflict: Some(kept),
            },
            now_ms,
        )
    }

    /// The answer to one exchange, and the receipt that records it: one value becomes both.
    fn answered(
        &mut self,
        who: &Caller<'_>,
        asked: &Exchange,
        digest: Value,
        reply: Reply,
        now_ms: u64,
    ) -> ServiceHttpAnswer {
        let stored = self.usage();
        let head = self.head();
        let current_write_sequence = reply.current_write_sequence.to_string();
        if let Some(id) = &asked.request_id {
            self.receipts.insert(
                (who.installation.clone(), id.clone()),
                Receipt {
                    digest: Some(digest),
                    outcome: reply.outcome,
                    record: reply.record.clone(),
                    current_revision: reply.current_revision.clone(),
                    current_write_sequence: Some(current_write_sequence.clone()),
                    conflict: reply.conflict.clone(),
                    key: head,
                    stored: Some(stored.clone()),
                    never_ran: false,
                    recorded_at_ms: now_ms,
                },
            );
        }
        answered(exchange_answer(
            reply.outcome,
            reply.record,
            reply.current_revision,
            current_write_sequence,
            reply.conflict,
            head,
            stored,
        ))
    }

    fn compare(&self, asked: &Compare, funded: bool) -> ServiceHttpAnswer {
        let known: BTreeMap<&str, &str> = asked
            .known
            .iter()
            .map(|(object, revision)| (object.as_str(), revision.as_str()))
            .collect();
        let rows: Vec<(&String, &Object)> = self
            .objects
            .iter()
            .filter(|(_, object)| asked.kind.is_none_or(|kind| kind == object.kind))
            .collect();
        let changed: Vec<Value> = rows
            .iter()
            .filter(|(id, object)| known.get(id.as_str()) != Some(&object.revision.as_str()))
            .take(PAGE)
            .map(|(id, object)| {
                let mut body = object.summary(id);
                if let Some(body) = body.as_object_mut() {
                    body.remove("bytes");
                }
                body["object"] = object.object.clone();
                body
            })
            .collect();
        // Removed means the collection does not hold it, not that this page does not carry it.
        let mut seen = BTreeSet::new();
        let removed: Vec<Value> = asked
            .known
            .iter()
            .map(|(object, _)| object)
            .filter(|object| seen.insert((*object).clone()))
            .filter(|object| {
                !rows.iter().any(|(id, _)| id == object) && !self.objects.contains_key(*object)
            })
            .map(|object| {
                json!({
                    "object_id": object,
                    "write_sequence": self.write_sequence_of(object).to_string(),
                })
            })
            .collect();
        let later: Vec<&Copy> = if asked.with_conflicts {
            self.copies
                .iter()
                .filter(|copy| copy.sequence > asked.conflicts_after)
                .collect()
        } else {
            Vec::new()
        };
        let more_conflicts = later.len() > PAGE;
        let page: Vec<&&Copy> = later.iter().take(PAGE).collect();
        let next = page
            .last()
            .map_or(asked.conflicts_after, |copy| copy.sequence);
        let mut stored = self.usage();
        stored["allowance_bytes"] = json!(if funded { ALLOWANCE_BYTES } else { "0" });
        let mut answer = json!({
            "changed": changed,
            "removed": removed,
            "revisions": rows.iter().map(|(id, object)| {
                let mut position = json!({
                    "object_id": id,
                    "revision": object.revision,
                    "write_sequence": object.write_sequence.to_string(),
                });
                if let Some(epoch) = object.key_epoch {
                    position["key_epoch"] = json!(epoch.to_string());
                }
                position
            }).collect::<Vec<_>>(),
            "conflicts": page.iter().map(|copy| copy.body()).collect::<Vec<_>>(),
            "next_conflicts_after_sequence": next.to_string(),
            "more_conflicts": more_conflicts,
            "recovery_id": null,
            // The one answer that reads the ledger, so the one that states the allowance.
            "stored": stored,
        });
        if let Some(answer) = answer.as_object_mut() {
            answer.extend(Head::members(self.head()));
        }
        answered(answer)
    }

    fn rekey(
        &mut self,
        who: &Caller<'_>,
        home: &str,
        asked: Rekey,
        now_ms: u64,
        funded: bool,
    ) -> ServiceHttpAnswer {
        let standing = self.standing(&who.installation, home);
        if standing == Standing::Stranger {
            return absent();
        }
        let digest = json!({
            "member": "rekey",
            "collection_id": asked.address.collection_id,
            "record": asked.document,
        });
        if let Some(answer) = self.recorded(who, Some(&asked.request_id), &digest, standing) {
            return answer;
        }
        if standing != Standing::Member {
            return absent();
        }
        let key = (who.installation.clone(), asked.request_id.clone());
        let head = self.head();
        if self.refuses(&asked.record) {
            let held = head.unwrap_or(Head {
                revision: 0,
                epoch: None,
            });
            let receipt = Receipt {
                digest: Some(digest),
                outcome: Outcome::RekeyRefused,
                record: None,
                current_revision: None,
                current_write_sequence: None,
                conflict: None,
                key: Some(held),
                stored: None,
                never_ran: false,
                recorded_at_ms: now_ms,
            };
            let answer = rekey_answer(&receipt);
            self.receipts.insert(key, receipt);
            return answered(answer);
        }
        if !funded {
            return quota_exhausted(
                "This principal's settings-sync allowance has no room for that record.",
            );
        }
        let bytes = kr_cbor::to_canonical_vec(&asked.record).map_or(0, |bytes| bytes.len() as u64);
        let members = asked
            .record
            .payload
            .members
            .iter()
            .map(|member| member.installation_id().to_string())
            .collect();
        let kept = Head {
            revision: asked.record.payload.revision.get(),
            epoch: Some(asked.record.payload.key_epoch.get()),
        };
        self.records.push(Record {
            record: asked.record,
            document: asked.document,
            bytes,
            members,
        });
        let receipt = Receipt {
            digest: Some(digest),
            outcome: Outcome::Rekeyed,
            record: None,
            current_revision: None,
            current_write_sequence: None,
            conflict: None,
            key: Some(kept),
            stored: None,
            never_ran: false,
            recorded_at_ms: now_ms,
        };
        let answer = rekey_answer(&receipt);
        self.receipts.insert(key, receipt);
        answered(answer)
    }

    /// Whether this record may not follow what the collection holds.
    ///
    /// The first record is a claim, taken only while the collection holds no object and no copy,
    /// so nothing in a claimed collection was ever written without an epoch. Every later one
    /// follows the newest by the successor rules.
    fn refuses(&self, record: &CollectionKeyRecord) -> bool {
        match self.records.last() {
            None => {
                !self.objects.is_empty()
                    || !self.copies.is_empty()
                    || check_genesis(record).is_err()
            }
            Some(newest) => check_successor(&newest.record, record).is_err(),
        }
    }
}

/// An exchange's answer: the reply, the head it names and the figures that hold.
fn exchange_answer(
    outcome: Outcome,
    record: Option<Value>,
    current_revision: Option<String>,
    current_write_sequence: String,
    conflict: Option<Value>,
    head: Option<Head>,
    stored: Value,
) -> Value {
    let mut answer = json!({
        "state": outcome.as_str(),
        "record": record,
        "current_revision": current_revision,
        "current_write_sequence": current_write_sequence,
        "conflict": conflict,
        "recovery_id": null,
        "stored": stored,
    });
    if let Some(members) = answer.as_object_mut() {
        members.extend(Head::members(head));
    }
    answer
}

/// What a `rekey` did, from its receipt.
fn rekey_answer(receipt: &Receipt) -> Value {
    let key = receipt.key.unwrap_or(Head {
        revision: 0,
        epoch: None,
    });
    json!({
        "state": if receipt.outcome == Outcome::Rekeyed { "applied" } else { "refused" },
        "key_revision": key.revision.to_string(),
        "key_epoch": key.epoch.map(|epoch| epoch.to_string()),
        "recovery_id": null,
    })
}
