//! The recovery bundle's read and write, answering as the Worker's settings-sync route does.
//!
//! One route, `sync.compare_exchange`, carries eight members. This answers two: a read of the
//! recovery bundle at its locator (`compare`), which a device restoring from a kit makes, and the
//! owner's write of it (`exchange`). The bundle belongs to an account, so each carries two proofs.
//! The signature is an installation's (a host's key is refused by the route), and the account token
//! beside it carries `backup.write` for a write and `backup.write` or `backup.restore` for a read.
//! A request without a usable token, a token another account holds, and a locator no write has
//! reached by an account that cannot own it are answered alike, as a collection that does not
//! exist.
//!
//! A write compares the revision it names against the one the bundle holds, and names none for a
//! bundle nobody has written. It applies when they agree and is otherwise answered `conflict`,
//! carrying where the bundle stands. A write whose request identity the service has answered is
//! answered what it was answered the first time, and one that reuses the identity for other content
//! is `ID_CONFLICT`. A write spends the account's backup storage, so an account the test has left
//! with no allowance is answered `QUOTA_EXHAUSTED`.
//!
//! The other members of the route are not modelled: they answer `INVALID_REQUEST` and say so. A
//! test may also put a bundle in place with [`crate::ServiceWeb::put_bundle`], which is what a
//! write by the owner leaves behind.
//!
//! The source is the web repository's `workers/api/src/sync/{index,collection}.ts` and
//! `packages/service-contracts/src/sync.ts`.

use std::collections::BTreeMap;

use kr_client::services::ServiceHttpAnswer;
use kr_protocol::scalars::Bytes;
use kr_protocol::sync::SealedRecoveryBundle;
use serde_json::{Value, json};

use crate::web::{BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, Token, answered, refusal};

/// Where the route is addressed.
pub(crate) const PATH: &str = "/api/sync/exchange";

/// The kind of the one object a recovery bundle's collection holds.
const RECOVERY_BUNDLE_KIND: &str = "recovery_bundle";

/// The members of a settings-sync request, of which one is named.
const MEMBERS: [&str; 8] = [
    "exchange",
    "compare",
    "resolve",
    "status",
    "fence",
    "keys",
    "rekey",
    "memberships",
];

/// The bundle a service holds at one locator, and who it belongs to.
#[derive(Clone, Debug, Default)]
pub(crate) struct Bundle {
    /// What the service answered each request identity of a write, with the content it was asked
    /// for, so that a repeat is answered from it.
    pub(crate) receipts: BTreeMap<String, (String, Value)>,
    /// The account whose first write applied there, or nobody before one has.
    pub(crate) owner: Option<String>,
    /// The history the collection is in: the identity it was put back under, or none.
    pub(crate) recovery: Option<String>,
    /// The stream and where it stands, once a write has applied.
    pub(crate) held: Option<Held>,
    /// How many writes the collection has taken.
    pub(crate) writes: u64,
}

/// One written bundle.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    /// The name the service gave the write.
    pub(crate) revision: String,
    /// The write's place in the order.
    pub(crate) write_sequence: u64,
    /// The sealed stream.
    pub(crate) ciphertext: Vec<u8>,
}

impl Bundle {
    /// A write by `account` of `ciphertext` has applied.
    pub(crate) fn write(&mut self, account: &str, ciphertext: Vec<u8>) {
        self.writes += 1;
        self.owner.get_or_insert_with(|| account.to_owned());
        self.held = Some(Held {
            revision: format!("{:08x}-0000-4000-8000-{:012x}", self.writes, self.writes),
            write_sequence: self.writes,
            ciphertext,
        });
    }
}

/// What the route answers one request that reached it, from the second proof's account.
///
/// `tokens` is what the service knows of each token, `token` the bearer beside the request, and
/// `funded` whether the account's backup storage admits a write.
pub(crate) fn exchange(
    bundles: &mut BTreeMap<String, Bundle>,
    tokens: &BTreeMap<String, Token>,
    body: &Value,
    token: Option<&str>,
    funded: bool,
) -> ServiceHttpAnswer {
    let Some(members) = body.as_object() else {
        return refuse("A settings-sync request is an object.");
    };
    let named: Vec<&str> = MEMBERS
        .into_iter()
        .filter(|member| members.contains_key(*member))
        .collect();
    let [member] = named.as_slice() else {
        return refuse(
            "A settings-sync request exchanges, compares, resolves, queries status, fences a request identity, reads or offers key records, or lists memberships, and asks for one of those.",
        );
    };
    let Some(fields) = members[*member].as_object() else {
        return refuse("A settings-sync request carries the fields of what it asks for.");
    };
    if !["compare", "exchange"].contains(member) || !fields.contains_key("locator") {
        return refuse(
            "This service answers a read and a write of the recovery bundle at its locator and no other settings-sync request.",
        );
    }
    let writing = *member == "exchange";
    // The request against its closed shape: a locator and the one kind a locator holds, and for a
    // write the identity, the revision it replaces and the object.
    let allowed: &[&str] = if writing {
        &[
            "request_id",
            "locator",
            "kind",
            "expected_revision",
            "object",
        ]
    } else {
        &["locator", "kind"]
    };
    if let Some(extra) = fields
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return refuse(&format!(
            "A read of the recovery bundle carries {extra}, which a request naming a locator does not."
        ));
    }
    let Some(locator) = fields["locator"].as_str().filter(|text| is_uuid(text)) else {
        return refuse(
            "A read of the recovery bundle names the bundle's locator as a canonical lowercase UUID.",
        );
    };
    if fields.get("kind").and_then(Value::as_str) != Some(RECOVERY_BUNDLE_KIND) {
        return refuse(
            "A read of the recovery bundle is of the kind recovery_bundle, the one kind a locator holds.",
        );
    }

    // The second proof: an account token carrying a scope a read is answered for. Missing, unknown,
    // expired and under-scoped are one answer, before the collection is reached.
    let scopes: &[&str] = if writing {
        &[BACKUP_WRITE_SCOPE]
    } else {
        &[BACKUP_WRITE_SCOPE, BACKUP_RESTORE_SCOPE]
    };
    let Some(account) = token.and_then(|token| {
        tokens
            .get(token)
            .filter(|held| held.live)
            .filter(|held| scopes.iter().any(|scope| held.scopes.contains(*scope)))
            .map(|held| held.account.as_str())
    }) else {
        return absent();
    };
    if writing {
        return write(bundles, locator, fields, account, funded);
    }
    let bundle = bundles.get(locator);
    // The owner, or before a write has applied anybody the route admitted, and nobody else.
    if bundle
        .and_then(|bundle| bundle.owner.as_deref())
        .is_some_and(|owner| owner != account)
    {
        return absent();
    }
    let recovery = bundle.and_then(|bundle| bundle.recovery.clone());
    let held = bundle.and_then(|bundle| bundle.held.as_ref());
    let changed: Vec<Value> = held
        .map(|held| {
            json!({
                "kind": RECOVERY_BUNDLE_KIND,
                "object_id": locator,
                "revision": held.revision,
                "write_sequence": held.write_sequence.to_string(),
                "object": serde_json::to_value(SealedRecoveryBundle {
                    ciphertext: Bytes::new(held.ciphertext.clone()),
                })
                .expect("a sealed bundle"),
                "updated_at": "2026-09-25T17:00:00.000Z",
            })
        })
        .into_iter()
        .collect();
    let revisions: Vec<Value> = held
        .map(|held| {
            json!({
                "object_id": locator,
                "revision": held.revision,
                "write_sequence": held.write_sequence.to_string(),
            })
        })
        .into_iter()
        .collect();
    answered(json!({
        "changed": changed,
        "removed": [],
        "revisions": revisions,
        "conflicts": [],
        "next_conflicts_after_sequence": "0",
        "more_conflicts": false,
        "recovery_id": recovery,
        "stored": {
            "objects": u64::from(held.is_some()).to_string(),
            "conflicts": "0",
            "bytes": held
                .map_or(0, |held| {
                    SealedRecoveryBundle {
                        ciphertext: Bytes::new(held.ciphertext.clone()),
                    }
                    .stored_bytes()
                })
                .to_string(),
            "object_limit": "1",
            "allowance_bytes": null,
        },
    }))
}

/// What the route answers a write of the bundle by `account`.
fn write(
    bundles: &mut BTreeMap<String, Bundle>,
    locator: &str,
    fields: &serde_json::Map<String, Value>,
    account: &str,
    funded: bool,
) -> ServiceHttpAnswer {
    let Some(request_id) = fields
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|text| is_uuid(text))
    else {
        return refuse("A write of the recovery bundle names its request by a canonical UUID.");
    };
    if fields.get("kind").and_then(Value::as_str) != Some(RECOVERY_BUNDLE_KIND) {
        return refuse(
            "A write of the recovery bundle is of the kind recovery_bundle, the one kind a locator holds.",
        );
    }
    let expected = match fields.get("expected_revision") {
        Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.as_str()),
        _ => {
            return refuse(
                "A write of the recovery bundle names the revision it replaces, or null for none.",
            );
        }
    };
    let Some(ciphertext) = fields
        .get("object")
        .and_then(|object| object.get("ciphertext"))
        .and_then(Value::as_str)
        .and_then(|text| kr_protocol::scalars::from_base64url(text).ok())
    else {
        return refuse("A write of the recovery bundle carries the sealed bundle.");
    };
    // The owner, or before a write has applied anybody the route admitted, and nobody else.
    if bundles
        .get(locator)
        .and_then(|bundle| bundle.owner.as_deref())
        .is_some_and(|owner| owner != account)
    {
        return absent();
    }
    // What the request asks, as the receipt compares it: everything but the identity.
    let content = format!(
        "{expected:?}/{}",
        kr_protocol::scalars::to_base64url(&ciphertext)
    );
    if let Some((held, answer)) = bundles
        .get(locator)
        .and_then(|bundle| bundle.receipts.get(request_id))
    {
        return if *held == content {
            answered(answer.clone())
        } else {
            refusal(
                409,
                "ID_CONFLICT",
                "That request identity was used for other content.",
            )
        };
    }
    if !funded {
        return refusal(
            402,
            "QUOTA_EXHAUSTED",
            "This account has no backup storage to write the recovery bundle to.",
        );
    }
    let bundle = bundles.entry(locator.to_owned()).or_default();
    let held_revision = bundle.held.as_ref().map(|held| held.revision.clone());
    let answer = if held_revision.as_deref() == expected {
        bundle.write(account, ciphertext);
        let held = bundle.held.as_ref().expect("the write left a bundle");
        json!({
            "state": "written",
            "record": summary(locator, held),
            "current_revision": held.revision,
            "current_write_sequence": held.write_sequence.to_string(),
            "conflict": null,
            "recovery_id": bundle.recovery,
            "stored": usage(Some(held)),
        })
    } else {
        // The comparison failed: the answer is the object as it stands, which is the record.
        json!({
            "state": "conflict",
            "record": bundle.held.as_ref().map(|held| summary(locator, held)),
            "current_revision": held_revision,
            "current_write_sequence": bundle
                .held
                .as_ref()
                .map_or(0, |held| held.write_sequence)
                .to_string(),
            "conflict": null,
            "recovery_id": bundle.recovery,
            "stored": usage(bundle.held.as_ref()),
        })
    };
    bundle
        .receipts
        .insert(request_id.to_owned(), (content, answer.clone()));
    answered(answer)
}

/// The summary of the object a collection holds, without its content.
fn summary(locator: &str, held: &Held) -> Value {
    json!({
        "kind": RECOVERY_BUNDLE_KIND,
        "object_id": locator,
        "revision": held.revision,
        "write_sequence": held.write_sequence.to_string(),
        "bytes": SealedRecoveryBundle {
            ciphertext: Bytes::new(held.ciphertext.clone()),
        }
        .stored_bytes()
        .to_string(),
        "updated_at": "2026-09-25T17:00:00.000Z",
    })
}

/// What a collection reports it holds.
fn usage(held: Option<&Held>) -> Value {
    json!({
        "objects": u64::from(held.is_some()).to_string(),
        "conflicts": "0",
        "bytes": held
            .map_or(0, |held| {
                SealedRecoveryBundle {
                    ciphertext: Bytes::new(held.ciphertext.clone()),
                }
                .stored_bytes()
            })
            .to_string(),
        "object_limit": "1",
        "allowance_bytes": null,
    })
}

/// What a caller is told about a collection that does not exist or is not its to read.
fn absent() -> ServiceHttpAnswer {
    refusal(
        404,
        "COLLECTION_ABSENT",
        "That collection does not exist, or this installation is not one of its members.",
    )
}

/// A request this route does not read.
fn refuse(message: &str) -> ServiceHttpAnswer {
    refusal(400, "INVALID_REQUEST", message)
}

/// Whether `text` is a canonical lowercase UUID.
fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(at, character)| match at {
            8 | 13 | 18 | 23 => character == '-',
            _ => character.is_ascii_digit() || ('a'..='f').contains(&character),
        })
}
