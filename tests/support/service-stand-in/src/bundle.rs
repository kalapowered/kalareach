//! An account's recovery bundle at the sync route, answering as the Worker's sync collection does.
//!
//! The bundle is one sealed object at a locator the recovery kit prints. The route is the one
//! settings sync uses, and a request that names a `locator` is about the bundle: it carries an
//! account token beside the signature, and a token that proves no account, or proves one without
//! the scope the request needs, is answered as for a collection that does not exist. A write
//! compares the revision it replaces against the one held; a write the comparison refuses keeps no
//! copy. Every write names its request identity, and the collection keeps a receipt for it, so a
//! write asked about or fenced after its answer was lost is settled by what the receipt holds.
//!
//! The service knows one account, so what it does with a second one is not modelled: the Worker
//! makes the account whose write first applies the collection's owner and answers every other
//! account as for a collection that does not exist. It is not modelled either what a sweep past the
//! receipts' retention does to a request signed before it, or a collection put back from an
//! archive.
//!
//! The source is the web repository's `workers/api/src/sync/{index,collection}.ts` and
//! `packages/service-contracts/src/sync.ts`. Settings-sync collections, drafts and key records use
//! the same route and are not modelled: a request for one panics, so a test that reaches one says
//! so rather than being answered as if it were the bundle.

use std::collections::BTreeMap;

use kr_client::services::ServiceHttpAnswer;
use kr_protocol::service::ServiceRequestSigner;
use serde_json::{Value, json};

use crate::web::{BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, Token, answered, refusal};

/// The bytes the service counts for the record around a sealed object, which the contract states.
const RECORD_BYTES: u64 = 256;
/// The fewest bytes a sealed bundle is.
const MIN_SEALED_BYTES: usize = 24 + 17;
/// The most bytes a sealed bundle is.
const MAX_SEALED_BYTES: usize = 128 * 1024;
/// The members a settings-sync request is exactly one of.
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

/// The bundle as the collection holds it.
#[derive(Clone, Debug)]
struct Kept {
    revision: String,
    write_sequence: u64,
    updated_at: String,
    /// The sealed stream as it arrived, in the form it travels in.
    ciphertext: Value,
    /// What the record around it and the stream count for.
    bytes: u64,
}

impl Kept {
    /// The record the service names the bundle by.
    fn record(&self, locator: &str) -> Value {
        json!({
            "kind": "recovery_bundle",
            "object_id": locator,
            "revision": self.revision,
            "write_sequence": self.write_sequence.to_string(),
            "updated_at": self.updated_at,
            "bytes": self.bytes.to_string(),
        })
    }
}

/// What one receipt recorded about one request identity.
#[derive(Clone, Debug)]
struct Receipt {
    /// What the write asked, less its identity: an exact retry asks the same.
    digest: Value,
    /// `written`, `conflict` or `fenced`.
    outcome: &'static str,
    /// What an exact retry of the write is answered again.
    answer: Option<Value>,
    /// The record the bundle had when the receipt was written.
    record: Option<Value>,
    current_revision: Option<String>,
    current_write_sequence: Option<String>,
    never_ran: bool,
    recorded_at: String,
}

/// The collection one locator names.
#[derive(Debug, Default)]
struct Collection {
    kept: Option<Kept>,
    receipts: BTreeMap<String, Receipt>,
    /// Revisions given so far, so each is new.
    revisions: u64,
}

/// Every recovery bundle the service keeps, by locator.
#[derive(Debug, Default)]
pub(crate) struct Bundles {
    collections: BTreeMap<String, Collection>,
}

/// Why a request about the bundle is not one the contract reads.
struct Unread(ServiceHttpAnswer);

impl Bundles {
    /// The write sequence and the sealed stream the bundle at `locator` stands at.
    pub(crate) fn held(&self, locator: &str) -> Option<(u64, Vec<u8>)> {
        let kept = self.collections.get(locator)?.kept.as_ref()?;
        let text = kept.ciphertext.as_str()?;
        Some((kept.write_sequence, decode(text)?))
    }

    /// What the service answers one request that carries a locator.
    ///
    /// `signer` is the kind of key that signed the request and `now_ms` the service's own clock.
    pub(crate) fn handle(
        &mut self,
        tokens: &BTreeMap<String, Token>,
        body: &Value,
        token: Option<&str>,
        signer: ServiceRequestSigner,
        now_ms: u64,
    ) -> ServiceHttpAnswer {
        if signer != ServiceRequestSigner::Installation {
            return refusal(
                401,
                "UNAUTHENTICATED",
                "This method is not proven by that kind of key.",
            );
        }
        let named: Vec<&str> = MEMBERS
            .into_iter()
            .filter(|member| body.get(*member).is_some())
            .collect();
        let [member] = named.as_slice() else {
            return refusal(
                400,
                "INVALID_REQUEST",
                "A settings-sync request exchanges, compares, resolves, queries status, fences a request identity, reads or offers key records, or lists memberships, and asks for one of those.",
            );
        };
        let Some(fields) = body[*member].as_object() else {
            return refusal(
                400,
                "INVALID_REQUEST",
                "A settings-sync request carries the fields of what it asks for.",
            );
        };
        assert!(
            fields.contains_key("locator"),
            "the stand-in models the recovery bundle at the sync route, and a settings-sync \
             collection ({member}) is not modelled"
        );
        let asked = match read(member, &body[*member]) {
            Ok(asked) => asked,
            Err(Unread(answer)) => return answer,
        };

        // The second proof: a live token that carries a scope this member is answered for. A
        // missing one, an unknown one, an expired one and one without the scope are one answer.
        let needs: &[&str] = if *member == "compare" {
            &[BACKUP_WRITE_SCOPE, BACKUP_RESTORE_SCOPE]
        } else {
            &[BACKUP_WRITE_SCOPE]
        };
        if !token
            .and_then(|token| tokens.get(token))
            .is_some_and(|held| held.live && needs.iter().any(|scope| held.scopes.contains(*scope)))
        {
            return absent();
        }
        let locator = asked.locator().to_owned();
        let held = self.collections.entry(locator.clone()).or_default();
        match asked {
            Asked::Exchange {
                request_id,
                expected,
                object,
                ..
            } => held.exchange(&locator, now_ms, &request_id, expected, object),
            Asked::Compare { .. } => held.compare(&locator),
            Asked::Status { request_id, .. } => held.status(&request_id),
            Asked::Fence { request_id, .. } => held.fence(&request_id, now_ms),
        }
    }
}

/// A request about the bundle, once the contract has read it.
enum Asked {
    Exchange {
        request_id: String,
        locator: String,
        expected: Option<String>,
        object: Value,
    },
    Compare {
        locator: String,
    },
    Status {
        request_id: String,
        locator: String,
    },
    Fence {
        request_id: String,
        locator: String,
    },
}

impl Asked {
    fn locator(&self) -> &str {
        match self {
            Self::Exchange { locator, .. }
            | Self::Compare { locator }
            | Self::Status { locator, .. }
            | Self::Fence { locator, .. } => locator,
        }
    }
}

/// What the service answers a caller the collection does not admit, and a collection nobody made.
fn absent() -> ServiceHttpAnswer {
    refusal(
        404,
        "COLLECTION_ABSENT",
        "That collection does not exist, or this installation is not one of its members.",
    )
}

fn invalid_request(message: &str) -> Unread {
    Unread(refusal(400, "INVALID_REQUEST", message))
}

fn invalid_argument(message: &str) -> Unread {
    Unread(refusal(400, "INVALID_ARGUMENT", message))
}

/// A canonical lowercase hyphenated UUID, as the contract reads one.
fn is_uuid(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 36
            && text.char_indices().all(|(at, character)| match at {
                8 | 13 | 18 | 23 => character == '-',
                _ => character.is_ascii_digit() || ('a'..='f').contains(&character),
            })
    })
}

/// A counter the contract reads exactly: decimal text of at most 16 digits, with no leading zero.
fn counter(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 16 || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Reads one request against the closed shape its member has.
fn read(member: &str, value: &Value) -> Result<Asked, Unread> {
    let (allowed, asked): (&[&str], &str) = match member {
        "exchange" => (
            &[
                "request_id",
                "locator",
                "kind",
                "expected_revision",
                "object",
            ],
            "A write of the recovery bundle",
        ),
        "compare" => (&["locator", "kind"], "A read of the recovery bundle"),
        "status" => (
            &["locator", "request_id"],
            "A status query about the recovery bundle",
        ),
        "fence" => (
            &[
                "locator",
                "request_id",
                "first_signed_at_ms",
                "last_signed_at_ms",
            ],
            "A fence at the recovery bundle",
        ),
        other => {
            return Err(invalid_request(&format!(
                "A recovery bundle is written, read, asked about and fenced, and nothing else \
                 names a locator, not {other}."
            )));
        }
    };
    let fields = value
        .as_object()
        .ok_or_else(|| invalid_request(&format!("{asked} is an object.")))?;
    let mut extra: Vec<&str> = fields
        .keys()
        .map(String::as_str)
        .filter(|field| !allowed.contains(field))
        .collect();
    extra.sort_unstable();
    if !extra.is_empty() {
        return Err(invalid_request(&format!(
            "{asked} carries {}, which a request naming a locator does not.",
            extra.join(", ")
        )));
    }
    if !is_uuid(&value["locator"]) {
        return Err(invalid_request(&format!(
            "{asked} names the bundle's locator as a canonical lowercase UUID."
        )));
    }
    let locator = value["locator"].as_str().unwrap_or_default().to_owned();
    let request_id = || -> Result<String, Unread> {
        match &value["request_id"] {
            Value::Null => Err(invalid_argument("A request identity is required.")),
            id if is_uuid(id) => Ok(id.as_str().unwrap_or_default().to_owned()),
            _ => Err(invalid_argument(
                "A request identity is a canonical lowercase UUID.",
            )),
        }
    };
    let kind = || -> Result<(), Unread> {
        if value["kind"] == "recovery_bundle" {
            Ok(())
        } else {
            Err(invalid_request(&format!(
                "{asked} is of the kind recovery_bundle, the one kind a locator holds."
            )))
        }
    };
    match member {
        "exchange" => {
            let request_id = request_id()?;
            kind()?;
            let expected = match &value["expected_revision"] {
                Value::Null => None,
                revision if is_uuid(revision) => revision.as_str().map(str::to_owned),
                _ => {
                    return Err(invalid_request(&format!(
                        "{asked} names the revision it replaces, one this service issued, or null \
                         for a locator that holds none."
                    )));
                }
            };
            let object = value["object"].clone();
            let length = object["ciphertext"]
                .as_str()
                .and_then(decode)
                .map(|bytes| bytes.len())
                .ok_or_else(|| {
                    invalid_request(
                        "A recovery bundle is never removed, so a write of it carries the bundle.",
                    )
                })?;
            if !(MIN_SEALED_BYTES..=MAX_SEALED_BYTES).contains(&length) {
                return Err(invalid_request(&format!(
                    "A recovery bundle is {MIN_SEALED_BYTES} to {MAX_SEALED_BYTES} bytes of sealed stream."
                )));
            }
            Ok(Asked::Exchange {
                request_id,
                locator,
                expected,
                object,
            })
        }
        "compare" => {
            kind()?;
            Ok(Asked::Compare { locator })
        }
        "status" => Ok(Asked::Status {
            request_id: request_id()?,
            locator,
        }),
        _ => {
            let request_id = request_id()?;
            let first = counter(&value["first_signed_at_ms"]);
            let last = counter(&value["last_signed_at_ms"]);
            let (Some(first), Some(last)) = (first, last) else {
                return Err(invalid_argument(
                    "A signing time is a counter this service compares exactly.",
                ));
            };
            if first > last {
                return Err(invalid_argument(
                    "A fence names the earliest attempt no later than the latest.",
                ));
            }
            Ok(Asked::Fence {
                request_id,
                locator,
            })
        }
    }
}

/// The bytes a sealed stream is, from the form it travels in.
fn decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .ok()
        })
}

/// A moment as the service writes one: ISO 8601 in UTC, to the millisecond.
fn instant(ms: u64) -> String {
    let days = i64::try_from(ms / 86_400_000).unwrap_or(i64::MAX);
    let in_day = ms % 86_400_000;
    // Civil date from a day count: Howard Hinnant's algorithm, for the proleptic Gregorian calendar.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        in_day / 3_600_000,
        in_day / 60_000 % 60,
        in_day / 1_000 % 60,
        in_day % 1_000
    )
}

/// The accounting every answer about the bundle ends with.
fn stored(kept: Option<&Kept>) -> Value {
    json!({
        "allowance_bytes": null,
        "bytes": kept.map_or(0, |kept| kept.bytes).to_string(),
        "conflicts": "0",
        "object_limit": "1",
        "objects": u8::from(kept.is_some()).to_string(),
    })
}

impl Collection {
    /// One write, in the service's order: a receipt for the identity, and then the comparison.
    fn exchange(
        &mut self,
        locator: &str,
        now_ms: u64,
        request_id: &str,
        expected: Option<String>,
        object: Value,
    ) -> ServiceHttpAnswer {
        let digest = json!({
            "locator": locator,
            "kind": "recovery_bundle",
            "expected_revision": expected,
            "object": object,
        });
        if let Some(receipt) = self.receipts.get(request_id) {
            if receipt.outcome == "fenced" {
                return refusal(
                    409,
                    "REQUEST_FENCED",
                    "That settings-sync request identity has been fenced and will not be run.",
                );
            }
            if receipt.digest != digest {
                return refusal(
                    409,
                    "ID_CONFLICT",
                    "That request identity was used for a different settings-sync request.",
                );
            }
            return answered(receipt.answer.clone().unwrap_or(Value::Null));
        }
        let recorded_at = instant(now_ms);
        let current = self.kept.clone();
        if current.as_ref().map(|kept| kept.revision.clone()) != expected {
            let answer = json!({
                "state": "conflict",
                "record": current.as_ref().map(|kept| kept.record(locator)),
                "current_revision": current.as_ref().map(|kept| kept.revision.clone()),
                "current_write_sequence": current
                    .as_ref()
                    .map_or(0, |kept| kept.write_sequence)
                    .to_string(),
                "conflict": null,
                "recovery_id": null,
                "stored": stored(current.as_ref()),
            });
            self.receipts.insert(
                request_id.to_owned(),
                Receipt {
                    digest,
                    outcome: "conflict",
                    answer: Some(answer.clone()),
                    record: current.as_ref().map(|kept| kept.record(locator)),
                    current_revision: current.as_ref().map(|kept| kept.revision.clone()),
                    current_write_sequence: current
                        .as_ref()
                        .map(|kept| kept.write_sequence.to_string()),
                    never_ran: false,
                    recorded_at,
                },
            );
            return answered(answer);
        }
        self.revisions += 1;
        let ciphertext = object["ciphertext"].clone();
        let sealed = ciphertext
            .as_str()
            .and_then(decode)
            .map_or(0, |bytes| bytes.len() as u64);
        let kept = Kept {
            revision: format!("00000000-0000-4000-8000-{:012x}", self.revisions),
            write_sequence: current.map_or(1, |kept| kept.write_sequence + 1),
            updated_at: instant(now_ms),
            ciphertext,
            bytes: sealed + RECORD_BYTES,
        };
        let answer = json!({
            "state": "written",
            "record": kept.record(locator),
            "current_revision": kept.revision,
            "current_write_sequence": kept.write_sequence.to_string(),
            "conflict": null,
            "recovery_id": null,
            "stored": stored(Some(&kept)),
        });
        self.receipts.insert(
            request_id.to_owned(),
            Receipt {
                digest,
                outcome: "written",
                answer: Some(answer.clone()),
                record: Some(kept.record(locator)),
                current_revision: Some(kept.revision.clone()),
                current_write_sequence: Some(kept.write_sequence.to_string()),
                never_ran: false,
                recorded_at,
            },
        );
        self.kept = Some(kept);
        answered(answer)
    }

    /// A read: the bundle and where it stands, or nothing.
    fn compare(&self, locator: &str) -> ServiceHttpAnswer {
        let (changed, revisions) = self.kept.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |kept| {
                (
                    vec![json!({
                        "kind": "recovery_bundle",
                        "object_id": locator,
                        "revision": kept.revision,
                        "write_sequence": kept.write_sequence.to_string(),
                        "object": { "ciphertext": kept.ciphertext },
                        "updated_at": kept.updated_at,
                    })],
                    vec![json!({
                        "object_id": locator,
                        "revision": kept.revision,
                        "write_sequence": kept.write_sequence.to_string(),
                    })],
                )
            },
        );
        answered(json!({
            "changed": changed,
            "removed": [],
            "revisions": revisions,
            "conflicts": [],
            "next_conflicts_after_sequence": "0",
            "more_conflicts": false,
            "recovery_id": null,
            "stored": stored(self.kept.as_ref()),
        }))
    }

    /// What a status query and a fence are answered about one receipt.
    fn receipt(request_id: &str, receipt: &Receipt) -> Value {
        let state = match receipt.outcome {
            "written" => "applied",
            "conflict" => "refused",
            _ => "fenced",
        };
        json!({
            "request_id": request_id,
            "state": state,
            "never_ran": receipt.never_ran,
            "outcome": receipt.outcome,
            "record": receipt.record,
            "current_revision": receipt.current_revision,
            "current_write_sequence": receipt.current_write_sequence,
            "conflict_id": null,
            "recovery_id": null,
            "recorded_at": receipt.recorded_at,
        })
    }

    fn status(&self, request_id: &str) -> ServiceHttpAnswer {
        answered(self.receipts.get(request_id).map_or_else(
            || {
                json!({
                    "request_id": request_id,
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
            |receipt| Self::receipt(request_id, receipt),
        ))
    }

    /// Ends a request identity: what the collection recorded stands, and an identity it recorded
    /// nothing for is refused from now on.
    fn fence(&mut self, request_id: &str, now_ms: u64) -> ServiceHttpAnswer {
        let receipt = self
            .receipts
            .entry(request_id.to_owned())
            .or_insert_with(|| Receipt {
                digest: Value::Null,
                outcome: "fenced",
                answer: None,
                record: None,
                current_revision: None,
                current_write_sequence: None,
                // A local deployment sweeps no receipt, so a fence that finds none can say that
                // nothing ever ran under the identity.
                never_ran: true,
                recorded_at: instant(now_ms),
            });
        answered(Self::receipt(request_id, receipt))
    }
}
