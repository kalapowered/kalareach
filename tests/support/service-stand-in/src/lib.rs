//! A stand-in for the managed storage, backup manifest, authority feed, mailbox delivery and relay
//! lease services.
//!
//! The service is the web repository's Worker, and what it answers is stated by that repository's
//! service contract. This crate answers as the contract states, with the state the service keeps,
//! so a test of a client or of a daemon can run against it on a machine with no Worker, no
//! network and no account. [`ServiceWeb`] is the service. It is handed requests in process, as an
//! HTTP transport would carry them, or it answers a socket on loopback ([`serve`]), which is how a
//! daemon's own transport reaches it.
//!
//! Where the stand-in and the Worker could differ, the Worker is right. The recorded answers a
//! local Worker gave (`fixtures/service/storage-answers.json` and
//! `fixtures/service/authority-answers.json`) are what a test holds the stand-in to, and what the
//! clients are held to read: `crates/kr-client/tests/service_answers.rs` and
//! `crates/kr-client/tests/authority_answers.rs`.
//!
//! # What each behaviour is held to
//!
//! A behaviour a test relies on is either recorded, which means the same script of requests was
//! run against a Worker and the stand-in and the status, the shape of the body and what the
//! clients decoded it to agree, or it is read from the contract and the Worker's source, because a
//! local Worker cannot be made to do it. The files are in the web repository: the contract in
//! `packages/service-contracts/src/{storage,backup,authority}.ts`, the Worker in
//! `workers/api/src`.
//!
//! | Behaviour | Held to | Worker | Test |
//! | --- | --- | --- | --- |
//! | A status with no account proof is `402 QUOTA_EXHAUSTED` | recorded | `storage/index.ts:271` | `the_stand_in_answers_as_the_worker_did` |
//! | A retention change against a revision it has left is `CONFLICT` carrying the retention as it stands | recorded | `storage/index.ts` | same |
//! | A second creation of an upload that is open is `403 FORBIDDEN` | recorded | `storage/upload.ts` | same; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | A part sent again, a completion sent again | recorded, answered as a duplicate | `storage/upload.ts` | same |
//! | A completion or a part for an upload nobody created is `NOT_FOUND`, which the client reads as the upload being gone | recorded | `storage/upload.ts` | same |
//! | A part sent to an upload that was abandoned is `403 FORBIDDEN`; an abandonment is answered again with what it released, which is the most the creation declared and not the size of the object (the script declares 3000 for an object of 1000 bytes and abandons the upload before it sends a part) | recorded | `storage/upload.ts:856` | same |
//! | A read past the end of an object is `INVALID_REQUEST`; a deletion answered again says it was already done; one of an object never held is `NOT_FOUND` | recorded | `storage/index.ts` | same |
//! | A publication before any writer is enrolled is `403 FORBIDDEN`; one of other content under a generation held is `403`; one below the checkpoint is `403` | recorded | `backup/collection.ts` | same |
//! | A publication sent again is a duplicate and needs no account proof | recorded | `backup/index.ts:116` | same |
//! | A collection reports the bytes its held descriptors take, its checkpoint and the generations it holds, newest first | recorded | `backup/collection.ts:875` | same |
//! | The history keeps 16 generations; the 17th publication drops the oldest and says so | recorded | `backup/collection.ts` | same |
//! | A fetch with a checkpoint newer than the collection, with a manifest the collection does not hold at that generation, or for a generation older than the checkpoint (one the checkpoint's own manifest names correctly) is `NOT_FOUND`, which the client reads as nothing to answer with; a checkpoint about another archive is `INVALID_REQUEST`, and the request is read before any collection is looked up, in the Worker's order: the archive, the generation, the checkpoint | recorded, apart from the order for an archive no collection holds, which no client sends and the Worker's source states | `backup/collection.ts:372-445`, `backup/index.ts:264-296` | same |
//! | A new generation published with no account proof is `402 QUOTA_EXHAUSTED` | contract and source only: a local deployment's free tier includes backup storage, so the Worker accepts it there | `backup/index.ts:224`, the production catalogue | the daemon's `an_account_the_service_turns_away_is_waited_for_as_a_person` reaches it through the status route instead |
//! | `RATE_LIMITED` and `SERVICE_UNAVAILABLE` carry `retryAfterSeconds`, and the `Retry-After` header | source only: a local Worker cannot be made to rate limit or to be unavailable | `object-call.ts:64-73`, `auth/routes.ts:369` | `Moment::Refuse`; the daemon's reaction table; the client's own reading of it in `services/signed.rs` |
//! | A collection deleted from the account console is `410 COLLECTION_DELETED` | source only | `storage/index.ts:211`, `backup/collection.ts:531` | `ServiceWeb::delete_collection`; `a_deleted_collection_stops_the_attempt` |
//! | A transport fault: the request never arrives, its answer is lost, the connection is held open with no answer, the body arrives cut short | none: the Worker does not choose these | not applicable | `Moment::{Before, After, Hold, Slow, BodyCut}` |
//! | A feed is addressed by the identifier of its host's authorisation key; the host reads it, and an owner who names it reads what the owner published | recorded | `authority-feed/index.ts:237-239` | `the_stand_in_answers_as_the_worker_did` in `authority_answers.rs` |
//! | A request the host proves reaches the host's own feed whatever its body names, and the host may publish to it and remove it | source only: the script keeps one host and has it read and revise | `authority-feed/index.ts:237-239, 515-527` | `feed.rs` in this crate |
//! | A publication is stored under the next sequence and sent again it is the same; another request under its identity is `403 FORBIDDEN`; one signed by a key other than the one that carried it, or altered after it was signed, is `403` | recorded | `authority-feed/index.ts:477-507`, `authority-feed/feed.ts:157-248` | same |
//! | A host sees every record; any other reader sees what it published | recorded | `authority-feed/feed.ts:683-739` | same |
//! | A revision follows the revision the feed holds, is above the one it names, and sent again is the same; another record under its number is `403`; a gap is `403`; one not above the revision it follows is `400` | recorded | `authority-feed/feed.ts:260-343` | same |
//! | An acknowledgement names a revision the host issued and the request that revision applied; a pending one is progress, a complete one settles the record and cannot be taken back, an older one than the one held is refused, one for a request nobody published is `404`, and one for a request the host refused is `400` | recorded | `authority-feed/feed.ts:355-452` | same |
//! | A refusal settles a record, sent again it is the same, and for a record nobody published it is `404` | recorded | `authority-feed/feed.ts:461-480` | same |
//! | The host names the keys that may remove it; a key it did not name that asks to remove it is `403`; a key it named removes it, which deletes every record, and the feed then answers its host `ok` with `removed` and answers a publication `404` | recorded | `authority-feed/feed.ts:489-527, 159-167, 741-766` | same |
//! | A cursor is a counter the feed issued (text of at most 16 digits that a number in the service's language holds exactly), and `null` is not one; a revision's number and the number it follows must be numbers that language holds exactly; each otherwise is `400` | source only: this crate's client sends a cursor only as a counter, so no recorded request carries `null` or a number beyond that | `authority-feed/index.ts:415-419`, `mailbox/request.ts:260-266`, `authority-feed/feed.ts:266-271` | `feed.rs` in this crate |
//! | A publication, a revision or an acknowledgement may carry an announcement, which the service validates and places in a mailbox and reports beside the change | not modelled: this crate's host client sends none, and the publisher that does is the companion's, with its own recording | `authority-feed/index.ts:272, 314, 351, 538-640` | none |
//! | A feed whose storage failed answers `503 SERVICE_UNAVAILABLE` with `retryAfterSeconds` 2, and a change the feed did not answer is `504 OUTCOME_UNKNOWN` | source only: a local Worker cannot be made to fail | `authority-feed/feed.ts:558-571`, `authority-feed/index.ts:89-93, 153-155` | `Moment::Refuse` |
//! | One publisher holds at most 32 records the host has not finished with, a feed at most 1,000, and 256 of those are for the keys the host named; past each the answer is `402 QUOTA_EXHAUSTED` | source only: it would make the recording grow with every request | `authority-feed/feed.ts:185-233` | `feed.rs` in this crate |
//! | A record the host finished with is dropped a week later | source only | `authority-feed/feed.ts:612-618` | `feed.rs` in this crate |
//! | A delivery names the mailbox it is for by the recipient's stored-envelope key; an envelope routed to another recipient, one the contract's closed schema does not read, and one the protocol's structure check refuses are `400 INVALID_REQUEST` | source only: the Worker's mailbox needs a Durable Object binding a local deployment does not run in this crate's tests | `mailbox/index.ts:94-132`, `mailbox/mailbox.ts:271-273, 1177-1217` | none: the daemon's tests deliver well-formed items to the right mailbox, and no test sends one of these |
//! | An envelope identifier delivered again with the same item is answered with the state `duplicate` and the position the first delivery was given; with a different item it is `403 FORBIDDEN` | source only | `mailbox/mailbox.ts:240-269` | the duplicate: the daemon's `a_delivery_whose_answer_was_lost_is_placed_again_and_stored_once`; the conflict: none |
//! | The newest delivery of a thread replaces the older unread item from the same writer and reports the position it replaced | source only | `mailbox/mailbox.ts:276-302` | none: no notification of this host names a thread |
//! | A mailbox holds 1,000 items or 32 MiB and one writer 128 items or 4 MiB, measured after a replacement; past each the answer is `402 QUOTA_EXHAUSTED` | source only | `mailbox/mailbox.ts:899-930` | the writer's share: the daemon's `a_mailbox_that_is_full_does_not_hold_the_push_back` fills it with 128 real deliveries; the mailbox's own totals: none |
//! | An identifier a mailbox has carried is remembered until the item's expiry and a day more | not modelled: remembered for good, which no test of this crate waits out | `mailbox/mailbox.ts:335-342` | none |
//! | An item is removed when it expires, and a delivery is refused unless an installation or a host signed it | not modelled: an item stays, and any signature that verifies is accepted | `mailbox/mailbox.ts:587-588`, `mailbox/index.ts:100-106` | none |
//! | Claiming, reading and acknowledging a mailbox | not modelled: the device's half, which nothing of this host uses yet | `mailbox/index.ts:168-279` | none |
//! | A lease request or a revocation is proven by the credential every managed-service method uses, over the origin, the method, a fresh nonce, the time and the digest of the canonical body, and a nonce is spent once; the stand-in rebuilds the digest from the values that arrived | source only: the two relay methods are not in the protocol's method registry yet, so the stand-in reads the credential field by field, as the Worker does | `relay/credential.ts:101-163, 197-220` | `a_paired_device_is_given_a_lease_for_its_pair` signs it through the real client |
//! | A host key draws on no allowance of its own: a host that names no account is `403 FORBIDDEN`, and one that names an account needs an authorisation that account gave its key, still in force, for that account | source only | `relay/lease.ts:2036-2092`, `relay/authorisation.ts` | `a_host_that_names_no_account_is_turned_away_and_the_owner_is_told` |
//! | A request for a pair that holds a lease revises that lease; naming a lease the service is not carrying is `400 INVALID_REQUEST`; a lease billed to another principal, issued to another caller or under another authorisation is `403 FORBIDDEN` | source only | `relay/lease.ts:466-540` | `a_lease_the_service_no_longer_carries_is_asked_for_again_as_a_new_one` |
//! | A refill states the new cumulative ceiling. One that asks for no more than the reservation holds is answered as it stands, deadline included; one that raises it moves the deadline later (to a month's end at the latest, which the stand-in does not model). What a payer authorises bounds the ceiling less the bytes the relay counted | source only | `relay/lease.ts:880-960`, `billing/ledger.ts:1818-1895` | `a_lease_is_refilled_before_it_runs_out_and_the_ceiling_follows_what_the_relay_counted`, `a_deadline_that_cannot_move_is_not_asked_for_at_once_again` |
//! | A principal holds at most 8 MiB outstanding across its leases, measured as the ceilings less the bytes counted. A hold past it, and a service with no relay instance, are `state: unavailable`; an allowance that is spent is `state: exhausted`, with the paths that still work and the grace (the grace figures are fixed here). The reservation of a lease past its deadline has been settled and holds nothing against the aggregate: a request for the pair is given a new lease with the figures of a new reservation, its cumulative ceiling clamped to what the payer authorises. A refill during a grace window raises nothing in the Worker; the stand-in has no grace window to refill in | source only | `relay/lease.ts:560-640, 820-840, 2215-2260`, `billing/ledger.ts:1840-1850` | `an_allowance_that_is_spent_is_shown_to_the_owner_and_asked_again`, `a_service_that_has_no_room_for_a_lease_says_so_and_is_asked_again_later`, `a_count_beyond_the_aggregate_does_not_stop_a_refill` |
//! | A revocation fences the lease and answers with the relay's figures and the settlement; sent again it answers the same; a lease the service never issued is `400`, one issued to another caller `403` | source only | `relay/lease.ts:1195-1260` | `an_ending_whose_answer_was_lost_is_asked_again_until_it_is_answered` |
//! | A refill of a lease whose relay is no longer one the service can bill through is `state: unavailable` with the message to revoke the lease and ask for another | source only | `relay/lease.ts:820-840` | `a_lease_on_a_retired_relay_is_ended_and_asked_for_afresh` |
//! | A lease an authorisation the host did not select as its default pays for is signed as sponsored by it | source only | `relay/lease.ts:662-671, 1983-1986` | the stand-in signs it through the protocol's own lease type |
//! | Withdrawing an authorisation revokes the leases issued under it | source only | `relay/index.ts:840-880` | `a_withdrawn_authorisation_ends_the_leases_and_the_owner_is_told` |
//! | The relay installing the lease, the relay's own counting and the settlement's evidence | not modelled: the stand-in answers that the lease is installed and counts the bytes a test says the relay counted | `relay/install.ts`, `relay/settlement.ts` | none |
//! | Uploads the service has lost answer `NOT_FOUND` | source only | `storage/upload.ts:607` | `Moment::UploadsLost`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | Storage not confirming the write of a part answers `INTERNAL` and closes the upload | source only | `storage/index.ts:830`, `storage/upload.ts:577` | `Moment::PartWriteFails`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |

mod feed;
mod http;
mod mailbox;
mod relay;
mod web;

pub use http::{Served, serve};
pub use relay::{RelayLeaseView, RelayPayerRecord};
pub use web::{
    ACCOUNT, Arrived, BACKUP_WRITE_SCOPE, Handled, IN_PROCESS_ORIGIN, MAX_GENERATIONS, Moment,
    PART, ServiceWeb, StaleRefusal, TOKEN, document_of, refusal, refusal_after,
};
