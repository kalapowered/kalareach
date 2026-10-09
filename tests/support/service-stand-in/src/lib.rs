//! A stand-in for the managed storage, backup manifest, authority feed and recovery bundle
//! services.
//!
//! The service is the web repository's Worker, and what it answers is stated by that repository's
//! service contract. This crate answers as the contract states, with the state the service keeps,
//! so a test of a client or of a daemon can run against it on a machine with no Worker, no
//! network and no account. [`ServiceWeb`] is the service. It is handed requests in process, as an
//! HTTP transport would carry them, or it answers a socket on loopback ([`serve`]), which is how a
//! daemon's own transport reaches it.
//!
//! Where the stand-in and the Worker could differ, the Worker is right. The recorded answers a
//! local Worker gave (`fixtures/service/storage-answers.json`,
//! `fixtures/service/authority-answers.json` and `fixtures/service/bundle-answers.json`) are what a
//! test holds the stand-in to, and what the clients are held to read:
//! `crates/kr-client/tests/service_answers.rs`, `crates/kr-client/tests/authority_answers.rs` and
//! `crates/kr-client/tests/bundle_answers.rs`.
//!
//! # What each behaviour is held to
//!
//! A behaviour a test relies on is either recorded, which means the same script of requests was
//! run against a Worker and the stand-in and the status, the shape of the body and what the
//! clients decoded it to agree, or it is read from the contract and the Worker's source, because a
//! local Worker cannot be made to do it. The files are in the web repository: the contract in
//! `packages/service-contracts/src/{storage,backup,authority,sync}.ts`, the Worker in
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
//! | A write of the recovery bundle at its locator, under a token with `backup.write`, is applied when it names the revision the locator holds, or none where it holds none, and is answered with the record and the place the write took; one that names another revision is `conflict`, keeps no copy and says where the bundle stands | recorded | `sync/collection.ts:484, 1568`, `sync/index.ts:813-935` | `the_stand_in_answers_as_the_worker_did` in `bundle_answers.rs`; the companion's `turning_recovery_on_*` |
//! | A write sent again under its identity is answered from its receipt; another bundle under that identity is `409 ID_CONFLICT`; a fenced identity is `409 REQUEST_FENCED` | recorded | `sync/collection.ts:605-680` | same |
//! | A read, a write, a status query and a fence under a token the account system did not issue, an expired one or one without the scope are `404 COLLECTION_ABSENT`, word for word as for a locator nobody wrote to; a read also admits `backup.restore`, and a write with that scope alone is turned away | recorded for an unissued token and for a write with `backup.restore` alone | `sync/index.ts:796-801, 956-975` | same |
//! | A status query says `applied` with the record, `refused` with the record the bundle had, or `unknown` for an identity never seen; a fence on an identity with no receipt ends it as `fenced` with `never_ran`, and answers the same again | recorded | `sync/collection.ts:1222-1380` | same |
//! | A request that names a locator is read against the closed shape of its member: another field, a locator that is not a canonical UUID, a revision that is not one, a bundle outside 41 bytes to 128 KiB, or a fence naming its earliest attempt after its latest, is `400` | source only: this crate's client sends none of these | `service-contracts/src/sync.ts:1411-1558` | none |
//! | A write signed before a collection's cutoff is `409 SIGNED_BEFORE_CUTOFF`; the account whose write first applies owns the collection and every other account is answered `COLLECTION_ABSENT`; a collection put back from an archive names a history | not modelled: the service knows one account and sweeps and restores nothing | `sync/collection.ts:2393-2460` | none |
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
//! | Uploads the service has lost answer `NOT_FOUND` | source only | `storage/upload.ts:607` | `Moment::UploadsLost`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | Storage not confirming the write of a part answers `INTERNAL` and closes the upload | source only | `storage/index.ts:830`, `storage/upload.ts:577` | `Moment::PartWriteFails`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |

mod bundle;
mod feed;
mod http;
mod web;

pub use http::{Served, serve};
pub use web::{
    ACCOUNT, Arrived, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, Handled, IN_PROCESS_ORIGIN,
    MAX_GENERATIONS, Moment, PART, RESTORE_TOKEN, ServiceWeb, StaleRefusal, TOKEN, document_of,
    refusal, refusal_after,
};
