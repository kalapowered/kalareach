//! A stand-in for the managed storage, backup manifest, authority feed and recovery bundle services.
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
//! `fixtures/service/authority-answers.json`, `fixtures/service/bundle-answers.json` and
//! `fixtures/service/bundle-write-answers.json`) are what a test holds the stand-in to, and what
//! the clients are held to read: `crates/kr-client/tests/service_answers.rs`,
//! `crates/kr-client/tests/authority_answers.rs`, `crates/kr-client/tests/bundle_answers.rs` and
//! `crates/kr-client/tests/bundle_writes.rs`.
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
//! | A read of an object another account stored is `404 NOT_FOUND`, as one never stored or tombstoned is | source only: a local deployment signs one account in | `storage/index.ts:1005-1025, 1193-1197` | `an_object_another_account_stored_is_told_as_no_object_is` in the daemon's suite |
//! | The owner's write of the recovery bundle compares the revision it names with the one held (none for a bundle nobody wrote) and applies when they agree; a write that disagrees is answered `conflict` carrying the object as it stands; a request identity sent again with the same content is answered what it was answered the first time, and with other content is `409 ID_CONFLICT`; a token that may only read, and a host's key, are refused | recorded | `sync/collection.ts` `exchange`, `sync/index.ts` | `the_stand_in_answers_as_the_worker_did` in `bundle_writes.rs` |
//! | An account with no backup allowance is refused the write of the bundle as `402 QUOTA_EXHAUSTED` | source only: the local deployment's free tier includes backup storage | `sync/collection.ts:1519` (the ledger's refusal), `service-contracts/src/index.ts:190` (the status of the code) | `an_account_with_no_allowance_is_refused_the_write` in `bundle_writes.rs`; the daemon's `a_bundle_the_service_refuses_is_followed_by_no_enrolment_and_no_setup` |
//! | The owner of a recovery bundle is the account whose write first applied; any other account's read or write at that locator is answered `404 COLLECTION_ABSENT`, as for a collection that does not exist | source only: a local deployment signs one account in | `sync/collection.ts:1697-1700` (the owner is recorded with the first write), `:2546-2560` (admission by the owner) | `an_account_that_does_not_own_the_bundle_is_told_it_is_not_there` in `bundle_writes.rs` |
//! | A collection put back from an export names its history (`recovery_id`) in a read of the bundle, whether the bundle is there or not | source only: a local deployment is not put back | `sync/collection.ts` `recoveryId` | `a_collection_put_back_names_its_history_with_or_without_the_bundle` in `bundle_answers.rs` |
//! | A refusal whose words repeat the request it refused, which can carry a bundle's locator | not applicable: a hostile service, as the transport faults are; the Worker's own error text is fixed (`object-call.ts:64-73`) | not applicable | `Moment::Echo`; the daemon's `a_refusal_the_service_words_with_the_locator_reaches_the_restore_without_it` |
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
//! | Uploads the service has lost answer `NOT_FOUND` | source only | `storage/upload.ts:607` | `Moment::UploadsLost`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | Storage not confirming the write of a part answers `INTERNAL` and closes the upload | source only | `storage/index.ts:830`, `storage/upload.ts:577` | `Moment::PartWriteFails`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | The recovery bundle is read at its locator by an installation's signature and an account token carrying `backup.write` or `backup.restore`; a locator no write has reached answers an empty read in a history never put back; a written bundle is answered with its place in the order, its revision and its stream | recorded | `sync/index.ts:207-212, 813-943`, `sync/collection.ts:756-830`, `service-contracts/src/sync.ts:1411-1448, 1511-1515` | `the_stand_in_answers_as_the_worker_did` in `bundle_answers.rs` |
//! | A read of the bundle with a token the service did not issue is `404 COLLECTION_ABSENT` | recorded | `sync/index.ts:845-857, 956-984`, `sync/collection.ts:2863` | same |
//! | A read with an expired token, or one issued without either scope, is answered as a token the service did not issue; so is any account's token other than the owner's on a locator that has an owner, word for word | source only: a local deployment signs one account in | `sync/index.ts:845-857, 956-984`, `sync/collection.ts:2549-2565` | `another_accounts_token_is_told_what_an_absent_collection_is_told` in `bundle_answers.rs` |
//! | The sync route is proven by an installation's key only: a host's key is `401 UNAUTHENTICATED` with "This method is not proven by that kind of key", before the origin, the freshness or the signature is read; the storage, manifest and feed routes accept either kind | recorded | `sync/index.ts:159-164`, `mailbox/request.ts:164-173` | same; every other test in this crate signs those routes as a host |
//! | A request to the sync route that is not a read of the bundle: an exchange, a status query, a fence and the members of a settings collection | not modelled: it answers `400 INVALID_REQUEST` and says so. A test puts the bundle in place with `ServiceWeb::put_bundle`. The nonce is spent before the token is read, as for every route here, where the Worker answers a request without a usable token before spending one | `sync/index.ts:207-250` | none |

mod feed;
mod http;
mod sync;
mod web;

pub use http::{Served, serve};
pub use web::{
    ACCOUNT, Arrived, BACKUP_RESTORE_SCOPE, BACKUP_WRITE_SCOPE, Handled, IN_PROCESS_ORIGIN,
    MAX_GENERATIONS, Moment, PART, ServiceWeb, StaleRefusal, TOKEN, document_of, refusal,
    refusal_after,
};
