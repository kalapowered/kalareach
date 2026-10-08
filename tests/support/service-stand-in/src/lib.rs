//! A stand-in for the managed storage and backup manifest services.
//!
//! The service is the web repository's Worker, and what it answers is stated by that repository's
//! service contract. This crate answers as the contract states, with the state the service keeps,
//! so a test of a client or of a daemon can run against it on a machine with no Worker, no
//! network and no account. [`StorageWeb`] is the service. It is handed requests in process, as an
//! HTTP transport would carry them, or it answers a socket on loopback ([`serve`]), which is how a
//! daemon's own transport reaches it.
//!
//! Where the stand-in and the Worker could differ, the Worker is right. The recorded answers a
//! local Worker gave (`fixtures/service/storage-answers.json`) are what a test holds the stand-in
//! to, and what the clients are held to read: `crates/kr-client/tests/service_answers.rs`.
//!
//! # What each behaviour is held to
//!
//! A behaviour a test relies on is either recorded, which means the same script of requests was
//! run against a Worker and the stand-in and the status, the shape of the body and what the
//! clients decoded it to agree, or it is read from the contract and the Worker's source, because a
//! local Worker cannot be made to do it. The files are in the web repository: the contract in
//! `packages/service-contracts/src/{storage,backup}.ts`, the Worker in `workers/api/src`.
//!
//! | Behaviour | Held to | Worker | Test |
//! | --- | --- | --- | --- |
//! | A status with no account proof is `402 QUOTA_EXHAUSTED` | recorded | `storage/index.ts:271` | `the_stand_in_answers_as_the_worker_did` |
//! | A retention change against a revision it has left is `CONFLICT` carrying the retention as it stands | recorded | `storage/index.ts` | same |
//! | A second creation of an upload that is open is `403 FORBIDDEN` | recorded | `storage/upload.ts` | same; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | A part sent again, a completion sent again | recorded, answered as a duplicate | `storage/upload.ts` | same |
//! | A completion or a part for an upload nobody created is `NOT_FOUND`, which the client reads as the upload being gone | recorded | `storage/upload.ts` | same |
//! | A part sent to an upload that was abandoned is `403 FORBIDDEN`; an abandonment is answered again with what it released, the upload's declared size | recorded | `storage/upload.ts:856` | same |
//! | A read past the end of an object is `INVALID_REQUEST`; a deletion answered again says it was already done; one of an object never held is `NOT_FOUND` | recorded | `storage/index.ts` | same |
//! | A publication before any writer is enrolled is `403 FORBIDDEN`; one of other content under a generation held is `403`; one below the checkpoint is `403` | recorded | `backup/collection.ts` | same |
//! | A publication sent again is a duplicate and needs no account proof | recorded | `backup/index.ts:116` | same |
//! | A collection reports the bytes its held descriptors take, its checkpoint and the generations it holds, newest first | recorded | `backup/collection.ts:875` | same |
//! | The history keeps 16 generations; the 17th publication drops the oldest and says so | recorded | `backup/collection.ts` | same |
//! | A fetch with a checkpoint newer than the collection, with a manifest the collection does not hold at that generation, or for a generation older than the checkpoint is `NOT_FOUND`, which the client reads as nothing to answer with; a checkpoint about another archive is `INVALID_REQUEST` | recorded | `backup/collection.ts:372-445`, `backup/index.ts:281` | same |
//! | A new generation published with no account proof is `402 QUOTA_EXHAUSTED` | contract and source only: a local deployment's free tier includes backup storage, so the Worker accepts it there | `backup/index.ts:224`, the production catalogue | the daemon's `an_account_the_service_turns_away_is_waited_for_as_a_person` reaches it through the status route instead |
//! | `RATE_LIMITED` and `SERVICE_UNAVAILABLE` carry `retryAfterSeconds`, and the `Retry-After` header | source only: a local Worker cannot be made to rate limit or to be unavailable | `object-call.ts:64-73`, `auth/routes.ts:369` | `Moment::Refuse`; the daemon's reaction table; the client's own reading of it in `services/signed.rs` |
//! | A collection deleted from the account console is `410 COLLECTION_DELETED` | source only | `storage/index.ts:211`, `backup/collection.ts:531` | `StorageWeb::delete_collection`; `a_deleted_collection_stops_the_attempt` |
//! | A transport fault: the request never arrives, its answer is lost, the connection is held open with no answer, the body arrives cut short | none: the Worker does not choose these | not applicable | `Moment::{Before, After, Hold, BodyCut}` |
//! | Uploads the service has lost answer `NOT_FOUND` | source only | `storage/upload.ts:607` | `Moment::UploadsLost`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |
//! | Storage not confirming the write of a part answers `INTERNAL` and closes the upload | source only | `storage/index.ts:830`, `storage/upload.ts:577` | `Moment::PartWriteFails`; the daemon's `an_upload_the_service_lost_or_closed_is_made_again` |

mod http;
mod web;

pub use http::{Served, serve};
pub use web::{
    ACCOUNT, Arrived, BACKUP_WRITE_SCOPE, Handled, IN_PROCESS_ORIGIN, MAX_GENERATIONS, Moment,
    PART, StaleRefusal, StorageWeb, TOKEN, document_of, refusal, refusal_after,
};
