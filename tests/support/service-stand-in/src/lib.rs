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
//! local Worker gave (`fixtures/service/`) are what a test holds the stand-in to.

mod http;
mod web;

pub use http::{Served, serve};
pub use web::{
    ACCOUNT, Arrived, BACKUP_WRITE_SCOPE, Handled, IN_PROCESS_ORIGIN, MAX_GENERATIONS, Moment,
    PART, StaleRefusal, StorageWeb, TOKEN, document_of, refusal, refusal_after,
};
