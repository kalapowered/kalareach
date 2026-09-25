//! Pairing, from the side of the devices that talk to a host.
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`room`] | The rendezvous room socket a host and a candidate open, with its role, its bounds and its typed failures |
//! | [`invitation`] | The one invitation reader: a scanned or pasted QR payload, read as the host issued it |
//! | [`candidate`] | This device pairing: the short-code attempt, the start's lookup, and the wait for the owner that both modes share |
//! | [`direct`] | Redeeming a direct invitation |
//! | [`link`] | How a device reaches a host over iroh: one dialling endpoint per set of services, and the pre-authorisation surface |
//! | [`paired`] | The paired-host records, and an attempt still waiting for its owner |
//! | [`owner`] | An owner device answering its hosts' owner-confirmation challenges |
//! | [`failure`] | How an attempt ended, as a person is told it |
//! | [`clock`] | The clock a device's attempts are measured on |
//!
//! kr-pairing holds the state machines and the proofs, with no transport. This module drives the
//! candidate's half over the transport the host serves: the room for a code, iroh for the finish
//! and for a direct invitation. What an application's interface is sent is [`AttemptState`],
//! [`PairingFailure`] and the owner confirmations' descriptions; none of it is a secret, a key, a
//! transcript, a challenge or a proof.

use std::future::Future;
use std::pin::Pin;

pub mod candidate;
pub mod clock;
pub mod direct;
pub mod failure;
pub mod invitation;
pub mod link;
pub mod owner;
pub mod paired;
pub mod room;

pub use candidate::{AttemptState, Candidate, CandidateRoom, HostView, Pairing, Stage};
pub use failure::{FailureKind, PairingFailure};

/// A boxed future, so the pairing seams stay usable behind trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
