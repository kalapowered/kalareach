//! KalaReach pairing.
//!
//! This crate is the two pairing state machines of section 10 and the cryptography that binds
//! them. It performs no transport, holds no database and runs no user-verification ceremony:
//! every one of those is an injected trait with an implementation in the tests, so the rules can
//! be exercised without a network, a disk or a person. The one store it keeps itself is the
//! candidate's own attempt budget ([`budget`]), a file every client on a device shares.

pub mod budget;
pub mod bundles;
pub mod client;
pub mod code;
pub mod confirm;
pub mod direct;
mod error;
pub mod grants;
pub mod host;
pub mod platform;
pub mod spake;
pub mod transcript;
pub mod vectors;

pub use crate::error::{PairingError, Result};
