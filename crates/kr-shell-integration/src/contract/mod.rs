//! The published contract, in the order a shell-package author meets it.
//!
//! A package starts at [`transport`]: it finds the bridge endpoint in its bootstrap environment,
//! presents what it is, and is either accepted or told exactly why it is not qualified. From then
//! on it reports through [`events`] and answers through [`requests`], and the worker's side of both
//! is decided by [`fence`]. [`qualification`] holds the rules that decide whether a package may
//! claim the contract at all, and [`fixtures`] holds the scenarios that demonstrate it does.

pub mod events;
pub mod fence;
pub mod fixtures;
pub mod qualification;
pub mod requests;
pub mod transport;
