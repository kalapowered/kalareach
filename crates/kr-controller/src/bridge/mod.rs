//! The invoking half of a local process bridge, and the environments this host has enrolled.
//!
//! Section 3 gives this environment's control daemon three jobs on the far side of a bridge, and
//! this module owns all three.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`launch`] | The exact argument vector each access class is started with |
//! | [`platform`] | Asking the platform whether an enrolled environment is running, and starting one |
//! | [`store`] | The owner-approved enrolment record and the cache of what was last observed |
//! | [`invoke`] | Opening a bridge: what may cross it, and what is refused before a process starts |
//!
//! **The bridge is never a hidden dependency.** A WSL installation of KalaReach works with no
//! native Windows installation at all: the Linux daemon inside the distribution owns its own
//! registry, its own endpoint and its own grants, and a WSL-only user runs the Linux command line
//! directly. What this side adds is discovery and pairing from Windows. Removing it removes that
//! convenience and nothing else, which is what
//! `crates/kr-controller/tests/bridge.rs` demonstrates by taking it away.
//!
//! **Authority never crosses.** Each Windows, WSL and enrolled container installation is its own
//! environment authority with its own paired endpoint and environment-local grants. Grouping them
//! for a person to look at grants nothing, and enrolling one here does not give this host's owner
//! any right inside it: the helper is authenticated over there by its own operating-system
//! credentials, under the user the enrolment names.

pub mod invoke;
pub mod launch;
pub mod platform;
pub mod store;
