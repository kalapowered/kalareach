//! The KalaReach plugin-runtime service.
//!
//! One process per environment, started when a binding first needs a component and not before. It
//! hosts component instances and nothing else: no journal, no ledger, no pending requests. Those
//! live in the workers, which is why this process can die without destroying anything.
//!
//! ```text
//! kr-controller ──start job──▶ service manager ──▶ kr-plugin-host
//!       │                                                ▲
//!       └──rendezvous──────────────────────────────────── │
//!                                                        │
//! kr-worker ──register, deliver, call, unbind ────────────┘
//! ```
//!
//! The control daemon starts it and takes its identity proof. After that the daemon is not in the
//! path: workers connect to the host's own owner-only endpoint, challenge the process behind it,
//! and talk to it directly. A daemon restart does not interrupt a binding, and a host restart does
//! not interrupt a session.
//!
//! # What it runs
//!
//! Wasmtime components under the section 11 limits: 64 MiB of linear memory, a 10 ms deadline for
//! observation and action preparation, 50 ms for decoding and encoding, 100 ms for a snapshot, and
//! 1 MiB of output per call, with instructions bounded by fuel and elapsed execution by an epoch
//! deadline. `crates/kr-plugin-runtime` owns all of that; this crate is the process around it.
//!
//! # What it refuses
//!
//! A caller who is not this user, by peer credentials. A component that imports anything outside
//! the four `kalareach:plugin` interfaces, by name. A component payload outside the packages
//! directory it was started with, or one whose bytes are not the digest the caller verified.

pub mod options;
pub mod run;

pub use crate::options::Options;
pub use crate::run::run;
