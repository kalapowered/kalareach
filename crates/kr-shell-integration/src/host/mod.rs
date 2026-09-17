//! The worker's side of the contract: the endpoint, the handshake and the gates around them.
//!
//! [`crate::contract`] is pure. This is where it meets the operating system: a socket inside an
//! owner-only directory, the kernel's answer about who connected, an HMAC over the bootstrap
//! transcript, and the phase a session has reached. The state machine itself stays in
//! [`crate::contract::fence`], driven by the worker; nothing here holds a second copy of its rules.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`endpoint`] | The per-session bridge endpoint and the bootstrap values the root shell starts with |
//! | [`handshake`] | The proof over the bootstrap secret, the kernel-observed peer and the accepted registration |
//! | [`phase`] | The integration phase, what each phase permits, and which methods are root methods |
//! | [`link`] | One bridge connection, with the direction of every frame enforced |
//! | [`scripted`] | The reference bridge: the client half of the endpoint, driven frame by frame by its caller |

pub mod endpoint;
pub mod error;
pub mod handshake;
pub mod link;
pub mod phase;
pub mod scripted;

pub use crate::host::error::{HostError, Result};
