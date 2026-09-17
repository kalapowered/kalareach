//! Reaching the plugin host, and being it.
//!
//! The engine lives in one process per environment, and a worker talks to it. This module is both
//! sides of that conversation: the protocol they speak, the descriptor a worker finds the host
//! through, the client a worker uses, and the launcher that starts the host and takes its identity
//! proof.
//!
//! # Why a separate process at all
//!
//! Because a component fault must not be a worker fault. A worker owns a shell, a pseudo-terminal
//! and an approval ledger; a component is vendor code compiled from a catalogue. Putting the second
//! inside the first would make a trap in a vendor's arithmetic a risk to somebody's session. With
//! the split, a plugin host that dies invalidates rich bindings and nothing else: the worker
//! notices, re-registers what it had, and no request was ever in the other process to lose.
//!
//! # Modules
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`protocol`] | The frames, the two proof transcripts and the published descriptor |
//! | [`client`] | What a worker uses: connect, verify, register, deliver, call, unbind |
//! | [`launcher`] | Starting the host as its own job, taking its rendezvous, publishing its descriptor |
//! | [`host`] | Serving workers: the accept loop, peer credentials and the request handling |
//! | [`notices`] | The bounded queue a connection's unasked-for news waits in |

pub mod client;
pub mod host;
pub mod launcher;
pub mod notices;
pub mod protocol;
