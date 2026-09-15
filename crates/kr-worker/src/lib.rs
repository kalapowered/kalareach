//! The KalaReach session worker.
//!
//! One worker owns one terminal session for the whole of its life: the pseudo-terminal, the root
//! shell it launched, the canonical geometry, the single input lease, the retained output every
//! attachment reads from, and the private journal its receipts live in. Nothing else writes those.
//! That is what lets the control daemon restart, or crash, without touching a running shell.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`attachments`] | Attachments, geometry ownership and succession |
//! | [`environment`] | The root shell's environment: what is inherited, what is replaced, what is refused |
//! | [`history`] | Retained output: a resident window, an indexed spool and explicit gaps |
//! | [`input`] | The single input lease, its epochs and paste-delimiter framing |
//! | [`journal`] | The private receipt journal: acceptance, dispatch markers, de-duplication and retention |
//! | [`output`] | Fan-out with bounded per-attachment queues and explicit resynchronisation |
//! | [`ownership`] | Which processes a session owns, and how much of that the host can account for |
//! | [`projection`] | The boundary a terminal of another size is served through |
//! | [`pty`] | The pseudo-terminal, created before the root shell, and the shell it runs |
//! | [`session`] | The session: lifecycle, the serial order every change shares, and closure |
//! | [`runtime`] | The reader, the writer, the recogniser timer and the closure sequence |
//! | [`service`] | The private endpoint: the handshake, the challenge and the method dispatch |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |

pub mod attachments;
pub mod environment;
pub mod error;
pub mod history;
pub mod input;
pub mod journal;
pub mod output;
pub mod ownership;
pub mod projection;
pub mod pty;
pub mod runtime;
pub mod service;
pub mod session;

pub use crate::error::{Result, WorkerError};
