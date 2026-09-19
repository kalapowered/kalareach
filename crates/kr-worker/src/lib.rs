//! The KalaReach session worker.
//!
//! One worker owns one terminal session for the whole of its life: the pseudo-terminal, the root
//! shell it launched, the canonical geometry, the single input lease, the retained output every
//! attachment reads from, and the private journal its receipts live in. Nothing else writes those.
//! That is what lets the control daemon restart, or crash, without touching a running shell.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`action`] | Section 9's action model: freshness windows, de-duplication, cancellation, observation and the host time contract |
//! | [`attachments`] | Attachments, geometry ownership and succession |
//! | [`attention`] | Section 25's attention engine, its feature store and the review and attention methods |
//! | [`desktop`] | The desktop a session runs on, whether it is still there, and what may be done on it |
//! | [`environment`] | The root shell's environment: what is inherited, what is replaced, what is refused |
//! | [`fence`] | The root editor's fence and detach machine, driven against the real clock and the real bridge |
//! | [`history`] | Retained output: a resident window, an indexed spool and explicit gaps |
//! | [`history_filter`] | The one host-side filter every history and derived-content surface shares |
//! | [`input`] | The single input lease, its epochs and paste-delimiter framing |
//! | [`journal`] | The private receipt journal: acceptance, dispatch markers, de-duplication and retention |
//! | [`lifecycle`] | What a live session is watched for: the root shell's exit, its desktop, and what it owns |
//! | [`output`] | Fan-out with bounded per-attachment queues and explicit resynchronisation |
//! | [`privacy`] | Privacy mode: the generation, the four things it asks of every subsystem, and what it keeps |
//! | [`persistence`] | The durability contract: commit points, per-store declarations, the journal-fault seam, the outbox, retention and migrations |
//! | [`ownership`] | Which processes a session owns, and how much of that the host can account for |
//! | [`projection`] | The canonical grid, the filtered stream and the presentation a terminal is served |
//! | [`render`] | Turning a side-effect-free restoration into terminal bytes |
//! | [`pty`] | The pseudo-terminal, created before the root shell, and the shell it runs |
//! | [`questions`] | The question ledger: what an agent asks, and what a person answers |
//! | [`session`] | The session: lifecycle, the serial order every change shares, and closure |
//! | [`snapshot`] | The projection a client holds: snapshots, bounded row pages, deltas and resets |
//! | [`runtime`] | The reader, the writer, the recogniser timer, the supervision and the closure sequence |
//! | [`service`] | The private endpoint: the handshake, the challenge and the method dispatch |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |

pub mod action;
pub mod attachments;
pub mod attention;
pub mod conpty;
pub mod desktop;
pub mod environment;
pub mod error;
pub mod fence;
pub mod history;
pub mod history_filter;
pub mod input;
pub mod journal;
pub mod lifecycle;
pub mod output;
pub mod ownership;
pub mod persistence;
pub mod privacy;
pub mod projection;
pub mod pty;
pub mod questions;
pub mod render;
pub mod runtime;
pub mod service;
pub mod session;
pub mod snapshot;

pub use crate::error::{Result, WorkerError};
