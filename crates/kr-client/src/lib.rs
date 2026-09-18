//! The KalaReach native client library.
//!
//! One client library serves the CLI, the desktop and mobile applications and anything else that
//! talks to a host. It connects over local IPC or over iroh, performs the connection handshake,
//! multiplexes the protocol's stream kinds, and keeps the bookkeeping the protocol requires:
//! request correlation, action identifiers, receipts, event cursors and the connection's action
//! window.
//!
//! # What the registry decides
//!
//! Every call goes through `kr-protocol`'s method registry rather than around it. [`Session::read`]
//! refuses a method the registry marks as a mutation, [`Session::mutate`] refuses a read, and a
//! mutation carries the freshness its entry demands. A client cannot reach an effect the registry
//! does not list, and cannot present a request shape the host would have to reject.
//!
//! # Modules
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`transport`] | The shape both transports share, and the iroh connection |
//! | [`encoder`] | The shared terminal input encoder: keys, modifiers, pointers and pastes |
//! | [`viewport`] | The clipped window onto the canonical grid, and the presentation switch |
//! | [`drafts`] | Drafts this device owns, and the attachment that only presents one |
//! | [`ipc`] | The local socket or named pipe, with the host-stamped freshness context |
//! | [`projection`] | The screen a projected client holds, and the renderer that draws it |
//! | [`session`] | Requests, receipts, events and the action window |
//! | [`cursors`] | Cursors, receipts and the order state is restored in |
//! | [`reconnect`] | The reconnect loop and what it refuses to carry across |
//! | [`retry`] | What a failure means for the request, and what it means for the person |
//! | [`services`] | Replaceable service clients and the null implementation |
//!
//! # What this crate does not do
//!
//! It holds no terminal state and no authority. It carries requests to a host and answers back,
//! and it knows which of its own actions are unresolved. Everything a request means belongs to the
//! host.

#![forbid(unsafe_code)]

pub mod cursors;
pub mod drafts;
pub mod encoder;
pub mod error;
pub mod ipc;
pub mod projection;
pub mod reconnect;
pub mod retry;
pub mod services;
pub mod session;
pub mod transport;
pub mod viewport;

pub use error::{ClientError, Result};
pub use session::{Session, Settled};
