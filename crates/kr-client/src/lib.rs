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
//! | [`answers`] | Answers kept on this device while the host cannot be reached, and what a reconnect makes of them |
//! | [`chunks`] | Where one transfer's chunks travel: the attachment-chunk lane, which never shares the control connection |
//! | [`transport`] | The shape both transports share, and the iroh connection |
//! | [`encoder`] | The shared terminal input encoder: keys, modifiers, pointers and pastes |
//! | [`viewport`] | The clipped window onto the canonical grid, and the presentation switch |
//! | [`controls`] | What a client shows, and what it lets a person invoke |
//! | [`drafts`] | Drafts this device owns, and the attachment that only presents one |
//! | [`ipc`] | The local socket or named pipe, with the host-stamped freshness context |
//! | [`pairing`] | Pairing from a device's side: the room socket, the invitation reader, both candidate modes, the paired hosts and the owner's confirmations |
//! | [`projection`] | The screen a projected client holds, and the renderer that draws it |
//! | [`session`] | Requests, receipts, events and the action window |
//! | [`shown`] | The one type of text a diagnostic may show, and the only ways input becomes it |
//! | [`sync`] | Encrypted settings sync, its compare-and-swap client and its privacy hook |
//! | [`cursors`] | Cursors, receipts and the order state is restored in |
//! | [`reconnect`] | The reconnect loop and what it refuses to carry across |
//! | [`recovery`] | The recovery seed, its kit, the bundle at its locator and what a restore puts back |
//! | [`retry`] | What a failure means for the request, and what it means for the person |
//! | [`services`] | Replaceable service clients and the null implementation |
//! | [`uploads`] | One upload, from a local file to a verified attachment handle |
//!
//! # What this crate does not do
//!
//! It holds no terminal state and no authority. It carries requests to a host and answers back,
//! and it knows which of its own actions are unresolved. Everything a request means belongs to the
//! host.

#![forbid(unsafe_code)]

pub mod answers;
pub mod chunks;
pub mod controls;
pub mod cursors;
pub mod drafts;
pub mod encoder;
pub mod error;
pub mod ipc;
pub mod pairing;
/// The projected screen a client paints, and the pinned Unicode width model it measures with.
///
/// Present when the `terminal` feature is on, which is the default. A client on a system with no
/// local terminal takes this library without it; nothing else in the library changes.
#[cfg(feature = "terminal")]
pub mod projection;
pub mod reconnect;
pub mod recovery;
pub mod retry;
pub mod services;
pub mod session;
pub mod shown;
pub mod sync;
pub mod transport;
pub mod uploads;
pub mod viewport;

pub use error::{ClientError, Result};
pub use session::{Session, Settled};
pub use shown::{IoFault, Plain, Said, Shown};
