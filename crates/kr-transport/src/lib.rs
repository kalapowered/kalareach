//! KalaReach transport.
//!
//! This crate carries KalaReach's wire contract over iroh. It builds endpoints from an explicit
//! selection of network services, performs the connection handshake, multiplexes the five stream
//! kinds, and holds the three host-side resources a remote request depends on: the verified actor
//! envelope, the action window and the remote dispatch lease.
//!
//! # The shape of a connection
//!
//! ```text
//!   endpoint      config.rs, endpoint.rs   one selection, no inherited defaults
//!     |
//!   connection    ALPN `kalareach`, iroh authenticates both transport keys
//!     |
//!   first bidirectional stream            handshake.rs
//!     |  hello        offer and selection, versions and limits negotiated
//!     |  kr-connect/1 both authorisation keys proved over the same transcript
//!     v
//!   control stream                        requests, responses, receipts, events
//!     |
//!     +-- terminal output / input / semantic updates / attachment chunks
//!                                          streams.rs, scheduler.rs
//! ```
//!
//! A connection whose endpoint is not paired stops one line short of the control stream: it
//! reaches the bounded pre-authorisation pairing surface in [`preauth`] and nothing else.
//!
//! # Modules
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`config`] | The selected relay map, Pkarr publisher, Pkarr resolver and DNS origin |
//! | [`endpoint`] | Endpoint construction from `presets::Minimal` and the ALPN |
//! | [`codec`] | Length-delimited KR-CBOR-1 frames over a QUIC stream |
//! | [`handshake`] | `hello` and the `kr-connect/1` mutual proof |
//! | [`preauth`] | The bounded pre-authorisation pairing surface |
//! | [`streams`] | Stream headers, data streams and revocation |
//! | [`scheduler`] | Send priorities and the bulk-stream budget |
//! | [`actor`] | The verified actor envelope and the 0-RTT rule |
//! | [`window`] | Action windows and the deadline derivation |
//! | [`lease`] | The remote dispatch lease and the revocation barrier's status |
//! | [`reconnect`] | Backoff, and the input lane a reconnect never carries across |
//! | [`clock`] | The suspend-aware continuous clock every deadline is measured on |
//! | [`listener`] | One registration call for the host |
//!
//! # What this crate does not do
//!
//! It holds no session state, no terminal state and no authority store. It decides that a request
//! may be admitted, never what the request means: the method's own effect belongs to the host.

#![forbid(unsafe_code)]

pub mod actor;
pub mod clock;
pub mod codec;
pub mod config;
pub mod endpoint;
pub mod error;
pub mod handshake;
pub mod lease;
pub mod listener;
pub mod preauth;
pub mod random;
pub mod reconnect;
pub mod scheduler;
pub mod streams;
pub mod window;

pub use error::{Result, TransportError};
pub use kr_protocol::hello::ALPN;
