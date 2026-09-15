//! The KalaReach terminal engine.
//!
//! A KalaReach session is one terminal with several windows onto it, some of them on the other side
//! of a network. That is the whole reason this crate exists: the moment two terminals can see the
//! same application, the ordinary assumption that the terminal in front of you *is* the terminal
//! stops being true.
//!
//! Three things follow, and they shape everything here.
//!
//! **One parse.** [`lexer::Lexer`] reads the output stream once. It keeps the original bytes, the
//! span they occupy, the parsed parameters and whether the parser is standing on ground. Every
//! other part of the engine works from those events. Nothing re-reads the bytes, so nothing can
//! disagree about where a sequence began or what it was.
//!
//! **One responder.** [`broker::QueryBroker`] answers every query from the virtual profile and the
//! session's own state. No query is forwarded to an attached terminal, so two attachments cannot
//! both answer and a physical terminal cannot answer on the session's behalf. Replies travel on
//! [`lane::ResponseLane`], which is bounded and which no human input can be mistaken for.
//!
//! **One destination.** A side effect leaves the terminal, so it goes to exactly one place: the
//! attachment that currently holds the input lease. A broadcast would put a secret on every
//! attached device, so there is no broadcast.
//!
//! # The class table
//!
//! Every sequence gets one of five classes, which [`classify`] implements row by row:
//!
//! | Class | Meaning |
//! | --- | --- |
//! | `D` | Display. Applied to the canonical grid, and forwarded unchanged in direct mode. |
//! | `M` | Mode. Tracked and forwarded live. |
//! | `Q` | Query. Consumed; the broker answers. |
//! | `S` | Side effect. Consumed; routed to one named destination under policy. |
//! | `X` | Extension. Consumed, with a rate-limited diagnostic. |
//!
//! `X` is the default, deliberately. An unrecognised sequence is not forwarded in the hope that it
//! is harmless; it is consumed until a profile revision gives it a class.
//!
//! # Flow
//!
//! ```text
//! bytes -> lexer -> events -> policy -> grid reducer   (D and M)
//!                                    -> query broker   (Q) -> response lane
//!                                    -> side effects   (S) -> one named destination
//!                                    -> diagnostics    (X)
//! ```
//!
//! # Example
//!
//! ```
//! use kr_term::engine::{Engine, EngineConfig};
//! use kr_term::lane::LaneGate;
//!
//! let mut engine = Engine::new(EngineConfig::default())?;
//!
//! // Ordinary output is display: the grid tracks it and the original bytes may be forwarded.
//! let outcome = engine.feed(b"hello", 0);
//! assert_eq!(outcome.forward.len(), 1);
//!
//! // A query stops here. The application gets an answer; no attached terminal sees the question.
//! let outcome = engine.feed(b"\x1b[c", 0);
//! assert!(outcome.forward.is_empty());
//! assert_eq!(outcome.responses, 1);
//!
//! let replies = engine.lane_mut().drain(LaneGate::default(), 4096);
//! assert_eq!(replies[0].bytes, b"\x1b[?62;1;22c");
//! # Ok::<(), kr_term::error::TermError>(())
//! ```

pub mod adapter;
pub mod broker;
pub mod budget;
pub mod class;
pub mod classify;
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod diag;
pub mod engine;
pub mod error;
pub mod event;
pub mod grid;
pub mod lane;
pub mod lexer;
pub mod modes;
pub mod palette;
pub mod policy;
pub mod probe;
pub mod profile;
pub mod sideeffect;
pub mod snapshot;
pub mod span;
pub mod terminfo;
pub mod title;
pub mod unicode;

pub use crate::class::SequenceClass;
pub use crate::engine::{Engine, EngineConfig, FeedOutcome};
pub use crate::error::{Result, TermError};
pub use crate::event::{Event, EventKind};
pub use crate::profile::Profile;
