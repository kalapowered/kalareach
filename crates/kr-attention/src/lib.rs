//! The KalaReach attention engine.
//!
//! Section 25 puts the engine on the host, running from typed events, with a rule set whose
//! identifiers are stable, a sixty-second de-duplication window, quiet hours, escalation, review
//! acknowledgements and a changed-since-last-visit view. This crate is that engine, and section
//! 24's environment feature store it is rebuilt from: one store for the environment, holding every
//! session's conditions and the environment's own, with one inbox across them.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`time`] | The host time contract's answer, as the engine receives it. Nothing here reads a clock |
//! | [`event`] | The typed events the engine runs from, the cursors that make a replay safe, and whose sources they are |
//! | [`key`] | Deriving an item's key from the subject its condition is about |
//! | [`rule`] | The rule set, each rule's escalation ladder and its de-duplication window |
//! | [`engine`] | The inbox: raising, de-duplicating, deferring, escalating, resolving and acknowledging |
//! | [`scope`] | What one caller may see of it |
//! | [`review`] | Review acknowledgements, bound to versions, per actor |
//! | [`visit`] | Each session's change log, the visits into it and the log views an actor keeps |
//! | [`store`] | The environment feature store the whole of it is rebuilt from |
//! | [`host`] | The two put together: apply an event, persist what changed, answer a read |
//! | [`error`] | The failures above |
//!
//! # Three properties the whole design rests on
//!
//! **Nothing here reads a clock.** Every decision that depends on time takes a
//! [`time::HostReading`] from the caller, which comes from the host time contract. Two clocks
//! arrive: the boot-scoped continuous one, which measures every interval and needs nobody's trust,
//! and the wall clock with the host's own statement of whether it can prove it, which is what
//! decides quiet hours. A test drives a five-minute reminder by handing over a reading five minutes
//! later.
//!
//! **Nothing here mutates code.** There is no operation that writes a file, applies a patch, moves
//! a branch or approves a command. Marking a review complete moves a row and nothing else, which is
//! section 14's rule that promotion is a separate authorised action, expressed as the absence of
//! the capability rather than as a policy somebody has to remember.
//!
//! **A gap is never an ending.** Reconstruction is a replay of the retained events, and an event
//! the engine has already consumed changes nothing. A jump in the sequence is a range retention
//! took: the engine records it, marks every unresolved item the missing range could have resolved
//! as uncertain, and leaves it in the inbox. Section 24 forbids reading a gap as an approval or a
//! completion, and saying "the host cannot tell" is the only other honest answer.
//!
//! **A session's text is not kept here.** An item keeps the record its text came from, and the
//! text is read from that record's owner when it is served, under that session's privacy state at
//! that moment. Only the host's own words are stored.
//!
//! # Example
//!
//! ```
//! use kr_attention::event::{EventCursor, EventKind, SourceEvent};
//! use kr_attention::time::BootMark;
//! use kr_attention::{Engine, HostReading, Outcome};
//! use kr_protocol::attention::AttentionSource;
//! use kr_protocol::ids::{ApprovalRequestId, SessionId};
//! use kr_protocol::scalars::{TimestampMs, Uuid};
//!
//! let mut engine = Engine::new();
//! let now = HostReading::new(BootMark::of(b"this boot"), 0, 1_700_000_000_000, true);
//! let outcomes = engine.apply(
//!     &SourceEvent::new(
//!         EventCursor::new(AttentionSource::Receipts, 1),
//!         TimestampMs::new(1_700_000_000_000),
//!         EventKind::ApprovalRequested {
//!             request_id: ApprovalRequestId::new("req-1").expect("an identifier"),
//!             session_id: SessionId::new(Uuid::from_bytes([1; 16])),
//!             summary: "write to /etc/hosts".to_owned(),
//!         },
//!     ),
//!     now,
//! );
//! assert!(matches!(outcomes.first(), Some(Outcome::Raised { .. })));
//!
//! // Replaying the same record changes nothing.
//! let again = engine.apply(
//!     &SourceEvent::new(
//!         EventCursor::new(AttentionSource::Receipts, 1),
//!         TimestampMs::new(1_700_000_000_000),
//!         EventKind::ApprovalRequested {
//!             request_id: ApprovalRequestId::new("req-1").expect("an identifier"),
//!             session_id: SessionId::new(Uuid::from_bytes([1; 16])),
//!             summary: "write to /etc/hosts".to_owned(),
//!         },
//!     ),
//!     now,
//! );
//! assert!(again.is_empty());
//! ```

pub mod engine;
pub mod error;
pub mod event;
pub mod host;
pub mod key;
pub mod review;
pub mod rule;
pub mod scope;
pub mod store;
pub mod subject;
pub mod time;
pub mod visit;

pub use crate::engine::{Content, Engine, Item, Outcome, Text};
pub use crate::error::{Error, Result};
pub use crate::event::{EventCursor, EventKind, Origin, SourceEvent};
pub use crate::host::{ActionKey, Answer, Attention, ChangedPage, InboxPage, Mutation, Performed};
pub use crate::rule::{RULES, Rule};
pub use crate::scope::{DeviceScope, Viewer};
pub use crate::store::{ActionRecord, Claimant, Liveness};
pub use crate::subject::Subject;
pub use crate::time::HostReading;
