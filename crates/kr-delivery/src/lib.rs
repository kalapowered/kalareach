//! The KalaReach delivery producer.
//!
//! Section 24 gives this environment one delivery journal, *keyed by underlying event, destination
//! and attempt*, and section 16 says what a notification made from one of those events may carry.
//! This crate is both: the store and the producer that writes into it.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`journal`] | The environment delivery journal: events taken, destinations, notifications, attempts, the outbox |
//! | [`destination`] | What a destination is, push and external, and what each one needs before content may leave |
//! | [`preview`] | Sealing a preview to the destination's notification-preview key, and the two size bounds |
//! | [`budget`] | The host's own burst and sustained account, and the five-minute collapse |
//! | [`push`] | The send-and-receipt seam, the retry schedule and what each gateway answer means |
//! | [`external`] | Webhook, Slack, email, Discord and Telegram delivery, and the uncertainty a destination without idempotency leaves |
//! | [`producer`] | Taking from attention and from the worker outbox, and producing notifications from what was taken |
//! | [`privacy`] | The content-bearing outbox privacy mode fences, cancels and reconciles |
//! | [`error`] | The failures above |
//!
//! # Four rules the whole crate rests on
//!
//! **The host event comes first, and the store is what proves it.** A notification row names the
//! event row it was produced from, and the foreign key is enforced: a notification for an event
//! this journal has not taken cannot be written at all. Taking an event and producing from it are
//! two transactions, so a host that dies between them has the event and no notification, which is
//! the direction section 16 asks for. Nothing here compares timestamps to decide the order.
//!
//! **A consumer's cursor is committed with its effect.** Taking a page from either source writes
//! the de-duplication record, the notifications produced from it and the cursor in one
//! transaction. The upstream acknowledgement - `settle_announcements` for attention,
//! `note_outbox_consumed` for the worker outbox - happens after that transaction, so a crash in
//! between replays a page this journal already holds and the de-duplication record absorbs it.
//! Both consumers register before they rely on collection keeping anything for them.
//!
//! **Nothing about the work reaches a provider in the clear.** The alert is one of six sentences
//! from [`kr_protocol::push::PushAlert`]. The preview is sealed to the destination's
//! `notification_preview` key and to no other key. The collapse identifier is derived under a
//! secret this store holds, so it groups without naming. There is no field on the wire for text a
//! producer supplies.
//!
//! **External delivery is not private, and says so.** Section 19 and section 25 are explicit:
//! recipients of an external message can read it, and encrypted KalaReach routing does not change
//! that. Every external message carries that sentence, and nothing in this crate claims otherwise.

pub mod budget;
pub mod destination;
mod error;
pub mod external;
pub mod journal;
pub mod preview;
pub mod privacy;
pub mod producer;
pub mod push;

pub use crate::error::{DeliveryError, Result};
