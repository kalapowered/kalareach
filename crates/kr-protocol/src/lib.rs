//! The KalaReach wire contract.
//!
//! Rust is canonical. Every wire type lives here as a serde type; the JSON Schema in
//! `packages/protocol/schema/` and the TypeScript package are generated from these types and
//! checked in continuous integration, so the two languages cannot drift.
//!
//! # Two representations, one contract
//!
//! Each type has one canonical wire form and one JSON form:
//!
//! * The wire form is KR-CBOR-1 (see the `kr-cbor` crate). Identifiers are 16-byte strings,
//!   counters are unsigned 64-bit integers, timestamps are integer UTC milliseconds and text is
//!   valid UTF-8. Signatures and digests always cover these bytes.
//! * The JSON form is the managed HTTP representation. Identifiers are hyphenated text, opaque
//!   bytes are unpadded base64url and counters are decimal strings so a JavaScript consumer cannot
//!   lose precision. Nothing is ever signed from JSON.
//!
//! [`scalars`] implements both forms; every other module builds on them.
//!
//! # Modules
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`scalars`] | Identifier, counter, timestamp and byte-string scalars, and `Nullable` |
//! | [`ids`] | One type per identifier in the identity and object model |
//! | [`rights`] | The closed action-right vocabulary |
//! | [`actor`] | The host-constructed verified actor envelope and its ingress classes |
//! | [`grant`] | Grants, selectors, history scope, expiry and the delegation rule |
//! | [`authority`] | The authority vocabulary every method entry is written in |
//! | [`method`] | The method registry: one exhaustive entry per method, and the deny rule |
//! | [`envelope`] | Request, mutation, response and notification envelopes |
//! | [`receipt`] | Receipt states and the transition contract |
//! | [`relay`] | Relay leases, consumption receipts and relay instance registration |
//! | [`error`] | Error codes, retry categories and the error object |
//! | [`frame`] | Stream headers and the length-delimited frame codec |
//! | [`hello`] | Version negotiation and the `kr-connect/1` proof transcript |
//! | [`pairing`] | Pairing contexts, bundles, transcripts, QR payloads and owner confirmation |
//! | [`mailbox`] | Stored mailbox envelopes and their size buckets |
//! | [`service`] | The credential every managed-service method authenticates with |
//! | [`push`] | Push registration, sender authorisation and delivery |
//! | [`archive`] | Backup key wraps, manifests, descriptors and recovery material |
//! | [`account`] | Membership leases and the organisation policy-signing authority chain |
//! | [`digest`] | The mutation payload digest |
//! | [`limits`] | Protocol defaults |
//! | [`local`] | The local IPC handshake and the control-stream message union |
//! | [`identity`] | Boot, process-start and worker-profile identities |
//! | [`session`] | The session lifecycle, closure records and the session method group |
//! | [`attachment`] | Attachments, geometry ownership and the attachment method group |
//! | [`input`] | The single input lease and the input method group |
//! | [`root`] | The trusted root integration: the editor fence, its events and the launch transaction |
//! | [`recovery`] | Subscriptions, snapshots, history pages and resynchronisation |
//! | [`semantic`] | The semantic snapshot's bounds and the continuation that stands where they stop |
//! | [`hostinfo`] | Host and environment reads, and read-only diagnostics |
//! | [`worker`] | Worker descriptors, the startup rendezvous, the verify challenge and the generation token |
//! | [`schema`] | Deterministic JSON Schema and method-table generation |
//! | [`vectors`] | The cross-language vectors under `fixtures/service` and `fixtures/push` |
//!
//! # What this crate does not do
//!
//! It carries no transport, no cryptography and no storage. It defines the types those layers
//! exchange, the rules a receiver can check without any of them, and the digests they sign.
//!
//! # Example
//!
//! ```
//! use kr_protocol::actor::ActorIngress;
//! use kr_protocol::authority::{AuthorityDecision, DenialReason, EffectClass};
//! use kr_protocol::method::{MethodVersion, decide};
//!
//! // A listed method resolves to its exhaustive authority entry.
//! let decision = decide("session.read", MethodVersion::V1, ActorIngress::PairedDevice);
//! let AuthorityDecision::Listed(entry) = decision else {
//!     unreachable!("session.read is listed");
//! };
//! assert_eq!(entry.effect, EffectClass::Read);
//!
//! // Anything unlisted is denied, and private IPC methods are unreachable from the network.
//! assert_eq!(
//!     decide("host.shutdown", MethodVersion::V1, ActorIngress::PairedDevice),
//!     AuthorityDecision::Denied(DenialReason::UnlistedMethod)
//! );
//! assert_eq!(
//!     decide("root.editor.enter", MethodVersion::V1, ActorIngress::PairedDevice),
//!     AuthorityDecision::Denied(DenialReason::ForbiddenIngress {
//!         ingress: ActorIngress::PairedDevice
//!     })
//! );
//! ```

pub mod account;
pub mod actor;
pub mod archive;
pub mod attachment;
pub mod authority;
pub mod digest;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod grant;
pub mod hello;
pub mod hostinfo;
pub mod identity;
pub mod ids;
pub mod input;
pub mod limits;
pub mod local;
pub mod mailbox;
pub mod method;
pub mod pairing;
pub mod push;
pub mod receipt;
pub mod recovery;
pub mod relay;
pub mod rights;
pub mod root;
pub mod scalars;
pub mod schema;
pub mod semantic;
pub mod service;
pub mod session;
pub mod sync;
pub mod vectors;
pub mod worker;
