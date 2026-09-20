//! The KalaReach voice coordinator.
//!
//! Section 2 ¶6 puts the voice coordinator on the host and gives voice processing an explicit
//! data-access boundary, separate from the encryption of terminal transport. This crate is that
//! coordinator, and the boundary is stated here and enforced by its types.
//!
//! # The data-access boundary
//!
//! **What the coordinator may read.** One thing: content a host has already passed through the
//! shared host-side history filter at `Surface::VoiceContext`, under a viewer scope built from the
//! requesting device's own grant. The seam that delivers it ([`ContextSource`]) takes that grant
//! and nothing else, so there is no shape of call that asks for the host owner's broader history.
//! The coordinator then applies the grant's history lower bound a second time to every item it was
//! handed: a caller that filtered incorrectly does not get its mistake past this crate.
//!
//! **What the coordinator may send.** The bounded selection of section 15 ¶12 — session
//! description, working directory, active application, pending decision summaries and the last
//! twenty semantic messages, capped at eight thousand text tokens — plus whatever content classes
//! the person explicitly selected. File contents, environment variables, raw terminal scrollback
//! and attachment bytes are excluded until selected, and the exclusion is a closed vocabulary
//! ([`kr_protocol::voice::VoiceContextClass`]) rather than a rule to remember. Configured secret
//! patterns are replaced on the way out; that is a **secondary** measure and this crate says so
//! beside every selection it produces, because filtering does not prove the remainder holds no
//! secrets.
//!
//! **Where it sends it.** To the paired client that asked, and nowhere else. The host does not
//! reach the managed broker with context: section 15 ¶9 routes selected context and host results
//! from the paired client to the broker as bounded context requests, and the only broker call this
//! crate makes is creating and ending the call itself.
//!
//! **What the managed operator can see.** The trusted sideband receives transcripts and reflected
//! audio, so the operator has technical access to the conversation even though media travels
//! directly between the device and the provider, and it can see whatever this host selected.
//! [`kr_protocol::voice::VOICE_DISCLOSURE`] is that statement, and a voice session carries it
//! where the choice is made rather than in a policy page.
//!
//! **What is never authority.** A transcript, a provider delegation identifier and a model
//! statement that the user agreed to something are all content, and section 19 says content is
//! never authority. Every effect this crate proposes is decided against a grant in the host's one
//! authority store, and the actions that need a confirmation on an unlocked screen need a
//! signature from the paired device's identity key, which no provider text can produce.
//!
//! # A voice session is not a shell session
//!
//! [`VoiceSessions`] holds voice sessions with their own identities and their own lives. Stopping
//! one revokes the voice grant it runs under, immediately and independently of the broker's
//! billing finalisation, and leaves every terminal session it reached running.
//!
//! # What this crate does not do
//!
//! It opens no store, holds no connection but the broker client, and performs no host effect. It
//! reads through [`ContextSource`], decides against the grants [`VoiceAuthority`] gives it, and
//! proposes through [`ActionSubmitter`]. The host implements those three, and the host's own
//! checks run afterwards exactly as they do for a typed request: the coordinator proposes and the
//! worker validates normally.

#![forbid(unsafe_code)]

/// The managed voice broker contract, re-exported.
///
/// A host that hosts this coordinator needs the broker's types to configure one, and re-exporting
/// them here is what keeps the dependency edge the one decision D-089 draws: `kr-controller`
/// depends on `kr-voice`, and `kr-voice` depends on `kr-client`.
pub use kr_client::services::voice as broker;

pub mod confirm;
pub mod context;
pub mod delegate;
pub mod error;
pub mod grant;
pub mod seams;
pub mod session;

pub use crate::confirm::{
    ConfirmationLedger, issue_confirmation, sign_confirmation, verify_confirmation,
};
pub use crate::context::{SecretPatterns, Selection, select_context, token_bound};
pub use crate::delegate::{Coordinator, Proposal, narrower_history};
pub use crate::error::{Result, VoiceError};
pub use crate::grant::{
    GrantBinding, VoiceGrantPlan, permits, permitted_actions, plan_voice_grant,
};
pub use crate::seams::{
    ActionSubmitter, ContextItem, ContextRequest, ContextSource, GatheredContext, HostReceipt,
    SelectedItem, VoiceAuthority, VoiceFuture, WithheldRun,
};
pub use crate::session::{NewVoiceSession, VoiceSessionRecord, VoiceSessions};
