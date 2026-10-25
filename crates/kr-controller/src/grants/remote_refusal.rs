//! The refusals the authority feed puts on remote grants, as one word.
//!
//! Three of them stand on every remote grant: this host is behind its feed, this host waits for the
//! person at this machine to confirm a policy it found restored, and the feed shows a withdrawal
//! this host cannot verify. A fourth, the feed's removal of this host, stands by kind of
//! grant. The word mirrors the policy's flags and is changed with them under the policy's lock,
//! because a check that runs inside a transaction cannot take that lock again. Everything that
//! commits on a remote device's authority reads it there: a request admitted before a refusal rose
//! does not complete under the standing it had, and nor does an owner confirmation a remote owner
//! device signed, which is spent under the standing of that device's pairing grant.

use std::sync::atomic::{AtomicU8, Ordering};

use super::Refusal;

/// Which of the refusals on remote grants stand now.
///
/// One word, so a reader sees them in one reading.
#[derive(Debug, Default)]
pub struct RemoteRefusal(AtomicU8);

impl RemoteRefusal {
    /// The bit that stands while this host is behind its feed.
    pub(crate) const BEHIND_ITS_FEED: u8 = 1;
    /// The bit that stands while the feed shows a withdrawal this host cannot verify.
    pub(crate) const WITHDRAWAL_UNVERIFIED: u8 = 2;
    /// The bit that stands once the feed has answered that it removed this host. Unlike the two
    /// above it refuses by kind of grant.
    pub(crate) const FEED_REMOVED: u8 = 4;
    /// The bit that says personal grants rest on the feed now, which is what makes the removal
    /// refuse them: it mirrors the policy, and is changed with it.
    pub(crate) const PERSONAL_GRANTS_REST_ON_THE_FEED: u8 = 8;
    /// The bit that stands while this host waits for the person at this machine to confirm the
    /// policy it holds, which it found restored from an earlier state.
    pub(crate) const RESTORED_POLICY_WAITS: u8 = 16;

    /// A word with `bits` standing.
    #[must_use]
    pub(crate) const fn with(bits: u8) -> Self {
        Self(AtomicU8::new(bits))
    }

    /// The word as it stands.
    #[must_use]
    pub(crate) fn word(&self) -> u8 {
        self.0.load(Ordering::SeqCst)
    }

    /// Makes `bits` stand.
    pub(crate) fn raise(&self, bits: u8) {
        self.0.fetch_or(bits, Ordering::SeqCst);
    }

    /// Ends `bits`.
    pub(crate) fn lower(&self, bits: u8) {
        self.0.fetch_and(!bits, Ordering::SeqCst);
    }

    /// The refusal that stands on every remote grant now, if one does: being behind the feed, a
    /// restored policy that waits for the person at this machine, or a withdrawal this host cannot
    /// verify. The feed's removal of this host is not among them,
    /// because it refuses by kind of grant ([`Self::standing_of`]).
    #[must_use]
    pub fn standing(&self) -> Option<Refusal> {
        self.standing_of(None)
    }

    /// The refusal that stands now for `grant`, if one does: the three that stand on every remote
    /// grant, and the feed's removal of this host when `grant` rests on the feed. That is an
    /// organisation's grant, and a personal one while personal grants rest on the feed. No grant is
    /// no removal.
    ///
    /// The word is read once, so the answer is one reading of the refusals.
    #[must_use]
    pub fn standing_of(&self, grant: Option<&kr_protocol::grant::Grant>) -> Option<Refusal> {
        let word = self.word();
        if word & Self::BEHIND_ITS_FEED != 0 {
            Some(Refusal::BehindItsFeed)
        } else if word & Self::RESTORED_POLICY_WAITS != 0 {
            Some(Refusal::RestoredPolicyWaits)
        } else if word & Self::WITHDRAWAL_UNVERIFIED != 0 {
            Some(Refusal::WithdrawalUnverified)
        } else if word & Self::FEED_REMOVED != 0
            && grant.is_some_and(|grant| {
                grant.organisation.is_present()
                    || word & Self::PERSONAL_GRANTS_REST_ON_THE_FEED != 0
            })
        {
            Some(Refusal::AuthorityFeedRemoved)
        } else {
            None
        }
    }
}
