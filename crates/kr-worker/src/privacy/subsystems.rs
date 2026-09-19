//! The subsystems privacy mode reaches, each implementing the same contract.
//!
//! Two of them act on stores this crate owns and do the work outright. The other four are seams
//! for work that lives elsewhere: each carries the owner of the task that fills it in, and each
//! already answers the contract's four questions truthfully for what it can see. A stub that
//! answered "nothing outstanding" without knowing would be worse than no stub at all, so a seam
//! with no store behind it reports nothing to fence, nothing to cancel and nothing outstanding,
//! and says in its own documentation what will be true when its store exists.

use kr_protocol::scalars::TimestampMs;

use crate::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
};

/// Retained session output, over the session's own history.
///
/// This is the one section 24 names first: privacy mode disables content-history retention
/// prospectively and removes what is already retained. The spool and the resident window are the
/// content, and this is an adapter over them rather than a count of them: fencing stops the
/// capture, and removing takes the bytes.
///
/// Local deletion is logical cleanup. This host removes its own records and does not claim the
/// bytes are unrecoverable from the device they were on.
#[derive(Debug)]
pub struct RetainedHistory<'a> {
    history: &'a mut crate::history::OutputHistory,
    fenced: bool,
}

impl<'a> RetainedHistory<'a> {
    /// Builds the hook over one session's retained output.
    #[must_use]
    pub fn over(history: &'a mut crate::history::OutputHistory) -> Self {
        Self {
            history,
            fenced: false,
        }
    }

    /// Returns whether retention is fenced.
    #[must_use]
    pub const fn is_fenced(&self) -> bool {
        self.fenced
    }
}

impl PrivacySubsystem for RetainedHistory<'_> {
    fn name(&self) -> &'static str {
        "history"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        // The capture stops before the removal, so nothing is written behind the cleanup.
        self.fenced = true;
        self.history.stop_retaining();
        Fenced {
            queues: 1,
            items: 0,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        // Retained output is not dispatched anywhere. There is nothing to take back and nothing
        // in flight, and saying so is the honest answer rather than a count of nothing.
        Cancelled::default()
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        let (bytes, records) = self.history.discard_retained();
        Removed { bytes, records }
    }

    fn outstanding(&self) -> u64 {
        0
    }
}

/// The receipt journal: what privacy mode removes from it, and what it keeps.
///
/// A receipt is not all metadata. Its identity, state, revision, digests and deadline are, and
/// section 24 keeps them; the intent envelope the caller sent and the result the action produced
/// are the caller's own content, and a question's answer text lives in one of them. So this
/// removes those from receipts that have settled and keeps them for receipts that have not,
/// because recovery reads a pending envelope and a de-duplicated retry is answered from it.
#[derive(Debug)]
pub struct ReceiptMetadata<'a> {
    journal: Option<&'a mut crate::journal::Journal>,
    pending: u64,
    failure: Option<String>,
}

impl<'a> ReceiptMetadata<'a> {
    /// Builds the hook over one session's journal and its live pending questions and approvals.
    #[must_use]
    pub fn over(journal: Option<&'a mut crate::journal::Journal>, pending: u64) -> Self {
        Self {
            journal,
            pending,
            failure: None,
        }
    }

    /// Returns why the redaction could not finish, when it could not.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
}

impl PrivacySubsystem for ReceiptMetadata<'_> {
    fn name(&self) -> &'static str {
        "receipts"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        // A receipt does not travel anywhere on its own, so there is no queue here to stop. What
        // has to be taken out of it is taken by the removal below.
        Fenced::default()
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        // Cancelling an admitted action because privacy mode was enabled would be privacy mode
        // deciding what a caller's action does. It is not one of the four things section 24 asks
        // for, and the dispatch barrier is where an action is taken back.
        Cancelled::default()
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        let Some(journal) = self.journal.as_mut() else {
            return Removed::default();
        };
        match journal.redact_settled_content() {
            Ok(records) => Removed { bytes: 0, records },
            Err(error) => {
                // A store that refused the redaction has not done it, and this says so rather
                // than reporting a removal that did not happen. Reconciliation carries it.
                self.failure = Some(error.to_string());
                Removed::default()
            }
        }
    }

    fn outstanding(&self) -> u64 {
        // A redaction that failed is cleanup this host still owes.
        u64::from(self.failure.is_some())
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        let mut kept = vec![
            KeptExplicitly {
                what: "the receipt journal's operation metadata",
                why: "a host that forgot which actions it had admitted would dispatch a retry \
                      again, and could not tell a caller what its action did",
            },
            KeptExplicitly {
                what: "the minimal local authority this host holds",
                why: "a host that forgot its own authority could not refuse a withdrawn one",
            },
            KeptExplicitly {
                what: "the intent envelope of an action that has not settled",
                why: "recovery reads it, and a retry of an action this host may already have \
                      performed is answered from it",
            },
        ];
        if self.pending > 0 {
            kept.push(KeptExplicitly {
                what: "live pending questions and approvals",
                why: "they keep working under the grants they already have; their bodies are not \
                      exported as historical content",
            });
        }
        kept
    }
}

/// The transfer service's previews.
///
/// A preview is a decoded image of somebody's file, which is content, and the queue that holds
/// one is content-bearing. The store is `kr-transfer`'s, so what is here is the seam: the counts
/// come from the host that owns the service.
///
/// **Owner:** the transfer service's own privacy pass, which walks its drafts and previews. Until
/// it exists this reports what it is given, and a host that gives it nothing is a host with no
/// previews rather than one that has not looked.
#[derive(Debug, Default)]
pub struct TransferPreviews {
    previews: u64,
    undispatched: u64,
    in_flight: u64,
    fenced: bool,
}

impl TransferPreviews {
    /// Builds the seam over the previews and the work a host has counted.
    #[must_use]
    pub const fn new(previews: u64, undispatched: u64, in_flight: u64) -> Self {
        Self {
            previews,
            undispatched,
            in_flight,
            fenced: false,
        }
    }

    /// Records that one piece of in-flight work has been cleaned up.
    pub fn note_reconciled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

impl PrivacySubsystem for TransferPreviews {
    fn name(&self) -> &'static str {
        "transfer_previews"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        self.fenced = true;
        Fenced {
            queues: u64::from(self.previews > 0),
            items: self.previews,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: std::mem::take(&mut self.undispatched),
            in_flight: self.in_flight,
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        Removed {
            bytes: 0,
            records: std::mem::take(&mut self.previews),
        }
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
    }
}

/// Description inference.
///
/// A description is a model's account of somebody's screen, so the work is content-bearing on the
/// way out and the answer is content on the way back. Privacy mode disables it prospectively,
/// cancels what has not been sent, and refuses what comes back for what had been.
///
/// **Owner:** T-036's description service, which holds the queue and the model binding. The
/// late-result rule is the trait's own, so a description that returns under an older generation
/// is already refused by the contract rather than by that task remembering to.
#[derive(Debug, Default)]
pub struct DescriptionInference {
    queued: u64,
    in_flight: u64,
    generated: u64,
    fenced: bool,
}

impl DescriptionInference {
    /// Builds the seam over the work a host has counted.
    #[must_use]
    pub const fn new(queued: u64, in_flight: u64, generated: u64) -> Self {
        Self {
            queued,
            in_flight,
            generated,
            fenced: false,
        }
    }

    /// Records that one in-flight description has been reconciled.
    pub fn note_reconciled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

impl PrivacySubsystem for DescriptionInference {
    fn name(&self) -> &'static str {
        "description_inference"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        self.fenced = true;
        Fenced {
            queues: u64::from(self.queued > 0 || self.in_flight > 0),
            items: self.queued,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: std::mem::take(&mut self.queued),
            in_flight: self.in_flight,
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        // Generated descriptions go with the rest of the content. A pinned label a person wrote
        // is not one of these: section 24 keeps it locally unless it is explicitly cleared.
        Removed {
            bytes: 0,
            records: std::mem::take(&mut self.generated),
        }
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
    }
}

/// The sync outbox.
///
/// **Owner:** the client sync service. What is here is the contract it implements: a content
/// bearing outbox is fenced at once, its undispatched entries are cancelled, and what had already
/// been uploaded is shown rather than claimed to be erased.
#[derive(Debug, Default)]
pub struct SyncOutbox {
    queued: u64,
    in_flight: u64,
    uploaded: Vec<Exported>,
    fenced: bool,
}

impl SyncOutbox {
    /// Builds the seam over the work and the copies a host has counted.
    #[must_use]
    pub const fn new(queued: u64, in_flight: u64, uploaded: Vec<Exported>) -> Self {
        Self {
            queued,
            in_flight,
            uploaded,
            fenced: false,
        }
    }

    /// Records that one in-flight upload has been reconciled.
    pub fn note_reconciled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

impl PrivacySubsystem for SyncOutbox {
    fn name(&self) -> &'static str {
        "sync"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        self.fenced = true;
        Fenced {
            queues: 1,
            items: self.queued,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: std::mem::take(&mut self.queued),
            in_flight: self.in_flight,
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        Removed::default()
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
    }

    fn exported(&self) -> Vec<Exported> {
        self.uploaded.clone()
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![KeptExplicitly {
            what: "user-pinned labels",
            why: "section 24 keeps them locally unless they are explicitly cleared, and excludes \
                  them from later sync while privacy mode is on",
        }]
    }
}

/// The backup outbox.
///
/// **Owner:** the backup service. The same contract as the sync outbox, over a different queue.
#[derive(Debug, Default)]
pub struct BackupOutbox {
    queued: u64,
    in_flight: u64,
    archives: Vec<Exported>,
    fenced: bool,
}

impl BackupOutbox {
    /// Builds the seam over the work and the archives a host has counted.
    #[must_use]
    pub const fn new(queued: u64, in_flight: u64, archives: Vec<Exported>) -> Self {
        Self {
            queued,
            in_flight,
            archives,
            fenced: false,
        }
    }

    /// Records that one in-flight backup has been reconciled.
    pub fn note_reconciled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

impl PrivacySubsystem for BackupOutbox {
    fn name(&self) -> &'static str {
        "backup"
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        self.fenced = true;
        Fenced {
            queues: 1,
            items: self.queued,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: std::mem::take(&mut self.queued),
            in_flight: self.in_flight,
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        Removed::default()
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
    }

    fn exported(&self) -> Vec<Exported> {
        self.archives.clone()
    }
}

/// A subsystem that records what it was asked, for the tests of the contract itself.
#[derive(Debug)]
pub struct Recording {
    name: &'static str,
    fenced: bool,
    cancelled: bool,
    in_flight: u64,
}

impl Recording {
    /// Builds one with nothing in flight.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            fenced: false,
            cancelled: false,
            in_flight: 0,
        }
    }

    /// Builds one with work still in flight.
    #[must_use]
    pub const fn with_in_flight(name: &'static str, in_flight: u64) -> Self {
        Self {
            name,
            fenced: false,
            cancelled: false,
            in_flight,
        }
    }

    /// Records that one piece of in-flight work has been reconciled.
    pub fn note_reconciled(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Returns whether this subsystem was cancelled.
    #[must_use]
    pub const fn was_cancelled(&self) -> bool {
        self.cancelled
    }
}

impl PrivacySubsystem for Recording {
    fn name(&self) -> &'static str {
        self.name
    }

    fn fence(&mut self, _generation: PrivacyGeneration) -> Fenced {
        self.fenced = true;
        Fenced {
            queues: 1,
            items: 0,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        // The order matters, so it is checked rather than assumed: a cancellation that ran before
        // this subsystem was fenced reports nothing taken back, and the test sees it.
        if !self.fenced {
            return Cancelled::default();
        }
        self.cancelled = true;
        Cancelled {
            undispatched: 1,
            in_flight: self.in_flight,
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        Removed::default()
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
    }
}

/// Builds an exported copy this host holds a reference it can delete through.
///
/// `deletable` is a fact about the reference rather than about the copy: it says this host has a
/// way to ask for that object's removal, not that removal will succeed or that no other copy
/// exists. A host reporting a copy it cannot reach builds an [`Exported`] with `deletable` false.
#[must_use]
pub fn exported(kind: &str, reference: &str, left_at_ms: TimestampMs) -> Exported {
    Exported {
        kind: kind.to_owned(),
        reference: reference.to_owned(),
        left_at_ms,
        deletable: true,
    }
}
