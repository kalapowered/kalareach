//! Reading one's own mailbox: the open half of section 20, in one place.
//!
//! A host and a device each read the mailbox their stored-envelope key addresses, and each opens
//! what it finds under the same rules. Those rules are security checks, so they are written once,
//! here, and both readers call them; what a reader keeps for itself is where its records live, how
//! it reaches the service, how it waits, and what it does with what it took.
//!
//! # What an item has to pass
//!
//! An item is taken only if it opens against the stored-envelope key of a sender the reader has
//! paired and whose pairing is in force ([`Reading::senders`]), under
//! [`kr_crypto::envelope::open_delivered_envelope`]: the routing record outside the envelope is
//! untrusted and must match what the box authenticated, the expiry must not have passed at the
//! moment the item is opened, an identifier the reader has accepted before is refused, and a
//! payload that bears authority is refused whoever sealed it. Anything else is dropped.
//!
//! # What is durable, and in which order
//!
//! The identifier of an item the reader accepts is written down ([`Reading::record`]) before the
//! reader acts on the item and before the service is told the page may be removed. A reader that
//! stops between the two reads the item again and refuses it as a replay, and then acknowledges
//! it. No item the reader accepted leaves the service before it is on record; an item it dropped
//! leaves it without a record, because nothing it could be replayed to do is done. When a write
//! fails the page is not acknowledged: the items before the failure are handed over with
//! [`Reading::taken`], and the pass ends with the reader's own error.
//!
//! A caller that drops a pass, as a deadline does, gets the same order, and with it a limit. An
//! item whose write finished before the drop is on record, and is never accepted again, but it is
//! handed over only if the pass reached the end of its page: the write of a later item on the page
//! may be what the pass was waiting for. So [`Reading::taken`] tells a reader what a pass took, and
//! a reader must not rely on it for anything that has to happen once for every item on record.
//! A write that is already running on another thread finishes after the drop. A reader whose
//! records must stay exact when its pass is dropped has to finish the page before it applies a
//! deadline.
//!
//! # One pass
//!
//! A pass reads the mailbox page by page from the start, because everything before the cursor the
//! service holds has already been acknowledged, and ends when a page says there is no more, or
//! after [`MOST_PAGES`] pages, so a mailbox that fills as fast as it is read does not hold the
//! pass for ever. The paired set and the replay ledger are read again at the start of each pass,
//! from the reader's own records: an identifier that was not written down is not one the pass
//! remembers, and a sender whose pairing has ended is no sender.

use std::future::Future;

use kr_crypto::envelope::{PairedSenders, ReplayLedger, open_delivered_envelope};
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::{EnvelopePlaintext, replay_id_retained_until_ms};

use crate::error::ClientError;
use crate::services::mailbox::MailboxClient;

/// The most pages one pass reads before it ends.
pub const MOST_PAGES: usize = 16;

/// What a reader supplies to the pass: whom it trusts, what it has accepted, and where it writes.
pub trait Reading: Sync {
    /// What the reader's own records fail with.
    type Error: Send;

    /// The time on the reader's clock, in UTC milliseconds. It is read for each item, because the
    /// expiry is judged at the moment the item is opened and not at the start of the pass, which
    /// may be a page of exchanges ago.
    fn now_ms(&self) -> u64;

    /// The senders this reader has paired with and whose pairing is in force, read from its
    /// records now. A reader that cannot read them fails: an empty set from a record that could
    /// not be read would drop every item and acknowledge it.
    fn senders(&self) -> impl Future<Output = Result<PairedSenders, Self::Error>> + Send;

    /// The identifiers this reader has accepted, as its durable record holds them at `now_ms`,
    /// with every identifier whose retention has ended forgotten.
    fn ledger(&self, now_ms: u64)
    -> impl Future<Output = Result<ReplayLedger, Self::Error>> + Send;

    /// Writes down that the item `id` was accepted and may be forgotten at `retained_until_ms`.
    /// The write is on the disk when this returns `Ok`.
    fn record(
        &self,
        id: EnvelopeId,
        retained_until_ms: u64,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Hands over what one page yielded, once for each page that held items, after its last write
    /// and before the page is acknowledged or the pass ends on a failed write. Everything in
    /// [`Page::accepted`] is on record. A pass that is dropped before the end of its page hands
    /// that page over never, though the items already written stay on record.
    fn taken(&self, page: Page);
}

/// What one page of the mailbox yielded.
///
/// It has no `Debug`: the plaintexts it holds are what a mailbox delivered, and a formatted page
/// would print them.
#[derive(Default)]
pub struct Page {
    /// The items that opened and are on record, in the order the service held them.
    pub accepted: Vec<EnvelopePlaintext>,
    /// How many items did not open and were dropped.
    pub dropped: usize,
}

/// How a pass that did not fail ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The service said there was nothing more.
    ReadThrough,
    /// [`MOST_PAGES`] pages were read and the service held more.
    PageLimit,
}

/// Why a pass stopped.
#[derive(Debug)]
pub enum Stop<E> {
    /// The service could not be reached, refused a request, or answered something this client
    /// cannot read. The pass has acknowledged nothing it did not read.
    Service(ClientError),
    /// The reader's own records could not be read or written. The service is not at fault.
    Local(E),
}

/// Reads one pass of the mailbox `key` addresses, through `client`, for `reading`.
///
/// The client claims the mailbox on the first read if it is unclaimed, with the private half of
/// `key`; a mailbox another key has claimed is refused.
///
/// # Errors
///
/// Returns [`Stop::Service`] when the service fails or refuses, and [`Stop::Local`] when the
/// reader's records cannot be read or written.
pub async fn read_mailbox<R: Reading>(
    client: &MailboxClient,
    key: &StoredEnvelopeKeyPair,
    reading: &R,
) -> Result<Outcome, Stop<R::Error>> {
    let senders = reading.senders().await.map_err(Stop::Local)?;
    let mut ledger = reading
        .ledger(reading.now_ms())
        .await
        .map_err(Stop::Local)?;

    for _ in 0..MOST_PAGES {
        let page = client.read_as(key, None).await.map_err(Stop::Service)?;
        let Some(last) = page.items.last().map(|item| item.sequence.get()) else {
            return Ok(Outcome::ReadThrough);
        };

        let mut yielded = Page::default();
        let mut unwritten = None;
        for item in &page.items {
            match open_delivered_envelope(
                key,
                &senders,
                &mut ledger,
                &item.envelope,
                reading.now_ms(),
            ) {
                Ok(plaintext) => {
                    let until = replay_id_retained_until_ms(plaintext.expires_at_ms.get());
                    if let Err(error) = reading.record(plaintext.envelope_id, until).await {
                        unwritten = Some(error);
                        break;
                    }
                    yielded.accepted.push(plaintext);
                }
                Err(_) => yielded.dropped += 1,
            }
        }
        // What is on record is acted on even when a later item on the page could not be written
        // down: that item is read again, and nothing is acknowledged until it is.
        reading.taken(yielded);
        if let Some(error) = unwritten {
            return Err(Stop::Local(error));
        }
        // Everything on the page is written down or dropped, so the service may remove it.
        client
            .acknowledge(key.public(), last)
            .await
            .map_err(Stop::Service)?;
        if !page.more {
            return Ok(Outcome::ReadThrough);
        }
    }
    Ok(Outcome::PageLimit)
}
