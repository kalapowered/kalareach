//! An ordered delivery of one session's notifications to its owner.
//!
//! A session hands its notifications on through a broadcast that never waits: a holder that reads
//! slowly loses the oldest, and the cursors drop a sequence that goes back, which a host that
//! numbers every delivery from zero does after a resubscription. A holder that must see every
//! notification, in the order the host sent them, and know how the connection ended, starts its
//! session with [`crate::session::Session::start_ordered`]: the session's reader then hands each
//! notification to it through one bounded channel, whole and in wire order, and waits while that
//! channel is full.
//!
//! What waits with it: while the channel is full the reader reads nothing from the connection, so
//! the answers to requests, the renewals of the action window and the host's refusal of the
//! connection wait too. The holder keeps draining the channel while any call waits for its answer.
//! A holder that awaits a call and does not drain stalls itself.
//!
//! The broadcast and the cursors see every notification as they do on any session, and the
//! session keeps everything else it reads for itself: answers, receipts and window renewals never
//! reach the channel.

use kr_protocol::envelope::Notification;
use kr_protocol::error::ProtocolError;
use tokio::sync::mpsc;

use crate::error::ClientError;

/// How a session's control stream ended, as the reader read it.
pub enum Ended {
    /// The host finished its side of the stream and sent nothing more.
    Finished,
    /// Reading the stream failed: the transport's own failure.
    Failed(ClientError),
    /// The host refused the connection, and said why. The refusal comes before the end on the
    /// stream, so it is complete when this is delivered.
    Refused(ProtocolError),
    /// The host sent a frame that a client may not receive, and the session ended on it.
    Unexpected,
}

/// What the ordered channel carries.
pub enum Ordered {
    /// A notification, exactly as the host sent it.
    Notification(Notification),
    /// The end of the session's reading. Every notification read before it was delivered before
    /// it, and nothing follows it.
    Ended(Ended),
}

crate::debug_as_name!(Ended, Ordered, OrderedEvents);

/// The notifications of one session, in the order the host sent them.
pub struct OrderedEvents {
    receiver: mpsc::Receiver<Ordered>,
}

impl OrderedEvents {
    /// Waits for the next item. The end of the session's reading is the [`Ordered::Ended`] item,
    /// and nothing comes after it. The result is none only once the session has been dropped and
    /// the channel is drained.
    pub async fn recv(&mut self) -> Option<Ordered> {
        self.receiver.recv().await
    }
}

/// The reader's end of the ordered channel.
pub(crate) struct OrderedSender {
    sender: mpsc::Sender<Ordered>,
}

impl OrderedSender {
    /// Hands a notification on, and waits while the channel is full. A holder that dropped its end
    /// is not waited for: the reader goes on reading, as the broadcast goes on with no receiver.
    pub(crate) async fn deliver(&self, notification: Notification) {
        let _ = self.sender.send(Ordered::Notification(notification)).await;
    }

    /// Hands the end on, behind everything delivered before it.
    pub(crate) async fn end(&self, ended: Ended) {
        let _ = self.sender.send(Ordered::Ended(ended)).await;
    }
}

/// A channel that holds `capacity` items, and at least one.
pub(crate) fn channel(capacity: usize) -> (OrderedSender, OrderedEvents) {
    let (sender, receiver) = mpsc::channel(capacity.max(1));
    (OrderedSender { sender }, OrderedEvents { receiver })
}
