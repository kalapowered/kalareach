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
//!
//! What the reader has taken from the connection is the holder's: closing or dropping the session
//! stops further reads and nothing else. Each notification already read, then the end, then the
//! channel's end still arrive, and the reader holds no lock while it waits for the holder to take
//! them.

use kr_protocol::envelope::Notification;
use kr_protocol::error::ProtocolError;
use tokio::sync::mpsc;

use crate::error::ClientError;

/// How a session's control stream ended, as the reader read it.
pub enum Ended {
    /// The stream ended without a failure. A transport returns this for this side's own close,
    /// which it knows by itself: the owner closed or dropped the session, which is how the reader
    /// tells the owner's close, or, on the local link, the transport closed itself after a write
    /// that a limit cut or that failed or was dropped part way (the call that cut the frame has
    /// the cause, and each later call fails before a byte). On the network it is also the host's
    /// clean end of the stream at a frame's boundary, and a close by this side counts only when
    /// the transport's own close was called: a close that the transport did not make (the
    /// endpoint's, under a live connection) is [`Ended::Failed`]. On the local link it is never
    /// the peer: the peer's end there is [`Ended::Failed`].
    Finished,
    /// Reading the stream failed: the transport's own failure, with what the transport said. On
    /// the local link every failed read is one, the peer's end at a frame's boundary included; on
    /// the network the peer's clean end is [`Ended::Finished`].
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
///
/// The holder drains it to its end or drops it when it is done: a holder that keeps it and reads
/// nothing keeps the session's reader task, with the closed transport, the session's state and
/// the item the reader waits to hand on, alive for as long as it keeps it.
pub struct OrderedEvents {
    receiver: mpsc::Receiver<Ordered>,
}

impl OrderedEvents {
    /// Waits for the next item. The end of the session's reading is the [`Ordered::Ended`] item,
    /// and the result is none right after it: the channel ends with the reader, whether or not the
    /// session, a lane or an answer that still holds the session's state lives. Closing or
    /// dropping the session loses none of what the reader had taken before: each notification,
    /// the end and then none still arrive, in that order.
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
