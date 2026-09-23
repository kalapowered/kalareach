//! What the bridge has told a session and no check has taken yet.

use std::collections::VecDeque;

use kr_shell_integration::contract::events::{BridgeEvent, ReaderIdle};

use super::{Received, name_of_event};

/// Whether this event is one of the two decisions the worker manages the gesture with.
#[must_use]
pub fn is_managed_decision(event: &BridgeEvent) -> bool {
    matches!(
        event,
        BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
    )
}

/// The events a session has been told and no check has taken, with a count of the managed
/// decisions among everything that arrived since the last boundary.
///
/// Every wait takes what it was waiting for and drops what stood in front of it, which is what
/// makes a run of waits read as a sequence: each asks for the next thing the reader does. A
/// managed decision cannot go that way, because the check that rejects one runs after waits that
/// could have dropped it. So each is counted here as it arrives, and the count goes only at
/// [`Inbox::boundary`], where a check says it is done with everything before. The queue belongs to
/// this type: nothing reaches it except through [`Inbox::arrive`], and nothing takes an event off
/// it without the count still holding what that event was.
#[derive(Default)]
pub struct Inbox {
    queue: VecDeque<Received>,
    managed_decisions: usize,
}

impl Inbox {
    /// Takes one event in, in the order the endpoint delivered it.
    pub fn arrive(&mut self, received: Received) {
        if is_managed_decision(&received.event) {
            self.managed_decisions += 1;
        }
        self.queue.push_back(received);
    }

    /// Takes the first event `accept` takes, and drops everything in front of it.
    pub fn take_first(&mut self, accept: impl Fn(&Received) -> bool) -> Option<Received> {
        let position = self.queue.iter().position(accept)?;
        self.queue.drain(..position);
        self.queue.pop_front()
    }

    /// Takes the next report of the reader's, with the lifecycle count it was stamped with.
    ///
    /// What is in front of it is dropped, and where no report is waiting everything is: each call
    /// asks for the next thing the reader said about itself.
    pub fn take_reader_report(&mut self) -> Option<(ReaderIdle, u64)> {
        while let Some(received) = self.queue.pop_front() {
            if let BridgeEvent::ReaderIdle(idle) = received.event {
                return Some((idle, received.reader_lifetime));
            }
        }
        None
    }

    /// Drops every event, and the count of managed decisions with them.
    ///
    /// This is the one place the count goes. A check that draws a boundary says it is done with
    /// everything before it, so nothing before it may count against what the check claims next.
    pub fn boundary(&mut self) {
        self.queue.clear();
        self.managed_decisions = 0;
    }

    /// How many managed decisions arrived since the last boundary, wherever they are now.
    #[must_use]
    pub fn managed_decisions(&self) -> usize {
        self.managed_decisions
    }

    /// The events still waiting, by name, for a failure that says what did arrive.
    #[must_use]
    pub fn waiting(&self) -> Vec<&'static str> {
        self.queue
            .iter()
            .map(|received| name_of_event(&received.event))
            .collect()
    }
}
