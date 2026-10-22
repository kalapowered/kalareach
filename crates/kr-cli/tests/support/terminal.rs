//! A terminal's output as a test collects it, and the replies the terminal owes the questions its
//! program asks.
//!
//! The command's capability handshake with the terminal it runs on has one second in all. A
//! terminal answers in microseconds, so a test that stands for one answers as fast: the reply is
//! typed by the thread that collects what the terminal is sent, the moment the question has
//! arrived. A thread that looks from time to time is woken late on a machine under load or under a
//! coarse timer, and the question's second runs out while it sleeps.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The writing end of a terminal, shared by whoever types into it.
pub type Keys = Arc<Mutex<Box<dyn Write + Send>>>;

/// Shares a terminal's writer, which a pseudo-terminal hands out once.
#[must_use]
pub fn keys(writer: Box<dyn Write + Send>) -> Keys {
    Arc::new(Mutex::new(writer))
}

/// What a terminal has been sent, and the replies it still owes.
#[derive(Debug, Default)]
pub struct Transcript {
    /// Every byte the terminal has been sent, as it was sent.
    pub bytes: Vec<u8>,
    owed: Vec<Owed>,
    /// Set when the terminal's output has ended, so that no question is going to arrive.
    ended: bool,
}

impl Transcript {
    /// Takes the replies whose question has arrived, leaving the rest owed.
    fn take_due(&mut self) -> Vec<Owed> {
        let (due, waiting) = std::mem::take(&mut self.owed)
            .into_iter()
            .partition(|owed| owed.is_due(&self.bytes));
        self.owed = waiting;
        due
    }
}

/// A reply a terminal types the moment the question it answers has arrived.
#[derive(Debug)]
struct Owed {
    question: &'static [u8],
    reply: Vec<u8>,
    keys: Keys,
    typed: Sender<bool>,
}

impl Owed {
    fn is_due(&self, sent: &[u8]) -> bool {
        sent.windows(self.question.len())
            .any(|window| window == self.question)
    }

    /// Types the reply, and says whether the terminal took it.
    fn type_into(self) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        let typed = keys
            .write_all(&self.reply)
            .and_then(|()| keys.flush())
            .is_ok();
        let _ = self.typed.send(typed);
    }
}

/// A terminal's transcript, which a thread of its own fills.
pub type Collected = Arc<Mutex<Transcript>>;

/// Collects what `reader` produces on a thread of its own, and types the replies owed as the
/// questions they answer arrive.
#[must_use]
pub fn collect(mut reader: Box<dyn Read + Send>) -> Collected {
    let collected = Collected::default();
    let seen = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            let due = {
                let mut transcript = seen.lock().unwrap_or_else(PoisonError::into_inner);
                transcript.bytes.extend_from_slice(&buffer[..read]);
                transcript.take_due()
            };
            for owed in due {
                owed.type_into();
            }
        }
        // Once the output has ended a question that has not come is not going to: whoever waits
        // for its reply is told so, and so is whoever asks to wait after this.
        let mut transcript = seen.lock().unwrap_or_else(PoisonError::into_inner);
        transcript.ended = true;
        transcript.owed.clear();
    });
    collected
}

/// Everything the terminal has been sent so far.
#[must_use]
pub fn bytes(collected: &Collected) -> Vec<u8> {
    collected
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .bytes
        .clone()
}

/// A reply a terminal owes, which [`Answering::typed_within`] waits for.
#[derive(Debug)]
pub struct Answering(Receiver<bool>);

impl Answering {
    /// Whether the reply was typed within `within`. It is not when the terminal's output ended
    /// without the question, when the terminal would not take the reply, and when the question did
    /// not come in time.
    #[must_use]
    pub fn typed_within(self, within: Duration) -> bool {
        self.0.recv_timeout(within).unwrap_or(false)
    }
}

/// Types `reply` through `keys` the moment `question` is among the bytes sent, or at once when it
/// already is.
#[must_use]
pub fn reply_to(
    collected: &Collected,
    question: &'static [u8],
    reply: &[u8],
    keys: &Keys,
) -> Answering {
    let (typed, outcome) = channel();
    let owed = Owed {
        question,
        reply: reply.to_vec(),
        keys: Arc::clone(keys),
        typed,
    };
    let mut transcript = collected.lock().unwrap_or_else(PoisonError::into_inner);
    if owed.is_due(&transcript.bytes) {
        drop(transcript);
        owed.type_into();
    } else if !transcript.ended {
        transcript.owed.push(owed);
    }
    Answering(outcome)
}
