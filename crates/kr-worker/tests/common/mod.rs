//! What the suites that drive a real session share: how a test waits, and how it makes the
//! application write the next thing.
//!
//! Each of these suites runs a real shell in a real pseudo-terminal and reads what arrives at a
//! real client, so each of them needs the same two things. The first is a way to know what the
//! session has already seen, which is the retained output: the history and the canonical grid are
//! two views of one stream, written under one lock in that order, so a marker visible in the
//! history has already been through the engine and whatever follows can attach, subscribe or read
//! a presentation knowing it. The second is a way to make the application write, which is the
//! input lease and a keystroke over it.
//!
//! Neither is a length of time. A fixture that prints on a timetable of its own and a test that
//! hopes to arrive between two of its lines are two clocks racing, and the machine decides which
//! wins: the shell's `sleep` is real time and does not slow down under load, while everything the
//! test does - starting a service, connecting, attaching, building a screen - does. A fixture that
//! waits for a line is not a clock at all.

#![allow(
    dead_code,
    reason = "each test binary compiles the whole module and uses the part of it that suite needs"
)]

use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{
    ActionId, AttachmentId, EnvironmentId, InputLeaseEpoch, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_worker::runtime::SessionRuntime;

/// How long a wait for something to happen is given.
///
/// A liveness bound is not a measurement: it is what a test that never reaches its condition fails
/// at, rather than hanging. The five, ten and thirty second windows these waits used to have were
/// inside the range the slowest host this suite runs on reaches when a dozen other suites share
/// it, which turned each of them into a coin toss; two minutes is outside it. A wait that succeeds
/// costs what it always did.
pub const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns whether `haystack` carries `needle`.
pub fn carries(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Returns how many times `haystack` carries `needle`.
pub fn carried_times(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Reads everything the session has retained of what the application wrote.
pub fn retained(runtime: &SessionRuntime) -> Vec<u8> {
    let session = runtime.session();
    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = session
            .history_page(cursor, 1024 * 1024)
            .expect("reads the retained output");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        seen.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    seen
}

/// Waits until `marker` is in the session's retained output.
///
/// This is the ordinary way a test waits for an application to have written something, because an
/// application's own pace is the machine's business and never the test's.
///
/// A marker names what the *terminal* carried, which is not byte for byte what the application
/// printed: the line discipline turns each line feed into a carriage return and a line feed, so a
/// line the application ended with `\n` arrives as `\r\n`. A marker carries the line ending whole,
/// because one stopping short of it would be satisfied while a line feed that has still to scroll
/// the grid is on its way.
pub async fn produced(runtime: &SessionRuntime, marker: &[u8]) {
    produced_times(runtime, marker, 1).await;
}

/// Waits until the session's retained output carries `marker` `count` times.
///
/// The same wait as [`produced`] for an application that writes the same thing more than once, or
/// for a host that answers the same question more than once: the second answer is not the first,
/// and a test waiting for "an answer" would go on from the one that had already arrived.
pub async fn produced_times(runtime: &SessionRuntime, marker: &[u8], count: usize) {
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    loop {
        let seen = retained(runtime);
        if carried_times(&seen, marker) >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {:?} for {count} of {} in the session's retained output, which carries {} of \
             them and ends {}",
            started.elapsed(),
            String::from_utf8_lossy(marker).escape_debug(),
            carried_times(&seen, marker),
            String::from_utf8_lossy(&seen[seen.len().saturating_sub(512)..]).escape_debug()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The input lease one attachment holds, which is how a test makes an application write.
///
/// It is the lease rather than a client of its own, because the attachment that has to hold the
/// keys is often the one the test is watching: a side effect has one destination, and that
/// destination is whoever holds these.
pub struct Keys {
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
}

/// Takes the input lease for an attachment that asked for input when it attached.
pub async fn take_the_keys(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    session_id: SessionId,
    attachment_id: AttachmentId,
) -> Keys {
    let lease: InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &InputAcquireParams {
                session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the lease is granted")
        .to_typed()
        .expect("decodes");
    Keys {
        attachment_id,
        epoch: lease.lease.epoch,
        sequence: 0,
    }
}

impl Keys {
    /// The attachment these keys belong to.
    pub const fn attachment(&self) -> AttachmentId {
        self.attachment_id
    }

    /// Types `bytes` into the application through the lease this attachment holds.
    ///
    /// The keystrokes go through the session's own input path rather than over the socket the
    /// lease was taken on, because a client that is waiting for an answer to a call of its own
    /// drops the notifications that arrive while it waits: it asked for one thing and something
    /// else arrived. The attachment that types here is usually the attachment the test is reading,
    /// and everything the host queued for it - the screen it was drawn, the output that followed -
    /// is exactly what would be dropped. This is the same call the worker makes when it handles a
    /// keystroke from a socket, with the lease this attachment really holds.
    pub fn type_bytes(&mut self, runtime: &SessionRuntime, bytes: &[u8]) {
        let accepted = {
            let mut session = runtime.session();
            session
                .write_input(
                    self.attachment_id,
                    self.epoch.get(),
                    self.sequence,
                    bytes,
                    None,
                    Instant::now(),
                )
                .expect("the keystrokes are accepted")
        };
        assert_eq!(
            accepted.forwarded_bytes,
            bytes.len() as u64,
            "the host took every byte of {} rather than holding any back",
            String::from_utf8_lossy(bytes).escape_debug()
        );
        self.sequence += 1;
        // Outside the session, because the batches are sent to the terminal while the session is
        // held and a second caller holding it would have nowhere to go.
        runtime.flush_input();
    }

    /// Releases the next step of an application that is waiting for a line.
    pub fn release(&mut self, runtime: &SessionRuntime) {
        self.type_bytes(runtime, b"\n");
    }
}
