//! What a candidate does when the room says that no host was attached to carry its first frame.
//!
//! The host reserves a code's locator and attaches to the locator's room in a task of its own, and
//! the room serves a candidate the record at once but closes the candidate's socket with `HostGone`
//! when it relays a frame and no host is attached. A device that enters the code as soon as the host
//! has issued it can reach the room first, so the pairing leg of the deployment checkpoint enters
//! the code again when, and only when, the room says so at the first frame, before anything of the
//! attempt can have reached a host.
//!
//! These cases run the device's own candidate exchange, through the product's frames and a socket
//! behind TLS a test issues, against a room that says `HostGone` as the deployed one does. No
//! deployment is involved.

#[path = "../../../../crates/kr-client/tests/support/room_tls.rs"]
mod room_tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kr_e2e_m1b::device::{Device, PairingStopped, Patience};
use kr_protocol::ids::InvitationId;
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::pairing::RendezvousOrigin;
use kr_protocol::rendezvous::{
    ClientFrame, CloseReason, ServiceFrame, decode_client_frame, encode_frame, encode_message,
};
use kr_protocol::scalars::Uuid;
use tokio_websockets::Message;

/// A code the device can parse: four characters of locator and six of secret.
const CODE: &str = "2tWk9mXyBq";

/// What the room does with the first frame an attempt relays.
#[derive(Clone, Copy)]
enum Meets {
    /// No host is attached: the socket is closed with `HostGone`.
    NoHost,
    /// A host answers, with a message that is not the one the device waits for.
    AHostThatAnswers,
}

/// A room whose n-th connection meets `script[n]`, or the last of it once the script is spent, and
/// how many connections it has had.
async fn room(
    authority: &room_tls::Authority,
    script: Vec<Meets>,
) -> (RendezvousOrigin, Arc<AtomicUsize>) {
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    let origin = room_tls::serve(authority, move |stream, _origin| {
        let nth = counted.fetch_add(1, Ordering::SeqCst);
        let meets = script
            .get(nth)
            .or_else(|| script.last())
            .copied()
            .expect("a script");
        candidate(stream, meets)
    })
    .await;
    (origin, connections)
}

/// One candidate's socket: the record first, as the deployed room sends it, then what `meets` says.
async fn candidate(stream: room_tls::Stream, meets: Meets) {
    let Some((_locator, _role, mut end)) = room_tls::upgrade(stream).await else {
        return;
    };
    let record = ServiceFrame::Record {
        invitation_id: InvitationId::new(Uuid::from_bytes([9; 16])),
        expires_at_ms: 1_764_003_600_000,
    };
    if end
        .send(Message::binary(encode_frame(&record).expect("a frame")))
        .await
        .is_err()
    {
        return;
    }
    while let Some(Ok(message)) = end.next().await {
        if message.is_close() {
            return;
        }
        if !message.is_binary() {
            continue;
        }
        let Ok(frame) = decode_client_frame(message.as_payload()) else {
            return;
        };
        let ClientFrame::Relay { attempt_id, .. } = frame else {
            continue;
        };
        let reply = match meets {
            Meets::NoHost => ServiceFrame::Closed {
                reason: CloseReason::HostGone,
            },
            Meets::AHostThatAnswers => ServiceFrame::Relay {
                attempt_id,
                payload: encode_message(&RendezvousMessage::BundleAccepted).expect("a message"),
            },
        };
        let closing = matches!(reply, ServiceFrame::Closed { .. });
        if end
            .send(Message::binary(encode_frame(&reply).expect("a frame")))
            .await
            .is_err()
        {
            return;
        }
        if closing {
            let _ = end.close().await;
            return;
        }
    }
}

/// A device that dials only rooms behind `authority`.
async fn device_trusting(authority: &room_tls::Authority, directory: &std::path::Path) -> Device {
    Device::create("a device", directory)
        .await
        .trusting(Arc::new(authority.client_config()))
}

/// The pauses are short here: the cases wait on the room's answers.
const PATIENCE: Patience = Patience {
    pause: Duration::from_millis(10),
    within: Duration::from_secs(120),
};

/// The attempt a leg makes once: the room closes it with `HostGone` at the first frame, which the
/// device reports as the host not being attached and not as a stop of the exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_room_that_says_no_host_is_attached_at_the_first_frame_ends_one_attempt_as_such() {
    let authority = room_tls::Authority::new("a room's authority");
    let (origin, connections) = room(&authority, vec![Meets::NoHost]).await;
    let directory = tempfile::tempdir().expect("a directory");
    let device = device_trusting(&authority, directory.path()).await;

    let stopped = device
        .enter_code(&origin, CODE)
        .await
        .expect_err("the room has no host");

    assert_eq!(stopped, PairingStopped::HostNotAttached);
    assert!(
        stopped.to_string().contains("HostGone"),
        "it says what the room said: {stopped}"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

/// The host attaches after the second try: the leg enters the code again, and the third try is
/// answered by a host, whatever it answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_entered_before_the_host_attached_is_entered_again_until_a_host_answers() {
    let authority = room_tls::Authority::new("a room's authority");
    let (origin, connections) = room(
        &authority,
        vec![Meets::NoHost, Meets::NoHost, Meets::AHostThatAnswers],
    )
    .await;
    let directory = tempfile::tempdir().expect("a directory");
    let device = device_trusting(&authority, directory.path()).await;

    let stopped = device
        .enter_code_once_the_host_is_attached(&origin, CODE, &PATIENCE)
        .await
        .expect_err("the host answers with a message the device did not wait for");

    assert!(
        matches!(&stopped, PairingStopped::Room(why) if why.contains("PAKE")),
        "the third try reached a host and stopped where the host's answer is not the device's \
         next message: {stopped}"
    );
    assert_eq!(
        connections.load(Ordering::SeqCst),
        3,
        "two tries met no host and the third was answered"
    );
}

/// No host is ever attached: the tries end when the device's budget of attempts for the code is
/// spent, and the leg is told how many times the room said so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_room_that_never_has_a_host_ends_the_tries_when_the_devices_attempts_are_spent() {
    let authority = room_tls::Authority::new("a room's authority");
    let (origin, _connections) = room(&authority, vec![Meets::NoHost]).await;
    let directory = tempfile::tempdir().expect("a directory");
    let device = device_trusting(&authority, directory.path()).await;

    let stopped = device
        .enter_code_once_the_host_is_attached(&origin, CODE, &PATIENCE)
        .await
        .expect_err("no host ever answers");

    assert!(
        matches!(stopped, PairingStopped::HostNeverAttached { times: 5, .. }),
        "five attempts are all a code is given: {stopped}"
    );
}
