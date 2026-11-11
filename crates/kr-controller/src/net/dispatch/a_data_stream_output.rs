//! The write boundary of a data stream, beside the control stream's.
//!
//! A connection has one authority, and so one latch: the boundary of each of its data streams and
//! the boundary of its control stream read it, and a withdrawal through any of them stops them all.
//! A data stream is also taken away by itself, when a newer stream replaces it or the control
//! stream is lost, and that ends the stream and leaves the connection and its other streams alone.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::ids::ActorId;

use super::output::{FrameSink, RemoteOutput, Written};
use super::write_boundary::authority_for;

/// A stream whose peer does not read: a write on it waits until the stream is revoked, and what
/// it holds of a frame never reaches the peer.
#[derive(Debug)]
struct DataStreamSink {
    /// One permit each time a write begins to wait.
    waiting: tokio::sync::Semaphore,
    revoked: tokio::sync::watch::Sender<bool>,
    /// The frames that reached the peer whole.
    written: std::sync::Mutex<Vec<ControlFrame>>,
    closed: AtomicBool,
}

impl DataStreamSink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            waiting: tokio::sync::Semaphore::new(0),
            revoked: tokio::sync::watch::channel(false).0,
            written: std::sync::Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        })
    }

    /// Returns once a write has begun to wait.
    async fn waited(&self) {
        self.waiting
            .acquire()
            .await
            .expect("the count stays open")
            .forget();
    }

    fn revoke(&self) {
        self.revoked.send_replace(true);
    }

    fn written(&self) -> usize {
        self.written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl FrameSink for Arc<DataStreamSink> {
    fn send_while<'a>(
        &'a self,
        frame: &'a ControlFrame,
        admits: kr_transport::codec::Admission<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            self.waiting.add_permits(1);
            let mut revoked = self.revoked.subscribe();
            // A revoked stream fails the write as a transport's does, and never refuses it.
            if revoked.wait_for(|revoked| *revoked).await.is_ok() {
                return Err(kr_transport::TransportError::ControlLost);
            }
            Ok(admits(&mut || {
                self.written
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(frame.clone());
            }))
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// A stream that takes every frame the authority lets go.
#[derive(Debug, Default)]
struct ControlSink {
    written: std::sync::Mutex<usize>,
}

impl FrameSink for Arc<ControlSink> {
    fn send_while<'a>(
        &'a self,
        _frame: &'a ControlFrame,
        admits: kr_transport::codec::Admission<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(async move {
            Ok(admits(&mut || {
                *self
                    .written
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            }))
        })
    }

    fn close(&self) {}
}

fn frame() -> ControlFrame {
    ControlFrame::Event(ControlEvent::Keepalive)
}

/// The two boundaries of one connection: its control stream's and one data stream's, built on one
/// authority as a connection builds them.
fn boundaries(
    controller: &Arc<crate::service::Controller>,
) -> (
    RemoteOutput,
    Arc<ControlSink>,
    RemoteOutput,
    Arc<DataStreamSink>,
) {
    let authority = authority_for(
        controller,
        ActorId::new("device:test").expect("a principal"),
    );
    let control_sink = Arc::new(ControlSink::default());
    let data_sink = DataStreamSink::new();
    let control =
        RemoteOutput::writing_to(Box::new(Arc::clone(&control_sink)), Arc::clone(&authority));
    let data = RemoteOutput::writing_to(Box::new(Arc::clone(&data_sink)), authority);
    (control, control_sink, data, data_sink)
}

/// A write on a data stream that waits for a peer which does not read stops when the connection is
/// withdrawn through the control stream's boundary, and nothing is written to the stream after it:
/// the two boundaries share the connection's latch. The control is a data stream that is revoked
/// with the latch not set: its write fails, the connection stands, and the control stream's
/// boundary goes on writing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_stream_write_stops_with_the_connection_and_a_revoked_stream_leaves_it_standing() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::super::tests::daemon(&temp).await;

    let (control, control_sink, data, data_sink) = boundaries(&controller);
    let frame = frame();
    let (written, ()) = tokio::join!(data.write(&frame, &[], None), async {
        data_sink.waited().await;
        control.withdraw();
    });
    assert_eq!(
        written,
        Written::Withdrawn,
        "a write waiting on a data stream stops when the connection is withdrawn"
    );
    assert_eq!(data_sink.written(), 0, "nothing reaches the stream");
    assert!(
        !control.send(&frame).await,
        "the withdrawn connection writes nothing more on its control stream either"
    );
    assert_eq!(*control_sink.written.lock().unwrap(), 0);

    let (control, control_sink, data, data_sink) = boundaries(&controller);
    let (written, ()) = tokio::join!(data.write(&frame, &[], None), async {
        data_sink.waited().await;
        data_sink.revoke();
    });
    assert_eq!(
        written,
        Written::Withdrawn,
        "a revoked data stream ends the write"
    );
    assert!(
        !data_sink.closed.load(Ordering::Acquire)
            && !control.authority.latch.load(Ordering::Acquire),
        "and withdraws nothing: the stream's loss is not the connection's"
    );
    assert!(
        control.send(&frame).await,
        "the connection's control stream goes on writing"
    );
    assert_eq!(*control_sink.written.lock().unwrap(), 1);
}
