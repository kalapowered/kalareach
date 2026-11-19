//! The device's half of a host-controlled call, against a host that answers as scripted. Time is
//! paused: every bound here is read from the clock the control itself reads, and nothing sleeps.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::scalars::U64;
use kr_protocol::voice::VoiceDelegationId;
use kr_protocol::voice_host::{VoiceNews, VoiceNewsItem};

use super::*;

const BEAT: Duration = Duration::from_secs(20);
const MISS: Duration = Duration::from_secs(10);
const SILENT: Duration = Duration::from_secs(120);

fn limits() -> HostLimits {
    HostLimits {
        beat: BEAT,
        miss_after: MISS,
        silent_after: SILENT,
        within: Duration::from_secs(20),
    }
}

/// Limits under which no second heartbeat is sent within a case, so the case's own writes are the
/// only ones the host is scripted for.
fn quiet() -> HostLimits {
    HostLimits {
        beat: Duration::from_secs(3_600),
        silent_after: Duration::from_secs(7_200),
        ..limits()
    }
}

/// What the host does with one write.
enum Step {
    Answer(VoiceControlResult),
    Hang,
    Fail(LinkError),
}

/// A host that answers each `voice.control` as scripted and keeps what it was sent.
struct Script {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<(ActionId, VoiceControlParams)>>,
    context: Mutex<VecDeque<std::result::Result<VoiceContextSendResult, LinkError>>>,
}

impl Script {
    fn new(steps: impl IntoIterator<Item = Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into_iter().collect()),
            seen: Mutex::new(Vec::new()),
            context: Mutex::new(VecDeque::new()),
        })
    }

    fn seen(&self) -> Vec<(ActionId, VoiceControlParams)> {
        self.seen.lock().expect("the record").clone()
    }
}

impl HostLink for Script {
    fn control<'a>(
        &'a self,
        action_id: ActionId,
        params: &'a VoiceControlParams,
    ) -> LinkFuture<'a, VoiceControlResult> {
        self.seen
            .lock()
            .expect("the record")
            .push((action_id, params.clone()));
        let step = self.steps.lock().expect("the script").pop_front();
        Box::pin(async move {
            match step {
                Some(Step::Answer(answer)) => Ok(answer),
                Some(Step::Fail(error)) => Err(error),
                Some(Step::Hang) | None => std::future::pending().await,
            }
        })
    }

    fn send_context<'a>(
        &'a self,
        _action_id: ActionId,
        _params: &'a VoiceContextSendParams,
    ) -> LinkFuture<'a, VoiceContextSendResult> {
        let answer = self
            .context
            .lock()
            .expect("the script")
            .pop_front()
            .unwrap_or(Err(LinkError::NotSent));
        Box::pin(async move { answer })
    }
}

fn voice_session() -> VoiceSessionId {
    VoiceSessionId::new(kr_ipc::new_uuid())
}

fn open_beat(news: Vec<VoiceNews>) -> Step {
    Step::Answer(VoiceControlResult::Heartbeat {
        state: VoiceHostCallState::Open,
        remaining_seconds: 1_700,
        news,
        dropped: false,
    })
}

fn heard(seq: u64, id: &str, offset: u64) -> VoiceNews {
    VoiceNews {
        seq: U64::new(seq),
        item: VoiceNewsItem::Delegation {
            delegation_id: VoiceDelegationId::new(id).expect("an identifier"),
            offset_ms: U64::new(offset),
        },
    }
}

/// Reads the next piece of news, giving the control the time it asks for.
async fn next(events: &mut HostEvents) -> HostNews {
    events.next().await.expect("the control told something")
}

#[tokio::test(start_paused = true)]
async fn a_heartbeat_goes_at_once_under_a_fresh_action_and_acknowledges_the_news_it_holds() {
    let script = Script::new([
        open_beat(vec![heard(1, "d-1", 400), heard(2, "d-2", 900)]),
        open_beat(vec![heard(2, "d-2", 900)]),
        open_beat(Vec::new()),
    ]);
    let (control, mut events) = HostControl::open(script.clone(), voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: false }
    );
    assert_eq!(
        next(&mut events).await,
        HostNews::Delegation {
            delegation_id: "d-1".to_owned(),
            offset_ms: 400
        }
    );
    assert_eq!(
        next(&mut events).await,
        HostNews::Delegation {
            delegation_id: "d-2".to_owned(),
            offset_ms: 900
        }
    );
    // The second beat repeats an item the device already holds: it is told once.
    tokio::time::advance(BEAT).await;
    tokio::time::advance(BEAT).await;
    tokio::task::yield_now().await;
    assert!(
        events.news.try_recv().is_err(),
        "news already held is told again"
    );
    control.stop();
    let seen = script.seen();
    assert!(seen.len() >= 3, "{} heartbeats were sent", seen.len());
    let after: Vec<u64> = seen
        .iter()
        .map(|(_, params)| match &params.arm {
            VoiceControlArm::Heartbeat { after_seq } => after_seq.get(),
            other => panic!("not a heartbeat: {other:?}"),
        })
        .collect();
    assert_eq!(
        &after[..3],
        &[0, 2, 2],
        "each beat acknowledges what arrived"
    );
    let mut ids: Vec<ActionId> = seen.iter().map(|(id, _)| *id).collect();
    ids.dedup();
    assert_eq!(
        ids.len(),
        seen.len(),
        "a heartbeat reused an action identifier"
    );
}

#[tokio::test(start_paused = true)]
async fn two_heartbeats_in_a_row_that_get_no_answer_are_told_once_and_an_answer_takes_it_back() {
    let script = Script::new([
        open_beat(Vec::new()),
        Step::Hang,
        Step::Fail(LinkError::Unknown),
        Step::Hang,
        open_beat(Vec::new()),
    ]);
    let (control, mut events) = HostControl::open(script, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: false }
    );
    // The second beat, at 20 s, is not answered: its miss is counted at 30 s and tells nothing.
    tokio::time::advance(Duration::from_secs(35)).await;
    tokio::task::yield_now().await;
    assert!(
        events.news.try_recv().is_err(),
        "a single miss was told to the person"
    );
    // The third beat, at 40 s, comes back as an error: the second miss is told, once.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(next(&mut events).await, HostNews::Detached);
    // The fourth, at 60 s, is not answered either: the same outage is not told twice.
    tokio::time::advance(Duration::from_secs(25)).await;
    tokio::task::yield_now().await;
    assert!(
        events.news.try_recv().is_err(),
        "the same outage was told twice"
    );
    // The fifth, at 80 s, is answered: the notice is taken back.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: true }
    );
    control.stop();
}

#[tokio::test(start_paused = true)]
async fn a_host_not_heard_for_two_minutes_ends_the_control_at_that_moment_and_not_before() {
    let script = Script::new([open_beat(Vec::new())]);
    let (_control, mut events) = HostControl::open(script, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: false }
    );
    let heard_at = Instant::now();
    // Two misses are told; nothing ends the call before the bound.
    assert_eq!(next(&mut events).await, HostNews::Detached);
    assert!(
        Instant::now() - heard_at < SILENT,
        "the control ended before the bound"
    );
    assert_eq!(next(&mut events).await, HostNews::Ended(HostEnding::Silent));
    assert_eq!(
        Instant::now() - heard_at,
        SILENT,
        "the control ended at another moment than the bound"
    );
    assert!(events.next().await.is_none(), "news followed the end");
}

#[tokio::test(start_paused = true)]
async fn a_heartbeat_the_host_refuses_and_a_closed_call_end_the_control_with_their_reason() {
    let refused = Script::new([Step::Answer(VoiceControlResult::Refused {
        reason: VoiceHostRefusal::UnknownCall,
    })]);
    let (_control, mut events) = HostControl::open(refused, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Ended(HostEnding::NotKnown(VoiceHostRefusal::UnknownCall))
    );
    assert!(events.next().await.is_none());

    let closed = Script::new([Step::Answer(VoiceControlResult::Heartbeat {
        state: VoiceHostCallState::Closed {
            reason: VoiceEndReason::ProviderClosed,
        },
        remaining_seconds: 0,
        news: Vec::new(),
        dropped: true,
    })]);
    let (_control, mut events) = HostControl::open(closed, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: false }
    );
    assert_eq!(next(&mut events).await, HostNews::Dropped);
    assert_eq!(
        next(&mut events).await,
        HostNews::Ended(HostEnding::Reason(VoiceEndReason::ProviderClosed))
    );
    assert!(events.next().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_note_a_mute_and_a_question_about_a_delegation_are_written_as_the_arms_the_host_reads() {
    let script = Script::new([
        Step::Hang,
        Step::Answer(VoiceControlResult::Admitted {
            note: Nullable::some(VoiceNote::DelegationAdmitted),
        }),
        Step::Answer(VoiceControlResult::Admitted {
            note: Nullable::null(),
        }),
        Step::Answer(VoiceControlResult::Heard {
            offset_ms: U64::new(1_250),
        }),
        Step::Answer(VoiceControlResult::NotHeard),
        Step::Answer(VoiceControlResult::Refused {
            reason: VoiceHostRefusal::AlreadyTold,
        }),
    ]);
    let (control, _events) = HostControl::open(script.clone(), voice_session(), quiet());
    tokio::task::yield_now().await;
    assert_eq!(
        control
            .note(VoiceNote::DelegationAdmitted, Some("d-1"))
            .await,
        Ok(())
    );
    assert_eq!(control.mute(true).await, Ok(()));
    assert_eq!(control.heard("d-1").await, Ok(Some(1_250)));
    assert_eq!(control.heard("d-2").await, Ok(None));
    assert_eq!(
        control
            .note(VoiceNote::DelegationAdmitted, Some("d-1"))
            .await,
        Err(HostSendError::Refused(Some(VoiceHostRefusal::AlreadyTold)))
    );
    let arms: Vec<VoiceControlArm> = script.seen().into_iter().map(|(_, p)| p.arm).collect();
    assert!(matches!(arms[0], VoiceControlArm::Heartbeat { .. }));
    assert!(matches!(
        &arms[1],
        VoiceControlArm::Note { note: VoiceNote::DelegationAdmitted, delegation_id }
            if delegation_id.as_ref().is_some_and(|id| id.as_str() == "d-1")
    ));
    assert!(matches!(arms[2], VoiceControlArm::Mute { muted: true }));
    assert!(
        matches!(&arms[3], VoiceControlArm::Heard { delegation_id } if delegation_id.as_str() == "d-1")
    );
    control.stop();
}

#[tokio::test(start_paused = true)]
async fn a_write_the_host_does_not_answer_is_unanswered_after_its_bound_and_one_never_sent_is_not()
{
    let script = Script::new([Step::Hang, Step::Hang, Step::Fail(LinkError::NotSent)]);
    let (control, _events) = HostControl::open(script, voice_session(), quiet());
    tokio::task::yield_now().await;
    assert_eq!(control.mute(true).await, Err(HostSendError::Unanswered));
    assert_eq!(
        control.note(VoiceNote::NothingWasDone, Some("d-1")).await,
        Err(HostSendError::Unanswered)
    );
    assert_eq!(control.mute(false).await, Err(HostSendError::NotSent));
    // An identifier the host would refuse is not written at all.
    assert_eq!(
        control.note(VoiceNote::NothingWasDone, Some("")).await,
        Err(HostSendError::NotSent)
    );
    control.stop();
}

#[tokio::test(start_paused = true)]
async fn a_context_send_is_queued_with_its_identity_or_refused_with_the_hosts_reason() {
    let script = Script::new([]);
    {
        let mut context = script.context.lock().expect("the script");
        context.push_back(Ok(VoiceContextSendResult::Queued { appends: 3 }));
        context.push_back(Ok(VoiceContextSendResult::Refused {
            reason: VoiceHostRefusal::Busy,
        }));
    }
    let (control, _events) = HostControl::open(script, voice_session(), quiet());
    let session = SessionId::new(kr_ipc::new_uuid());
    let queued = control
        .send_context(session, None)
        .await
        .expect("the host queued it");
    assert_eq!(queued.appends, 3);
    assert_eq!(
        control.send_context(session, None).await,
        Err(HostSendError::Refused(Some(VoiceHostRefusal::Busy)))
    );
    control.stop();
}
