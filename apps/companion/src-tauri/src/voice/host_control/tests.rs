//! The device's half of a host-controlled call, against a host that answers as scripted. Time is
//! paused: every bound here is read from the clock the control itself reads, and nothing sleeps.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::scalars::U64;
use kr_protocol::voice::VoiceDelegationId;
use kr_protocol::voice_host::{VoiceNews, VoiceNewsItem, VoiceProviderClose};

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
    Answer(VoiceControlAnswer),
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
    ) -> LinkFuture<'a, VoiceControlAnswer> {
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
    Step::Answer(VoiceControlAnswer::Heartbeat {
        state: VoiceHostCallState::Open,
        remaining_seconds: 1_700,
        news,
        dropped: false,
        provider_close: Nullable::null(),
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
    // The second beat repeats an item the device already holds: it is told once. The wait ends just
    // after the third beat went.
    tokio::time::sleep_until(Instant::now() + 2 * BEAT + Duration::from_millis(1)).await;
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
    assert!(
        events.news.try_recv().is_err(),
        "news already held is told again"
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
    let attached_at = Instant::now();
    // The second beat is not answered: its miss tells nothing. The clock is taken through the beat
    // and the miss, to just after the miss.
    tokio::time::sleep_until(attached_at + BEAT + MISS + Duration::from_secs(1)).await;
    assert!(
        events.news.try_recv().is_err(),
        "a single miss was told to the person"
    );
    // The third beat comes back as an error: the second miss is told, once.
    assert_eq!(next(&mut events).await, HostNews::Detached);
    // The fourth is not answered either: the same outage is not told twice. The clock is taken
    // through its miss.
    tokio::time::sleep_until(attached_at + 3 * BEAT + MISS + Duration::from_secs(1)).await;
    assert!(
        events.news.try_recv().is_err(),
        "the same outage was told twice"
    );
    // The fifth is answered: the notice is taken back.
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
    tokio::time::sleep_until(heard_at + SILENT - Duration::from_millis(1)).await;
    assert!(
        events.news.try_recv().is_err(),
        "the control ended before the bound"
    );
    tokio::time::sleep_until(heard_at + SILENT + Duration::from_millis(1)).await;
    assert_eq!(
        events.news.try_recv(),
        Ok(HostNews::Ended(HostEnding::Silent)),
        "the control did not end at the bound"
    );
    assert!(events.next().await.is_none(), "news followed the end");
}

#[tokio::test(start_paused = true)]
async fn a_heartbeat_the_host_refuses_and_a_closed_call_end_the_control_with_their_reason() {
    let refused = Script::new([Step::Answer(VoiceControlAnswer::Refused {
        reason: VoiceHostRefusal::UnknownCall,
    })]);
    let (_control, mut events) = HostControl::open(refused, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Ended(HostEnding::NotKnown(VoiceHostRefusal::UnknownCall))
    );
    assert!(events.next().await.is_none());

    let closed = Script::new([Step::Answer(VoiceControlAnswer::Heartbeat {
        state: VoiceHostCallState::Closed {
            reason: VoiceEndReason::ProviderClosed,
        },
        remaining_seconds: 0,
        news: Vec::new(),
        dropped: true,
        provider_close: Nullable::some(VoiceProviderClose::Confirmed),
    })]);
    let (_control, mut events) = HostControl::open(closed, voice_session(), limits());
    assert_eq!(
        next(&mut events).await,
        HostNews::Attached { reattached: false }
    );
    assert_eq!(next(&mut events).await, HostNews::Dropped);
    assert_eq!(
        next(&mut events).await,
        HostNews::Ended(HostEnding::Reason {
            reason: VoiceEndReason::ProviderClosed,
            provider_close: VoiceProviderClose::Confirmed,
        })
    );
    assert!(events.next().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_closed_heartbeat_tells_the_providers_close_on_the_ended_item_and_on_the_state_alone() {
    let ended_item = |seq| VoiceNews {
        seq: U64::new(seq),
        item: VoiceNewsItem::Ended {
            reason: VoiceEndReason::Deadline,
        },
    };
    let closed = |news: Vec<VoiceNews>, provider_close| {
        Script::new([Step::Answer(VoiceControlAnswer::Heartbeat {
            state: VoiceHostCallState::Closed {
                reason: VoiceEndReason::Deadline,
            },
            remaining_seconds: 0,
            news,
            dropped: false,
            provider_close,
        })])
    };
    let told = |word| {
        HostNews::Ended(HostEnding::Reason {
            reason: VoiceEndReason::Deadline,
            provider_close: word,
        })
    };
    // The word is the heartbeat's own, so the same item is told by the word beside it, and a state
    // that carries no item is told by it as well. A word that is missing is no confirmation.
    for (news, word, expected) in [
        (
            vec![ended_item(1)],
            Nullable::some(VoiceProviderClose::Confirmed),
            VoiceProviderClose::Confirmed,
        ),
        (
            vec![ended_item(1)],
            Nullable::some(VoiceProviderClose::Unconfirmed),
            VoiceProviderClose::Unconfirmed,
        ),
        (
            Vec::new(),
            Nullable::some(VoiceProviderClose::Confirmed),
            VoiceProviderClose::Confirmed,
        ),
        (
            Vec::new(),
            Nullable::some(VoiceProviderClose::Unconfirmed),
            VoiceProviderClose::Unconfirmed,
        ),
        (
            Vec::new(),
            Nullable::null(),
            VoiceProviderClose::Unconfirmed,
        ),
    ] {
        let (_control, mut events) =
            HostControl::open(closed(news, word), voice_session(), limits());
        assert_eq!(
            next(&mut events).await,
            HostNews::Attached { reattached: false }
        );
        assert_eq!(next(&mut events).await, told(expected));
        assert!(events.next().await.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn a_note_a_mute_and_a_question_about_a_delegation_are_written_as_the_arms_the_host_reads() {
    let script = Script::new([
        Step::Hang,
        Step::Answer(VoiceControlAnswer::Admitted {
            note: Nullable::some(VoiceNote::DelegationAdmitted),
        }),
        Step::Answer(VoiceControlAnswer::Admitted {
            note: Nullable::null(),
        }),
        Step::Answer(VoiceControlAnswer::Heard {
            offset_ms: U64::new(1_250),
        }),
        Step::Answer(VoiceControlAnswer::NotHeard),
        Step::Answer(VoiceControlAnswer::Refused {
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
    // The first step is the heartbeat that goes at once; the case's own writes follow it.
    let script = Script::new([
        Step::Hang,
        Step::Hang,
        Step::Hang,
        Step::Fail(LinkError::NotSent),
    ]);
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
    let ours = ActionId::new(kr_ipc::new_uuid());
    let queued = control
        .send_context(ours, session, None)
        .await
        .expect("the host queued it");
    assert_eq!(queued.appends, 3);
    assert_eq!(
        queued.action_id, ours,
        "the news about the send names the caller's identity"
    );
    assert_eq!(
        control
            .send_context(ActionId::new(kr_ipc::new_uuid()), session, None)
            .await,
        Err(HostSendError::Refused(Some(VoiceHostRefusal::Busy)))
    );
    control.stop();
}

fn poll_limits() -> PollLimits {
    PollLimits {
        beat: Duration::from_secs(1),
        within: Duration::from_secs(40),
        request_within: Duration::from_secs(20),
    }
}

fn closing_beat() -> Step {
    Step::Answer(VoiceControlAnswer::Heartbeat {
        state: VoiceHostCallState::Closing,
        remaining_seconds: 0,
        news: Vec::new(),
        dropped: false,
        provider_close: Nullable::null(),
    })
}

fn closed_beat(word: VoiceProviderClose) -> Step {
    Step::Answer(VoiceControlAnswer::Heartbeat {
        state: VoiceHostCallState::Closed {
            reason: VoiceEndReason::Stop,
        },
        remaining_seconds: 0,
        news: vec![VoiceNews {
            seq: U64::new(1),
            item: VoiceNewsItem::Ended {
                reason: VoiceEndReason::Stop,
            },
        }],
        dropped: false,
        provider_close: Nullable::some(word),
    })
}

fn acknowledges_nothing(script: &Script) -> bool {
    script.seen().iter().all(|(_, params)| {
        matches!(
            &params.arm,
            VoiceControlArm::Heartbeat { after_seq } if after_seq.get() == 0
        )
    })
}

#[tokio::test(start_paused = true)]
async fn a_look_for_the_final_status_asks_again_while_the_host_closes_and_offers_the_word_it_holds()
{
    for word in [
        VoiceProviderClose::Confirmed,
        VoiceProviderClose::Unconfirmed,
    ] {
        let script = Script::new([closing_beat(), closing_beat(), closed_beat(word)]);
        let evidence = CloseEvidence::default();
        final_close_word(&*script, voice_session(), &evidence, poll_limits()).await;
        assert_eq!(evidence.get(), Some(word));
        assert_eq!(
            script.seen().len(),
            3,
            "asked again until the host's status was final"
        );
        assert!(
            acknowledges_nothing(&script),
            "the look acknowledges nothing, so the status stays for later reads"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_look_asks_again_after_a_request_that_was_not_sent_or_whose_answer_was_lost() {
    let script = Script::new([
        Step::Fail(LinkError::NotSent),
        Step::Fail(LinkError::Unknown),
        closed_beat(VoiceProviderClose::Confirmed),
    ]);
    let evidence = CloseEvidence::default();
    final_close_word(&*script, voice_session(), &evidence, poll_limits()).await;
    assert_eq!(evidence.get(), Some(VoiceProviderClose::Confirmed));
    assert_eq!(script.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_look_ends_with_no_word_when_the_host_holds_no_such_call_or_refuses_or_does_not_answer() {
    let ends = [
        Step::Answer(VoiceControlAnswer::Refused {
            reason: VoiceHostRefusal::UnknownCall,
        }),
        Step::Fail(LinkError::Refused("no".to_owned())),
        Step::Answer(VoiceControlAnswer::NotHeard),
        Step::Hang,
    ];
    for step in ends {
        let script = Script::new([step]);
        let evidence = CloseEvidence::default();
        final_close_word(&*script, voice_session(), &evidence, poll_limits()).await;
        assert_eq!(evidence.get(), None);
        assert_eq!(script.seen().len(), 1, "no second request");
    }
}

#[tokio::test(start_paused = true)]
async fn a_look_is_cut_at_its_bound_whatever_the_request_that_is_waiting_then_is_doing() {
    // The host is still closing the call at every look until the last, which begins at 39 seconds
    // and is never answered: it would be given 20 seconds more, and is cut at 40.
    let mut steps: Vec<Step> = (0..39).map(|_| closing_beat()).collect();
    steps.push(Step::Hang);
    let script = Script::new(steps);
    let evidence = CloseEvidence::default();
    let began = Instant::now();
    final_close_word(&*script, voice_session(), &evidence, poll_limits()).await;
    assert_eq!(evidence.get(), None);
    assert_eq!(script.seen().len(), 40);
    assert_eq!(began.elapsed(), Duration::from_secs(40));
}

#[tokio::test(start_paused = true)]
async fn a_look_ends_at_its_next_turn_when_the_news_has_offered_the_word_meanwhile() {
    let evidence = CloseEvidence::default();
    // A word that was in the evidence before the look began needs no request at all.
    let known = Script::new([closing_beat()]);
    evidence.offer(VoiceProviderClose::Confirmed);
    final_close_word(&*known, voice_session(), &evidence, poll_limits()).await;
    assert!(known.seen().is_empty());

    let evidence = CloseEvidence::default();
    let script = Script::new([closing_beat(), closing_beat()]);
    let heard = evidence.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        heard.offer(VoiceProviderClose::Unconfirmed);
    });
    final_close_word(&*script, voice_session(), &evidence, poll_limits()).await;
    assert_eq!(script.seen().len(), 1, "the second request was not needed");
    assert_eq!(evidence.get(), Some(VoiceProviderClose::Unconfirmed));
    // The first word stands: a later offer changes nothing.
    evidence.offer(VoiceProviderClose::Confirmed);
    assert_eq!(evidence.get(), Some(VoiceProviderClose::Unconfirmed));
}
