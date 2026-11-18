//! Pairing admission, from the client's side: what it asks the managed service for, what it keeps,
//! and what it never does.
//!
//! A device that holds no lease with a host cannot reach it through a managed relay, so as it dials
//! it asks the managed service for an admission (section 17's bounded bootstrap allowance, drawn
//! from the free-service abuse budget). The service here is the stand-in held to the Worker's
//! source, over the client's real credential, so what is checked is the request the Worker reads and
//! the answers it gives. What the cache keeps is decided by a clock the test moves.
//!
//! The vector is pinned here and in `infra/relay/vectors/admission.json` in the website repository,
//! where the service rebuilds the same bytes from the JSON it receives.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::pairing::{FailureKind, PairingFailure};
use kr_client::retry::UserAction;
use kr_client::services::admission::RelayAdmissionIssueBody;
use kr_client::services::{
    AdmissionAnswer, AdmissionClock, AdmissionRequest, Alternatives, LeaseRequest,
    ManagedPairingAdmission, ManagedRelayLeaseService, PairingAdmissionService, PairingAdmissions,
    RelayDirection, RelayLeaseService, RelayRefusal, ServiceFuture, ServiceHttp, ServiceHttpAnswer,
    ServiceSigner,
};
use kr_client::{ClientError as Error, Result};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::pairing::{NetworkConfig, NetworkHint};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Nullable, Signature64};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::{AdmissionBehaviour, Moment, ServiceWeb};

/// An answer that the service is unable, naming `delay` and the paths that still work.
fn unable(delay: Option<u64>) -> Result<AdmissionAnswer> {
    Ok(AdmissionAnswer::Unavailable {
        message: "Managed capacity for new pairing invitations is not available now.".to_owned(),
        alternatives: STILL_WORK.iter().map(|path| (*path).to_owned()).collect(),
        retry_after_seconds: delay,
    })
}

/// A request that got no answer.
fn no_answer() -> Result<AdmissionAnswer> {
    Err(Error::refusal(
        ErrorCode::ResourceUnavailable,
        "no answer".into(),
    ))
}

/// A request that got no answer, and was refused with a delay to wait before the same request is
/// sent again, as a service's refusal says when it names one.
fn no_answer_for(delay: u64) -> Result<AdmissionAnswer> {
    Err(Error::Refused {
        error: ProtocolError::new(ErrorCode::ResourceUnavailable, "no answer".to_owned()),
        retry_after_seconds: Some(delay),
        action: UserAction::Wait,
        service_code: None,
        alternatives: Alternatives::default(),
    })
}

/// What [`waits_at`] finds at each of `probes` for a service that gives `script`, the last of which
/// repeats.
async fn waits_for(
    script: Vec<Result<AdmissionAnswer>>,
    probes: &[u64],
) -> Vec<(u64, usize, Option<u64>)> {
    let clock = AdmissionClock::standing();
    let service = Scripted::new(script);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    waits_at(&service, &clock, &admissions, probes).await
}

/// KR-REQ-17.48: a request that fails lifts the time the answer is kept to the time the device asks
/// again, so that no failed dial between them is told nothing, and the answer stops at that time and
/// not after it. The answer names 50 seconds and is kept to 60; the request at 50 fails, and the
/// device asks again at 70, where the answer has stopped and the third request is made.
#[tokio::test]
async fn kr_req_17_48_a_failed_request_keeps_the_answer_until_the_device_asks_again() {
    let seen = waits_for(
        vec![unable(Some(50)), no_answer()],
        &[0, 50, 59, 60, 65, 69, 70],
    )
    .await;
    assert_eq!(
        seen,
        [
            (0, 1, Some(50)),
            (50, 2, Some(20)),
            (59, 2, Some(11)),
            (60, 2, Some(10)),
            (65, 2, Some(5)),
            (69, 2, Some(1)),
            (70, 3, None),
        ]
    );
}

/// KR-REQ-17.48: a failure that names a delay above the ten minutes after the third request keeps
/// the answer that stood until the device asks again, and not until the ten minutes are over. The
/// answers come at 0 and 21 seconds and are kept to 81; the third request, at 61, fails and names
/// 900 seconds, so the device asks again at 961 and a failed dial before then is told what is left.
#[tokio::test]
async fn kr_req_17_48_a_failure_that_names_more_than_ten_minutes_keeps_the_answer_that_stood() {
    let seen = waits_for(
        vec![unable(None), unable(None), no_answer_for(900), no_answer()],
        &[0, 21, 26, 61, 66, 640, 700, 960, 961],
    )
    .await;
    assert_eq!(
        seen,
        [
            (0, 1, Some(20)),
            (21, 2, Some(20)),
            (26, 2, Some(15)),
            (61, 3, Some(900)),
            (66, 3, Some(895)),
            (640, 3, Some(321)),
            (700, 3, Some(261)),
            (960, 3, Some(1)),
            (961, 4, None),
        ]
    );
}

/// KR-REQ-17.48: an answer that stood as a request was made stands when the failure of that request
/// comes after the time it was kept to: it is kept until the device asks again, and not dropped for
/// the late failure.
#[tokio::test]
async fn kr_req_17_48_a_failure_that_comes_after_the_keep_time_keeps_the_answer_that_stood() {
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated_script(vec![unable(Some(50)), no_answer()]);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    // The answer names 50 seconds and is kept to 60. The request at 50 is not answered until 65.
    gate.notify_one();
    admissions.before_dial(&relays, &host, key(0x22)).await;
    clock.advance(Duration::from_secs(50));
    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(service.asks(), 2);
    clock.advance(Duration::from_secs(15));
    gate.notify_one();
    service.answered_to(2).await;

    assert_eq!(handed_on(&admissions.refusal(&relays, &host)), Some(20));
    clock.advance(Duration::from_secs(19));
    assert_eq!(handed_on(&admissions.refusal(&relays, &host)), Some(1));
}

/// What a lost dial is reported as, by the candidate's own rule: the failure that a standing refusal
/// gives, with the paths it named, and the host being out of reach when none stands.
fn reported_as(refusal: Option<RelayRefusal>) -> (FailureKind, Vec<String>) {
    match refusal {
        Some(refusal) => {
            let failure = PairingFailure::of_relay(refusal);
            (failure.kind, words_of(&failure.alternatives))
        }
        None => out_of_reach(),
    }
}

/// The failure for want of capacity, with the paths that [`unable`] names and the device's wait.
fn no_capacity(wait: u64) -> (FailureKind, Vec<String>) {
    (
        FailureKind::RelayCapacity {
            retry_after_seconds: wait,
        },
        STILL_WORK.iter().map(|path| (*path).to_owned()).collect(),
    )
}

/// The host being out of reach: no refusal explains the lost dial.
fn out_of_reach() -> (FailureKind, Vec<String>) {
    (FailureKind::HostUnreachable, Vec::new())
}

/// The failure of the service itself, which names no path, with the device's wait.
fn a_fault(wait: u64) -> (FailureKind, Vec<String>) {
    (
        FailureKind::RelayFault {
            retry_after_seconds: wait,
        },
        Vec::new(),
    )
}

/// Whether a lost dial was told the lack of capacity with its paths, whatever the wait.
fn is_no_capacity(told: &(FailureKind, Vec<String>)) -> bool {
    matches!(told.0, FailureKind::RelayCapacity { .. }) && told.1 == no_capacity(0).1
}

/// A second request that is on its way past the time the first answer was kept to, on the cache's
/// own clock. The first answer comes at 0 s and names no delay, so it is kept to 60 s and the device
/// asks again after 20 s. The second request is made at `started` seconds, and the service answers
/// it with `second` only when the test lets it.
struct OnItsWay {
    clock: AdmissionClock,
    service: Arc<Scripted>,
    gate: Arc<tokio::sync::Notify>,
    admissions: PairingAdmissions,
    host: EndpointKey,
    relays: NetworkConfig,
    /// Milliseconds since the first dial.
    at: u64,
}

impl OnItsWay {
    async fn start(second: Result<AdmissionAnswer>, started: u64) -> Self {
        Self::start_script(vec![unable(None), second], started).await
    }

    /// The same, with the service's answers given whole: the first at 0 s, the second to the
    /// request made at `started`, and any later ones to the requests after it.
    async fn start_script(script: Vec<Result<AdmissionAnswer>>, started: u64) -> Self {
        let clock = AdmissionClock::standing();
        let (service, gate) = Scripted::gated_script(script);
        let admissions =
            scripted_admissions(Arc::clone(&service), &clock).waiting(Duration::from_millis(20));
        let (host, relays) = (key(0x11), network(&[MANAGED]));

        gate.notify_one();
        admissions.before_dial(&relays, &host, key(0x22)).await;
        // The dial's wait ends after 20 ms whether or not the request has, so the first answer is
        // waited for itself before the clock moves.
        service.answered_to(1).await;
        clock.advance(Duration::from_secs(started));
        admissions.before_dial(&relays, &host, key(0x22)).await;
        service.asked_to(2).await;
        assert_eq!(service.asks(), 2, "the second request is on its way");
        Self {
            clock,
            service,
            gate,
            admissions,
            host,
            relays,
            at: started * 1000,
        }
    }

    /// Moves the clock to `seconds` after the first dial.
    fn at(&mut self, seconds: u64) -> &Self {
        self.at_ms(seconds * 1000)
    }

    /// Moves the clock to `milliseconds` after the first dial.
    fn at_ms(&mut self, milliseconds: u64) -> &Self {
        self.clock
            .advance(Duration::from_millis(milliseconds - self.at));
        self.at = milliseconds;
        self
    }

    /// A dial to the host that starts now, as the candidate's link makes one.
    async fn dial(&self) {
        self.admissions
            .before_dial(&self.relays, &self.host, key(0x22))
            .await;
    }

    /// What a dial that is lost now is reported as.
    fn lost_dial(&self) -> (FailureKind, Vec<String>) {
        reported_as(self.admissions.refusal(&self.relays, &self.host))
    }

    /// Lets the request that is on its way (the latest one made) end with the answer it was given,
    /// and waits until the cache has it.
    async fn the_request_ends(&self) {
        self.gate.notify_one();
        self.service.answered_to(self.service.asks()).await;
    }
}

/// A service whose first request's task panics, and which answers every later one that it is
/// unable.
#[derive(Debug)]
struct PanicsFirst {
    asked: AtomicUsize,
}

impl PairingAdmissionService for PanicsFirst {
    fn admit<'a>(&'a self, _request: &'a AdmissionRequest) -> ServiceFuture<'a, AdmissionAnswer> {
        let nth = self.asked.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            assert!(nth > 1, "the task of the first request panics");
            unable(None)
        })
    }
}

/// KR-REQ-10.54, KR-REQ-17.40, KR-REQ-17.48: a lost dial is reported as the lack of managed
/// capacity, and not as the host being out of reach, while the next request for the answer is on its
/// way, though the time the answer was kept to has passed. The answer comes at 0 s and is kept to 60;
/// the second request is made at 52 and is not answered until 65. At 59, 60 and 62 the dial is told
/// what the answer says.
#[tokio::test]
async fn kr_req_17_48_a_lost_dial_is_still_the_lack_of_capacity_while_the_next_request_is_on_its_way()
 {
    let mut order = OnItsWay::start(no_answer(), 52).await;
    for second in [59, 60, 62] {
        assert_eq!(
            order.at(second).lost_dial(),
            no_capacity(0),
            "at {second} s"
        );
    }
}

/// KR-REQ-10.54, KR-REQ-17.40, KR-REQ-17.48: when the request that was on its way fails, the answer
/// explains a failed dial with no gap from the moment the request was made to the time the device
/// asks again, and stops there. The request is made at 52 and fails at 65, so the device asks again
/// at 85.
#[tokio::test]
async fn kr_req_17_48_the_request_that_was_on_its_way_fails_and_the_capacity_explanation_goes_on() {
    let mut order = OnItsWay::start(no_answer(), 52).await;
    assert_eq!(order.at(62).lost_dial(), no_capacity(0), "on its way");

    order.at(65).the_request_ends().await;
    for (second, wait) in [(65, 20), (84, 1)] {
        assert_eq!(
            order.at(second).lost_dial(),
            no_capacity(wait),
            "at {second} s"
        );
    }
    assert_eq!(order.at(85).lost_dial(), out_of_reach(), "the device asks");
}

/// KR-REQ-17.48: when the request that was on its way brings another answer, that answer replaces
/// the old one at once, whatever it is, and what a lost dial is told follows it. The request is made
/// at 52 and answered at 65.
#[tokio::test]
async fn kr_req_17_48_another_answer_replaces_the_one_that_stood_at_once() {
    let other = || vec!["Another way that the service named.".to_owned()];
    let answers = [
        (
            Ok(AdmissionAnswer::Admitted {
                expires_in_seconds: 600,
                byte_ceiling: 512 * 1024,
            }),
            out_of_reach(),
        ),
        (Ok(AdmissionAnswer::NotNeeded), out_of_reach()),
        (
            Ok(AdmissionAnswer::Unavailable {
                message: "Managed capacity is not available now.".to_owned(),
                alternatives: other(),
                retry_after_seconds: Some(90),
            }),
            (
                FailureKind::RelayCapacity {
                    retry_after_seconds: 90,
                },
                other(),
            ),
        ),
        (
            Ok(AdmissionAnswer::Faulted {
                code: ErrorCode::ResourceUnavailable,
                retry_after_seconds: None,
            }),
            (
                FailureKind::RelayFault {
                    retry_after_seconds: 20,
                },
                Vec::new(),
            ),
        ),
    ];
    for (answer, told) in answers {
        let mut order = OnItsWay::start(answer, 52).await;
        assert_eq!(
            order.at(62).lost_dial(),
            no_capacity(0),
            "the old answer stands while the request is on its way"
        );

        order.at(65).the_request_ends().await;
        assert_eq!(order.lost_dial(), told, "the new answer, at once");
    }
}

/// KR-REQ-17.48, unchanged: with no request on its way, the answer stops when it is no longer kept.
/// It comes at 0 s and is kept to 60, nothing asks again, and a dial lost at 60 is told nothing.
#[tokio::test]
async fn kr_req_17_48_with_no_request_on_its_way_the_answer_stops_when_it_is_no_longer_kept() {
    let clock = AdmissionClock::standing();
    let service = Scripted::new(vec![unable(None)]);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    admissions.before_dial(&relays, &host, key(0x22)).await;
    service.answered_to(1).await;
    let mut at = 0;
    for (second, told) in [
        (0, no_capacity(20)),
        (59, no_capacity(0)),
        (60, out_of_reach()),
        (62, out_of_reach()),
    ] {
        clock.advance(Duration::from_secs(second - at));
        at = second;
        assert_eq!(
            reported_as(admissions.refusal(&relays, &host)),
            told,
            "at {second} s"
        );
    }
    assert_eq!(service.asks(), 1, "nothing asked again");
}

/// KR-REQ-10.54, KR-REQ-17.40, KR-REQ-17.48: a request that is alive keeps the old answer standing
/// for as long as it is alive, however long that is on the clock, and no second request starts
/// beside it. The request is made at 52 and is not answered: a dial lost at 62, 72, 73, 80 and 3,600
/// is told the lack of capacity, and the dial that starts at each of them asks nothing (the service
/// has been asked twice, in all).
#[tokio::test]
async fn kr_req_17_48_a_request_that_is_alive_keeps_the_answer_standing_and_no_second_one_starts() {
    let mut order = OnItsWay::start(no_answer(), 52).await;
    for second in [62, 72, 73, 80, 3_600] {
        order.at(second).dial().await;
        assert_eq!(
            order.service.asks(),
            2,
            "at {second} s no second request starts"
        );
        assert_eq!(
            order.lost_dial(),
            no_capacity(0),
            "at {second} s a lost dial is told the capacity"
        );
    }
}

/// KR-REQ-10.54, KR-REQ-17.40, KR-REQ-17.48: when a process that was not polled resumes (a phone
/// suspended the application while a request was open), the keep time has passed on the clock, and
/// a dial reads the cache before the request's task runs: it is told the lack of capacity, the dial
/// that starts asks nothing, and when the task runs and fails, the explanation goes on to the next
/// ask time. The request is made at 52; the clock is at 90 at the resume; the request fails then,
/// and the device asks again at 110.
#[tokio::test]
async fn kr_req_17_48_a_dial_that_reads_the_cache_at_the_resume_is_told_the_capacity() {
    let mut order = OnItsWay::start(no_answer(), 52).await;
    assert_eq!(
        order.at(90).lost_dial(),
        no_capacity(0),
        "the dial reads the cache before the request's task runs"
    );
    order.dial().await;
    assert_eq!(order.service.asks(), 2, "the dial that starts asks nothing");

    order.the_request_ends().await;
    assert_eq!(order.lost_dial(), no_capacity(20), "after the failure");
    assert_eq!(order.at(109).lost_dial(), no_capacity(1));
    assert_eq!(order.at(110).lost_dial(), out_of_reach(), "the device asks");
}

/// KR-REQ-17.48: a request whose task panicked is finished, so its mark does not stay: the next dial
/// asks, and the answer to that request is kept.
#[tokio::test]
async fn kr_req_17_48_a_request_whose_task_panicked_does_not_stop_the_next_ask() {
    let clock = AdmissionClock::standing();
    let service = Arc::new(PanicsFirst {
        asked: AtomicUsize::new(0),
    });
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let admissions = PairingAdmissions::new(Arc::clone(&service) as _, &origin)
        .expect("admissions")
        .on_clock(clock.clone());
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(service.asked.load(Ordering::SeqCst), 1);
    assert!(admissions.refusal(&relays, &host).is_none());

    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(
        service.asked.load(Ordering::SeqCst),
        2,
        "the next dial asks"
    );
    assert_eq!(handed_on(&admissions.refusal(&relays, &host)), Some(20));
}

/// KR-REQ-17.48: when a request's task has ended, the next dial that is due asks, and the answers
/// are applied in the order of the requests. The answer at 0 s is kept to 60; the request at 52
/// fails at 55, so the device asks again at 75 and the answer stands to 75; a dial at 74 asks
/// nothing; the dial at 75 asks, and as the answer has stopped it is dropped; the answer to that
/// request, with another list, is what a lost dial is told after it, with the ten minutes that the
/// third ask leaves before another.
#[tokio::test]
async fn kr_req_17_48_when_a_request_ends_the_next_dial_asks_and_the_answers_are_applied_in_order()
{
    let other = || vec!["Another way that the service named.".to_owned()];
    let later = Ok(AdmissionAnswer::Unavailable {
        message: "Managed capacity is not available now.".to_owned(),
        alternatives: other(),
        retry_after_seconds: Some(90),
    });
    let mut order = OnItsWay::start_script(vec![unable(None), no_answer(), later], 52).await;

    order.at(55).the_request_ends().await;
    assert_eq!(order.lost_dial(), no_capacity(20), "the failure lifts it");
    order.at(74).dial().await;
    assert_eq!(order.service.asks(), 2, "the device does not ask yet");

    order.at(75).dial().await;
    assert_eq!(order.service.asks(), 3, "the request has ended: it asks");
    assert_eq!(
        order.lost_dial(),
        out_of_reach(),
        "the answer that had stopped is dropped as the request is made"
    );
    order.the_request_ends().await;
    assert_eq!(
        order.lost_dial(),
        (
            FailureKind::RelayCapacity {
                retry_after_seconds: 600
            },
            other()
        ),
        "the answer of the last request is the one that stands, with the wait of the third ask's window"
    );
}

/// KR-REQ-17.48: one request for an entry is alive at a time in the order of two dials too, where
/// one has counted its ask and started its request and has not returned: a dial that reads the
/// entry then finds that request alive and starts none. The answer comes at 0 s
/// and is kept to 60. At 52 the dial of one candidate counts its ask and starts the second request,
/// whose call to the service stays behind its gate, and the cache's testing hook holds that dial just
/// after its locked step. The dial of another candidate then reads the same entry. The service has
/// been asked twice when that dial has returned, and twice, in all, when the held one has too.
#[tokio::test]
async fn kr_req_17_48_a_dial_that_reads_the_entry_while_another_holds_its_new_request_starts_none()
{
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated_script(vec![unable(None), no_answer()]);
    let (reached, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let held = key(0x33);
    let admissions = scripted_admissions(Arc::clone(&service), &clock)
        .waiting(Duration::from_millis(20))
        .after_the_locked_step({
            let (reached, release) = (Arc::clone(&reached), Arc::clone(&release));
            move |candidate| {
                let (reached, release) = (Arc::clone(&reached), Arc::clone(&release));
                Box::pin(async move {
                    if candidate == held {
                        reached.notify_one();
                        release.notified().await;
                    }
                })
            }
        });
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    gate.notify_one();
    admissions.before_dial(&relays, &host, key(0x22)).await;
    service.answered_to(1).await;
    clock.advance(Duration::from_secs(52));

    let held_dial = tokio::spawn({
        let (admissions, relays) = (admissions.clone(), relays.clone());
        async move { admissions.before_dial(&relays, &host, held).await }
    });
    tokio::time::timeout(Duration::from_secs(30), reached.notified())
        .await
        .expect("the dial reaches the hook");
    service.asked_to(2).await;
    assert_eq!(
        service.asks(),
        2,
        "the held dial has started the second request"
    );

    admissions.before_dial(&relays, &host, key(0x22)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        service.asks(),
        2,
        "the dial that reads the entry beside the held one starts no third request"
    );

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(30), held_dial)
        .await
        .expect("the held dial returns")
        .expect("the held dial's task");
    gate.notify_one();
    service.answered_to(2).await;
    assert_eq!(service.asks(), 2, "two requests in all");
}

/// KR-REQ-17.48: one request for an entry is alive at a time on a first ask too, when the cache holds
/// nothing for the entry yet: the first request stays behind its gate, and a dial that starts while it
/// is alive asks nothing, at the same moment and 25 s later (when a held answer would be asked
/// again). The service has been asked once, in all, and the answer to that request is kept.
#[tokio::test]
async fn kr_req_17_48_while_the_first_request_for_an_entry_is_alive_no_other_dial_asks() {
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated_script(vec![unable(None)]);
    let admissions =
        scripted_admissions(Arc::clone(&service), &clock).waiting(Duration::from_millis(20));
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    admissions.before_dial(&relays, &host, key(0x22)).await;
    service.asked_to(1).await;
    assert_eq!(service.asks(), 1, "the first request is on its way");
    for advance in [0, 25] {
        clock.advance(Duration::from_secs(advance));
        admissions.before_dial(&relays, &host, key(0x22)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            service.asks(),
            1,
            "a dial that starts {advance} s on asks nothing while the first request is alive"
        );
    }

    gate.notify_one();
    service.answered_to(1).await;
    let told = reported_as(admissions.refusal(&relays, &host));
    assert!(is_no_capacity(&told), "the answer is kept: {told:?}");
    assert_eq!(service.asks(), 1, "one request in all");
}

/// KR-REQ-17.48: a failure of the service itself stands as the lack of capacity does while the next
/// request is on its way, and is lifted by that request's failure. The answer at 0 s names no path
/// and is kept to 60; the request at 52 fails at 90.
#[tokio::test]
async fn kr_req_17_48_a_fault_of_the_service_stands_while_the_next_request_is_on_its_way() {
    let fault = Ok(AdmissionAnswer::Faulted {
        code: ErrorCode::ResourceUnavailable,
        retry_after_seconds: None,
    });
    let mut order = OnItsWay::start_script(vec![fault, no_answer()], 52).await;
    for second in [59, 62, 90] {
        assert_eq!(order.at(second).lost_dial(), a_fault(0), "at {second} s");
    }
    order.the_request_ends().await;
    assert_eq!(order.lost_dial(), a_fault(20), "after the failure");
}

/// KR-REQ-10.54, KR-REQ-17.40, KR-REQ-17.48: a request that fails some seconds after it was made, at
/// a time later than the one the answer was kept to, finds the old answer still standing and lifts
/// it, so that a lost dial is told the lack of capacity at every moment from the request's start to
/// the time the device asks again. The answer is kept to 60; the request is made at 52, fails at
/// 72.003, and the device asks again at 92.003.
#[tokio::test]
async fn kr_req_17_48_a_request_that_fails_some_seconds_after_it_was_made_leaves_no_gap() {
    let mut order = OnItsWay::start(no_answer(), 52).await;
    for second in [52, 59, 60, 62, 65, 71, 72] {
        assert_eq!(
            order.at(second).lost_dial(),
            no_capacity(0),
            "at {second} s"
        );
    }
    assert_eq!(
        order.at_ms(72_003).lost_dial(),
        no_capacity(0),
        "past the time the answer was kept to, with the request still on its way"
    );

    order.the_request_ends().await;
    for second in [73, 80, 91] {
        let told = order.at(second).lost_dial();
        assert!(is_no_capacity(&told), "at {second} s: {told:?}");
    }
    assert_eq!(order.at(93).lost_dial(), out_of_reach());
}

/// KR-REQ-17.48: a request that is made after the old answer stopped does not bring it back while it
/// is on its way. The answer comes at 0 s and is kept to 60; the second request is made at 61 and is
/// not answered until 70.
#[tokio::test]
async fn kr_req_17_48_a_request_made_after_the_answer_stopped_does_not_bring_it_back() {
    let mut order = OnItsWay::start(no_answer(), 61).await;
    for second in [61, 62, 69] {
        assert_eq!(
            order.at(second).lost_dial(),
            out_of_reach(),
            "at {second} s"
        );
    }

    order.at(70).the_request_ends().await;
    for second in [70, 71, 100] {
        assert_eq!(
            order.at(second).lost_dial(),
            out_of_reach(),
            "at {second} s"
        );
    }
}

/// KR-REQ-17.48: an answer that had stopped before the third request does not come back when that
/// request fails. The answers come at 0 and 21 seconds and are kept to 81; the request at 199 fails,
/// and a failed dial is told nothing until the device asks again ten minutes later.
#[tokio::test]
async fn kr_req_17_48_an_answer_that_had_stopped_does_not_come_back_after_a_failed_third_ask() {
    let seen = waits_for(
        vec![unable(None), unable(None), no_answer()],
        &[0, 21, 26, 199, 205, 700, 798, 799],
    )
    .await;
    assert_eq!(
        seen,
        [
            (0, 1, Some(20)),
            (21, 2, Some(20)),
            (26, 2, Some(15)),
            (199, 3, None),
            (205, 3, None),
            (700, 3, None),
            (798, 3, None),
            (799, 4, None),
        ]
    );
}

/// KR-REQ-17.48: an answer that had stopped is not read while the request that follows it is on its
/// way, and not after that request fails. The third request is made at 200 seconds, after the answers
/// of 0 and 21 were kept to 81.
#[tokio::test]
async fn kr_req_17_48_an_answer_that_had_stopped_is_not_read_while_the_next_request_is_on_its_way()
{
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated_script(vec![unable(None), unable(None), no_answer()]);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    gate.notify_one();
    admissions.before_dial(&relays, &host, key(0x22)).await;
    clock.advance(Duration::from_secs(21));
    gate.notify_one();
    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(
        handed_on(&admissions.refusal(&relays, &host)),
        Some(20),
        "the second answer stands"
    );

    clock.advance(Duration::from_secs(179));
    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(service.asks(), 3);
    assert_eq!(
        handed_on(&admissions.refusal(&relays, &host)),
        None,
        "the request is on its way"
    );

    gate.notify_one();
    service.answered_to(3).await;
    assert_eq!(handed_on(&admissions.refusal(&relays, &host)), None);
}

/// KR-REQ-17.48, unchanged: a request that fails before the answer's keep time ends changes nothing
/// the service said. The device asks again at 41 seconds, and the answer is kept to 60.
#[tokio::test]
async fn kr_req_17_48_a_failed_request_inside_the_keep_time_changes_only_the_time_it_asks_again() {
    let seen = waits_for(vec![unable(None), no_answer()], &[0, 21, 26, 40]).await;
    assert_eq!(
        seen,
        [
            (0, 1, Some(20)),
            (21, 2, Some(20)),
            (26, 2, Some(15)),
            (40, 2, Some(1)),
        ]
    );
}

/// KR-REQ-17.48, unchanged: an answer that had stopped is not brought back by a failed second
/// request: it was kept to 60 seconds and the request at 100 fails.
#[tokio::test]
async fn kr_req_17_48_an_answer_that_had_stopped_is_not_brought_back_by_a_failed_second_ask() {
    let seen = waits_for(vec![unable(None), no_answer()], &[0, 100, 105, 119]).await;
    assert_eq!(
        seen,
        [
            (0, 1, Some(20)),
            (100, 2, None),
            (105, 2, None),
            (119, 2, None),
        ]
    );
}

/// KR-REQ-17.48, unchanged: where no answer is held, a failed dial is told nothing, through two failed
/// requests and the ten minutes after the third.
#[tokio::test]
async fn kr_req_17_48_where_nothing_is_held_a_failed_request_leaves_a_dial_with_no_reason() {
    let seen = waits_for(vec![no_answer()], &[0, 5, 20, 25, 40, 45, 639, 640]).await;
    assert_eq!(
        seen,
        [
            (0, 1, None),
            (5, 1, None),
            (20, 2, None),
            (25, 2, None),
            (40, 3, None),
            (45, 3, None),
            (639, 3, None),
            (640, 4, None),
        ]
    );
}

/// The canonical bytes an admission request's body digest covers, for [`vector_request`], and
/// their digest. The same strings are the `admission_request_body` case of
/// `infra/relay/vectors/admission.json`.
const REQUEST_HEX: &str = "82781c6b722d72656c61792d61646d697373696f6e2d726571756573742f31a36972656c61795f75726c781e68747470733a2f2f72656c61792d312e72656163682e6b616c612e746f2f71686f73745f656e64706f696e745f6b6579582011111111111111111111111111111111111111111111111111111111111111117663616e6469646174655f656e64706f696e745f6b657958202222222222222222222222222222222222222222222222222222222222222222";
const REQUEST_SHA256: &str = "6a6cd47f988a8a8b43d0e59475595e801cf97b32a87255a95b5f9fb6b4458dd4";

/// An installation's device authorisation key, held the way a client holds one.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl Installation {
    fn new() -> Arc<Self> {
        Arc::new(Self(AuthorisationKeyPair::generate().expect("a key pair")))
    }
}

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a domain-tagged transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(byte: u8) -> EndpointKey {
    EndpointKey::from_bytes([byte; 32])
}

fn request(relay: &str) -> AdmissionRequest {
    AdmissionRequest {
        host: key(0x11),
        candidate: key(0x22),
        relay_url: relay.to_owned(),
    }
}

/// A network configuration that names `relays`, in that order.
fn network(relays: &[&str]) -> NetworkConfig {
    NetworkConfig {
        relay_urls: relays
            .iter()
            .map(|relay| NetworkHint::new(*relay).expect("a hint"))
            .collect(),
        pkarr_publisher_url: Nullable::null(),
        pkarr_resolver_url: Nullable::null(),
        dns_origin: Nullable::null(),
        direct_addresses: Vec::new(),
    }
}

const MANAGED: &str = "https://relay-1.reach.kala.to";

/// The managed service as the stand-in answers it, and the client over it.
struct Service {
    web: Arc<ServiceWeb>,
    admissions: PairingAdmissions,
    clock: AdmissionClock,
}

impl Service {
    fn start() -> Self {
        let web = Arc::new(ServiceWeb::new());
        let origin = GatewayOrigin::new(web.origin()).expect("an origin");
        let clock = AdmissionClock::standing();
        let service = Arc::new(ManagedPairingAdmission::new(
            origin.clone(),
            Arc::clone(&web) as _,
            Installation::new(),
        ));
        let admissions = PairingAdmissions::new(service, &origin)
            .expect("admissions")
            .on_clock(clock.clone());
        Self {
            web,
            admissions,
            clock,
        }
    }

    fn asked(&self) -> Vec<String> {
        self.web
            .relay_admission_requests()
            .into_iter()
            .map(|asked| asked.relay_url)
            .collect()
    }
}

/// KR-REQ-10.39: the bytes a request's credential covers are the bytes the service rebuilds.
#[test]
fn the_body_a_request_covers_is_the_one_the_service_rebuilds() {
    let body = RelayAdmissionIssueBody::of(&AdmissionRequest {
        host: key(0x11),
        candidate: key(0x22),
        relay_url: "https://relay-1.reach.kala.to/".to_owned(),
    });
    let input = body.signing_input().expect("a canonical body");

    assert_eq!(hex(&input), REQUEST_HEX);
    assert_eq!(hex(&kr_cbor::sha256(&input)), REQUEST_SHA256);
}

/// KR-REQ-10.39, KR-REQ-17.48: the service answers an admission, a spent budget, a relay it does
/// not carry and a pair that holds a lease, and each answer is one the client reads, over the
/// credential the service itself checks.
#[tokio::test]
async fn the_services_four_answers_are_read() {
    let service = Service::start();
    let origin = GatewayOrigin::new(service.web.origin()).expect("an origin");
    let signer = Installation::new();
    let admit = ManagedPairingAdmission::new(
        origin.clone(),
        Arc::clone(&service.web) as _,
        signer.clone(),
    );

    // Admitted, with what the service says it holds.
    let answered = admit.admit(&request(MANAGED)).await.expect("an answer");
    assert_eq!(
        answered,
        AdmissionAnswer::Admitted {
            expires_in_seconds: 600,
            byte_ceiling: 512 * 1024,
        }
    );
    let asked = service.web.relay_admission_requests();
    assert_eq!((asked[0].host, asked[0].candidate), (key(0x11), key(0x22)));

    // A relay the service does not carry is not named to anything.
    let answered = admit
        .admit(&request("https://relay.other.test"))
        .await
        .expect("an answer");
    assert_eq!(answered, AdmissionAnswer::NotManaged);

    // A relay is known by the URL the Worker's registry reads, whichever way each side spells the
    // host's case, the default port and the trailing slash.
    service.web.carry_relay(
        "https://Relay-2.reach.kala.to:443/",
        AdmissionBehaviour::Admit,
    );
    assert!(matches!(
        admit
            .admit(&request("https://relay-2.reach.kala.to"))
            .await
            .expect("an answer"),
        AdmissionAnswer::Admitted { .. }
    ));

    // The budget is spent: the paths that still work, and nothing is installed.
    service.web.spend_admission_budget(true);
    let AdmissionAnswer::Unavailable {
        alternatives,
        retry_after_seconds,
        ..
    } = admit.admit(&request(MANAGED)).await.expect("an answer")
    else {
        panic!("a spent budget is unavailable capacity");
    };
    assert!(!alternatives.is_empty());
    assert_eq!(retry_after_seconds, None);
    service.web.spend_admission_budget(false);

    // A pair that holds a lease needs none: the lease decides it alone.
    let leases = ManagedRelayLeaseService::new(origin, Arc::clone(&service.web) as _, signer);
    leases
        .issue(&LeaseRequest {
            source: key(0x11),
            destination: key(0x22),
            direction: RelayDirection::Bidirectional,
            byte_ceiling: 4 * 1024 * 1024,
            duration_seconds: 300,
            region_preference: None,
            payer: None,
            lease_id: None,
        })
        .await
        .expect("a lease");
    assert_eq!(
        admit.admit(&request(MANAGED)).await.expect("an answer"),
        AdmissionAnswer::NotNeeded
    );
}

/// A service whose answers a test scripts, for what the wire cannot be made to do: never answer,
/// answer when told to, or say it serves no such route.
#[derive(Debug)]
struct Scripted {
    answers: Mutex<Vec<Result<AdmissionAnswer>>>,
    asked: AtomicUsize,
    answered: AtomicUsize,
    gate: Option<Arc<tokio::sync::Notify>>,
    /// The request, counted from 1 in the order they are made, whose task ends by unwinding when
    /// the gate lets it through, with no answer.
    unwinds_at: Option<usize>,
}

impl Scripted {
    fn new(answers: Vec<Result<AdmissionAnswer>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            asked: AtomicUsize::new(0),
            answered: AtomicUsize::new(0),
            gate: None,
            unwinds_at: None,
        })
    }

    fn gated(answer: AdmissionAnswer) -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        Self::gated_script(vec![Ok(answer)])
    }

    /// A service that answers a request only when its gate lets it: a `notify_one` before a dial
    /// lets that dial's request through at once, and one after it lets a request that is on its way
    /// finish.
    fn gated_script(
        answers: Vec<Result<AdmissionAnswer>>,
    ) -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        Self::gated_script_unwinding_at(answers, None)
    }

    /// As [`Scripted::gated_script`], and the task of the `unwinds_at`th request that is made ends
    /// when the gate lets that request through, by `resume_unwind`: no panic line is printed, and
    /// the script is not read for it. The request counts as answered then, though no answer is kept.
    fn gated_script_unwinding_at(
        answers: Vec<Result<AdmissionAnswer>>,
        unwinds_at: Option<usize>,
    ) -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        let gate = Arc::new(tokio::sync::Notify::new());
        (
            Arc::new(Self {
                answers: Mutex::new(answers),
                asked: AtomicUsize::new(0),
                answered: AtomicUsize::new(0),
                gate: Some(Arc::clone(&gate)),
                unwinds_at,
            }),
            gate,
        )
    }

    fn asks(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }

    /// Waits until `count` requests have been made of the service, answered or not.
    async fn asked_to(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while self.asks() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request is made");
    }

    /// Waits until `count` requests have been answered, and so kept by the cache.
    async fn answered_to(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while self.answered.load(Ordering::SeqCst) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request is answered");
        // The cache keeps an answer in the same turn of the task that read it; one more turn of
        // this one is enough to be sure it has.
        tokio::task::yield_now().await;
    }
}

impl PairingAdmissionService for Scripted {
    fn admit<'a>(&'a self, _request: &'a AdmissionRequest) -> ServiceFuture<'a, AdmissionAnswer> {
        let nth = self.asked.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            if self.unwinds_at == Some(nth) {
                self.answered.fetch_add(1, Ordering::SeqCst);
                std::panic::resume_unwind(Box::new("the request's task ends"));
            }
            let mut answers = self.answers.lock().expect("the script");
            self.answered.fetch_add(1, Ordering::SeqCst);
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone_answer()
            }
        })
    }
}

trait CloneAnswer {
    fn clone_answer(&self) -> Self;
}

impl CloneAnswer for Result<AdmissionAnswer> {
    fn clone_answer(&self) -> Self {
        match self {
            Ok(answer) => Ok(answer.clone()),
            Err(error) => Err(Error::refusal(error.code(), "the script's refusal".into())),
        }
    }
}

fn scripted_admissions(service: Arc<Scripted>, clock: &AdmissionClock) -> PairingAdmissions {
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone())
        .waiting(Duration::from_millis(200))
}

/// A transport that answers every request with the one status and body it was given, byte for byte,
/// and counts the requests: the service's answer as the client's own reader meets it.
#[derive(Debug)]
struct Exact {
    status: u16,
    body: String,
    requests: AtomicUsize,
}

impl Exact {
    fn new(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            status,
            body: body.to_owned(),
            requests: AtomicUsize::new(0),
        })
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl ServiceHttp for Exact {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(ServiceHttpAnswer {
                status: self.status,
                body: self.body.as_bytes().to_vec(),
            })
        })
    }
}

/// The answer the service gives for a relay it could not admit a pair through: its words, the paths
/// that still work (none, when the cause is its own fault) and the wait it names when it names one.
fn unavailable_body(message: &str, alternatives: &[&str], delay: Option<u64>) -> String {
    let mut data = serde_json::json!({
        "state": "unavailable",
        "message": message,
        "alternatives": alternatives,
    });
    if let Some(seconds) = delay {
        data["retry_after_seconds"] = serde_json::json!(seconds);
    }
    serde_json::json!({ "ok": true, "data": data }).to_string()
}

/// The two paths that still work, as the service names them when a budget is short.
const STILL_WORK: [&str; 2] = [
    "A direct connection between the devices, which needs no managed relay.",
    "A relay that the host's owner runs. The host must name it in its configuration and use no \
     managed relay. A new invitation from that host then names it.",
];

/// When, in seconds after the first dial, the cache is dialled to in the timeline below.
const PROBES: [u64; 13] = [0, 4, 6, 12, 21, 26, 61, 66, 130, 700, 3601, 3700, 90_000];

/// What the cache did over `PROBES` when the service answered `body` to every request: at each
/// dial, how many requests the service had been sent by then and whether a failed dial would be
/// reported as the managed relay having no capacity.
async fn timeline(body: &str) -> Vec<(u64, usize, bool)> {
    let clock = AdmissionClock::standing();
    let http = Exact::new(200, body);
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let service = Arc::new(ManagedPairingAdmission::new(
        origin.clone(),
        Arc::clone(&http) as _,
        Installation::new(),
    ));
    let admissions = PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone());
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for probe in PROBES {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((
            probe,
            http.requests(),
            admissions.refusal(&relays, &host).is_some(),
        ));
    }
    seen
}

/// KR-REQ-17.48: a service that cannot admit a pair for a reason of its own says so with the member
/// that names the paths that still work present and empty, and the client's reader holds it as it
/// holds an answer that names them: the same answer kind, the same requests at the same moments, an
/// explanation of a failed dial for as long, with a wait named and without. What the explanation
/// says differs, and is told apart in its own case. An answer that leaves the member out is still
/// not one it reads.
#[tokio::test]
async fn kr_req_17_48_an_unavailable_answer_with_an_empty_list_is_held_as_one_with_entries() {
    const FAULT: &str = "The managed relay service could not admit this pairing now.";
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";

    for delay in [
        None,
        Some(0),
        Some(5),
        Some(3600),
        Some(86_400),
        Some(200_000),
    ] {
        let with_entries = unavailable_body(SHORT, &STILL_WORK, delay);
        let with_none = unavailable_body(FAULT, &[], delay);

        let (named, empty) = (timeline(&with_entries).await, timeline(&with_none).await);
        println!("TIMELINE delay {delay:?} | entries {named:?} | empty {empty:?}");
        assert_eq!(named, empty, "delay {delay:?}");
        assert!(
            named[0].2 && named[0].1 == 1,
            "the first dial asks once and is explained as capacity: {named:?}"
        );

        let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
        let read = |body: &str| {
            ManagedPairingAdmission::new(
                origin.clone(),
                Exact::new(200, body) as _,
                Installation::new(),
            )
        };
        let (entries, none) = (
            read(&with_entries).admit(&request(MANAGED)).await,
            read(&with_none).admit(&request(MANAGED)).await,
        );
        assert_eq!(
            entries.expect("an answer"),
            AdmissionAnswer::Unavailable {
                message: SHORT.to_owned(),
                alternatives: STILL_WORK.map(str::to_owned).to_vec(),
                retry_after_seconds: delay,
            }
        );
        assert_eq!(
            none.expect("an answer"),
            AdmissionAnswer::Unavailable {
                message: FAULT.to_owned(),
                alternatives: Vec::new(),
                retry_after_seconds: delay,
            }
        );
    }

    // The member is what the reader needs: an answer that leaves it out is not read, and the cache
    // holds that as a failed request, which explains no dial.
    let without = serde_json::json!({
        "ok": true,
        "data": {"state": "unavailable", "message": "The relay did not answer."},
    })
    .to_string();
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let unread =
        ManagedPairingAdmission::new(origin, Exact::new(200, &without) as _, Installation::new())
            .admit(&request(MANAGED))
            .await;
    assert!(unread.is_err(), "a missing member is read as an answer");
    assert!(
        !timeline(&without)
            .await
            .iter()
            .any(|(_, _, refused)| *refused),
        "an answer that cannot be read explained a dial"
    );
}

/// KR-REQ-10.39, KR-REQ-10.54: an invitation that names a managed relay causes one request for it
/// before the dial and none for a relay that is not the service's: a self-hosted relay, an unrelated
/// name, an address where the service has a name, and names that only look like the service's.
#[tokio::test]
async fn only_a_relay_of_the_managed_service_is_ever_named_to_it() {
    let service = Service::start();
    let host = key(0x11);

    service
        .admissions
        .before_dial(
            &network(&[
                "https://relay.other.test",
                "https://127.0.0.1:9",
                "https://reach.kala.to.evil.test",
                "https://evilreach.kala.to",
                MANAGED,
            ]),
            &host,
            key(0x22),
        )
        .await;

    assert_eq!(service.asked(), vec![MANAGED.to_owned()]);

    // A service at an address names its relays by that address.
    let web = Arc::new(ServiceWeb::at("http://127.0.0.1:9100"));
    web.name_relay_url("https://127.0.0.1:9101");
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let admissions = PairingAdmissions::new(
        Arc::new(ManagedPairingAdmission::new(
            origin.clone(),
            Arc::clone(&web) as _,
            Installation::new(),
        )),
        &origin,
    )
    .expect("admissions");
    admissions
        .before_dial(
            &network(&["https://127.0.0.2:9101", "https://127.0.0.1:9101"]),
            &host,
            key(0x22),
        )
        .await;
    let asked: Vec<String> = web
        .relay_admission_requests()
        .into_iter()
        .map(|asked| asked.relay_url)
        .collect();
    assert_eq!(asked, vec!["https://127.0.0.1:9101".to_owned()]);
}

/// KR-REQ-10.39: one request serves a dial and its re-dials while the admission stands, and a dial
/// that connected leaves nothing in doubt.
#[tokio::test]
async fn a_re_dial_after_a_connection_reuses_the_admission() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    service.admissions.dial_succeeded(&relays, &host);
    service.clock.advance(Duration::from_secs(120));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    service.admissions.dial_succeeded(&relays, &host);

    assert_eq!(
        service.asked(),
        vec![MANAGED.to_owned()],
        "one request in all"
    );

    // An admission that is about to end is asked for again.
    service.clock.advance(Duration::from_secs(500));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);
}

/// KR-REQ-10.39: a dial that was cut short before it connected leaves its entry in doubt, and a later
/// dial asks again after twenty seconds, at most three times between connections.
#[tokio::test]
async fn a_dial_that_never_connected_is_asked_about_again_a_few_times() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    // The first dial ended by its route's deadline: nothing ran at cancellation, nothing connected.
    service.clock.advance(Duration::from_secs(10));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        1,
        "ten seconds is not long enough to doubt it"
    );

    service.clock.advance(Duration::from_secs(15));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);

    service.clock.advance(Duration::from_secs(25));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 3);

    service.clock.advance(Duration::from_secs(25));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        3,
        "three is the most between connections"
    );

    // A connection settles the doubt, and the count starts again.
    service.admissions.dial_succeeded(&relays, &host);
    service.clock.advance(Duration::from_secs(580));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 4);
}

/// KR-REQ-10.39: three requests with no connection between them are the most in ten minutes, not the
/// most for good: a person whose host was off, or whose network blocked the relay, and who tries again
/// after fixing it, is asked about again, from the same device and the same cache.
#[tokio::test]
async fn a_device_whose_dials_all_failed_asks_again_when_the_ten_minutes_have_passed() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    for _ in 0..3 {
        service
            .admissions
            .before_dial(&relays, &host, key(0x22))
            .await;
        service.clock.advance(Duration::from_secs(25));
    }
    assert_eq!(service.asked().len(), 3);

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        3,
        "the most inside the window, whatever the dials came to"
    );

    // Past ten minutes from the last request, the admission that came with it has ended too.
    service.clock.advance(Duration::from_secs(10 * 60));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(
        service.asked().len(),
        4,
        "a device that never connected is never asked again"
    );
}

/// KR-REQ-17.40, KR-REQ-17.48: a service that is unable and names no time to try again is believed as
/// long as the cache will not ask it again. After three requests with no connection that is until
/// ten minutes after the last, not the minute the answer is kept for: a person who tries again a few
/// minutes on is told the managed relay had no capacity, and not that the host is out of reach.
#[tokio::test]
async fn an_answer_that_the_service_is_unable_stands_while_the_cache_will_not_ask_again() {
    let service = Service::start();
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: None,
        },
    );

    for _ in 0..3 {
        service
            .admissions
            .before_dial(&relays, &host, key(0x22))
            .await;
        assert!(service.admissions.refusal(&relays, &host).is_some());
        service.clock.advance(Duration::from_secs(25));
    }
    assert_eq!(service.asked().len(), 3);

    // Two minutes on, past the minute the answer is kept for. No request is made, and the answer
    // that explains the failure still stands.
    service.clock.advance(Duration::from_secs(120));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 3);
    assert!(
        service.admissions.refusal(&relays, &host).is_some(),
        "a refusal with no retry time stopped explaining the failure while nothing asked again"
    );

    // Ten minutes after the last request it is asked again, and the answer is the service's own.
    service.clock.advance(Duration::from_secs(10 * 60));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 4);
}

/// KR-REQ-17.40, KR-REQ-17.48: what the service said it cannot do explains a dial that failed for a
/// minute, though a dial asks again when the service said to, and a relay that was named first is the
/// one that decides.
#[tokio::test]
async fn an_answer_that_the_service_is_unable_explains_a_failed_dial_but_not_for_ever() {
    let service = Service::start();
    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: Some(5),
        },
    );
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert!(service.admissions.refusal(&relays, &host).is_some());

    // Four seconds on, nothing more is asked; six seconds on, it is.
    service.clock.advance(Duration::from_secs(4));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 1);
    service.clock.advance(Duration::from_secs(2));
    service
        .admissions
        .before_dial(&relays, &host, key(0x22))
        .await;
    assert_eq!(service.asked().len(), 2);

    // And the answer still stands for the route that asks fifty seconds after it came, though no
    // dial has begun since.
    service.clock.advance(Duration::from_secs(50));
    assert!(service.admissions.refusal(&relays, &host).is_some());
    service.clock.advance(Duration::from_secs(20));
    assert!(service.admissions.refusal(&relays, &host).is_none());
}

/// KR-REQ-17.40: it is the relay a dial addresses that decides what a failed dial is reported as: the
/// first the host names. One that is unavailable while another admits, and the other way round, and a
/// pair that holds a lease there, each say what that relay says.
#[tokio::test]
async fn the_relay_a_dial_addresses_is_the_one_that_decides() {
    let service = Service::start();
    let second = "https://relay-2.reach.kala.to";
    service.web.carry_relay(second, AdmissionBehaviour::Admit);
    let host = key(0x11);

    service.web.carry_relay(
        MANAGED,
        AdmissionBehaviour::Unavailable {
            retry_after_seconds: None,
        },
    );
    let first_is_unavailable = network(&[MANAGED, second]);
    service
        .admissions
        .before_dial(&first_is_unavailable, &host, key(0x22))
        .await;
    assert!(
        service
            .admissions
            .refusal(&first_is_unavailable, &host)
            .is_some()
    );

    // The same relays in the other order: the dial addresses the one that admits.
    let first_admits = network(&[second, MANAGED]);
    assert!(service.admissions.refusal(&first_admits, &host).is_none());

    // A pair that holds a lease at the first relay needs no admission there, which is not capacity.
    let other = key(0x33);
    let leased = Service::start();
    leased.web.carry_relay(MANAGED, AdmissionBehaviour::Admit);
    let origin = GatewayOrigin::new(leased.web.origin()).expect("an origin");
    let signer = Installation::new();
    ManagedRelayLeaseService::new(origin, Arc::clone(&leased.web) as _, signer)
        .issue(&LeaseRequest {
            source: other,
            destination: key(0x44),
            direction: RelayDirection::Bidirectional,
            byte_ceiling: 4 * 1024 * 1024,
            duration_seconds: 300,
            region_preference: None,
            payer: None,
            lease_id: None,
        })
        .await
        .expect("a lease");
    leased
        .admissions
        .before_dial(&network(&[MANAGED]), &other, key(0x44))
        .await;
    assert!(
        leased
            .admissions
            .refusal(&network(&[MANAGED]), &other)
            .is_none()
    );
}

/// KR-REQ-10.39: a service that never answers does not stop a dial, and what it answers later is kept
/// for the next one. The wait is the test's; what decides is that the dial went on.
#[tokio::test]
async fn a_service_that_does_not_answer_does_not_hold_up_a_dial() {
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated(AdmissionAnswer::Unavailable {
        message: "spent".to_owned(),
        alternatives: vec!["a direct connection".to_owned()],
        retry_after_seconds: None,
    });
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    tokio::time::timeout(
        Duration::from_secs(30),
        admissions.before_dial(&relays, &host, key(0x22)),
    )
    .await
    .expect("the dial goes on without the answer");
    assert_eq!(service.asks(), 1);
    assert!(
        admissions.refusal(&relays, &host).is_none(),
        "nothing has been said yet"
    );

    // The answer arrives after the dial went on, and is kept.
    gate.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        while admissions.refusal(&relays, &host).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a later answer is kept");
}

/// KR-REQ-10.39: a dial that its route ends while it waits for the service leaves the request running.
/// The answer that comes after the dial is gone is kept, the next dial reads it, and the service is
/// not asked a second time.
#[tokio::test]
async fn a_dial_that_its_route_ends_while_it_waits_leaves_its_request_to_finish() {
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated(AdmissionAnswer::Unavailable {
        message: "spent".to_owned(),
        alternatives: vec!["a direct connection".to_owned()],
        retry_after_seconds: None,
    });
    // The wait for the answer is far longer than the test will give the dial, so that only the
    // route's own cut can end it.
    let admissions =
        scripted_admissions(Arc::clone(&service), &clock).waiting(Duration::from_secs(600));
    let (host, relays) = (key(0x11), network(&[MANAGED]));

    // The route's own deadline ends the dial long before the wait for the answer would.
    let ended = tokio::time::timeout(
        Duration::from_millis(50),
        admissions.before_dial(&relays, &host, key(0x22)),
    )
    .await;
    assert!(ended.is_err(), "the dial was not cut short while it waited");
    assert_eq!(service.asks(), 1);
    assert!(admissions.refusal(&relays, &host).is_none());

    // The service answers once the dial has gone, and the answer is kept.
    gate.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        while admissions.refusal(&relays, &host).is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the answer to a dial that was cut short is kept");

    // The next dial reads it and asks nothing.
    admissions.before_dial(&relays, &host, key(0x22)).await;
    assert_eq!(service.asks(), 1);
}

/// KR-REQ-10.39: a service that says it serves no such route, or does not allow this device to ask,
/// stops every request for ten minutes, and what it said is no reason a person is shown.
#[tokio::test]
async fn a_service_without_the_route_is_left_alone_for_ten_minutes() {
    let clock = AdmissionClock::standing();
    let service = Scripted::new(vec![Err(Error::refusal(
        ErrorCode::InvalidArgument,
        "the service has no such route".into(),
    ))]);
    let admissions = scripted_admissions(Arc::clone(&service), &clock);
    let relays = network(&[MANAGED]);

    admissions.before_dial(&relays, &key(0x11), key(0x22)).await;
    assert_eq!(service.asks(), 1);
    assert!(
        admissions.refusal(&relays, &key(0x11)).is_none(),
        "that is no capacity text"
    );

    // Another host, a minute on: nothing is asked.
    clock.advance(Duration::from_secs(60));
    admissions.before_dial(&relays, &key(0x33), key(0x22)).await;
    assert_eq!(service.asks(), 1);

    // Ten minutes on, it is.
    clock.advance(Duration::from_secs(10 * 60));
    admissions.before_dial(&relays, &key(0x33), key(0x22)).await;
    assert_eq!(service.asks(), 2);
}

/// KR-REQ-10.39: a deployment of the service that has no such route answers 404, as the Worker does,
/// which the client's own reading of an answer turns into the same ten minutes of being left alone.
#[tokio::test]
async fn a_real_not_found_from_the_service_stops_requests_for_ten_minutes() {
    let service = Service::start();
    let relays = network(&[MANAGED]);
    service.web.fail(
        "/api/relay/admission",
        1,
        Moment::Refuse {
            status: 404,
            code: "NOT_FOUND",
            retry_after_seconds: None,
        },
    );

    service
        .admissions
        .before_dial(&relays, &key(0x11), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 1);
    assert!(
        service.admissions.refusal(&relays, &key(0x11)).is_none(),
        "that is no capacity text"
    );

    // Another host a minute on: nothing is sent.
    service.clock.advance(Duration::from_secs(60));
    service
        .admissions
        .before_dial(&relays, &key(0x33), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 1);

    service.clock.advance(Duration::from_secs(10 * 60));
    service
        .admissions
        .before_dial(&relays, &key(0x33), key(0x22))
        .await;
    assert_eq!(service.web.requests_to("/api/relay/admission"), 2);
}

/// A transport whose exchange ends before the service has said anything: there is no status and no
/// body to read. It counts the requests it was given.
#[derive(Debug, Default)]
struct Unreached {
    requests: AtomicUsize,
}

impl ServiceHttp for Unreached {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(Error::refusal(
                ErrorCode::ResourceUnavailable,
                "the exchange ended".into(),
            ))
        })
    }
}

/// The service's own envelope for a refusal, with the wait it names when it names one.
fn refusal_body(code: &str, delay: Option<u64>) -> String {
    let mut error = serde_json::json!({
        "code": code,
        "message": "The service could not do that now.",
    });
    if let Some(seconds) = delay {
        error["retryAfterSeconds"] = serde_json::json!(seconds);
    }
    serde_json::json!({ "ok": false, "error": error }).to_string()
}

/// How many requests the transport had been sent at each of [`PROBES`], and what a failed dial
/// would be explained by, when `http` answers every request.
async fn series(
    http: Arc<dyn ServiceHttp>,
    sent: impl Fn() -> usize,
) -> Vec<(u64, usize, Option<RelayRefusal>)> {
    let clock = AdmissionClock::standing();
    let origin = GatewayOrigin::new("https://reach.kala.to").expect("an origin");
    let service = Arc::new(ManagedPairingAdmission::new(
        origin.clone(),
        http,
        Installation::new(),
    ));
    let admissions = PairingAdmissions::new(service, &origin)
        .expect("admissions")
        .on_clock(clock.clone());
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for probe in PROBES {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((probe, sent(), admissions.refusal(&relays, &host)));
    }
    seen
}

/// KR-REQ-17.48: when a request is asked again does not depend on what the answer to the one before
/// it let a failed dial be explained by. An answer that is a refusal in the service's envelope, with
/// a status of the 5xx class or another, an answer that is not the envelope and an exchange that
/// ended with no answer are each asked about again at the moments they always were.
#[tokio::test]
async fn kr_req_17_48_a_refused_or_unreadable_answer_is_asked_about_again_at_the_same_moments() {
    const ASKED: [usize; 13] = [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7];
    let bodies: [(&str, u16, String, [usize; 13]); 7] = [
        ("503 internal", 503, refusal_body("INTERNAL", None), ASKED),
        // A wait under twenty seconds is still asked again after twenty.
        ("503 delay 5", 503, refusal_body("INTERNAL", Some(5)), ASKED),
        (
            "500 delay 3600",
            500,
            refusal_body("INTERNAL", Some(3600)),
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3],
        ),
        // A service that says it is not configured stops every request for ten minutes.
        (
            "501 not configured",
            501,
            refusal_body("NOT_CONFIGURED", None),
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3, 4],
        ),
        (
            "429 delay 30",
            429,
            refusal_body("RATE_LIMITED", Some(30)),
            [1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5, 6],
        ),
        (
            "502 no envelope",
            502,
            "<html>Bad Gateway</html>".to_owned(),
            ASKED,
        ),
        ("503 no error", 503, r#"{"ok":false}"#.to_owned(), ASKED),
    ];
    for (name, status, body, expected) in bodies {
        let http = Exact::new(status, &body);
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        let asked: Vec<usize> = seen.iter().map(|(_, asked, _)| *asked).collect();
        assert_eq!(asked, expected, "{name}");
    }
    let http = Arc::new(Unreached::default());
    let seen = series(Arc::clone(&http) as _, || {
        http.requests.load(Ordering::SeqCst)
    })
    .await;
    let asked: Vec<usize> = seen.iter().map(|(_, asked, _)| *asked).collect();
    assert_eq!(asked, ASKED, "an exchange that ended with no answer");
}

/// What a service that is not updated and one that is name beside an answer that it is unable, as
/// words: the paths that still work. Only the first and the last are this build's own texts.
const OLD_SERVICE_LIST: [&str; 2] = [
    "A direct connection between the devices, which needs no managed relay.",
    "A self-hosted relay configured in the service settings.",
];

/// The delays an answer names, and none.
const DELAYS: [Option<u64>; 6] = [
    None,
    Some(0),
    Some(5),
    Some(3600),
    Some(86_400),
    Some(200_000),
];

/// How many requests the service has been sent at each of [`PROBES`] when it answers that it is
/// unable and names `delay`: the table of the control, typed from a run before the list and the
/// delay were kept.
fn control_asked(delay: Option<u64>) -> [usize; 13] {
    match delay {
        None => [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7],
        Some(0) => [1, 2, 3, 3, 3, 3, 3, 3, 3, 4, 5, 6, 7],
        Some(5) => [1, 1, 2, 3, 3, 3, 3, 3, 3, 4, 5, 6, 7],
        Some(3600) => [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3],
        Some(86_400 | 200_000) => [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2],
        Some(other) => panic!("no control for a delay of {other}"),
    }
}

fn asked_at_each_probe(seen: &[(u64, usize, Option<RelayRefusal>)]) -> Vec<usize> {
    seen.iter().map(|(_, asked, _)| *asked).collect()
}

/// The paths a failure holds, as words.
fn words_of(alternatives: &kr_client::services::Alternatives) -> Vec<String> {
    alternatives
        .as_given()
        .iter()
        .map(|shown| shown.as_str().to_owned())
        .collect()
}

/// KR-REQ-17.48: an answer that the service is unable, with a list that has an entry, is kept with
/// that list, as it wrote it, and the device's wait, for as long as it explains a failed dial, and
/// is asked again at the moments it always was. A service that is not updated, whose list has the
/// old second item or any other, reads the same way.
#[tokio::test]
async fn kr_req_17_48_a_kept_answer_holds_the_list_and_the_delay_it_named() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    let lists: [Vec<&str>; 3] = [
        STILL_WORK.to_vec(),
        OLD_SERVICE_LIST.to_vec(),
        vec!["A path that this build has never heard of."],
    ];
    for list in lists {
        for delay in DELAYS {
            let http = Exact::new(200, &unavailable_body(SHORT, &list, delay));
            let seen = series(Arc::clone(&http) as _, || http.requests()).await;
            assert_eq!(
                asked_at_each_probe(&seen),
                control_asked(delay),
                "{delay:?}"
            );
            for (probe, _, refusal) in seen {
                let Some(RelayRefusal::Capacity {
                    alternatives,
                    retry_after_seconds,
                }) = refusal
                else {
                    panic!("at {probe}s with {delay:?}: {refusal:?}");
                };
                assert_eq!(words_of(&alternatives), list, "at {probe}s");
                assert!(
                    retry_after_seconds <= 86_400,
                    "at {probe}s with {delay:?}: {retry_after_seconds}"
                );
            }
        }
    }
}

/// KR-REQ-17.48: an answer that the service is unable, whose list has no entry, is a fault of the
/// service and never exhausted capacity, with the device's own wait, and is kept and asked again at
/// the same moments as one with entries.
#[tokio::test]
async fn kr_req_17_48_an_unavailable_answer_with_no_entry_is_a_fault_and_never_capacity() {
    const FAULT: &str = "The managed relay service could not admit this pairing now.";
    for delay in DELAYS {
        let http = Exact::new(200, &unavailable_body(FAULT, &[], delay));
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert_eq!(
            asked_at_each_probe(&seen),
            control_asked(delay),
            "{delay:?}"
        );
        for (probe, _, refusal) in seen {
            let Some(RelayRefusal::Fault {
                retry_after_seconds,
            }) = refusal
            else {
                panic!("at {probe}s with {delay:?}: {refusal:?}");
            };
            assert!(
                retry_after_seconds <= 86_400,
                "at {probe}s with {delay:?}: {retry_after_seconds}"
            );
        }
    }
}

/// KR-REQ-17.48: a refusal in the service's envelope under a status of the 5xx class is a fault of
/// the service, explained for as long as an answer that it is unable is, with the device's own wait
/// that the delay the envelope named sets, and is asked again at the moments a refusal always was.
#[tokio::test]
async fn kr_req_17_48_a_refusal_of_the_5xx_class_in_the_envelope_is_a_fault() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    // The same wait, said as unavailable: asked again after a wait of twenty seconds or more at the
    // same moments, so the whole series is equal.
    for (status, delay, told) in [(503, None, 20), (500, Some(3600), 3600)] {
        let refused = Exact::new(status, &refusal_body("INTERNAL", delay));
        let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
        let unavailable = Exact::new(200, &unavailable_body(SHORT, &STILL_WORK, delay));
        let baseline = series(Arc::clone(&unavailable) as _, || unavailable.requests()).await;
        let explained = |seen: &[(u64, usize, Option<RelayRefusal>)]| -> Vec<(u64, usize, bool)> {
            seen.iter()
                .map(|(probe, asked, refusal)| (*probe, *asked, refusal.is_some()))
                .collect()
        };
        assert_eq!(explained(&seen), explained(&baseline), "{status} {delay:?}");
        assert_eq!(
            seen[0].2,
            Some(RelayRefusal::Fault {
                retry_after_seconds: told
            })
        );
    }
    // A wait under twenty seconds is still asked again after twenty, as any refusal is.
    let refused = Exact::new(503, &refusal_body("INTERNAL", Some(5)));
    let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
    assert_eq!(
        asked_at_each_probe(&seen),
        [1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 5, 6, 7]
    );
    // And is told so: the wait is until the device asks again, which is twenty seconds.
    assert_eq!(
        seen[0].2,
        Some(RelayRefusal::Fault {
            retry_after_seconds: 20
        })
    );
    // A service that says it is not configured is a fault as well, and is not asked for ten
    // minutes: a device told so waits for the stop, though the service named no delay.
    let refused = Exact::new(501, &refusal_body("NOT_CONFIGURED", None));
    let seen = series(Arc::clone(&refused) as _, || refused.requests()).await;
    assert_eq!(
        asked_at_each_probe(&seen),
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 3, 4]
    );
    assert_eq!(
        seen[0].2,
        Some(RelayRefusal::Fault {
            retry_after_seconds: 600
        })
    );
}

/// KR-REQ-17.48: what is neither exhausted capacity nor a fault of the service explains nothing: an
/// exchange that ended with no answer, an answer that is not the service's envelope under a status
/// of the 5xx class, a refusal in the envelope under another status, and a refusal that names no
/// error.
#[tokio::test]
async fn kr_req_17_48_a_transport_failure_and_an_answer_without_the_envelope_are_neither() {
    let answers: [(u16, String); 5] = [
        (502, "<html>Bad Gateway</html>".to_owned()),
        (503, r#"{"ok":false}"#.to_owned()),
        (503, "not json".to_owned()),
        (429, refusal_body("RATE_LIMITED", Some(30))),
        (400, refusal_body("INVALID_REQUEST", None)),
    ];
    for (status, body) in answers {
        let http = Exact::new(status, &body);
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert!(
            seen.iter().all(|(_, _, refusal)| refusal.is_none()),
            "{status} {body}: {seen:?}"
        );
    }
    let http = Arc::new(Unreached::default());
    let seen = series(Arc::clone(&http) as _, || {
        http.requests.load(Ordering::SeqCst)
    })
    .await;
    assert!(seen.iter().all(|(_, _, refusal)| refusal.is_none()));
}

/// The wait a standing refusal hands on, of either kind.
fn handed_on(refusal: &Option<RelayRefusal>) -> Option<u64> {
    match refusal {
        Some(
            RelayRefusal::Capacity {
                retry_after_seconds,
                ..
            }
            | RelayRefusal::Fault {
                retry_after_seconds,
            },
        ) => Some(*retry_after_seconds),
        None => None,
    }
}

/// KR-REQ-17.48: what a failed dial hands on as the wait is the seconds from now until this device
/// asks the service again, and never less than what is left of the delay the service named: not the
/// delay as it was named when the answer was read, which is kept past itself while no request is
/// made. Rounded up. Where the service named no delay, the device asks again twenty seconds after
/// the answer.
#[tokio::test]
async fn kr_req_17_48_the_wait_handed_on_is_the_wait_until_the_device_asks_again() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    // The figures at the 13 dials, by hand from the times of the control: the answer's retry time
    // while asks are left; the end of the ten minutes after the third ask, while they are used up
    // (the count starts again at each ask made ten minutes after the last).
    let tables: [(Option<u64>, [u64; 13]); 4] = [
        // No delay named: the device still asks again after twenty seconds, or when the ten
        // minutes after its third ask have passed.
        (None, [20, 16, 14, 8, 20, 15, 600, 595, 531, 20, 20, 20, 20]),
        (Some(5), [5, 1, 5, 600, 591, 586, 551, 546, 482, 5, 5, 5, 5]),
        (
            Some(3600),
            [
                3600, 3596, 3594, 3588, 3579, 3574, 3539, 3534, 3470, 2900, 3600, 3501, 3600,
            ],
        ),
        (
            Some(0),
            [0, 0, 600, 594, 585, 580, 545, 540, 476, 0, 0, 0, 0],
        ),
    ];
    for (delay, expected) in tables {
        for body in [
            unavailable_body(SHORT, &STILL_WORK, delay),
            unavailable_body(
                "The managed relay service could not admit this pairing now.",
                &[],
                delay,
            ),
        ] {
            let http = Exact::new(200, &body);
            let seen = series(Arc::clone(&http) as _, || http.requests()).await;
            let handed: Vec<Option<u64>> = seen.iter().map(|(_, _, one)| handed_on(one)).collect();
            assert_eq!(handed, expected.map(Some), "{delay:?} {body}");
        }
    }
}

/// KR-REQ-17.48: while every request is stopped, the wait handed on is what is left of the stop, and
/// not the delay the service named: a service that says it is not configured stops requests for ten
/// minutes.
#[tokio::test]
async fn kr_req_17_48_the_wait_handed_on_runs_to_the_end_of_a_stop_of_requests() {
    let http = Exact::new(501, &refusal_body("NOT_CONFIGURED", Some(30)));
    let seen = series(Arc::clone(&http) as _, || http.requests()).await;
    let handed: Vec<Option<u64>> = seen
        .iter()
        .take(6)
        .map(|(_, _, one)| handed_on(one))
        .collect();
    // The dials at 0, 4, 6, 12, 21 and 26 seconds.
    assert_eq!(
        handed,
        [
            Some(600),
            Some(596),
            Some(594),
            Some(588),
            Some(579),
            Some(574)
        ]
    );
}

/// KR-REQ-17.48: a list in which no entry has text names no path, so the answer is a fault and
/// carries no list; a list in which one entry has text is kept as it was written.
#[tokio::test]
async fn kr_req_17_48_a_list_with_no_text_is_no_list() {
    const WORDS: &str = "Managed capacity for new pairing invitations is not available now.";
    for blank in [vec![""], vec!["  ", ""], vec![" \t "]] {
        let http = Exact::new(200, &unavailable_body(WORDS, &blank, Some(30)));
        let seen = series(Arc::clone(&http) as _, || http.requests()).await;
        assert!(
            matches!(seen[0].2, Some(RelayRefusal::Fault { .. })),
            "{blank:?}: {:?}",
            seen[0].2
        );
    }
    let mixed = ["", "A path that this build has never heard of."];
    let http = Exact::new(200, &unavailable_body(WORDS, &mixed, None));
    let seen = series(Arc::clone(&http) as _, || http.requests()).await;
    let Some(RelayRefusal::Capacity { alternatives, .. }) = &seen[0].2 else {
        panic!("{:?}", seen[0].2);
    };
    assert_eq!(words_of(alternatives), mixed);
}

/// What `admissions` hands on at each of `probes` (seconds after the first dial): how many requests
/// the service has been sent, and the wait a failed dial is told, when a refusal explains it.
async fn waits_at(
    service: &Arc<Scripted>,
    clock: &AdmissionClock,
    admissions: &PairingAdmissions,
    probes: &[u64],
) -> Vec<(u64, usize, Option<u64>)> {
    let (host, relays) = (key(0x11), network(&[MANAGED]));
    let mut seen = Vec::new();
    let mut at = 0;
    for &probe in probes {
        clock.advance(Duration::from_secs(probe - at));
        at = probe;
        admissions.before_dial(&relays, &host, key(0x22)).await;
        seen.push((
            probe,
            service.asks(),
            handed_on(&admissions.refusal(&relays, &host)),
        ));
    }
    seen
}

/// KR-REQ-17.48: a request that fails keeps the answer that the service is unable, for as long as
/// that answer stands, and moves only the time a dial asks again. A third request that got no
/// answer does not turn the next ten minutes into "the host cannot be reached" with no wait: each
/// try is told what the answer said, with the wait that is left until the device asks again.
#[tokio::test]
async fn kr_req_17_48_a_failed_request_keeps_the_answer_that_still_stands() {
    const SHORT: &str = "Managed capacity for new pairing invitations is not available now.";
    let lists: [&[&str]; 2] = [&STILL_WORK, &[]];
    for alternatives in lists {
        let unavailable = || {
            Ok(AdmissionAnswer::Unavailable {
                message: SHORT.to_owned(),
                alternatives: alternatives.iter().map(|path| (*path).to_owned()).collect(),
                retry_after_seconds: None,
            })
        };
        let failed = || {
            Err(Error::refusal(
                ErrorCode::ResourceUnavailable,
                "no answer".into(),
            ))
        };
        let (host, relays) = (key(0x11), network(&[MANAGED]));

        // Answers at 0 s and 21 s, then no answer to the third request at 61 s, then each try
        // inside the ten minutes after it. The dial at 661 s asks again and gets none, and what the
        // answers said has ended by then.
        let clock = AdmissionClock::standing();
        let service = Scripted::new(vec![unavailable(), unavailable(), failed()]);
        let admissions = scripted_admissions(Arc::clone(&service), &clock);
        let seen = waits_at(
            &service,
            &clock,
            &admissions,
            &[0, 21, 26, 61, 66, 130, 400, 660, 661],
        )
        .await;
        assert_eq!(
            seen,
            [
                (0, 1, Some(20)),
                (21, 2, Some(20)),
                (26, 2, Some(15)),
                (61, 3, Some(600)),
                (66, 3, Some(595)),
                (130, 3, Some(531)),
                (400, 3, Some(261)),
                (660, 3, Some(1)),
                (661, 4, None),
            ],
            "{alternatives:?}"
        );

        // A request that fails before the third: the answer still stands, and the next request is
        // made when the failure moved the time to, twenty seconds on, not when the answer named it.
        let clock = AdmissionClock::standing();
        let service = Scripted::new(vec![unavailable(), failed()]);
        let admissions = scripted_admissions(Arc::clone(&service), &clock);
        let seen = waits_at(&service, &clock, &admissions, &[0, 21, 26, 41, 46]).await;
        assert_eq!(
            seen,
            [
                (0, 1, Some(20)),
                (21, 2, Some(20)),
                (26, 2, Some(15)),
                (41, 3, Some(600)),
                (46, 3, Some(595)),
            ],
            "{alternatives:?}"
        );
        // It is still the answer's own, of the kind it was.
        match admissions.refusal(&relays, &host) {
            Some(RelayRefusal::Capacity {
                alternatives: kept, ..
            }) => {
                assert_eq!(words_of(&kept), alternatives);
            }
            Some(RelayRefusal::Fault { .. }) => assert!(alternatives.is_empty()),
            None => panic!("a failed request replaced the answer that still stood"),
        }
    }
}

/// A request that the service refuses with a code that stops every request for ten minutes: this
/// device is not allowed to ask.
fn stops_requests() -> Result<AdmissionAnswer> {
    Err(Error::refusal(
        ErrorCode::PermissionDenied,
        "not allowed".into(),
    ))
}

/// A refusal in the service's own envelope under a 5xx status, with a code that stops no request.
fn fault_that_stops_nothing() -> Result<AdmissionAnswer> {
    Ok(AdmissionAnswer::Faulted {
        code: ErrorCode::OutcomeUnknown,
        retry_after_seconds: None,
    })
}

const HOST_A: u8 = 0x11;
const HOST_B: u8 = 0x33;
const HOST_C: u8 = 0x44;

/// The hosts of one managed relay on one clock, asked of a scripted service, for the orders in which
/// a stop of requests meets answers that stand, answers that are on their way and answers that have
/// not come. A service that holds its requests lets one through when the test says so, and the script
/// is read in the order they pass.
struct Hosts {
    clock: AdmissionClock,
    service: Arc<Scripted>,
    gate: Option<Arc<tokio::sync::Notify>>,
    admissions: PairingAdmissions,
    relays: NetworkConfig,
    /// Seconds since the clock's start.
    at: u64,
}

impl Hosts {
    /// A service that answers each request at once, so that a dial returns with its answer kept.
    fn answering(script: Vec<Result<AdmissionAnswer>>) -> Self {
        let clock = AdmissionClock::standing();
        let service = Scripted::new(script);
        let admissions = scripted_admissions(Arc::clone(&service), &clock);
        Self {
            clock,
            service,
            gate: None,
            admissions,
            relays: network(&[MANAGED]),
            at: 0,
        }
    }

    /// A service that holds each request until the test lets one through.
    fn holding(script: Vec<Result<AdmissionAnswer>>) -> Self {
        Self::holding_and_unwinding_at(script, None)
    }

    /// As [`Hosts::holding`], and the task of the `unwinds_at`th request that is made ends when the
    /// test lets that request through, with no answer.
    fn holding_and_unwinding_at(
        script: Vec<Result<AdmissionAnswer>>,
        unwinds_at: Option<usize>,
    ) -> Self {
        let clock = AdmissionClock::standing();
        let (service, gate) = Scripted::gated_script_unwinding_at(script, unwinds_at);
        let admissions =
            scripted_admissions(Arc::clone(&service), &clock).waiting(Duration::from_millis(20));
        Self {
            clock,
            service,
            gate: Some(gate),
            admissions,
            relays: network(&[MANAGED]),
            at: 0,
        }
    }

    /// Moves the clock to `seconds` after its start.
    fn go_to(&mut self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds - self.at));
        self.at = seconds;
    }

    /// A dial to `host` that starts now, as the candidate's link makes one.
    async fn dial(&self, host: u8) {
        self.admissions
            .before_dial(&self.relays, &key(host), key(0x22))
            .await;
    }

    fn asks(&self) -> usize {
        self.service.asks()
    }

    fn refusal(&self, host: u8) -> Option<RelayRefusal> {
        self.admissions.refusal(&self.relays, &key(host))
    }

    /// What a dial to `host` that is lost now is reported as.
    fn told(&self, host: u8) -> (FailureKind, Vec<String>) {
        reported_as(self.refusal(host))
    }

    fn gate(&self) -> &tokio::sync::Notify {
        self.gate.as_deref().expect("a service that holds requests")
    }

    fn answered(&self) -> usize {
        self.service.answered.load(Ordering::SeqCst)
    }

    /// A dial whose request is let through as it is made: waits until the cache has the answer.
    async fn dial_and_answer(&self, host: u8) {
        let answered = self.answered();
        self.gate().notify_one();
        self.dial(host).await;
        self.service.answered_to(answered + 1).await;
    }

    /// Lets the request that has waited longest through, and waits until the cache has its answer.
    async fn lets_the_oldest_through(&self) {
        let answered = self.answered();
        self.gate().notify_one();
        self.service.answered_to(answered + 1).await;
    }

    /// Lets the request that was made last through, and waits until the cache has its answer.
    async fn lets_the_newest_through(&self) {
        let answered = self.answered();
        self.gate().notify_last();
        self.service.answered_to(answered + 1).await;
    }
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a standing clock reads what a test has added and
/// nothing else, so a wait that a case counts is not changed by the real time that a loaded machine
/// takes between a move of the clock and a read of it. Many readings are taken one after the other,
/// and every clone of the clock is moved with it.
#[test]
fn kr_req_17_48_a_standing_clock_reads_what_a_test_added_and_nothing_else() {
    let clock = AdmissionClock::standing();
    let first = clock.now();
    for _ in 0..200_000 {
        assert_eq!(clock.now(), first, "a standing clock does not run");
    }
    let clone = clock.clone();
    clone.advance(Duration::from_millis(1500));
    for _ in 0..200_000 {
        assert_eq!(
            clock.now(),
            first + Duration::from_millis(1500),
            "the clock reads what was added, through any clone"
        );
    }
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a failed request that stops every request for ten
/// minutes does not end the answer that stood when it began: a lost dial is told the lack of
/// capacity, with the paths and the wait that is left of the stop, until the stop ends, and not
/// that the host could not be reached. The answer comes at 0 s; the request at 25 s fails with a
/// refusal of this device, so no request is made until 625 s, though the answer's own keep time ends
/// at 60 s. What a person is sent at 61 s is the failure of the relay's capacity, by its wire kind.
#[tokio::test]
async fn kr_req_17_48_a_stop_of_requests_keeps_the_capacity_answer_that_stood_when_it_began() {
    let mut hosts = Hosts::answering(vec![unable(None), stops_requests()]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    hosts.go_to(25);
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 2, "the request at 25 s is the second");

    for (second, wait) in [(26, 599), (61, 564), (300, 325), (624, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 2, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
        let refusal = hosts.refusal(HOST_A).expect("the answer stands");
        assert_eq!(
            serde_json::to_value(PairingFailure::of_relay(refusal)).expect("a failure is sent"),
            serde_json::json!({
                "kind": "relay_capacity",
                "tries_left": null,
                "alternatives": STILL_WORK,
                "retry_after_seconds": wait,
            }),
            "what a person is sent at {second} s"
        );
    }

    hosts.go_to(625);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 3, "the first dial after the stop asks again");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: the same when the request that stops requests is the
/// third, whose window of ten minutes ends before the stop does. The asks are at 0, 25 and 50 s; the
/// third is answered at 65 s with a refusal of this device. The window ends at 650 s and the stop at
/// 665 s, and the answer is told to the stop's end.
#[tokio::test]
async fn kr_req_17_48_a_stop_that_the_third_ask_begins_keeps_the_answer_to_its_end() {
    let mut hosts = Hosts::holding(vec![unable(None), unable(None), stops_requests()]);
    hosts.go_to(0);
    hosts.dial_and_answer(HOST_A).await;
    hosts.go_to(25);
    hosts.dial_and_answer(HOST_A).await;
    hosts.go_to(50);
    hosts.dial(HOST_A).await;
    hosts.service.asked_to(3).await;
    hosts.go_to(65);
    hosts.lets_the_oldest_through().await;

    for (second, wait) in [(655, 10), (664, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 3, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(665);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: an answer that is written while a stop lasts, by a
/// request that was on its way when the stop began, is kept to the stop's end too. Host A's answer
/// comes at 0 s and its second request is made at 25 s and held; host B's request at 30 s is
/// refused, so no request is made until 630 s; A's held request is answered at 40 s that the service
/// is unable. At 101 s, when that new answer's own keep time has passed, a lost dial is still told
/// the lack of capacity.
#[tokio::test]
async fn kr_req_17_48_a_word_written_during_a_stop_is_kept_to_its_end() {
    let mut hosts = Hosts::holding(vec![unable(None), stops_requests(), unable(None)]);
    hosts.go_to(0);
    hosts.dial_and_answer(HOST_A).await;
    hosts.go_to(25);
    hosts.dial(HOST_A).await;
    hosts.service.asked_to(2).await;
    hosts.go_to(30);
    hosts.dial(HOST_B).await;
    hosts.service.asked_to(3).await;
    hosts.lets_the_newest_through().await;
    hosts.go_to(40);
    hosts.lets_the_oldest_through().await;

    for (second, wait) in [(101, 529), (629, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 3, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(630);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: the first answer of a host that arrives while a stop
/// lasts is kept to the stop's end, whether it says the service is unable or that it failed on its
/// side with a code that stops nothing. Host C's first request is made at 5 s and held; host B's
/// request at 30 s is refused, so no request is made until 630 s; C's request is answered at 40 s.
#[tokio::test]
async fn kr_req_17_48_a_first_answer_that_arrives_during_a_stop_is_kept_to_its_end() {
    for (answer, told) in [
        (unable(None), no_capacity(529)),
        (fault_that_stops_nothing(), a_fault(529)),
    ] {
        let mut hosts = Hosts::holding(vec![stops_requests(), answer]);
        hosts.go_to(5);
        hosts.dial(HOST_C).await;
        hosts.service.asked_to(1).await;
        hosts.go_to(30);
        hosts.dial(HOST_B).await;
        hosts.service.asked_to(2).await;
        hosts.lets_the_newest_through().await;
        hosts.go_to(40);
        hosts.lets_the_oldest_through().await;

        hosts.go_to(101);
        hosts.dial(HOST_C).await;
        assert_eq!(hosts.asks(), 2, "a dial at 101 s asks nothing");
        assert_eq!(hosts.told(HOST_C), told, "at 101 s");
        hosts.go_to(630);
        assert_eq!(hosts.told(HOST_C), out_of_reach(), "the stop has ended");
    }
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: an answer that needs no explanation of a failed dial
/// replaces a kept answer at once, during a stop as at any time, and the stop is unchanged. As the
/// order of the case with a request on its way, but A's held request is answered at 40 s that the
/// pair needs no admission, in a second order that an admission is installed, and in a third that
/// the host is not managed: no refusal is held from 41 s, and no request is made until the stop ends
/// at 630 s. That answer is held to 640 s, so the first dial after the stop asks then.
#[tokio::test]
async fn kr_req_17_48_a_newer_answer_that_is_no_refusal_replaces_a_kept_word_at_once_during_a_stop()
{
    let admitted = || {
        Ok(AdmissionAnswer::Admitted {
            expires_in_seconds: 3600,
            byte_ceiling: 1_000_000,
        })
    };
    for (newer, asks_again_at) in [
        (Ok(AdmissionAnswer::NotNeeded), 630),
        (admitted(), 630),
        (Ok(AdmissionAnswer::NotManaged), 640),
    ] {
        let mut hosts = Hosts::holding(vec![unable(None), stops_requests(), newer]);
        hosts.go_to(0);
        hosts.dial_and_answer(HOST_A).await;
        hosts.go_to(25);
        hosts.dial(HOST_A).await;
        hosts.service.asked_to(2).await;
        hosts.go_to(30);
        hosts.dial(HOST_B).await;
        hosts.service.asked_to(3).await;
        hosts.lets_the_newest_through().await;
        hosts.go_to(40);
        hosts.lets_the_oldest_through().await;

        hosts.go_to(41);
        assert!(hosts.refusal(HOST_A).is_none(), "the newer answer at 41 s");
        hosts.go_to(101);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 3, "no request is made during the stop");
        assert!(hosts.refusal(HOST_A).is_none(), "the newer answer at 101 s");
        hosts.go_to(630);
        hosts.dial(HOST_A).await;
        if asks_again_at > 630 {
            assert_eq!(
                hosts.asks(),
                3,
                "the newer answer is held to {asks_again_at} s"
            );
            hosts.go_to(asks_again_at);
            hosts.dial(HOST_A).await;
        }
        assert_eq!(hosts.asks(), 4, "the first dial after the stop asks again");
    }
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a stop that another host's request begins keeps this
/// host's answer to the stop's end, since the stop holds back every host's request and nothing renews
/// the answer. Host A's answer comes at 0 s; host B's request at 10 s is refused, so no request is
/// made until 610 s; at 61 s, when A's own keep time has passed, a lost dial to A is told the lack of
/// capacity.
#[tokio::test]
async fn kr_req_17_48_a_stop_that_another_host_begins_keeps_this_hosts_answer() {
    let mut hosts = Hosts::answering(vec![unable(None), stops_requests()]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    hosts.go_to(10);
    hosts.dial(HOST_B).await;
    assert_eq!(hosts.asks(), 2, "B's request at 10 s is the second");

    for (second, wait) in [(61, 549), (609, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 2, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(610);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a stop does not bring back an answer that had stopped.
/// Host C's answer comes at 0 s and stops at 60 s, with no request made for it since; host B's
/// request at 100 s is refused. C's lost dial is told the host could not be reached, as before the
/// stop.
#[tokio::test]
async fn kr_req_17_48_a_stop_that_another_host_begins_does_not_bring_back_an_answer_that_had_stopped()
 {
    let mut hosts = Hosts::answering(vec![unable(None), stops_requests()]);
    hosts.go_to(0);
    hosts.dial(HOST_C).await;
    hosts.go_to(100);
    hosts.dial(HOST_B).await;
    assert_eq!(hosts.asks(), 2, "B's request at 100 s is the second");

    for second in [101, 300] {
        hosts.go_to(second);
        hosts.dial(HOST_C).await;
        assert_eq!(hosts.asks(), 2, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_C), out_of_reach(), "at {second} s");
    }
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a failure of the service itself that stops requests
/// is told as that failure, with the wait that is left of the stop, to the stop's end. The service
/// answers in its envelope that it is not configured, naming 30 seconds: its new answer is kept for
/// 60, and the stop for 600.
#[tokio::test]
async fn kr_req_17_48_a_service_fault_that_begins_a_stop_stands_as_long_as_the_stop() {
    let mut hosts = Hosts::answering(vec![Ok(AdmissionAnswer::Faulted {
        code: ErrorCode::HostNotConfigured,
        retry_after_seconds: Some(30),
    })]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 1);

    for (second, wait) in [(26, 574), (61, 539), (599, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 1, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), a_fault(wait), "at {second} s");
    }
    hosts.go_to(601);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a request that fails with a code that stops nothing,
/// after its answer's keep time and while another host's request has begun a stop, does not end the
/// answer before the stop ends. A's second request is made at 55 s and held; B's request at 65 s is
/// refused, so no request is made until 665 s; A's request fails at 70 s. At 91 s, when the failed
/// request's own time to ask again has passed, a lost dial is still told the lack of capacity.
#[tokio::test]
async fn kr_req_17_48_a_request_that_fails_after_the_keep_time_does_not_end_the_answer_before_the_stop()
 {
    let mut hosts = Hosts::holding(vec![unable(None), stops_requests(), no_answer()]);
    hosts.go_to(0);
    hosts.dial_and_answer(HOST_A).await;
    hosts.go_to(55);
    hosts.dial(HOST_A).await;
    hosts.service.asked_to(2).await;
    hosts.go_to(65);
    hosts.dial(HOST_B).await;
    hosts.service.asked_to(3).await;
    hosts.lets_the_newest_through().await;
    hosts.go_to(70);
    hosts.lets_the_oldest_through().await;

    for (second, wait) in [(91, 574), (664, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 3, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(665);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: an answer that stands through the window of ten minutes
/// after its third request, because the asks are used up, is kept to the end of a stop that begins
/// inside the window, though the window ends first. Host A asks at 0, 21 and 41 s and gets that the
/// service is unable twice and then no answer; its keep time ends at 81 s and its window at 641 s.
/// Host B's request at 100 s is refused, so no request is made until 700 s. At 650 s a lost dial to A
/// is told the lack of capacity.
#[tokio::test]
async fn kr_req_17_48_an_answer_that_stands_through_the_third_ask_window_is_kept_to_the_stops_end()
{
    let mut hosts = Hosts::answering(vec![
        unable(None),
        unable(None),
        no_answer(),
        stops_requests(),
    ]);
    for second in [0, 21, 41] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
    }
    assert_eq!(hosts.asks(), 3, "A is asked three times");
    hosts.go_to(100);
    hosts.dial(HOST_B).await;
    assert_eq!(hosts.asks(), 4, "B's request at 100 s is the fourth");

    for (second, wait) in [(650, 50), (699, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 4, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(700);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: the stop's end is a least keep, and not an expiry: an
/// answer that names a delay of an hour is kept for that hour, though a stop that begins at 10 s ends
/// at 610 s. A lost dial at 700 s is told the lack of capacity with the wait that is left of the
/// hour.
#[tokio::test]
async fn kr_req_17_48_a_longer_named_delay_outlasts_the_stop() {
    let mut hosts = Hosts::answering(vec![unable(Some(3600)), stops_requests()]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    hosts.go_to(10);
    hosts.dial(HOST_B).await;
    assert_eq!(hosts.asks(), 2, "B's request at 10 s is the second");

    hosts.go_to(700);
    hosts.dial(HOST_A).await;
    assert_eq!(
        hosts.asks(),
        2,
        "the delay the service named has not passed"
    );
    assert_eq!(hosts.told(HOST_A), no_capacity(2900), "at 700 s");
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a failure that begins no stop keeps the answer no longer
/// than before. A's second request at 25 s fails with a code that stops nothing: the answer stands to
/// its keep time at 60 s and a dial then asks again. In a second order the service answers in its
/// envelope with a failure that stops nothing: that is a new answer, kept for its own 60 seconds,
/// to 85 s.
#[tokio::test]
async fn kr_req_17_48_a_failure_that_begins_no_stop_keeps_the_answer_no_longer_than_before() {
    let mut hosts = Hosts::answering(vec![unable(None), no_answer()]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    hosts.go_to(25);
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 2, "the request at 25 s is the second");
    for (second, wait) in [(26, 19), (59, 0)] {
        hosts.go_to(second);
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(61);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the answer has stopped");
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 3, "no stop held the dial back");

    let mut hosts = Hosts::answering(vec![unable(None), fault_that_stops_nothing()]);
    hosts.go_to(0);
    hosts.dial(HOST_A).await;
    hosts.go_to(25);
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 2, "the request at 25 s is the second");
    for (second, wait) in [(26, 19), (84, 0)] {
        hosts.go_to(second);
        assert_eq!(hosts.told(HOST_A), a_fault(wait), "at {second} s");
    }
    hosts.go_to(86);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the answer has stopped");
    hosts.dial(HOST_A).await;
    assert_eq!(hosts.asks(), 3, "no stop held the dial back");
}

const MANAGED_SECOND: &str = "https://relay-2.reach.kala.to";

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a dial that is held between two relays reads the time
/// again for the second, so it does not keep, as it makes a request, an answer that stopped while it
/// was held. The second relay's answer comes at 0 s and is kept to 60 s. A dial over both relays at
/// 25 s makes its request for the first relay and is held; the clock moves to 61 s, and the dial goes
/// on to the second relay, whose request drops the answer that has stopped: a lost dial to that relay
/// is told the host could not be reached, though the request is on its way.
#[tokio::test]
async fn kr_req_17_48_a_dial_held_between_two_relays_does_not_keep_an_answer_that_stopped_meanwhile()
 {
    let clock = AdmissionClock::standing();
    let (service, gate) = Scripted::gated_script(vec![unable(None), no_answer()]);
    let (reached, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let (held, holds) = (key(0x33), Arc::new(AtomicBool::new(true)));
    let admissions = scripted_admissions(Arc::clone(&service), &clock)
        .waiting(Duration::from_millis(20))
        .after_the_locked_step({
            let (reached, release) = (Arc::clone(&reached), Arc::clone(&release));
            move |candidate| {
                let (reached, release, holds) = (
                    Arc::clone(&reached),
                    Arc::clone(&release),
                    Arc::clone(&holds),
                );
                Box::pin(async move {
                    // Once: the hook runs after the second relay's step as well.
                    if candidate == held && holds.swap(false, Ordering::SeqCst) {
                        reached.notify_one();
                        release.notified().await;
                    }
                })
            }
        });
    let host = key(0x11);
    let (second, both) = (
        network(&[MANAGED_SECOND]),
        network(&[MANAGED, MANAGED_SECOND]),
    );

    gate.notify_one();
    admissions.before_dial(&second, &host, key(0x22)).await;
    service.answered_to(1).await;
    clock.advance(Duration::from_secs(25));
    assert_eq!(
        reported_as(admissions.refusal(&second, &host)),
        no_capacity(0),
        "the second relay's answer stands at 25 s"
    );

    let held_dial = tokio::spawn({
        let (admissions, both) = (admissions.clone(), both.clone());
        async move { admissions.before_dial(&both, &host, held).await }
    });
    tokio::time::timeout(Duration::from_secs(30), reached.notified())
        .await
        .expect("the dial reaches the hook after the first relay's step");
    service.asked_to(2).await;
    clock.advance(Duration::from_secs(36));
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(30), held_dial)
        .await
        .expect("the held dial returns")
        .expect("the held dial's task");
    service.asked_to(3).await;
    assert_eq!(
        service.asks(),
        3,
        "the second relay's request at 61 s is the third"
    );
    assert_eq!(
        reported_as(admissions.refusal(&second, &host)),
        out_of_reach(),
        "at 61 s the answer has stopped"
    );
}

/// KR-REQ-17.48, KR-REQ-10.54, KR-REQ-17.40: a request whose task ends with no answer, as a panic
/// ends it, does not take away the answer that a stop kept for it. A's answer comes at 0 s and is
/// kept to 60 s; A's second request is made at 55 s and held; B's request at 65 s is refused, so no
/// request is made until 665 s, and the stop keeps A's answer because a request for it is alive; A's
/// request ends its task at 70 s. At 91 s, when the answer's own keep time and its time to ask again
/// have passed, a lost dial is still told the lack of capacity, to the stop's end.
#[tokio::test]
async fn kr_req_17_48_a_request_whose_task_ends_with_no_answer_leaves_the_answer_that_a_stop_kept()
{
    let mut hosts = Hosts::holding_and_unwinding_at(vec![unable(None), stops_requests()], Some(2));
    hosts.go_to(0);
    hosts.dial_and_answer(HOST_A).await;
    hosts.go_to(55);
    hosts.dial(HOST_A).await;
    hosts.service.asked_to(2).await;
    hosts.go_to(65);
    hosts.dial(HOST_B).await;
    hosts.service.asked_to(3).await;
    hosts.lets_the_newest_through().await;
    hosts.go_to(70);
    hosts.lets_the_oldest_through().await;

    for (second, wait) in [(91, 574), (664, 1)] {
        hosts.go_to(second);
        hosts.dial(HOST_A).await;
        assert_eq!(hosts.asks(), 3, "a dial at {second} s asks nothing");
        assert_eq!(hosts.told(HOST_A), no_capacity(wait), "at {second} s");
    }
    hosts.go_to(665);
    assert_eq!(hosts.told(HOST_A), out_of_reach(), "the stop has ended");
}
