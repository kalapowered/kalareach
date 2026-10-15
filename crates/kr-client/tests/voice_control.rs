//! A managed voice call's control socket, against the service's control route on loopback.
//!
//! The route answers as the service's contract states, so each test drives the product's own
//! control client and reads what the route saw and what the client told its owner. The timings
//! are shortened where a test waits for a loss to pass; every wait is for an event, and the only
//! clock is the watchdog that ends a test that hangs.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::ClientError;
use kr_client::Shown;
use kr_client::services::ServiceFuture;
use kr_client::services::account::{AccountToken, AccountTokenSource};
use kr_client::services::voice::{
    VOICE_CLIENT_ABSENT_SECONDS, VOICE_HEARTBEAT_SECONDS, VoiceCommand, VoiceControlEvent,
};
use kr_client::services::voice_control::{
    ContextRefusal, ControlConnector, ControlEnd, ControlEvents, ControlNews, ControlTarget,
    ControlTimings, SendError, VOICE_KNOWN_DELEGATIONS, VoiceControl, call_start_appends,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::voice::{VoiceContextClass, VoiceContextSelection, VoiceSelectedContent};

#[path = "support/control_route.rs"]
mod control_route;
#[path = "support/room_tls.rs"]
mod room_tls;

use control_route::{ControlRoute, PATH, TOKEN, WATCHDOG, session};

const fn ms(count: u64) -> Duration {
    Duration::from_millis(count)
}

/// The control's timings with the waits shortened. The silence and the answer limits stay long
/// enough that a busy machine does not trip them in a test that is not about them.
fn quick() -> ControlTimings {
    ControlTimings {
        heartbeat: ms(50),
        silence: ms(2000),
        absent: ms(1500),
        ready_within: ms(2000),
        answer_within: ms(2000),
        write_within: ms(2000),
        retry_first: ms(10),
        retry_most: ms(40),
        burst_window: ms(300),
        minute_window: ms(1800),
    }
}

/// The account service as far as a control needs it: a token for a scope, or a failure.
#[derive(Debug)]
struct Tokens {
    token: Mutex<String>,
    asked: Mutex<Vec<String>>,
    failures: Mutex<VecDeque<ErrorCode>>,
}

impl Tokens {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(TOKEN.to_owned()),
            asked: Mutex::new(Vec::new()),
            failures: Mutex::new(VecDeque::new()),
        })
    }

    fn replace(&self, token: &str) {
        *self.token.lock().expect("the tokens") = token.to_owned();
    }

    fn fail_with(&self, codes: &[ErrorCode]) {
        self.failures
            .lock()
            .expect("the tokens")
            .extend(codes.iter().copied());
    }

    fn scopes(&self) -> Vec<String> {
        self.asked.lock().expect("the tokens").clone()
    }
}

impl AccountTokenSource for Tokens {
    fn token<'a>(&'a self, scope: &'a str) -> ServiceFuture<'a, AccountToken> {
        Box::pin(async move {
            self.asked
                .lock()
                .expect("the tokens")
                .push(scope.to_owned());
            if let Some(code) = self.failures.lock().expect("the tokens").pop_front() {
                return Err(ClientError::refusal(code, Shown::said("scripted")));
            }
            AccountToken::new(self.token.lock().expect("the tokens").clone())
        })
    }
}

fn connector() -> ControlConnector {
    ControlConnector::with_tls(
        tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
        .with_no_client_auth(),
    )
    .with_timings(quick())
}

/// A control opened on `route` with the shortened timings.
fn open(route: &ControlRoute, tokens: &Arc<Tokens>) -> (VoiceControl, ControlEvents) {
    VoiceControl::open(&connector(), route.target(), Arc::clone(tokens) as _)
}

/// The next news of any kind.
async fn raw(news: &mut ControlEvents) -> ControlNews {
    tokio::time::timeout(WATCHDOG, news.next())
        .await
        .expect("news within the watchdog")
        .expect("the control ended without telling its owner")
}

/// The next news that is not the service answering a heartbeat, which comes whenever the socket
/// has been quiet for an interval.
async fn next(news: &mut ControlEvents) -> ControlNews {
    loop {
        match raw(news).await {
            ControlNews::Event(VoiceControlEvent::HeartbeatAcknowledged { .. }) => {}
            other => return other,
        }
    }
}

/// The next news is the attachment; returns whether it was a reattachment, and the delegations.
async fn attached(news: &mut ControlEvents) -> (bool, Vec<String>) {
    match next(news).await {
        ControlNews::Attached {
            reattached,
            delegations,
        } => (reattached, delegations),
        other => panic!("expected an attachment, got {other:?}"),
    }
}

/// Reads news until one is an event the test wants, and returns it.
async fn event_where(
    news: &mut ControlEvents,
    wanted: impl Fn(&VoiceControlEvent) -> bool,
) -> VoiceControlEvent {
    loop {
        if let ControlNews::Event(event) = raw(news).await
            && wanted(&event)
        {
            return event;
        }
    }
}

async fn ended(news: &mut ControlEvents) -> ControlEnd {
    loop {
        if let ControlNews::Ended(end) = next(news).await {
            return end;
        }
    }
}

/// How many context requests the route read.
fn contexts(route: &ControlRoute) -> usize {
    route
        .report()
        .frames
        .iter()
        .filter(|frame| frame.contains(r#""type":"context""#))
        .count()
}

/// The product's figures are the service's.
#[test]
fn the_product_waits_the_services_heartbeat_and_absent_figures() {
    let product = ControlTimings::default();
    assert_eq!(
        product.heartbeat,
        Duration::from_secs(u64::from(VOICE_HEARTBEAT_SECONDS))
    );
    assert_eq!(
        product.absent,
        Duration::from_secs(u64::from(VOICE_CLIENT_ABSENT_SECONDS))
    );
    assert!(product.silence > product.heartbeat * 2);
    assert!(product.silence < product.absent);
}

#[tokio::test]
async fn the_control_presents_the_voice_token_and_is_told_the_delegations_so_far() {
    let route = ControlRoute::start().await;
    route.list(vec!["del-1".to_owned(), "del-2".to_owned()]);
    let tokens = Tokens::new();
    let (_control, mut news) = open(&route, &tokens);

    let (reattached, delegations) = attached(&mut news).await;

    assert!(!reattached);
    assert_eq!(delegations, ["del-1", "del-2"]);
    let report = route.report();
    assert_eq!(report.upgrades.len(), 1);
    assert_eq!(report.upgrades[0].path, PATH);
    assert_eq!(
        report.upgrades[0].authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(tokens.scopes(), ["voice"]);
}

#[tokio::test]
async fn the_same_control_attaches_over_tls_the_platform_would_verify() {
    let authority = room_tls::Authority::new("voice control test authority");
    let route = ControlRoute::start_with(Some(authority.acceptor()), None).await;
    let tokens = Tokens::new();

    // A client that trusts the authority attaches and presents the token.
    let trusting = authority.control_connector().with_timings(quick());
    let (_control, mut news) =
        VoiceControl::open(&trusting, route.target(), Arc::clone(&tokens) as _);
    attached(&mut news).await;
    assert_eq!(
        route.report().upgrades[0].authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    // One that does not trust it never reaches the route, and the token never leaves the device
    // for a service whose certificate it cannot verify.
    let other = ControlRoute::start_with(Some(authority.acceptor()), None).await;
    let (_control, mut news) = VoiceControl::open(&connector(), other.target(), tokens);
    assert_eq!(ended(&mut news).await, ControlEnd::Unreachable);
    assert!(other.report().upgrades.is_empty());
}

#[tokio::test]
async fn an_address_that_is_neither_https_nor_loopback_is_not_opened() {
    let target = ControlTarget::new("http://192.0.2.7:9", &session()).expect("a target");
    let (_control, mut news) = VoiceControl::open(&connector(), target, Tokens::new());

    assert_eq!(ended(&mut news).await, ControlEnd::Misconfigured);
}

#[tokio::test]
async fn a_heartbeat_goes_on_the_interval_and_its_answer_reaches_the_owner() {
    let route = ControlRoute::start().await;
    let (_control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    route
        .until("three heartbeats", |report| report.heartbeats >= 3)
        .await;
    let event = event_where(&mut news, |event| {
        matches!(event, VoiceControlEvent::HeartbeatAcknowledged { .. })
    })
    .await;

    assert!(matches!(
        event,
        VoiceControlEvent::HeartbeatAcknowledged {
            remaining_seconds: 600
        }
    ));
}

#[tokio::test]
async fn a_request_is_accepted_and_the_models_admission_comes_as_news() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.announce("del-1", 1200);
    event_where(&mut news, |event| {
        matches!(event, VoiceControlEvent::Delegation { .. })
    })
    .await;

    let accepted = control
        .send(
            VoiceCommand::Commentary,
            Some("del-1"),
            Some("Nothing was done."),
        )
        .await
        .expect("accepted");

    let admitted = event_where(&mut news, |event| {
        matches!(event, VoiceControlEvent::ContextAdmitted { .. })
    })
    .await;
    assert!(matches!(
        admitted,
        VoiceControlEvent::ContextAdmitted { ref id, .. } if *id == accepted.id
    ));
    let sent = route.report().sent;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, accepted.id);
    assert_eq!(sent[0].command, "commentary");
    assert_eq!(sent[0].delegation.as_deref(), Some("del-1"));
    assert_eq!(sent[0].content.as_deref(), Some("Nothing was done."));
}

#[tokio::test]
async fn the_clients_own_rules_refuse_before_anything_is_written() {
    let route = ControlRoute::start().await;
    route.list(vec!["x".repeat(4100)]);
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    let invalid = |outcome: Result<_, SendError>| {
        assert!(matches!(outcome, Err(SendError::Invalid(_))), "{outcome:?}");
    };

    // An append over the bound.
    invalid(
        control
            .send(VoiceCommand::Thinking, None, Some(&"a".repeat(501)))
            .await,
    );
    // A command that carries text, without any; one that carries none, with some.
    invalid(control.send(VoiceCommand::Thinking, None, None).await);
    invalid(control.send(VoiceCommand::Mute, None, Some("quiet")).await);
    // A delegation this call never heard, and an empty one.
    invalid(
        control
            .send(VoiceCommand::Commentary, Some("del-invented"), Some("done"))
            .await,
    );
    invalid(
        control
            .send(VoiceCommand::Commentary, Some(""), Some("done"))
            .await,
    );
    // A frame over the service's bound, which a delegation the call did hear can make.
    let long = "x".repeat(4100);
    invalid(
        control
            .send(VoiceCommand::Commentary, Some(&long), Some("done"))
            .await,
    );
    assert_eq!(contexts(&route), 0);

    // The control: the same bound, met exactly, goes through.
    control
        .send(VoiceCommand::Thinking, None, Some(&"é".repeat(250)))
        .await
        .expect("an append of exactly 500 bytes");
    assert_eq!(contexts(&route), 1);
}

#[tokio::test]
async fn a_call_remembers_only_the_newest_delegations_it_is_listed() {
    let route = ControlRoute::start().await;
    let listed: Vec<String> = (0..VOICE_KNOWN_DELEGATIONS + 44)
        .map(|index| format!("del-{index}"))
        .collect();
    route.list(listed.clone());
    let (control, mut news) = open(&route, &Tokens::new());

    let (_, delegations) = attached(&mut news).await;

    assert_eq!(delegations.len(), VOICE_KNOWN_DELEGATIONS);
    assert_eq!(delegations.first(), Some(&"del-44".to_owned()));
    assert_eq!(delegations.last(), listed.last());
    // The route knows all of them. It is the client that holds the call to the newest.
    let dropped = control
        .send(VoiceCommand::Commentary, Some("del-43"), Some("done"))
        .await;
    assert!(matches!(dropped, Err(SendError::Invalid(_))), "{dropped:?}");
    assert_eq!(contexts(&route), 0);
    control
        .send(VoiceCommand::Commentary, Some("del-44"), Some("done"))
        .await
        .expect("the oldest delegation still held");

    // Announcements push the oldest out, one for one.
    route.announce("del-new", 5);
    event_where(&mut news, |event| {
        matches!(event, VoiceControlEvent::Delegation { .. })
    })
    .await;
    let pushed_out = control
        .send(VoiceCommand::Commentary, Some("del-44"), Some("again"))
        .await;
    assert!(
        matches!(pushed_out, Err(SendError::Invalid(_))),
        "{pushed_out:?}"
    );
    control
        .send(VoiceCommand::Commentary, Some("del-new"), Some("done"))
        .await
        .expect("a delegation announced on this socket");
}

#[tokio::test]
async fn a_refusal_of_the_service_is_the_answer_to_the_request() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.provider_down(true);

    let refused = control
        .send(VoiceCommand::Thinking, None, Some("context"))
        .await;

    match refused {
        Err(SendError::Refused { reason, .. }) => {
            assert_eq!(reason, ContextRefusal::MeteringUnavailable);
        }
        other => panic!("expected the service's refusal, got {other:?}"),
    }
    // The control: with the provider back the same request goes through.
    route.provider_down(false);
    control
        .send(VoiceCommand::Thinking, None, Some("context"))
        .await
        .expect("accepted");
}

#[tokio::test]
async fn requests_keep_inside_the_services_rate_without_being_refused() {
    let route = ControlRoute::start_with(None, Some((ms(300), ms(1800)))).await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    for number in 0..25 {
        control
            .send(
                VoiceCommand::Thinking,
                None,
                Some(&format!("part {number}")),
            )
            .await
            .expect("accepted");
    }

    let report = route.report();
    assert_eq!(report.sent.len(), 25);
    assert_eq!(report.rate_refusals, 0);
}

#[tokio::test]
async fn a_client_that_ignores_the_rate_is_refused_for_it() {
    // The control for the test above: the route does enforce the rate, and it is the client's
    // pacing that keeps a call inside it. The client here is told the windows are a millisecond.
    let route = ControlRoute::start_with(
        None,
        Some((Duration::from_secs(5), Duration::from_secs(30))),
    )
    .await;
    let unpaced = ControlConnector::with_tls(
        tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
        .with_no_client_auth(),
    )
    .with_timings(ControlTimings {
        burst_window: ms(1),
        minute_window: ms(1),
        ..quick()
    });
    let (control, mut news) = VoiceControl::open(&unpaced, route.target(), Tokens::new());
    attached(&mut news).await;

    let mut refused = 0;
    for number in 0..15 {
        let outcome = control
            .send(
                VoiceCommand::Thinking,
                None,
                Some(&format!("part {number}")),
            )
            .await;
        if let Err(SendError::Refused { reason, .. }) = outcome {
            assert_eq!(reason, ContextRefusal::Rate);
            refused += 1;
        }
    }

    assert_eq!(refused, 5);
    assert_eq!(route.report().sent.len(), 10);
}

#[tokio::test]
async fn a_frame_this_build_does_not_know_is_recorded_by_type_and_the_rest_are_dropped() {
    let route = ControlRoute::start().await;
    let (_control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    route.say(&serde_json::json!({ "type": "provider_event", "raw": "response.create" }));
    // A known type of the wrong shape, text that is not JSON, JSON that is not an object, bytes,
    // and an object that names a member twice are not frames this client acts on.
    route.say(&serde_json::json!({ "type": "usage", "seconds": "many", "provisional": true }));
    route.say_text("this is not json");
    route.say_text("[1, 2, 3]");
    route.say_binary(&[0, 1, 2, 3]);
    route.say_text(r#"{"type":"usage","seconds":1,"seconds":2,"provisional":false}"#);
    route.usage(5, true);

    // The first thing the owner is told after the attachment is the unknown frame, by its type
    // alone, and the second is the usage that follows the dropped ones on the same socket.
    assert_eq!(
        next(&mut news).await,
        ControlNews::Event(VoiceControlEvent::Unknown {
            frame_type: "provider_event".to_owned()
        })
    );
    assert_eq!(
        next(&mut news).await,
        ControlNews::Event(VoiceControlEvent::Usage {
            seconds: 5,
            provisional: true
        })
    );
    assert_eq!(route.report().upgrades.len(), 1);
}

#[tokio::test]
async fn a_frame_larger_than_the_client_reads_loses_the_socket_and_the_control_opens_another() {
    let route = ControlRoute::start().await;
    let (_control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    route.say_text(&"x".repeat(70 * 1024));

    assert!(matches!(next(&mut news).await, ControlNews::Detached));
    let (reattached, _) = attached(&mut news).await;
    assert!(reattached);
    assert_eq!(route.report().upgrades.len(), 2);
}

#[tokio::test]
async fn a_dropped_socket_is_opened_again_with_the_token_held_now() {
    let route = ControlRoute::start().await;
    let tokens = Tokens::new();
    let (_control, mut news) = open(&route, &tokens);
    attached(&mut news).await;
    tokens.replace("account-token-2");
    route.list(vec!["del-late".to_owned()]);

    route.drop_sockets();

    assert!(matches!(next(&mut news).await, ControlNews::Detached));
    let (reattached, delegations) = attached(&mut news).await;
    assert!(reattached);
    assert_eq!(delegations, ["del-late"]);
    let upgrades = route.report().upgrades;
    assert_eq!(upgrades.len(), 2);
    assert_eq!(
        upgrades[1].authorization.as_deref(),
        Some("Bearer account-token-2")
    );
    assert_eq!(tokens.scopes(), ["voice", "voice"]);
}

#[tokio::test]
async fn a_request_the_socket_dropped_on_is_written_again_and_the_model_hears_it_once() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.swallow_next_request_and_drop();

    let accepted = control
        .send(VoiceCommand::Thinking, None, Some("remember this"))
        .await
        .expect("accepted after the socket was opened again");

    let report = route.report();
    let written: Vec<&String> = report
        .frames
        .iter()
        .filter(|frame| frame.contains("remember this"))
        .collect();
    assert_eq!(written.len(), 2, "written to two sockets");
    assert_eq!(
        written[0], written[1],
        "the same request, under the same identifier"
    );
    assert!(written[0].contains(&accepted.id));
    assert_eq!(report.sent.len(), 1, "sent to the provider once");
    assert_eq!(report.repeats, 1);
    assert_eq!(report.upgrades.len(), 2);
}

#[tokio::test]
async fn a_request_made_while_the_socket_is_down_waits_for_it() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.refuse_all(Some(503));
    route.drop_sockets();
    assert!(matches!(next(&mut news).await, ControlNews::Detached));

    let waiting = tokio::spawn({
        let control = control.clone();
        async move {
            control
                .send(VoiceCommand::Thinking, None, Some("while away"))
                .await
        }
    });
    route
        .until("an upgrade refused", |report| report.refused_upgrades >= 2)
        .await;
    assert_eq!(
        contexts(&route),
        0,
        "nothing can be written to a socket that is not open"
    );
    route.refuse_all(None);

    waiting
        .await
        .expect("the task")
        .expect("accepted once the socket was back");
    assert_eq!(route.report().sent.len(), 1);
}

#[tokio::test]
async fn a_service_that_stays_unreachable_ends_the_control_when_the_absent_window_passes() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.refuse_all(Some(503));
    route.drop_sockets();
    assert!(matches!(next(&mut news).await, ControlNews::Detached));
    let waiting = tokio::spawn({
        let control = control.clone();
        async move {
            control
                .send(VoiceCommand::Thinking, None, Some("never delivered"))
                .await
        }
    });

    assert_eq!(ended(&mut news).await, ControlEnd::Unreachable);

    let waited = waiting.await.expect("the task");
    assert!(matches!(waited, Err(SendError::Lost)), "{waited:?}");
    assert!(
        route.report().refused_upgrades >= 2,
        "it tried again before it gave up"
    );
    let after = control
        .send(VoiceCommand::Thinking, None, Some("too late"))
        .await;
    assert!(matches!(after, Err(SendError::Lost)), "{after:?}");
    assert!(news.next().await.is_none(), "nothing follows the end");
}

#[tokio::test]
async fn an_answer_that_reconnecting_cannot_change_ends_the_control_at_once() {
    for (status, end) in [
        (401, ControlEnd::NotAuthorised),
        (403, ControlEnd::NoSuchCall),
        (404, ControlEnd::NoSuchCall),
        (400, ControlEnd::Refused(400)),
    ] {
        let route = ControlRoute::start().await;
        route.refuse_next(&[status]);
        let (_control, mut news) = open(&route, &Tokens::new());

        assert_eq!(ended(&mut news).await, end, "status {status}");

        assert_eq!(
            route.report().refused_upgrades,
            1,
            "status {status} is not tried again"
        );
        assert!(news.next().await.is_none());
    }
}

#[tokio::test]
async fn an_answer_that_may_pass_is_tried_again() {
    let route = ControlRoute::start().await;
    route.refuse_next(&[429, 502, 408, 503]);
    let (_control, mut news) = open(&route, &Tokens::new());

    let (reattached, _) = attached(&mut news).await;

    assert!(!reattached, "it was never attached before");
    let report = route.report();
    assert_eq!(report.refused_upgrades, 4);
    assert_eq!(report.upgrades.len(), 1);
}

#[tokio::test]
async fn a_ready_that_names_another_call_ends_the_control() {
    let route = ControlRoute::start().await;
    route.name_another_call();
    let (_control, mut news) = open(&route, &Tokens::new());

    assert_eq!(ended(&mut news).await, ControlEnd::NoSuchCall);
}

#[tokio::test]
async fn no_account_token_ends_the_control_and_a_service_that_is_down_does_not() {
    let route = ControlRoute::start().await;
    let tokens = Tokens::new();
    tokens.fail_with(&[ErrorCode::HostNotConfigured]);
    let (_control, mut news) = open(&route, &tokens);
    assert_eq!(ended(&mut news).await, ControlEnd::NoToken);
    assert!(route.report().upgrades.is_empty());

    let tokens = Tokens::new();
    tokens.fail_with(&[
        ErrorCode::UpstreamUnavailable,
        ErrorCode::UpstreamUnavailable,
    ]);
    let (_control, mut news) = open(&route, &tokens);
    attached(&mut news).await;
    assert_eq!(tokens.scopes().len(), 3);
}

#[tokio::test]
async fn a_route_that_stops_answering_is_lost_by_its_silence_and_found_again() {
    let route = ControlRoute::start().await;
    let (_control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    route.go_silent(true);
    assert!(matches!(next(&mut news).await, ControlNews::Detached));
    route.go_silent(false);

    let (reattached, _) = attached(&mut news).await;
    assert!(reattached);
}

#[tokio::test]
async fn usage_is_told_as_the_cumulative_figure_it_is_and_the_service_ending_the_call_ends_the_control()
 {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    route.usage(5, true);
    route.usage(9, true);
    route.close_call("deadline", 30);

    for seconds in [5, 9] {
        assert_eq!(
            next(&mut news).await,
            ControlNews::Event(VoiceControlEvent::Usage {
                seconds,
                provisional: true
            })
        );
    }
    assert_eq!(
        ended(&mut news).await,
        ControlEnd::Closed {
            reason: "deadline".to_owned(),
            seconds: 30,
            provisional: false
        }
    );
    assert!(news.next().await.is_none());
    let after = control
        .send(VoiceCommand::Thinking, None, Some("late"))
        .await;
    assert!(matches!(after, Err(SendError::Lost)), "{after:?}");
}

#[tokio::test]
async fn closing_the_call_returns_what_the_service_finalised() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    let closure = control.close().await.expect("confirmed");

    assert_eq!(closure.reason, "client_closed");
    assert_eq!(closure.seconds, 42);
    assert!(!closure.provisional);
    assert!(matches!(
        ended(&mut news).await,
        ControlEnd::Closed { seconds: 42, .. }
    ));
    assert_eq!(contexts(&route), 1);
}

#[tokio::test]
async fn a_closure_the_service_never_confirms_is_not_known_to_have_happened() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.go_silent(true);

    let closure = control.close().await;

    assert!(matches!(closure, Err(SendError::Unanswered)), "{closure:?}");
}

#[tokio::test]
async fn stopping_the_control_leaves_the_call_open_and_the_waiting_requests_lost() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    route.go_silent(true);
    let waiting = tokio::spawn({
        let control = control.clone();
        async move {
            control
                .send(VoiceCommand::Thinking, None, Some("unanswered"))
                .await
        }
    });
    route
        .until("the request", |report| {
            report.frames.iter().any(|f| f.contains("unanswered"))
        })
        .await;

    control.stop();

    let waited = waiting.await.expect("the task");
    assert!(matches!(waited, Err(SendError::Lost)), "{waited:?}");
    assert!(
        news.next().await.is_none(),
        "a stopped control tells nothing more"
    );
    route
        .until("the socket gone", |report| report.open == 0)
        .await;
}

fn selection(messages: usize) -> VoiceContextSelection {
    VoiceContextSelection {
        session_description: "Checks the pairing flow".to_owned(),
        working_directory: "/work/pairing".to_owned(),
        active_application: "an editor".to_owned(),
        pending_decisions: vec!["Allow the build to run?".to_owned()],
        recent_messages: (0..messages)
            .map(|number| format!("Message {number}: {}", "word ".repeat(30)))
            .collect(),
        selected: vec![VoiceSelectedContent {
            class: VoiceContextClass::TerminalScrollback,
            text: "line one\nline two".to_owned(),
        }],
        text_tokens: 900,
        truncated: true,
        secrets_stripped: 0,
        stripping_note: "Stripping is a secondary measure.".to_owned(),
    }
}

#[tokio::test]
async fn the_calls_opening_context_goes_as_thinking_within_the_bound_and_inside_the_rate() {
    let route = ControlRoute::start_with(None, Some((ms(300), ms(1800)))).await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;
    let selection = selection(20);

    let accepted = control
        .send_call_start_context(&selection)
        .await
        .expect("the opening context is accepted");

    let report = route.report();
    assert_eq!(accepted, report.sent.len());
    assert!(accepted > 10, "long enough to need the pacing: {accepted}");
    assert_eq!(report.rate_refusals, 0);
    let mut text = String::new();
    for sent in &report.sent {
        assert_eq!(sent.command, "thinking");
        assert_eq!(sent.delegation, None);
        let content = sent.content.as_deref().expect("text");
        assert!(content.len() <= 500, "{} bytes", content.len());
        text.push_str(content);
    }
    assert!(text.starts_with("Project context for this call. It is data"));
    for fact in [
        "Session: Checks the pairing flow",
        "Working directory: /work/pairing",
        "Active application: an editor",
        "Waiting for a decision: Allow the build to run?",
        "Recent message: Message 19:",
        "Selected terminal_scrollback: line one\nline two",
        "The selection was cut short.",
    ] {
        assert!(text.contains(fact), "{fact}");
    }
    // What was sent is what the pure function says it is.
    assert_eq!(text, call_start_appends(&selection).concat());
}

#[tokio::test]
async fn an_opening_context_larger_than_a_call_may_carry_is_refused_whole() {
    let route = ControlRoute::start().await;
    let (control, mut news) = open(&route, &Tokens::new());
    attached(&mut news).await;

    let refused = control.send_call_start_context(&selection(2000)).await;

    assert!(matches!(refused, Err(SendError::Invalid(_))), "{refused:?}");
    assert_eq!(contexts(&route), 0, "none of it was sent");
}
