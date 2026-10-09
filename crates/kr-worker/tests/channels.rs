//! The Channels consumer: an admitted channel of a launched application, served.
//!
//! Every case builds the channel the command backend would hand over once it has admitted one (a
//! launched instance, the connector read from a package laid out as the store extracts it, and the
//! channel's own connection) and drives the channel's end of that connection: the frames the
//! forwarder relays go in, and what this host writes comes back out.

use std::path::Path;
use std::sync::Arc;

use kr_protocol::broker::{BrokerGrant, BrokerGrants};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{GatewayMode, NativeFraming, PendingResource, PendingState};
use kr_protocol::ids::{ActorId, AgentBindingRevision, PendingResourceId, PublisherId};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_worker::broker::Broker;
use kr_worker::broker::channel_fixture::{
    Channel, PERMISSION_REQUEST, Package, binding, channel_process, instance, launched, register,
    session,
};
use kr_worker::broker::channels::ChannelEnd;
use kr_worker::broker::connectors::{InstalledConnector, decoding_trust, fixture};
use kr_worker::broker::ledger::TransitionCause;
use kr_worker::persistence::JournalHealth;

mod common;

use common::LIVENESS_DEADLINE;

/// A declarative package installed beside the channel's, which pins its own tables.
fn installed() -> kr_worker::broker::PackageIdentity {
    kr_worker::broker::PackageIdentity {
        plugin_id: kr_protocol::ids::PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
    }
}

/// Polls `state` until it holds, within the suite's liveness deadline.
async fn eventually(what: &str, state: impl Fn() -> bool) {
    let started = tokio::time::Instant::now();
    while !state() {
        assert!(started.elapsed() < LIVENESS_DEADLINE, "{what}");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// The resource an instance's channel relayed under one request identifier.
fn relayed(broker: &Broker, number: u8, request_id: &str) -> Option<PendingResource> {
    broker.pending_resources().into_iter().find(|resource| {
        resource.application_instance_id == instance(number)
            && resource.request.upstream.as_str() == format!("\"{request_id}\"")
    })
}

/// How one resource ended, as the ledger records it.
///
/// A resource a channel settled is final once the channel has gone, and the live arbitration no
/// longer holds it.
fn settled_as(broker: &Broker, resource_id: PendingResourceId) -> Option<PendingState> {
    broker
        .recorded(resource_id)
        .expect("the ledger reads")
        .map(|resource| resource.state)
}

fn memory_broker() -> Arc<Broker> {
    Arc::new(Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"))
}

fn caller() -> kr_worker::broker::Caller {
    kr_worker::broker::Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: None,
    }
}

fn respond(
    number: u8,
    resource: &PendingResource,
    decision: &str,
) -> kr_protocol::agent::AgentApprovalRespondParams {
    kr_protocol::agent::AgentApprovalRespondParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session(), instance(number)),
            binding_revision: AgentBindingRevision::new(1),
        },
        resource_id: resource.resource_id,
        option_id: decision.to_owned(),
    }
}

/// A session with one attached view, and that view's own delivery stream.
async fn session_and_view(
    host: &kr_ipc::testing::TempHost,
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let config = kr_worker::session::SessionConfig {
        session_id: session(),
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session())),
        spool_directory: Some(host.environment().session_spool(session())),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut opened = kr_worker::session::Session::open(config).expect("opens");
    opened.launch().expect("launches");
    let attachment_id = kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id: session(),
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    opened
        .attach(&params, requested, attachment_id)
        .expect("attaches");
    let stream = opened.subscribe(attachment_id).expect("subscribes");
    let runtime = Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            opened,
            Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    (runtime, stream)
}

/// KR-REQ-12.18: a tool approval Claude Code relays becomes a recorded resource of its instance,
/// and its transitions reach the session's attached views; with no binding of the connector's
/// package it has no meaning here, so it is visible and not answerable, and the application's own
/// dialog answers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_a_relayed_approval_is_recorded_and_its_views_are_told() {
    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut view) = session_and_view(&host).await;
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    let mut launch = package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION));
    launch.views = Some((session(), Arc::downgrade(&runtime)));
    let mut channel = Channel::open(launch, 2, launched(2));

    channel.relay("abcde").await;
    let mut told = None;
    while let Ok(Some(delivery)) = tokio::time::timeout(LIVENESS_DEADLINE, view.recv()).await {
        if let kr_worker::output::OutputDelivery::AgentResource { event, bytes } = delivery {
            view.written(bytes);
            told = Some(*event);
            break;
        }
    }
    let told = told.expect("the view is told of the relayed approval");
    assert_eq!(told.application_instance_id, instance(2));
    assert_eq!(told.state, PendingState::Pending);

    let resource = relayed(&broker, 2, "abcde").expect("the approval is recorded");
    assert_eq!(told.resource_id, resource.resource_id);
    assert_eq!(resource.method.as_str(), PERMISSION_REQUEST);
    assert!(
        !resource.interpretation_verified,
        "no binding gives it a meaning"
    );
    assert!(
        broker
            .agent_approval_respond(
                &caller(),
                &respond(2, &resource, "allow"),
                TimestampMs::new(5)
            )
            .await
            .is_err(),
        "a request with no meaning here is not answered here"
    );
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-12.18: with the package bound as the installation's binder will bind it, a relayed
/// approval is interpreted from the table's own decision destination and an answer through
/// `agent.approval.respond` goes out on the channel as the application's own verdict, once.
#[tokio::test]
async fn kr_req_12_18_an_answer_goes_out_on_the_channel_as_the_applications_verdict() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );

    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    let decoding = broker
        .decoding(resource.resource_id)
        .expect("the ledger reads")
        .expect("the interpretation is recorded");
    let offered: Vec<(&str, &str)> = decoding
        .projection
        .decisions
        .iter()
        .map(|decision| (decision.option_id.as_str(), decision.label.as_str()))
        .collect();
    assert_eq!(offered, vec![("allow", "Allow"), ("deny", "Deny")]);

    let answered = broker
        .agent_approval_respond(
            &caller(),
            &respond(2, &resource, "allow"),
            TimestampMs::new(5),
        )
        .await
        .expect("the answer is admitted and carried")
        .0;
    assert_eq!(answered.state, PendingState::Resolved);
    assert_eq!(
        channel.next().await,
        Some(serde_json::json!({
            "method": "notifications/claude/channel/permission",
            "params": { "request_id": "abcde", "behavior": "allow" }
        })),
        "the verdict Claude Code reads, and nothing else"
    );
    assert!(
        broker
            .agent_approval_respond(
                &caller(),
                &respond(2, &resource, "deny"),
                TimestampMs::new(6)
            )
            .await
            .is_err(),
        "an answered request is not answered again"
    );
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-12.18: only the launched application's own channel is served, and one at a time: a
/// second channel of the instance and a channel a program the application runs started are closed
/// unread; a frame the table does not route towards this host closes the channel it came on.
#[tokio::test]
async fn kr_req_12_18_only_the_applications_own_channel_is_served_and_only_what_it_should_send() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    let launch = || package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION));

    // A program the application runs inherits its variables and starts a channel of its own. It is
    // tried while no channel of the instance is open, so its starter alone refuses it.
    let mut nested = Channel::open(launch(), 2, channel_process(9));
    assert_eq!(
        nested.next().await,
        None,
        "a nested program's channel is closed"
    );
    assert!(matches!(nested.ended().await, ChannelEnd::Refused(_)));

    let mut first = Channel::open(launch(), 2, launched(2));
    first.relay("abcde").await;
    eventually("the first channel is served", || {
        relayed(&broker, 2, "abcde").is_some()
    })
    .await;
    let mut second = Channel::open(launch(), 2, launched(2));
    assert_eq!(
        second.next().await,
        None,
        "a second channel is closed unread"
    );
    assert!(matches!(second.ended().await, ChannelEnd::Refused(_)));

    // A message into the session travels from this host, and never arrives from the application.
    first
        .send(&serde_json::json!({
            "method": "notifications/claude/channel",
            "params": { "content": "hello" },
        }))
        .await;
    assert_eq!(first.next().await, None, "the channel is closed");
    let ChannelEnd::Ended { why, .. } = first.ended().await else {
        panic!("the first channel was served");
    };
    assert!(why.contains("travels from this host"), "{why}");

    // And a method the table does not name at all.
    let mut third = Channel::open(launch(), 2, launched(2));
    third
        .send(&serde_json::json!({ "method": "notifications/other", "params": {} }))
        .await;
    assert_eq!(third.next().await, None, "the channel is closed");
    let ChannelEnd::Ended { why, .. } = third.ended().await else {
        panic!("the third channel was served");
    };
    assert!(
        why.contains("not a method the connector's table routes"),
        "{why}"
    );
}

/// KR-REQ-12.18: a channel that closes settles what it relayed as what has already happened: a
/// request no answer went for is cancelled, because a closed channel can answer nothing it relayed,
/// and one an answer went for is uncertain.
#[tokio::test]
async fn kr_req_12_18_a_closed_channel_settles_what_it_relayed() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    channel.relay("fghij").await;
    eventually("both approvals are interpreted", || {
        ["abcde", "fghij"].iter().all(|request| {
            relayed(&broker, 2, request).is_some_and(|resource| resource.interpretation_verified)
        })
    })
    .await;
    let answered = relayed(&broker, 2, "abcde").expect("recorded");
    let unanswered = relayed(&broker, 2, "fghij").expect("recorded");

    // The answer's marker goes in and the channel's writer stops before its bytes.
    let (arrived, go) = broker.pause_before_channel_write();
    let answering = {
        let broker = Arc::clone(&broker);
        let params = respond(2, &answered, "allow");
        tokio::spawn(async move {
            broker
                .agent_approval_respond(&caller(), &params, TimestampMs::new(5))
                .await
                .map(|(result, _)| result)
        })
    };
    tokio::time::timeout(LIVENESS_DEADLINE, arrived)
        .await
        .expect("the answer reaches the channel's writer")
        .expect("the writer says so");

    channel.close().await;
    // Settled on a channel that has gone, so the ledger's record is the one that says how each
    // ended.
    eventually("the channel settles what it relayed", || {
        settled_as(&broker, unanswered.resource_id) == Some(PendingState::Cancelled)
            && settled_as(&broker, answered.resource_id) == Some(PendingState::Uncertain)
    })
    .await;
    drop(go);
    let _ = answering.await;
    let ChannelEnd::Ended { settled, .. } = channel.ended().await else {
        panic!("the channel was served");
    };
    assert_eq!(settled, 2);
}

/// A broker whose ledger is the file at `path`, and the session journal over the same file that the
/// attention store reads a session's sources from.
fn broker_over_a_journal(path: &Path) -> (Arc<Broker>, kr_worker::journal::Journal) {
    let journal = kr_worker::journal::Journal::open(path).expect("the journal opens");
    let broker = Arc::new(
        Broker::open(Some(path), session(), JournalHealth::shared()).expect("the broker opens"),
    );
    (broker, journal)
}

/// The approvals the attention store reads past `after`, from the journal.
fn approvals_after(
    journal: &kr_worker::journal::Journal,
    after: u64,
) -> kr_protocol::attention::AttentionApprovalSlice {
    approvals_page(journal, after, 64)
}

/// The same, at most `limit` of them: one page of the source.
fn approvals_page(
    journal: &kr_worker::journal::Journal,
    after: u64,
    limit: u64,
) -> kr_protocol::attention::AttentionApprovalSlice {
    kr_worker::attention_source::page(
        journal,
        &kr_protocol::attention::AttentionSourcesRequest {
            request_id: kr_protocol::ids::RequestId::new(1),
            questions_after: kr_protocol::scalars::U64::ZERO,
            approvals_after: kr_protocol::scalars::U64::new(after),
            host_events_after: kr_protocol::scalars::U64::ZERO,
            max_records: kr_protocol::scalars::U64::new(limit),
            wait_ms: kr_protocol::scalars::U64::ZERO,
            fingerprint_key: kr_protocol::scalars::SecretBytes32::from_bytes([1; 32]),
            recorded_generation: Nullable::null(),
        },
        0,
        usize::MAX,
    )
    .expect("a page")
    .approvals
}

/// The events the broker's ledger holds, in order.
fn recorded_events(broker: &Broker) -> Vec<kr_worker::broker::TransitionEvent> {
    let mut cursor = broker.stream_start();
    let mut recorded = Vec::new();
    loop {
        let replay = broker.replay_after(cursor).expect("the ledger replays");
        recorded.extend(replay.events);
        cursor = replay.cursor;
        if !replay.more {
            return recorded;
        }
    }
}

/// KR-REQ-25.01: what the broker records for a relayed approval is carried to the attention source,
/// in one numbering with every other record of the broker, and the transition that interpreted it
/// is the one that says so. A request nothing interprets (no binding of the connector's package)
/// is recorded and carried, and is never an approval; an answer, a closed channel and every
/// transition after the interpretation are carried as the end or the progress of what it was.
#[tokio::test]
async fn kr_req_25_01_an_approval_reaches_the_attention_source_from_its_interpretation_to_its_end()
{
    let directory = tempfile::tempdir().expect("a directory");
    let (broker, journal) = broker_over_a_journal(&directory.path().join("journal.sqlite3"));
    let package = Package::laid_out();
    register(&broker, 2);
    package.bind(&broker, 2);
    // The control: an instance with no binding of the package, whose relayed request nothing
    // gives a meaning.
    register(&broker, 3);
    let launch = |number: u8| package.launch(&broker, number, Some(fixture::QUALIFIED_VERSION));
    let mut bound = Channel::open(launch(2), 2, launched(2));
    let mut unbound = Channel::open(launch(3), 3, launched(3));

    bound.relay("abcde").await;
    unbound.relay("fghij").await;
    eventually(
        "the bound approval is interpreted and the other recorded",
        || {
            relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
                && relayed(&broker, 3, "fghij").is_some()
        },
    )
    .await;
    let approval = relayed(&broker, 2, "abcde").expect("recorded").resource_id;
    let request = relayed(&broker, 3, "fghij").expect("recorded").resource_id;

    let first = approvals_after(&journal, 0);
    let numbers: Vec<u64> = first
        .records
        .iter()
        .map(|record| record.sequence.get())
        .collect();
    assert_eq!(
        numbers,
        (1..=first.head.get()).collect::<Vec<_>>(),
        "one numbering, with no hole"
    );
    let of = |slice: &kr_protocol::attention::AttentionApprovalSlice, id: PendingResourceId| {
        slice
            .records
            .iter()
            .filter(|record| record.resource_id == id)
            .map(|record| (record.state, record.approval, record.interpreted))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        of(&first, approval),
        vec![
            (PendingState::Pending, false, false),
            (PendingState::Pending, true, true)
        ],
        "recorded, then interpreted: only the second is an approval's raise"
    );
    assert_eq!(
        of(&first, request),
        vec![(PendingState::Pending, false, false)],
        "a request nothing interprets is carried and is no approval"
    );

    // The answer goes out, and everything after the interpretation is the approval's progress.
    let seen = first.head.get();
    broker
        .agent_approval_respond(
            &caller(),
            &respond(2, &relayed(&broker, 2, "abcde").expect("recorded"), "allow"),
            TimestampMs::new(5),
        )
        .await
        .expect("the answer is admitted and carried");
    assert!(
        bound.next().await.is_some(),
        "the verdict reaches the channel"
    );
    // The closed channel cancels what it relayed and nothing answered.
    unbound.close().await;
    eventually("the unanswered request is cancelled", || {
        settled_as(&broker, request) == Some(PendingState::Cancelled)
    })
    .await;
    let rest = approvals_after(&journal, seen);
    let approval_later = of(&rest, approval);
    assert!(
        approval_later
            .iter()
            .all(|(_, approval, interpreted)| *approval && !interpreted),
        "nothing after the interpretation interprets it again: {approval_later:?}"
    );
    assert_eq!(
        approval_later.last().map(|(state, _, _)| *state),
        Some(PendingState::Resolved),
        "its end is carried"
    );
    assert_eq!(
        of(&rest, request),
        vec![(PendingState::Cancelled, false, false)],
        "the end of a request that was no approval is carried as no approval's"
    );
    // And a cursor at the head reads nothing more.
    assert!(
        approvals_after(&journal, rest.head.get())
            .records
            .is_empty()
    );

    // Read one record at a time, the source is the same records in the same order, each page's
    // head is the source's head, and the last page ends at it.
    let whole = approvals_after(&journal, 0);
    let mut one_at_a_time = Vec::new();
    let mut cursor = 0;
    loop {
        let page = approvals_page(&journal, cursor, 1);
        assert_eq!(page.head, whole.head);
        let Some(record) = page.records.into_iter().next() else {
            break;
        };
        cursor = record.sequence.get();
        one_at_a_time.push(record);
    }
    assert_eq!(one_at_a_time, whole.records);

    bound.close().await;
    assert!(matches!(bound.ended().await, ChannelEnd::Ended { .. }));
    assert!(matches!(unbound.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-25.01: a worker that starts again over the same journal carries on the numbering of the
/// broker's transitions, so the store's cursor, which sat at the end of what it read before, reads
/// exactly the new ones: none of the earlier records again, none of the new ones hidden below it,
/// and no hole between the two.
#[tokio::test]
async fn kr_req_25_01_the_numbering_carries_on_when_the_broker_starts_again() {
    let store = common::SharedStore::open();
    let package = Package::laid_out();
    let first = {
        let broker = Arc::new(
            Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens"),
        );
        register(&broker, 2);
        package.bind(&broker, 2);
        let mut channel = Channel::open(
            package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
            2,
            launched(2),
        );
        channel.relay("abcde").await;
        eventually("the approval is interpreted", || {
            relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
        })
        .await;
        channel.close().await;
        assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
        approvals_after(&store.journal, 0)
    };
    let seen = first.head.get();
    assert!(seen >= 3, "recorded, interpreted and ended");

    // Another process of the same session: its broker numbers above what the ledger holds.
    let broker = Arc::new(
        Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens again"),
    );
    register(&broker, 3);
    package.bind(&broker, 3);
    let mut channel = Channel::open(
        package.launch(&broker, 3, Some(fixture::QUALIFIED_VERSION)),
        3,
        launched(3),
    );
    channel.relay("fghij").await;
    eventually("the new approval is interpreted", || {
        relayed(&broker, 3, "fghij").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let new_resource = relayed(&broker, 3, "fghij").expect("recorded").resource_id;
    let later = approvals_after(&store.journal, seen);
    assert_eq!(
        later
            .records
            .iter()
            .map(|record| record.sequence.get())
            .collect::<Vec<_>>(),
        (seen + 1..=later.head.get()).collect::<Vec<_>>(),
        "the new records follow the old ones with no hole and repeat none"
    );
    assert!(
        later
            .records
            .iter()
            .all(|record| record.resource_id == new_resource),
        "and are the new approval's alone"
    );
    assert!(later.records.iter().any(|record| record.interpreted));
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-25.01: an approval that ends while the journal is out is carried to whoever follows the
/// session's approvals once the journal is back. Transitions made then are announced and not
/// recorded, and the recovery that follows writes the state each resource reached; it writes the
/// event that says so with it, so the follower reads the end without waiting for some later
/// transition to show that numbers were spent. That event names the last event the ledger holds
/// about the approval as its parent, and an approval the ledger first hears of in the recovery has
/// no parent. The control is an approval that stayed open through the whole gap, which the recovery
/// gives no event, and whose item is therefore not ended.
#[tokio::test]
async fn kr_req_25_01_an_approval_that_ends_while_the_journal_is_out_is_carried_when_it_returns() {
    let mut store = common::SharedStore::open();
    let broker = Arc::new(
        Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens"),
    );
    let package = Package::laid_out();
    let mut channels = Vec::new();
    for (number, request) in [(2, "abcde"), (3, "fghij")] {
        register(&broker, number);
        package.bind(&broker, number);
        let mut channel = Channel::open(
            package.launch(&broker, number, Some(fixture::QUALIFIED_VERSION)),
            number,
            launched(number),
        );
        channel.relay(request).await;
        eventually("the approval is interpreted", || {
            relayed(&broker, number, request)
                .is_some_and(|resource| resource.interpretation_verified)
        })
        .await;
        channels.push(channel);
    }
    let mut open_through = channels.pop().expect("two channels");
    let mut ending = channels.pop().expect("two channels");
    let ended = relayed(&broker, 2, "abcde").expect("recorded").resource_id;
    let stayed = relayed(&broker, 3, "fghij").expect("recorded").resource_id;
    let before = approvals_after(&store.journal, 0);
    assert!(
        before
            .records
            .iter()
            .any(|record| record.resource_id == ended && record.interpreted),
        "the approval was raised"
    );
    let last_recorded = recorded_events(&broker)
        .iter()
        .rev()
        .find(|event| event.resource_id == ended)
        .map(|event| event.sequence)
        .expect("the ledger holds events of the approval");

    // The store fails under the next approval, and the fence goes up. The channel that relayed the
    // approval closes inside the gap, which settles what it relayed in memory only.
    broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    open_through.relay("qrstu").await;
    eventually("the fence is up", || {
        broker.mode() == GatewayMode::NativeOnlyVolatile
    })
    .await;
    ending.close().await;
    assert!(matches!(ending.ended().await, ChannelEnd::Ended { .. }));
    assert_eq!(
        approvals_after(&store.journal, before.head.get())
            .records
            .len(),
        0,
        "nothing of the gap is recorded yet"
    );

    broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    store.recover_journal(20);
    broker
        .recover(TimestampMs::new(20))
        .expect("the gap is committed");
    let after = approvals_after(&store.journal, before.head.get());
    let ends: Vec<_> = after
        .records
        .iter()
        .filter(|record| record.resource_id == ended)
        .collect();
    assert_eq!(ends.len(), 1, "the end is written once: {after:?}");
    assert_eq!(ends[0].state, PendingState::Cancelled);
    assert!(
        ends[0].approval && !ends[0].interpreted,
        "it is the end of an approval and raises nothing"
    );
    assert!(
        ends[0].sequence.get() > before.head.get() + 1,
        "numbered above what the broker spent while the journal was out, so the hole shows"
    );
    assert!(
        after
            .records
            .iter()
            .all(|record| record.resource_id != stayed),
        "an approval that stayed open through the gap is given no event"
    );
    let first_heard = relayed(&broker, 3, "qrstu").expect("recorded").resource_id;
    let recovery_events: Vec<_> = recorded_events(&broker)
        .into_iter()
        .filter(|event| event.cause == TransitionCause::Reconciliation)
        .collect();
    let parent_of = |resource_id| {
        recovery_events
            .iter()
            .find(|event| event.resource_id == resource_id)
            .map(|event| event.parent_sequence)
    };
    assert_eq!(
        parent_of(ended),
        Some(Some(last_recorded)),
        "the end names the last event the ledger holds about the approval"
    );
    assert_eq!(
        parent_of(first_heard),
        Some(None),
        "an approval the ledger first hears of in the recovery follows no event"
    );
    open_through.close().await;
    assert!(matches!(
        open_through.ended().await,
        ChannelEnd::Ended { .. }
    ));
}

/// KR-REQ-25.01: whoever follows a session's approvals is woken by each transition the broker
/// commits, on the connection that writes it, and by the event a recovery writes for a transition
/// made while the journal was out. The worker reads the page again at once; whether it answers a
/// held request is the worker's own rule for the page. The signal is subscribed to before each is
/// made, so a commit that lands before the wait begins is still seen.
#[tokio::test]
async fn kr_req_25_01_a_relayed_approval_wakes_whoever_follows_the_approvals() {
    let mut store = common::SharedStore::open();
    let broker = Arc::new(
        Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens"),
    );
    let changes = Arc::new(tokio::sync::Notify::new());
    broker.attach_attention_changes(Arc::clone(&changes));
    let package = Package::laid_out();
    let mut channels = Vec::new();
    for number in [2, 3] {
        register(&broker, number);
        package.bind(&broker, number);
        channels.push(Channel::open(
            package.launch(&broker, number, Some(fixture::QUALIFIED_VERSION)),
            number,
            launched(number),
        ));
    }
    let mut open_through = channels.pop().expect("two channels");
    let mut ending = channels.pop().expect("two channels");

    // The first commit: a relayed approval is recorded on the connection that writes it.
    let mut woken = std::pin::pin!(changes.notified());
    woken.as_mut().enable();
    ending.relay("abcde").await;
    tokio::time::timeout(LIVENESS_DEADLINE, woken)
        .await
        .expect("the relayed approval's commit wakes the follower");
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;

    // The journal goes out under the next request, and the approval ends inside the gap, which
    // settles it in memory only.
    broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    open_through.relay("qrstu").await;
    eventually("the fence is up", || {
        broker.mode() == GatewayMode::NativeOnlyVolatile
    })
    .await;
    ending.close().await;
    assert!(matches!(ending.ended().await, ChannelEnd::Ended { .. }));

    // The recovery writes the end the gap hid, and wakes the follower with it.
    broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    store.recover_journal(20);
    let mut woken = std::pin::pin!(changes.notified());
    woken.as_mut().enable();
    broker
        .recover(TimestampMs::new(20))
        .expect("the gap is committed");
    tokio::time::timeout(LIVENESS_DEADLINE, woken)
        .await
        .expect("the recovery's event wakes the follower");
    open_through.close().await;
    assert!(matches!(
        open_through.ended().await,
        ChannelEnd::Ended { .. }
    ));
}

/// KR-REQ-12.18: a channel closed while the gateway is fenced, one closed while it recovers and one
/// open through the whole gap each leave nothing a recovery waits for, so the recovery finishes.
#[tokio::test]
async fn kr_req_12_18_no_channel_holds_a_recovery_open() {
    let mut store = common::SharedStore::open();
    let broker = Arc::new(
        Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens"),
    );
    let package = Package::laid_out();
    let mut channels = Vec::new();
    for (number, request) in [(2, "abcde"), (3, "fghij"), (4, "kmnop")] {
        register(&broker, number);
        let mut channel = Channel::open(
            package.launch(&broker, number, Some(fixture::QUALIFIED_VERSION)),
            number,
            launched(number),
        );
        channel.relay(request).await;
        eventually("the approval is recorded", || {
            relayed(&broker, number, request).is_some()
        })
        .await;
        channels.push(channel);
    }
    let mut open_through = channels.pop().expect("three channels");
    let mut closed_recovering = channels.pop().expect("three channels");
    let mut closed_fenced = channels.pop().expect("three channels");

    // The store fails under the next approval, and the fence goes up.
    broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    closed_fenced.relay("qrstu").await;
    eventually("the fence is up", || {
        broker.mode() == GatewayMode::NativeOnlyVolatile
    })
    .await;
    closed_fenced.close().await;
    assert!(matches!(
        closed_fenced.ended().await,
        ChannelEnd::Ended { settled: 2, .. }
    ));

    // The store returns and the recovery begins; one channel closes while it runs.
    broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    store.recover_journal(20);
    broker
        .recover(TimestampMs::new(20))
        .expect("the gap is committed");
    assert_eq!(broker.mode(), GatewayMode::Recovering);
    closed_recovering.close().await;
    assert!(matches!(
        closed_recovering.ended().await,
        ChannelEnd::Ended { settled: 1, .. }
    ));

    // The channel that stayed open carried the whole gap, so what its upstream holds is what this
    // host holds for it, and the recovery finishes.
    assert!(
        broker.reconcile_connected(TimestampMs::new(21)).is_some(),
        "the recovery finishes"
    );
    assert_eq!(broker.mode(), GatewayMode::Normal);
    assert_eq!(
        relayed(&broker, 4, "kmnop").map(|resource| resource.state),
        Some(PendingState::Pending),
        "the open channel's request is still its to answer"
    );
    open_through.close().await;
    assert!(matches!(
        open_through.ended().await,
        ChannelEnd::Ended { .. }
    ));
}

/// KR-REQ-12.18: a channel is served only for a version its table is qualified for, and the
/// version is the one a signed record names for the executable's digest: a version outside the
/// table's range, or an executable no record names, has its channel closed unread.
#[tokio::test]
async fn kr_req_12_18_a_channel_is_served_only_for_a_version_its_table_is_qualified_for() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    for version in [Some("2.1.277"), None] {
        let mut channel = Channel::open(package.launch(&broker, 2, version), 2, launched(2));
        assert_eq!(channel.next().await, None, "{version:?}: closed unread");
        let ChannelEnd::Refused(why) = channel.ended().await else {
            panic!("{version:?}: the channel was served");
        };
        assert_eq!(
            why.code(),
            kr_protocol::error::ErrorCode::UnsupportedCapability,
            "{why}"
        );
    }
    let mut qualified = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    qualified.relay("abcde").await;
    eventually("the qualified version's channel is served", || {
        relayed(&broker, 2, "abcde").is_some()
    })
    .await;
    qualified.close().await;
    assert!(matches!(qualified.ended().await, ChannelEnd::Ended { .. }));
}

/// Registers the package's own actions on its binding, as the installation's binder will.
fn register_actions(broker: &Broker, package: &Package, number: u8) {
    broker
        .register_actions(binding(number), &package.connector.manifest().actions)
        .expect("its actions are registered");
}

/// One `plugin.action.invoke` of an answer action, as a caller sends it.
fn invoke(
    plugin_id: kr_protocol::ids::PluginId,
    number: u8,
    resource: Option<&PendingResource>,
    parameters: &serde_json::Value,
) -> kr_protocol::agent::PluginActionInvokeParams {
    kr_protocol::agent::PluginActionInvokeParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session(), instance(number)),
            binding_revision: AgentBindingRevision::new(1),
        },
        plugin_id,
        action: kr_protocol::broker::ActionName::new("approval.answer").expect("valid"),
        draft_id: Nullable::null(),
        resource_id: Nullable::from(resource.map(|resource| resource.resource_id)),
        parameters: kr_protocol::scalars::Bytes::from(
            serde_json::to_vec(parameters).expect("encodes"),
        ),
    }
}

/// The answer action the package declares, as a registration builds it.
#[test]
fn an_answer_action_is_registered_as_an_answer() {
    let package = Package::laid_out();
    let declared = package
        .connector
        .manifest()
        .actions
        .iter()
        .find(|declared| declared.id.as_str() == "approval.answer")
        .expect("the package declares its answer");
    let registered =
        kr_worker::broker::RegisteredAction::from_declaration(declared).expect("registered");
    assert_eq!(registered.grant, BrokerGrant::ApprovalInterpreter);
    assert_eq!(
        registered
            .capability
            .as_ref()
            .map(|capability| capability.as_str()),
        Some("agent.approval")
    );
    assert_eq!(
        registered
            .decision
            .as_ref()
            .map(|decision| decision.as_str()),
        Some("decision")
    );
    assert_eq!(registered.operation, None, "no component prepares it");
}

/// KR-REQ-12.18: an answer action is refused before its marker when the call names no resource,
/// when its decision is not one the table maps, and when its package did not interpret the
/// resource; the resource is left exactly as it was, and nothing is written on the channel.
#[tokio::test]
async fn kr_req_12_18_a_plugin_answer_is_refused_before_its_marker_for_what_it_cannot_answer() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    register_actions(&broker, &package, 2);
    // Another package bound to the same instance, with an answer action of its own.
    let other = kr_protocol::ids::PluginId::new("kalareach/other").expect("valid");
    broker
        .bind_descriptor(
            binding(9),
            instance(2),
            other.clone(),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([7; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            None,
            TimestampMs::new(1),
        )
        .expect("the other package is bound");
    register_actions(&broker, &package, 9);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    let plugin_id = package.connector.plugin_id();

    let refusals = [
        (
            binding(2),
            invoke(
                plugin_id.clone(),
                2,
                None,
                &serde_json::json!({ "decision": "allow" }),
            ),
            "names none",
        ),
        (
            binding(2),
            invoke(
                plugin_id.clone(),
                2,
                Some(&resource),
                &serde_json::json!({ "decision": "maybe" }),
            ),
            "not one of the decisions",
        ),
        (
            binding(9),
            invoke(
                other,
                2,
                Some(&resource),
                &serde_json::json!({ "decision": "allow" }),
            ),
            "was not interpreted by",
        ),
    ];
    for (binding_id, params, reason) in refusals {
        let refused = broker
            .admit_plugin_answer(&caller(), binding_id, &params, TimestampMs::new(5))
            .expect_err("refused before the marker");
        assert!(refused.to_string().contains(reason), "{refused}");
        let now = broker.pending(resource.resource_id).expect("held");
        assert_eq!(now.state, PendingState::Pending, "left as it was");
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), channel.next())
            .await
            .is_err(),
        "nothing was written on the channel"
    );

    // The package that interpreted it answers it.
    let admitted = broker
        .admit_plugin_answer(
            &caller(),
            binding(2),
            &invoke(
                plugin_id,
                2,
                Some(&resource),
                &serde_json::json!({ "decision": "deny" }),
            ),
            TimestampMs::new(6),
        )
        .expect("the decoder's own answer is admitted");
    broker
        .record_approval(&admitted, TimestampMs::new(6))
        .expect("the marker is written and the answer goes")
        .settled(TimestampMs::new(6))
        .await
        .expect("the answer is written");
    assert_eq!(
        channel.next().await,
        Some(serde_json::json!({
            "method": "notifications/claude/channel/permission",
            "params": { "request_id": "abcde", "behavior": "deny" }
        }))
    );
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-12.18 and KR-REQ-11.33: once the channel that relayed an answered approval has closed,
/// the live arbitration no longer holds it, and every way of answering it is refused as it was
/// while it did: the package that interpreted it is told it ended, before and after its marker,
/// and another package is refused because it did not interpret it.
#[tokio::test]
async fn kr_req_12_18_an_answer_to_an_approval_whose_channel_closed_is_told_it_ended() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    register_actions(&broker, &package, 2);
    let other = kr_protocol::ids::PluginId::new("kalareach/other").expect("valid");
    broker
        .bind_descriptor(
            binding(9),
            instance(2),
            other.clone(),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([7; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            None,
            TimestampMs::new(1),
        )
        .expect("the other package is bound");
    register_actions(&broker, &package, 9);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    let plugin_id = package.connector.plugin_id();
    let decoders_answer = invoke(
        plugin_id,
        2,
        Some(&resource),
        &serde_json::json!({ "decision": "deny" }),
    );
    let admitted = broker
        .admit_plugin_answer(&caller(), binding(2), &decoders_answer, TimestampMs::new(6))
        .expect("the decoder's own answer is admitted");
    broker
        .record_approval(&admitted, TimestampMs::new(6))
        .expect("the marker is written and the answer goes")
        .settled(TimestampMs::new(6))
        .await
        .expect("the answer is written");
    assert!(channel.next().await.is_some(), "the answer went");
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
    assert!(
        broker.pending(resource.resource_id).is_none(),
        "the live arbitration no longer holds it"
    );
    assert_eq!(
        settled_as(&broker, resource.resource_id),
        Some(PendingState::Resolved)
    );

    let target = respond(2, &resource, "deny").target;
    let checked = broker
        .check_resource_answerable(&target, resource.resource_id, TimestampMs::new(7))
        .expect_err("an ended approval is not answerable");
    assert_eq!(checked.code(), ErrorCode::QuestionResolved, "{checked}");
    let checked = broker
        .check_answerable(&target, resource.resource_id, "deny", TimestampMs::new(7))
        .expect_err("with any decision");
    assert_eq!(checked.code(), ErrorCode::QuestionResolved, "{checked}");
    let again = broker
        .admit_plugin_answer(&caller(), binding(2), &decoders_answer, TimestampMs::new(7))
        .expect_err("the decoder's second answer is refused");
    assert_eq!(again.code(), ErrorCode::QuestionResolved, "{again}");
    let responded = broker
        .agent_approval_respond(
            &caller(),
            &respond(2, &resource, "deny"),
            TimestampMs::new(7),
        )
        .await
        .expect_err("and so is a rich answer");
    assert_eq!(responded.code(), ErrorCode::QuestionResolved, "{responded}");
    let foreign = broker
        .admit_plugin_answer(
            &caller(),
            binding(9),
            &invoke(
                other,
                2,
                Some(&resource),
                &serde_json::json!({ "decision": "allow" }),
            ),
            TimestampMs::new(7),
        )
        .expect_err("another package's answer is refused");
    assert!(
        foreign.to_string().contains("was not interpreted by"),
        "for the reason it was refused while the approval was held: {foreign}"
    );
}

/// KR-REQ-12.18: the right to answer comes from what the installation was granted, not from what
/// the package declares. An installation not granted `approval.respond` decodes and cannot
/// answer; one whose answer right is withdrawn afterwards cannot answer through either path; and
/// what was interpreted stays interpreted and visible in both.
#[tokio::test]
async fn kr_req_12_18_answering_follows_the_installations_grants() {
    // Granted decoding and not answering.
    let broker = memory_broker();
    register(&broker, 2);
    let root = std::env::temp_dir().join(format!("kr-channels-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&root).expect("the store's directory");
    let mut source = fixture::claude_code_package(&root, Path::new(fixture::FORWARDER))
        .expect("the package is written");
    source
        .granted
        .remove(&kr_plugin_sdk::capability::PluginCapability::ApprovalRespond);
    let package = Package {
        root,
        connector: Arc::new(InstalledConnector::read(source).expect("the installed package reads")),
    };
    package.bind(&broker, 2);
    register_actions(&broker, &package, 2);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    assert!(
        broker
            .agent_approval_respond(
                &caller(),
                &respond(2, &resource, "allow"),
                TimestampMs::new(5)
            )
            .await
            .is_err(),
        "an installation not granted the answer right does not answer"
    );
    assert!(
        broker
            .admit_plugin_answer(
                &caller(),
                binding(2),
                &invoke(
                    package.connector.plugin_id(),
                    2,
                    Some(&resource),
                    &serde_json::json!({ "decision": "allow" }),
                ),
                TimestampMs::new(5),
            )
            .is_err(),
        "through its action either"
    );
    let held = broker.pending(resource.resource_id).expect("held");
    assert_eq!(held.state, PendingState::Pending);
    assert!(held.interpretation_verified, "and it stays interpreted");
    channel.close().await;
    let _ = channel.ended().await;

    // Granted both, and the answer right withdrawn afterwards.
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    register_actions(&broker, &package, 2);
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    broker
        .withdraw_answering(binding(2))
        .expect("the answer right is withdrawn");
    assert!(
        broker
            .agent_approval_respond(
                &caller(),
                &respond(2, &resource, "allow"),
                TimestampMs::new(5)
            )
            .await
            .is_err(),
        "a withdrawn answer right answers nothing"
    );
    assert!(
        broker
            .admit_plugin_answer(
                &caller(),
                binding(2),
                &invoke(
                    package.connector.plugin_id(),
                    2,
                    Some(&resource),
                    &serde_json::json!({ "decision": "allow" }),
                ),
                TimestampMs::new(5),
            )
            .is_err(),
        "through its action either"
    );
    let held = broker.pending(resource.resource_id).expect("held");
    assert_eq!(held.state, PendingState::Pending);
    assert!(held.interpretation_verified, "and it stays interpreted");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), channel.next())
            .await
            .is_err(),
        "nothing was written on the channel"
    );
    channel.close().await;
    let _ = channel.ended().await;
}

/// The approval capability's record for one instance.
fn approval_evidence(
    broker: &Broker,
    number: u8,
) -> Option<kr_protocol::broker::InstanceCapabilityRecord> {
    broker
        .capabilities(instance(number))
        .record(&kr_protocol::ids::CapabilityId::new("agent.approval").expect("valid"))
        .cloned()
}

/// KR-REQ-12.18: a channel whose writer cannot deliver an answer, because the application stopped
/// reading it, is closed however long its reading end stays open: its transports go, what it
/// relayed is settled, the approval evidence is withdrawn with the identity that established it,
/// and the instance can open its channel again.
#[tokio::test]
async fn kr_req_12_18_a_channel_whose_writer_fails_is_closed_while_its_reader_is_open() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    package.bind(&broker, 2);
    // A connection that holds 64 bytes unread: an answer does not fit while nothing reads it.
    let mut channel = Channel::open_with(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
        64,
    );
    channel.relay("abcde").await;
    eventually("the approval is interpreted", || {
        relayed(&broker, 2, "abcde").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    let resource = relayed(&broker, 2, "abcde").expect("recorded");
    let connection = resource.request.connection;
    let evidence = approval_evidence(&broker, 2).expect("the relayed approval is evidence");
    assert!(evidence.state.is_usable());
    assert_eq!(
        evidence.identity.package_digest.as_ref(),
        Some(&package.connector.package_digest()),
        "the evidence names the package that established it"
    );
    assert_eq!(
        evidence
            .identity
            .schema_version
            .as_ref()
            .map(|version| version.0.as_str()),
        Some(fixture::QUALIFIED_VERSION)
    );
    assert_eq!(
        evidence.identity.binary_digest.as_ref(),
        Some(&Digest256::from_bytes([3; 32])),
        "and the executable the launch hashed"
    );

    let answering = {
        let broker = Arc::clone(&broker);
        let params = respond(2, &resource, "allow");
        tokio::spawn(async move {
            broker
                .agent_approval_respond(&caller(), &params, TimestampMs::new(5))
                .await
                .map(|(result, _)| result)
        })
    };
    let ChannelEnd::Ended { why, .. } = channel.ended_while_open().await else {
        panic!("the channel was served");
    };
    assert!(why.contains("writer"), "{why}");
    assert!(
        answering.await.expect("the answer's task joins").is_err(),
        "an answer that could not be written is not an applied one"
    );
    assert!(
        broker.connection_dispatch(connection).is_none(),
        "nothing carries answers on the closed channel"
    );
    assert_eq!(
        settled_as(&broker, resource.resource_id),
        Some(PendingState::Uncertain),
        "the answer went and nothing says whether it arrived"
    );
    let withdrawn = approval_evidence(&broker, 2).expect("the record is kept");
    assert_eq!(
        withdrawn.state,
        kr_protocol::broker::InstanceCapabilityState::TemporarilyUnavailable
    );
    assert_eq!(withdrawn.identity, evidence.identity, "with its identity");

    let mut again = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    again.relay("fghij").await;
    eventually("the instance's next channel is served", || {
        relayed(&broker, 2, "fghij").is_some()
    })
    .await;
    again.close().await;
    assert!(matches!(again.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-12.18: only a binding of exactly the package whose table the channel reads gives what it
/// relays a meaning. A binding of the same identifier at other bytes interprets nothing, and a
/// binding of the package itself does.
#[tokio::test]
async fn kr_req_12_18_only_the_channels_own_package_interprets_what_it_relays() {
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    let other = Digest256::from_bytes([7; 32]);
    let trust = decoding_trust(&package.connector, TimestampMs::new(1)).map(|trust| {
        kr_protocol::broker::DecodingTrust {
            package_digest: other,
            ..trust
        }
    });
    broker
        .bind_descriptor(
            binding(9),
            instance(2),
            package.connector.plugin_id(),
            PublisherId::new("kalareach").expect("valid"),
            other,
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            trust,
            TimestampMs::new(1),
        )
        .expect("the same identifier at other bytes is bound");
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    // A second frame recorded means the first has been handled whole, its interpretation included.
    channel.relay("fghij").await;
    eventually("both approvals are recorded", || {
        relayed(&broker, 2, "fghij").is_some()
    })
    .await;
    assert!(
        !relayed(&broker, 2, "abcde")
            .expect("recorded")
            .interpretation_verified,
        "another package's binding gives it no meaning"
    );

    package.bind(&broker, 2);
    channel.relay("kmnop").await;
    eventually("the package's own binding interprets it", || {
        relayed(&broker, 2, "kmnop").is_some_and(|resource| resource.interpretation_verified)
    })
    .await;
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}

/// KR-REQ-12.18: a channel's identifier is a live connection, so restoring a declarative connection
/// under it is refused, and the channel goes on being served.
#[tokio::test]
async fn kr_req_12_18_a_channels_identifier_is_not_restored_as_another_connection() {
    use kr_protocol::gateway::{
        DeclarativeEntry, DeclarativeTable, NativeMethodClass, RichMethodEntry, RichMethodTable,
        RichOperation,
    };
    use kr_protocol::ids::{MethodTableVersion, PluginId, UpstreamMethod};
    let broker = memory_broker();
    register(&broker, 2);
    let package = Package::laid_out();
    let mut channel = Channel::open(
        package.launch(&broker, 2, Some(fixture::QUALIFIED_VERSION)),
        2,
        launched(2),
    );
    channel.relay("abcde").await;
    eventually("the approval is recorded", || {
        relayed(&broker, 2, "abcde").is_some()
    })
    .await;
    let connection = relayed(&broker, 2, "abcde")
        .expect("recorded")
        .request
        .connection;
    let declarative = PluginId::new("kalareach.codex").expect("valid");
    let mut table = DeclarativeTable {
        plugin_id: declarative.clone(),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![DeclarativeEntry {
            method: UpstreamMethod::new("session/update").expect("valid"),
            class: NativeMethodClass::Observation,
            expects_response: false,
            approval_option_field: Nullable::null(),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    let rich = RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![RichMethodEntry {
            method: UpstreamMethod::new("session/cancel").expect("valid"),
            class: NativeMethodClass::Mutation,
            required_right: kr_protocol::rights::ActionRight::AgentCancel,
            operation: Nullable::some(RichOperation::TurnCancel),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        }],
    };
    broker
        .pin_table(instance(2), installed(), table, rich)
        .expect("a declarative table is pinned");
    let refused = broker
        .restore_native_connection(
            connection,
            instance(2),
            &[9; 32],
            &launched(2),
            &declarative,
            "1",
        )
        .expect_err("a live channel's identifier is not restored");
    assert!(refused.to_string().contains("live connection"), "{refused}");

    channel.relay("fghij").await;
    eventually("the channel is still served", || {
        relayed(&broker, 2, "fghij").is_some()
    })
    .await;
    channel.close().await;
    assert!(matches!(channel.ended().await, ChannelEnd::Ended { .. }));
}
