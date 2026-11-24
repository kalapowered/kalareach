//! A client that finds the fourth protocol through the environment's descriptors, and falls back to
//! the third when it cannot use them.
//!
//! The host here serves both protocols with its writer open, so what a case shows of the client is
//! what it does with a host that writes every member of `/4`.

use kr_plugin_runtime::runtime::binding::BindingRequest;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::error::ServiceResult;
use kr_plugin_service::launcher::{publish_descriptor, publish_descriptor4};
use kr_plugin_service::protocol::{ComponentSource, HostProtocol, Notice};
use kr_plugin_service::protocol4::HostDescriptor4;
use kr_protocol::identity::ProcessStartIdentity;

use super::super::{HANG_GUARD, Served, components};

fn descriptor4_of(served: &Served) -> HostDescriptor4 {
    let three = &served.descriptor;
    HostDescriptor4 {
        protocol: HostProtocol::V4.name.to_owned(),
        environment_id: three.environment_id,
        reservation_id: three.reservation_id,
        endpoint: served.endpoint4().to_owned(),
        boot_identity: three.boot_identity.clone(),
        process_start_identity: three.process_start_identity.clone(),
        host_public_key: three.host_public_key,
        build: Served::build(),
    }
}

/// The identity of a process that is not the one that has this identifier now.
fn another_process(identity: &ProcessStartIdentity) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        identity.pid.get(),
        identity.source,
        identity.start_value.get() + 1,
    )
}

fn publish_three(served: &Served) {
    publish_descriptor(
        &served._temp.environment(),
        &HostProtocol::V3,
        &served.descriptor,
    )
    .expect("the descriptor of the third protocol is published");
}

fn publish_four(served: &Served, descriptor: &HostDescriptor4) {
    publish_descriptor4(&served._temp.environment(), descriptor)
        .expect("the descriptor of the fourth protocol is published");
}

async fn connected(served: &Served) -> ServiceResult<PluginClient> {
    PluginClient::connect(&served._temp.environment()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_usable_descriptor_of_the_fourth_protocol_gives_a_connection_over_it() {
    let served = Served::start_dual(true).await;
    publish_three(&served);
    publish_four(&served, &descriptor4_of(&served));
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(
        client.protocol(),
        HostProtocol::V4,
        "the client used {:?}",
        client.protocol()
    );
    client.health().await.expect("the host answers over it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_no_descriptor_of_the_fourth_protocol_gives_a_connection_over_the_third() {
    let served = Served::start_dual(true).await;
    publish_three(&served);
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(client.protocol(), HostProtocol::V3);
    client.health().await.expect("the host answers over it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_descriptor_of_a_process_that_has_ended_is_not_used() {
    let served = Served::start_dual(true).await;
    publish_three(&served);
    let mut stale = descriptor4_of(&served);
    stale.process_start_identity = another_process(&stale.process_start_identity);
    // The endpoint is live, so a client that read nothing of the process would connect to it.
    publish_four(&served, &stale);
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(
        client.protocol(),
        HostProtocol::V3,
        "the client used the descriptor of a process that had ended"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_host_that_cannot_answer_the_challenge_with_the_published_key_is_not_used() {
    let served = Served::start_dual(true).await;
    publish_three(&served);
    // Another process holds the endpoint: it is live and speaks the protocol, but it is not the
    // one whose key the descriptor records.
    let other =
        kr_plugin_service::launcher::HostIdentity::generate(served.descriptor.environment_id)
            .expect("an identity");
    let mut foreign = descriptor4_of(&served);
    foreign.host_public_key = *other.public_key();
    publish_four(&served, &foreign);
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(
        client.protocol(),
        HostProtocol::V3,
        "the client trusted a host that could not sign the challenge with the published key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_each_connect_starts_at_the_fourth_protocol_again() {
    let served = Served::start_dual(true).await;
    publish_three(&served);
    let first = connected(&served).await.expect("the client connects");
    assert_eq!(first.protocol(), HostProtocol::V3);
    // A host of the fourth protocol appears: the next connect finds it.
    publish_four(&served, &descriptor4_of(&served));
    let second = connected(&served).await.expect("the client connects");
    assert_eq!(
        second.protocol(),
        HostProtocol::V4,
        "the client remembered that it had fallen back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_descriptor_left_by_a_host_that_is_gone_leaves_a_host_of_the_third_protocol_used()
 {
    let Some(component) = components::well_behaved() else {
        return;
    };
    let served = Served::start_held().await;
    publish_three(&served);
    // The descriptor of a host of `/4` that ended, whose endpoint is gone.
    let mut stale = descriptor4_of_gone(&served);
    stale.process_start_identity = another_process(&stale.process_start_identity);
    publish_four(&served, &stale);
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(client.protocol(), HostProtocol::V3);

    // And the first observation arrives over it.
    let (path, digest, bytes) = served.install("well-behaved", &component);
    let request = components::request("well-behaved", 61);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path,
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    client
        .deliver(request.binding_id, &components::scrape("se-1", "building"))
        .await
        .expect("the event is offered");
    let observed = tokio::time::timeout(HANG_GUARD, async {
        loop {
            if let Notice::Document { call, .. } =
                client.notice().await.expect("the connection is open")
                && call == "observe"
            {
                return true;
            }
        }
    })
    .await
    .expect("the observation never arrived");
    assert!(observed);
    drop(client);
}

/// The descriptor of a `/4` host that is gone: an endpoint nothing answers on.
fn descriptor4_of_gone(served: &Served) -> HostDescriptor4 {
    let three = &served.descriptor;
    HostDescriptor4 {
        protocol: HostProtocol::V4.name.to_owned(),
        environment_id: three.environment_id,
        reservation_id: three.reservation_id,
        endpoint: format!("{}.gone", three.endpoint),
        boot_identity: three.boot_identity.clone(),
        process_start_identity: three.process_start_identity.clone(),
        host_public_key: three.host_public_key,
        build: Served::build(),
    }
}

/// A host with its writer open writes every member of `/4`, and a client over it uses none: what
/// it reads of its bindings is what a client over `/3` reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_client_over_the_fourth_protocol_reads_every_member_and_uses_none() {
    let Some(component) = components::component("recording") else {
        return;
    };
    let served = Served::start_dual(true).await;
    publish_three(&served);
    publish_four(&served, &descriptor4_of(&served));
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(client.protocol(), HostProtocol::V4);

    let (path, digest, bytes) = served.install("recording", &component);
    let request: BindingRequest = components::request("recording", 62);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path,
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    client
        .deliver(request.binding_id, &components::scrape("se-1", "x"))
        .await
        .expect("the event is offered");
    // The host reports what the instance consumed after the pass, a checkpoint states it, and a
    // restore is answered with whether a record was set: the client is told none of it.
    let deadline = core::time::Duration::from_secs(20);
    let state = client
        .checkpoint(request.binding_id, deadline)
        .await
        .expect("the checkpoint runs")
        .state
        .expect("the state came back");
    client
        .restore(request.binding_id, state, deadline)
        .await
        .expect("the restore runs");
    client
        .deliver(request.binding_id, &components::scrape("se-2", "y"))
        .await
        .expect("the event is offered");
    // Every notice that arrives is one the third protocol has, and none is a gap that lost
    // nothing, which is what a report would look like if it were passed on.
    let mut documents = 0;
    tokio::time::timeout(HANG_GUARD, async {
        while documents < 3 {
            match client.notice().await.expect("the connection is open") {
                Notice::Document { .. } => documents += 1,
                other => panic!("the client was told {other:?}"),
            }
        }
    })
    .await
    .expect("the documents never arrived");
}

/// Registers `request`'s binding over `client`, with the component installed on `served`.
async fn register_over(
    client: &PluginClient,
    request: &BindingRequest,
    source: &ComponentSource,
) -> kr_plugin_service::error::ServiceResult<kr_plugin_service::client::Registration> {
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            source,
        )
        .await
}

/// A host refuses a second registration of a binding that has one, and keeps the first. The client
/// keeps the first too: its notices are read and its restores name it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_refused_duplicate_registration_leaves_the_registration_the_host_holds_the_clients()
 {
    let Some(component) = components::component("recording") else {
        return;
    };
    let served = Served::start_dual(true).await;
    publish_three(&served);
    publish_four(&served, &descriptor4_of(&served));
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(client.protocol(), HostProtocol::V4);
    let (path, digest, bytes) = served.install("recording", &component);
    let source = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request: BindingRequest = components::request("recording", 63);
    register_over(&client, &request, &source)
        .await
        .expect("the binding registers");
    let duplicate = register_over(&client, &request, &source).await;
    assert!(
        duplicate.is_err(),
        "the host registered a binding that it already held"
    );

    let deadline = core::time::Duration::from_secs(20);
    let state = client
        .checkpoint(request.binding_id, deadline)
        .await
        .expect("the checkpoint runs")
        .state
        .expect("the state came back");
    let restored = client.restore(request.binding_id, state, deadline).await;
    assert!(
        restored.is_ok(),
        "a restore after a refused duplicate was refused: {restored:?}"
    );
    client
        .deliver(request.binding_id, &components::scrape("se-1", "x"))
        .await
        .expect("the event is offered");
    let read = tokio::time::timeout(HANG_GUARD, client.notice())
        .await
        .expect("the notice never arrived");
    assert!(
        matches!(read, Some(Notice::Document { .. })),
        "the notices of the registration the host holds were dropped: {read:?}"
    );
}

/// A binding that is registered, removed and registered again is read under its new registration
/// each time, and a removal leaves the client holding nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_a_binding_registered_and_removed_again_is_read_under_each_new_registration() {
    let Some(component) = components::component("recording") else {
        return;
    };
    let served = Served::start_dual(true).await;
    publish_three(&served);
    publish_four(&served, &descriptor4_of(&served));
    let client = connected(&served).await.expect("the client connects");
    assert_eq!(client.protocol(), HostProtocol::V4);
    let (path, digest, bytes) = served.install("recording", &component);
    let source = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request: BindingRequest = components::request("recording", 64);
    for round in 0..3 {
        register_over(&client, &request, &source)
            .await
            .unwrap_or_else(|error| panic!("round {round}: the binding registers: {error:?}"));
        client
            .deliver(
                request.binding_id,
                &components::scrape(&format!("se-{round}"), "x"),
            )
            .await
            .expect("the event is offered");
        let read = tokio::time::timeout(HANG_GUARD, client.notice())
            .await
            .expect("the notice never arrived");
        assert!(
            matches!(read, Some(Notice::Document { .. })),
            "round {round}: the binding's notices were dropped: {read:?}"
        );
        assert!(
            client.unbind(request.binding_id).await.expect("unbinds"),
            "round {round}: the host held the registration"
        );
    }
}
