//! A device that accepts an invitation the host no longer holds open is refused in the host's words.
//!
//! The daemon is kr-controller's in-process host with its test support included by path. The
//! person's computer is this crate's backend on the mock runtime, connected to the daemon's own
//! socket; the device the session is shared with is a second backend on a paired connection of its
//! own, which a test holds before its acceptance leaves, as a connection that is slow does.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.13 | `an_invitation_withdrawn_after_the_device_read_its_list_is_refused_in_the_hosts_words` |
//! | KR-REQ-18.13 | `an_invitation_that_ran_out_after_the_device_read_its_list_is_refused_in_the_hosts_words` |
//! | KR-REQ-18.13 | `an_invitation_used_after_the_device_read_its_list_is_refused_in_the_hosts_words` |

#![cfg(unix)]
// The scene is the sharing suite's, and this suite uses the part of it that holds an acceptance back.
#![allow(dead_code, unused_imports)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;

include!("support/sharing_harness.rs");

use net_support::MovedWall;

impl Scene {
    /// As [`Self::start`], on a host whose wall clock `wall` moves.
    async fn start_on(wall: &MovedWall) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_on_clocks(&owner, wall.clocks()).await;
        Self::around(owner, host).await
    }
}

/// What changes an invitation after the device read its list and before its acceptance reaches the
/// host.
enum Change<'a> {
    /// The issuer withdraws it.
    Withdrawn,
    /// The host's clock passes its end.
    RunOut(&'a MovedWall),
    /// The device accepts it from another connection of its own.
    UsedElsewhere,
}

/// An acceptance the host refuses because its invitation stopped being open after the device read
/// its list: the device's acceptance is held before it leaves, `change` is made on the host, and
/// the acceptance is let go. Returns what the page was answered, and what the host itself says to
/// a device that asks for the same invitation afterwards.
async fn refused_after_the_list_was_read(
    scene: &Scene,
    created: &GrantCreateResult,
    change: Change<'_>,
) -> (Value, String) {
    let invitation_id = created.preview.invitation_id;
    let redeem = GrantRedeemParams { invitation_id };
    // Another connection of the same device, made before anything changes.
    let elsewhere = RawDevice::connect(&scene.host, &scene.device, &scene.record).await;

    let parked = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *scene
        .phone_faults
        .hold_next
        .lock()
        .unwrap_or_else(PoisonError::into_inner) =
        Some((Arc::clone(&parked), Arc::clone(&release)));
    let accepting = scene.phone.call(
        "grant_redeem",
        json!({ "params": serde_json::to_value(&redeem).expect("encodes") }),
    );
    let changing = async {
        parked.notified().await;
        match change {
            Change::Withdrawn => {
                scene
                    .issuer
                    .call(
                        "grant_revoke",
                        json!({ "params": serde_json::to_value(&GrantRevokeParams {
                            grant_id: created.grant.grant_id,
                        }).expect("encodes") }),
                    )
                    .await
                    .expect("the invitation is withdrawn");
            }
            Change::RunOut(wall) => wall.advance(Duration::from_secs(5 * 60)),
            Change::UsedElsewhere => {
                elsewhere
                    .mutate(
                        Method::GrantRedeem,
                        ActionId::new(kr_ipc::new_uuid()),
                        on_the_host(&scene.host),
                        &redeem,
                    )
                    .await
                    .expect("the invitation is accepted from the device's other connection");
            }
        }
        release.notify_one();
    };
    let (answered, ()) = tokio::join!(accepting, changing);
    let answered = answered.expect("the device is answered with the attempt, not refused");

    let hosts_own = elsewhere
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&scene.host),
            &redeem,
        )
        .await
        .expect_err("the host refuses a device that asks for the invitation now");
    elsewhere.close();
    (answered, hosts_own.message)
}

/// Whether the host holds `grant_id` as active.
fn is_active(scene: &Scene, grant_id: GrantId) -> bool {
    scene
        .host
        .controller()
        .sharing()
        .grants()
        .record(grant_id)
        .expect("readable")
        .expect("present")
        .is_active()
}

/// KR-REQ-18.13: the issuer withdraws an invitation after the device read its list. This shows the
/// host's words where the host answers: the host is asked, refuses the acceptance, and the person is
/// told so in the host's own words, that the invitation was withdrawn; nothing is accepted. An
/// invitation that has already left the device's list is not sent to the host at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_withdrawn_after_the_device_read_its_list_is_refused_in_the_hosts_words() {
    let scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&made["value"]);

    let (answered, hosts_words) =
        refused_after_the_list_was_read(&scene, &created, Change::Withdrawn).await;

    assert_eq!(answered["value"], Value::Null, "{answered}");
    let told = answered["attempt"]["refusal"].as_str().unwrap_or_default();
    assert!(told.contains("withdrawn"), "{answered}");
    assert_eq!(told, hosts_words, "the host's own words: {answered}");
    assert!(
        !is_active(&scene, created.grant.grant_id),
        "a withdrawn invitation accepts nothing"
    );
    scene.stop().await;
}

/// KR-REQ-18.13: an invitation's time runs out on the host's clock after the device read its list.
/// This shows the host's words where the host answers: the host is asked, refuses the acceptance,
/// and the person is told so in the host's own words, that the invitation expired; nothing is
/// accepted. An invitation that has already left the device's list is not sent to the host at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_that_ran_out_after_the_device_read_its_list_is_refused_in_the_hosts_words() {
    let wall = MovedWall::new();
    let scene = Scene::start_on(&wall).await;
    let made = scene
        .issuer
        .call(
            "grant_create",
            scene.invitation_lasting(SessionRole::Viewer, Some(60_000)),
        )
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&made["value"]);

    let (answered, hosts_words) =
        refused_after_the_list_was_read(&scene, &created, Change::RunOut(&wall)).await;

    assert_eq!(answered["value"], Value::Null, "{answered}");
    let told = answered["attempt"]["refusal"].as_str().unwrap_or_default();
    assert!(told.contains("expired"), "{answered}");
    assert_eq!(told, hosts_words, "the host's own words: {answered}");
    assert!(
        !is_active(&scene, created.grant.grant_id),
        "an invitation that ran out accepts nothing"
    );
    scene.stop().await;
}

/// KR-REQ-18.13: the device accepts an invitation from another connection of its own while the
/// page's acceptance is on its way. This shows the host's words where the host answers: the host is
/// asked, refuses the page's acceptance, and the person is told so in the host's own words, that the
/// invitation was already used; the grant is active because of the other connection's acceptance
/// alone. An invitation that has already left the device's list is not sent to the host at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_used_after_the_device_read_its_list_is_refused_in_the_hosts_words() {
    let scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&made["value"]);

    let (answered, hosts_words) =
        refused_after_the_list_was_read(&scene, &created, Change::UsedElsewhere).await;

    assert_eq!(answered["value"], Value::Null, "{answered}");
    let told = answered["attempt"]["refusal"].as_str().unwrap_or_default();
    assert!(told.contains("already been redeemed"), "{answered}");
    assert_eq!(told, hosts_words, "the host's own words: {answered}");
    assert!(
        is_active(&scene, created.grant.grant_id),
        "the other connection's acceptance stands"
    );
    scene.stop().await;
}
