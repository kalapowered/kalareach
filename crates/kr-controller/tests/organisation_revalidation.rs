//! What a host decides again when it wakes, when it boots, and when an older copy of its policy
//! comes back, against a real daemon and paired devices on clocks the suite moves.
//!
//! Nothing here asks the host to notice a wake: it decides every request against the clocks it
//! reads when the request arrives, so time that passed while nothing asked anything is already
//! counted.

#![cfg(unix)]

mod net_support;
mod organisation_fixture;
mod organisation_support;

use std::time::Duration;

use kr_controller::grants::LeaseRefused;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use organisation_fixture::*;
use organisation_support::LEASE_MS;

/// The longest a session invitation's grant lasts in these suites, and a little more.
const A_DAY_AND_MORE: Duration = Duration::from_secs(25 * 60 * 60);

/// KR-REQ-24.15: expiry is decided again when a host wakes. Both clocks pass a member's lease while
/// nothing asks the host anything, and the first request after is refused on the connection that
/// stayed up; both pass a device's expiring grant the same way, and the first request after is
/// refused or finds the connection ended. The owner's own device, whose grant never ends, is served
/// after both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_ended_while_the_host_slept_is_over_at_the_first_request_after() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let helper = net_support::Device::create().await;
    let helper_record = net_support::pair_with(
        &fixture.host,
        &helper,
        &fixture.owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    let helper_raw = net_support::RawDevice::connect(&fixture.host, &helper, &helper_record).await;
    helper_raw.claim();
    read_host_info(&raw).await.expect("served before it sleeps");
    read_host_info(&helper_raw)
        .await
        .expect("served before it sleeps");

    // The host sleeps past the lease's end. The grant of the helper, which lasts a day, is not over.
    fixture.pass(Duration::from_millis(LEASE_MS + 1_000));
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "the lease ended in the sleep"
    );
    read_host_info(&helper_raw)
        .await
        .expect("the grant is still in force");

    // And past the grant's end: the helper's request is refused, or finds its connection ended, and
    // the owner's grant, which has no end, serves.
    fixture.pass(A_DAY_AND_MORE);
    match helper_raw.try_read(Method::HostInfo, &()).await {
        None => {}
        Some(answer) => assert!(
            denied(&net_support::refusal(answer.map(|_| ()))),
            "the grant ended in the sleep"
        ),
    }
    // A new connection finds the same: it is refused at the door or at its first request.
    match net_support::RawDevice::try_connect(&fixture.host, &helper, &helper_record).await {
        Err(_) => {}
        Ok(fresh) => {
            fresh.claim();
            match fresh.try_read(Method::HostInfo, &()).await {
                None => {}
                Some(answer) => assert!(
                    denied(&net_support::refusal(answer.map(|_| ()))),
                    "a new connection of a device whose grant ended is not served"
                ),
            }
            fresh.close();
        }
    }
    let owner = net_support::RawDevice::connect(
        &fixture.host,
        fixture
            .host
            .owner_device
            .as_ref()
            .expect("the owner device"),
        fixture.host.owner.as_ref().expect("the owner's record"),
    )
    .await;
    owner.claim();
    read_host_info(&owner)
        .await
        .expect("the owner's grant has no end");
    owner.close();

    raw.close();
    helper_raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-24.15: a host that boots again holds no lease of the boot before it, whatever the new
/// boot's clock says, and keeps what was written down: the binding of the member's device, the
/// highest key revision the host accepted and the revision in force. A lease issued after the boot
/// serves the member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reboot_leaves_no_lease_of_the_boot_before_and_keeps_what_was_written_down() {
    let fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    let first = fixture.lease(2, &ada, SERVED);
    ada.present(&fixture, &raw, first.clone(), None)
        .await
        .expect("the lease");
    read_host_info(&raw).await.expect("served");
    raw.close();
    let before = fixture.listed().await;
    let revision = fixture.authority_revision();

    // A little time passes while the machine is down; the new boot's continuous clock counts from
    // nothing, which puts the first lease's deadline far ahead of it.
    fixture.pass_wall(Duration::from_secs(60));
    let fixture = fixture.reboot(7).await;
    let raw = ada.connect(&fixture).await;
    assert!(
        denied(&net_support::refusal(read_host_info(&raw).await)),
        "no lease is held in a new boot"
    );
    let error = ada
        .present(&fixture, &raw, first, None)
        .await
        .expect_err("the lease of the boot before");
    assert!(
        error
            .message
            .contains(LeaseRefused::InstalledEarlier.name()),
        "the lease of the boot before is refused as installed earlier: {error:?}"
    );
    let after = fixture.listed().await;
    assert_eq!(after.enrolments.len(), before.enrolments.len());
    assert_eq!(
        after.enrolments[0].members.len(),
        before.enrolments[0].members.len(),
        "the binding was read back"
    );
    assert_eq!(
        after.enrolments[0].accepted_head, before.enrolments[0].accepted_head,
        "the highest key revision accepted was read back"
    );
    assert_eq!(fixture.authority_revision(), revision);

    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("a lease issued in the new boot");
    read_host_info(&raw).await.expect("served again");
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-24.15: an older copy of the policy, put back while the host is down, cannot lower the
/// revision in force. The policy row an earlier moment wrote names a lower floor than the registry
/// holds after the owner left the organisation; the host starts, and keeps the higher revision, as
/// it does when a crash left the policy row behind the registry. A grant issued at the revision in
/// force is not refused as one nothing here issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_policy_row_cannot_lower_the_revision_in_force() {
    let fixture = Fixture::start().await;
    let organisation_id = fixture.organisation.organisation_id;
    let policy_row = |database: std::path::PathBuf| {
        rusqlite::Connection::open(database)
            .expect("the registry opens")
            .query_row(
                "SELECT value FROM host_authority WHERE key = 'policy'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("the policy row")
    };
    let older = policy_row(fixture.host.registry_database());
    let lower = fixture.authority_revision();

    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the owner leaves the organisation, which fences the host");
    drop(client);
    let higher = fixture.authority_revision();
    assert!(higher.get() > lower.get(), "the revision moved on");

    let Fixture {
        host,
        owner,
        organisation,
        revision,
        continuous,
        moved,
    } = fixture;
    let stopped = host.shut_down().await;
    rusqlite::Connection::open(stopped.tree().environment().registry_database())
        .expect("the registry opens")
        .execute(
            "INSERT OR REPLACE INTO host_authority (key, value) VALUES ('policy', ?1)",
            [older],
        )
        .expect("the older row is put back");
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    let fixture = Fixture {
        host,
        owner,
        organisation,
        revision,
        continuous,
        moved,
    };
    assert_eq!(
        fixture.authority_revision(),
        higher,
        "the older row did not lower the revision in force"
    );
    assert_eq!(
        fixture.host.controller().policy().accepted_floor(),
        higher,
        "or the floor"
    );

    // A device paired now holds a grant at the revision in force, and is served.
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &fixture.host,
        &device,
        &fixture.owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let raw = net_support::RawDevice::connect(&fixture.host, &device, &record).await;
    raw.claim();
    read_host_info(&raw)
        .await
        .expect("a grant at the revision in force is served");
    raw.close();
    fixture.host.stop().await;
}
