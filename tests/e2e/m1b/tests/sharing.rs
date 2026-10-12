//! Sharing a session with a guest, end to end.
//!
//! The host is the `kr-controller` daemon, its sessions are `kr-worker` processes, and the person
//! is `kr` on a real terminal; the owner's device and the guest's are this repository's client
//! library over iroh on loopback. No deployment is involved, so these run wherever the binaries
//! are built (`cargo build -p kr-cli -p kr-controller -p kr-worker --bins`).

#![cfg(unix)]

use kr_e2e_m1b::device::{Device, Remote};
use kr_e2e_m1b::host::{Host, HostOptions};
use kr_e2e_m1b::run::Run;
use kr_e2e_m1b::view::View;
use kr_e2e_m1b::{LIVENESS, ceremony};
use kr_protocol::confirmation::ConfirmationDisplay;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SessionId;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{SessionListParams, SessionListResult, SessionReadParams};
use kr_protocol::sharing::{
    GrantHeldParams, GrantHeldResult, GrantRedeemParams, GrantRedeemResult,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime for the devices")
}

/// What a device is told it is offered and holds.
fn held(runtime: &tokio::runtime::Runtime, device: &Remote) -> GrantHeldResult {
    runtime
        .block_on(device.read(
            Method::GrantHeld,
            &GrantHeldParams {
                offers_after: Nullable::null(),
                shares_after: Nullable::null(),
            },
        ))
        .unwrap_or_else(|why| panic!("grant.held: {why}"))
}

/// A new connection of a paired device: the host ends a connection that has acted under a share
/// when the share ends, so what a device may do after that is asked on a connection of its own.
fn reconnected(
    runtime: &tokio::runtime::Runtime,
    device: &Device,
    paired: &kr_e2e_m1b::device::PairedHost,
) -> Remote {
    runtime
        .block_on(device.connect(paired))
        .unwrap_or_else(|why| panic!("the device connects again: {why}"))
}

/// The error code of a refusal the host gave, when it gave one.
fn refused_with<T: std::fmt::Debug>(
    outcome: Result<T, kr_e2e_m1b::device::RequestError>,
    what: &str,
) -> ErrorCode {
    match outcome {
        Err(error) => error
            .refusal()
            .unwrap_or_else(|| panic!("{what} was not answered with a refusal: {error}")),
        Ok(answered) => panic!("{what} was not refused: {answered:?}"),
    }
}

/// Creates a headless session on the host and returns its identifier and display number.
fn new_session(host: &Host<'_>) -> (SessionId, String) {
    let work = host.run().work().display().to_string();
    let created = host.kr_json(&[
        "new",
        "--invisible",
        "--headless",
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
        "--cwd",
        &work,
    ]);
    let session_id: SessionId = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("a session identifier");
    let display = host
        .live_sessions()
        .iter()
        .find(|session| session["session_id"] == session_id.to_string())
        .and_then(|session| session["display_number"].as_u64())
        .expect("the session's display number")
        .to_string();
    (session_id, display)
}

/// A guest shown a session with its screen sees what it was offered before it accepts, and none of
/// the text on the screen until it has; it reads and watches under the share and is refused input
/// as a viewer; and when the owner takes the share back it is served nothing more. A guest paired
/// with no share reaches no session at all. KR-REQ-25.10, KR-REQ-19.01, KR-REQ-18.03.
#[test]
fn a_guest_is_shown_a_session_with_its_screen_and_loses_it_when_the_share_is_taken_back() {
    let runtime = runtime();
    let run = Run::start("sharing");
    let host = Host::start(&run, &HostOptions::default());
    let owner_device = runtime.block_on(Device::create("owner", &run.root().join("o")));
    let (_, owner) = ceremony::pair_first_owner(&host, &owner_device, &runtime);
    let (session_id, display) = new_session(&host);

    // The screen has a line of its own on it: the owner types it.
    let snapshot: EventsSnapshotResult = runtime
        .block_on(owner.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|why| panic!("events.snapshot: {why}"));
    let mut typing = runtime
        .block_on(View::attach(
            &owner,
            session_id,
            snapshot.geometry.dimensions,
            &kr_client::cursors::StreamCursors::new(),
        ))
        .unwrap_or_else(|why| panic!("the owner attaches: {why}"));
    runtime
        .block_on(typing.acquire(&owner))
        .unwrap_or_else(|why| panic!("{why}"));
    runtime
        .block_on(typing.type_text(&owner, "echo shared-screen-marker\n"))
        .unwrap_or_else(|why| panic!("{why}"));
    runtime
        .block_on(typing.wait_for(&owner, "shared-screen-marker", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));

    // A guest pairs and reaches no session.
    let guest_device = runtime.block_on(Device::create("guest", &run.root().join("g")));
    let (guest_paired, guest) = ceremony::pair_guest(&host, &owner, &guest_device, &runtime, "60");
    let refused = runtime.block_on(guest.read::<_, SessionListResult>(
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::null(),
            include_closed: false,
        },
    ));
    assert_eq!(
        refused_with(refused, "a guest's session.list"),
        ErrorCode::PermissionDenied
    );
    let listed = host.kr_json(&["device", "list"]);
    let entry = listed["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|device| device["device_id"] == guest_paired.device_id.to_string())
        .expect("the guest is listed");
    assert_eq!(
        entry["all_sessions"], false,
        "a guest's pairing opens no session"
    );
    assert!(held(&runtime, &guest).offers.is_empty());

    // The invitation is shown, with the screen, before it exists, and is issued only after the
    // person types `share`.
    let device_id = guest_paired.device_id.to_string();
    let (shown, issued) = ceremony::share_at_terminal(
        &host,
        &[&display, "--to", &device_id, "--live", "--for", "15m"],
        b"share",
    );
    assert!(
        shown.contains("shared-screen-marker"),
        "the screen is shown first: {shown}"
    );
    assert!(shown.contains("The live screen is included"), "{shown}");
    assert_eq!(issued.exit, 0, "the share: {}", issued.document);
    let grant_id = issued.document["grant_id"]
        .as_str()
        .expect("a grant")
        .to_owned();
    assert_eq!(issued.document["screen_changed"], false);

    // The guest is told what it is offered, and the text on the screen is not in it.
    let told = held(&runtime, &guest);
    assert_eq!(told.offers.len(), 1);
    let offer = &told.offers[0];
    assert_eq!(offer.session_id, session_id);
    assert!(offer.includes_live_screen);
    let carried = kr_cbor::to_canonical_vec(&told).expect("the offer encodes");
    assert!(
        !carried
            .windows(b"shared-screen-marker".len())
            .any(|window| window == b"shared-screen-marker"),
        "the offer carries no text of the screen"
    );

    // Until it accepts, the share reaches nothing.
    let before = runtime.block_on(guest.read::<_, kr_protocol::session::SessionReadResult>(
        Method::SessionRead,
        &SessionReadParams { session_id },
    ));
    assert_eq!(
        refused_with(before, "a read under a share nobody accepted"),
        ErrorCode::PermissionDenied
    );

    // It accepts, reads under the share, watches the screen, and is refused input as a viewer.
    let redeemed: GrantRedeemResult = runtime
        .block_on(guest.mutate_environment(
            Method::GrantRedeem,
            &GrantRedeemParams {
                invitation_id: offer.invitation_id,
            },
        ))
        .unwrap_or_else(|why| panic!("grant.redeem: {why}"));
    assert_eq!(redeemed.grant.grant_id.to_string(), grant_id);
    let holding = held(&runtime, &guest);
    assert!(holding.offers.is_empty());
    assert_eq!(holding.shares.len(), 1);
    runtime
        .block_on(guest.read::<_, kr_protocol::session::SessionReadResult>(
            Method::SessionRead,
            &SessionReadParams { session_id },
        ))
        .unwrap_or_else(|why| panic!("session.read under the share: {why}"));
    let snapshot: EventsSnapshotResult = runtime
        .block_on(guest.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|why| panic!("events.snapshot under the share: {why}"));
    let mut watching = runtime
        .block_on(View::attach(
            &guest,
            session_id,
            snapshot.geometry.dimensions,
            &kr_client::cursors::StreamCursors::new(),
        ))
        .unwrap_or_else(|why| panic!("the guest watches: {why}"));
    let input = runtime.block_on(watching.acquire(&guest));
    assert!(
        input
            .as_ref()
            .err()
            .is_some_and(|why| why.contains("PERMISSION_DENIED") || why.contains("permission")),
        "a viewer is refused input: {input:?}"
    );

    // `kr share list` shows the share, and taking it back serves the guest nothing more.
    let shares = host.kr_json(&["share", "list", &display]);
    let listed = shares["grants"].as_array().expect("grants");
    assert!(
        listed
            .iter()
            .any(|share| share["grant_id"] == grant_id && share["state"] == "active"),
        "the share is listed as active: {shares}"
    );
    let started = std::time::Instant::now();
    loop {
        let revoked = host.kr(&["share", "revoke", &grant_id, "--json"]);
        if revoked.status.success() {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the revocation never completed: {}{}",
            String::from_utf8_lossy(&revoked.stdout),
            String::from_utf8_lossy(&revoked.stderr)
        );
    }
    let guest = reconnected(&runtime, &guest_device, &guest_paired);
    let after = runtime.block_on(guest.read::<_, kr_protocol::session::SessionReadResult>(
        Method::SessionRead,
        &SessionReadParams { session_id },
    ));
    assert_eq!(
        refused_with(after, "a read after the share was taken back"),
        ErrorCode::PermissionDenied
    );
    assert!(held(&runtime, &guest).shares.is_empty());

    // A share without the live screen reaches no terminal: the offer says so, and the attach is
    // refused after the guest accepts it. It carries no consequence, so `--yes` skips the question.
    let plain = host.kr_json(&[
        "share", "invite", &display, "--to", &device_id, "--yes", "--for", "15m",
    ]);
    let plain_grant = plain["grant_id"].as_str().expect("a grant").to_owned();
    let offered = held(&runtime, &guest);
    assert_eq!(offered.offers.len(), 1);
    assert!(!offered.offers[0].includes_live_screen);
    let _: GrantRedeemResult = runtime
        .block_on(guest.mutate_environment(
            Method::GrantRedeem,
            &GrantRedeemParams {
                invitation_id: offered.offers[0].invitation_id,
            },
        ))
        .unwrap_or_else(|why| panic!("grant.redeem: {why}"));
    let attach = runtime.block_on(View::attach(
        &guest,
        session_id,
        snapshot.geometry.dimensions,
        &kr_client::cursors::StreamCursors::new(),
    ));
    assert!(
        attach
            .as_ref()
            .err()
            .is_some_and(|why| why.contains("PERMISSION_DENIED") || why.contains("permission")),
        "a share without the live screen attaches nothing: {:?}",
        attach.as_ref().err()
    );
    // And a share that carries a consequence is not issued by --yes.
    let refused = host.kr(&[
        "share",
        "invite",
        &display,
        "--to",
        &device_id,
        "--role",
        "controller",
        "--yes",
    ]);
    assert!(
        !refused.status.success(),
        "--yes does not skip the question for a share that carries a consequence"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--yes"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let _ = plain_grant;

    guest.close();
    owner.close();
    runtime.block_on(guest_device.close());
    runtime.block_on(owner_device.close());
    host.stop()
        .unwrap_or_else(|problem| panic!("the host did not stop cleanly: {problem}"));
    run.closing_check()
        .unwrap_or_else(|left| panic!("the leg left processes running: {left}"));
}

/// The owner hands a session's control to another device: the command waits for an owner device to
/// confirm exactly the plan the host describes, the transfer then completes, and the giving device
/// is refused where the receiving device now holds the session. KR-REQ-18.03.
#[test]
fn a_session_handed_to_another_device_is_held_by_it_and_refused_to_the_giver() {
    let runtime = runtime();
    let run = Run::start("sharing-transfer");
    let host = Host::start(&run, &HostOptions::default());
    let owner_device = runtime.block_on(Device::create("owner", &run.root().join("o")));
    let (_, owner) = ceremony::pair_first_owner(&host, &owner_device, &runtime);
    let (session_id, display) = new_session(&host);

    let giver_device = runtime.block_on(Device::create("giver", &run.root().join("g")));
    let (giver_paired, giver) = ceremony::pair_guest(&host, &owner, &giver_device, &runtime, "60");
    let taker_device = runtime.block_on(Device::create("taker", &run.root().join("t")));
    let (taker_paired, taker) = ceremony::pair_guest(&host, &owner, &taker_device, &runtime, "60");

    // The giver is shared the session as its owner, and accepts.
    let giver_id = giver_paired.device_id.to_string();
    let (_, issued) = ceremony::share_at_terminal(
        &host,
        &[
            &display, "--to", &giver_id, "--role", "owner", "--for", "15m",
        ],
        b"share",
    );
    assert_eq!(issued.exit, 0, "the share: {}", issued.document);
    let from = issued.document["grant_id"]
        .as_str()
        .expect("a grant")
        .to_owned();
    let offer = held(&runtime, &giver).offers.remove(0);
    let _: GrantRedeemResult = runtime
        .block_on(giver.mutate_environment(
            Method::GrantRedeem,
            &GrantRedeemParams {
                invitation_id: offer.invitation_id,
            },
        ))
        .unwrap_or_else(|why| panic!("grant.redeem: {why}"));
    runtime
        .block_on(giver.read::<_, kr_protocol::session::SessionReadResult>(
            Method::SessionRead,
            &SessionReadParams { session_id },
        ))
        .unwrap_or_else(|why| panic!("the giver reads under its share: {why}"));

    // The command waits; the owner device answers exactly that plan; the transfer completes.
    let taker_id = taker_paired.device_id.to_string();
    let transferring = ceremony::waiting(
        &host,
        &[
            "share", "transfer", &display, "--from", &from, "--to", &taker_id,
        ],
    );
    runtime
        .block_on(owner.confirm_pending(|display| {
            matches!(
                display,
                ConfirmationDisplay::TransferControl(plan)
                    if plan.to_device_id == taker_paired.device_id
                        && plan.from_device_id == giver_paired.device_id
            )
        }))
        .unwrap_or_else(|why| panic!("the owner device confirms the transfer: {why}"));
    let done = ceremony::finished(transferring, "kr share transfer");
    assert!(
        done.exit == 0 || done.exit == 1,
        "the transfer ended: {}",
        done.document
    );
    assert_eq!(
        done.document["to_device_id"].as_str(),
        Some(taker_id.as_str()),
        "{}",
        done.document
    );

    // The taker holds the session; the giver is refused, on a connection of its own, because the
    // host ended the one that had acted under the share it gave up.
    let giver = reconnected(&runtime, &giver_device, &giver_paired);
    assert_eq!(held(&runtime, &taker).shares.len(), 1);
    assert!(held(&runtime, &giver).shares.is_empty());
    runtime
        .block_on(taker.read::<_, kr_protocol::session::SessionReadResult>(
            Method::SessionRead,
            &SessionReadParams { session_id },
        ))
        .unwrap_or_else(|why| panic!("the taker reads under its share: {why}"));
    let refused = runtime.block_on(giver.read::<_, kr_protocol::session::SessionReadResult>(
        Method::SessionRead,
        &SessionReadParams { session_id },
    ));
    assert_eq!(
        refused_with(refused, "the giver's read after the transfer"),
        ErrorCode::PermissionDenied
    );

    giver.close();
    taker.close();
    owner.close();
    runtime.block_on(giver_device.close());
    runtime.block_on(taker_device.close());
    runtime.block_on(owner_device.close());
    host.stop()
        .unwrap_or_else(|problem| panic!("the host did not stop cleanly: {problem}"));
    run.closing_check()
        .unwrap_or_else(|left| panic!("the leg left processes running: {left}"));
}
