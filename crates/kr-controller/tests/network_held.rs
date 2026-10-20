//! What a paired device is told about the sessions shared with it, over real paired connections.
//!
//! A recipient learns of an invitation by asking the host, and by nothing else: `grant.held` lists
//! what is offered to the device that asks and the shares it holds, and tells no device anything
//! about another's. What these demonstrate: KR-REQ-25.10 (single-use, expiring invitations: an
//! invitation that is redeemed, withdrawn or run out is no longer offered) and KR-REQ-18.03 (a
//! scoped invitation is told to the device it names and to no other), and KR-REQ-18.12 (the owner is
//! refused an invitation for a session that is not open before it exists). Nothing here starts a
//! worker, so every answer is the daemon's own; a session is a reservation its registry holds as
//! open.

mod net_support;

use kr_controller::sharing::ShareRequest;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, DeviceId, GrantId, InvitationId, QuestionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantHeldParams, GrantHeldResult,
    GrantRedeemParams, GrantRevokeParams, OfferKey, RoleSelection, SessionRole, ShareKey,
};
use net_support::{
    Host, MovedWall, RawDevice, an_open_session, end_session, fail_session, on_the_host, recipient,
    recipient_ending_in, share_with,
};
use std::time::Duration;

/// What `device` is told on its connection, from the keys given.
async fn held(
    connection: &RawDevice,
    offers_after: Option<OfferKey>,
    shares_after: Option<ShareKey>,
) -> GrantHeldResult {
    connection
        .read(
            Method::GrantHeld,
            &GrantHeldParams {
                offers_after: Nullable(offers_after),
                shares_after: Nullable(shares_after),
            },
        )
        .await
        .expect("the host tells the device what it holds")
        .to_typed()
        .expect("decodes")
}

/// Everything `connection` is told, from the first page.
async fn all_of_it(connection: &RawDevice) -> GrantHeldResult {
    held(connection, None, None).await
}

/// Redeems `invitation_id` on `connection`.
async fn redeem(host: &Host, connection: &RawDevice, invitation_id: InvitationId) {
    connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            &GrantRedeemParams { invitation_id },
        )
        .await
        .expect("the invitation is redeemed");
}

/// Shares `session_id` as a viewer, through the host's own checks.
async fn share(host: &Host, session_id: SessionId, to: DeviceId) -> GrantCreateResult {
    share_with(
        host,
        session_id,
        to,
        RoleSelection::plain(SessionRole::Viewer),
        None,
    )
    .await
    .expect("the share is written")
}

/// Writes a share to `to` below the host's own checks, at `now_ms`, for `lifetime_ms`.
fn written(
    host: &Host,
    session_id: SessionId,
    to: DeviceId,
    now_ms: u64,
    lifetime_ms: u64,
) -> GrantCreateResult {
    let selection = RoleSelection::plain(SessionRole::Viewer);
    host.controller()
        .sharing()
        .share(
            &ShareRequest {
                invitation_id: InvitationId::new(kr_ipc::new_uuid()),
                grant_id: GrantId::new(kr_ipc::new_uuid()),
                environment_id: host.environment_id,
                session_id,
                issuer_device_id: host.controller().sharing().host_device_id(),
                recipient_device_id: to,
                parent_grant_id: None,
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Some(lifetime_ms),
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: host.controller().policy().authority_revision(),
                owner_confirmed: false,
                now_ms,
            },
            || Ok(()),
        )
        .expect("the share is written")
}

/// KR-REQ-18.03: the device an invitation names is told what it carries before it redeems, and
/// every other device is told nothing of it: a device asks for its own offers and for nobody
/// else's, since nothing in the request names a device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_an_offer_is_told_to_the_device_it_names_and_to_no_other() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (named, named_record) = recipient(&host, &owner).await;
    let (other, other_record) = recipient(&host, &owner).await;
    let (session_id, number) = an_open_session(&host);
    let issued = share(&host, session_id, named_record.device_id).await;

    let on_named = RawDevice::connect(&host, &named, &named_record).await;
    let told = all_of_it(&on_named).await;
    assert_eq!(told.offers.len(), 1, "the device is told of its invitation");
    let offer = &told.offers[0];
    assert_eq!(offer.invitation_id, issued.preview.invitation_id);
    assert_eq!(offer.grant_id, issued.grant.grant_id);
    assert_eq!(offer.session_id, session_id);
    assert_eq!(offer.display_number, number);
    assert_eq!(offer.role, Nullable::some(SessionRole::Viewer));
    assert_eq!(offer.actions, issued.preview.actions);
    assert_eq!(offer.notices, issued.preview.notices);
    assert!(!offer.includes_live_screen, "no screen was included");
    assert_eq!(
        Some(offer.history_from_ms),
        issued.grant.history.lower_bound_ms.0,
        "the offer says where its history begins"
    );
    assert_eq!(
        offer.ends_at_ms, issued.preview.expires_at_ms,
        "the invitation's end is the earlier one here"
    );
    assert!(!told.offers_more && told.shares.is_empty() && !told.shares_more);

    let on_other = RawDevice::connect(&host, &other, &other_record).await;
    let nothing = all_of_it(&on_other).await;
    assert!(
        nothing.offers.is_empty() && nothing.shares.is_empty(),
        "a device the invitation does not name is told nothing of it: {nothing:?}"
    );

    // The same holds for the share it becomes: the device that redeemed it holds it, and the one
    // the invitation never named is still told nothing.
    redeem(&host, &on_named, issued.preview.invitation_id).await;
    let holding = all_of_it(&on_named).await;
    assert_eq!(holding.shares.len(), 1, "the device that redeemed holds it");
    let nothing = all_of_it(&on_other).await;
    assert!(
        nothing.offers.is_empty() && nothing.shares.is_empty(),
        "a device the share is not the grant of is told nothing of it: {nothing:?}"
    );
    on_named.close();
    on_other.close();
    host.stop().await;
}

/// KR-REQ-25.10: redeeming moves an offer to the shares the device holds, with the grant it
/// activated, and the invitation is not offered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_redeemed_offer_becomes_a_share_the_device_holds() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, number) = an_open_session(&host);
    let issued = share(&host, session_id, record.device_id).await;
    let connection = RawDevice::connect(&host, &device, &record).await;

    redeem(&host, &connection, issued.preview.invitation_id).await;
    let told = all_of_it(&connection).await;
    assert!(told.offers.is_empty(), "a used invitation is not offered");
    assert_eq!(told.shares.len(), 1);
    let share = &told.shares[0];
    assert_eq!(share.grant.grant_id, issued.grant.grant_id);
    assert_eq!(share.display_number, number);
    assert_eq!(share.grant.recipient_device_id, record.device_id);
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: an invitation that was withdrawn, a share that was revoked and an invitation that
/// ran out are no longer told to the device. The run-out is decided on the host's clock, moved by
/// hand, and nothing here waits for time to pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_withdrawn_revoked_or_run_out_share_is_no_longer_told() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let wall = MovedWall::new();
    let host = Host::start_on_clocks(&owner, wall.clocks()).await;
    let (device, record) = recipient(&host, &owner).await;
    let connection = RawDevice::connect(&host, &device, &record).await;
    let revoke = |grant_id: GrantId| {
        let host = &host;
        async move {
            host.client()
                .await
                .mutate(
                    Method::GrantRevoke,
                    ActionId::new(kr_ipc::new_uuid()),
                    on_the_host(host),
                    &GrantRevokeParams { grant_id },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the grant is revoked");
        }
    };

    let (withdrawn_session, _) = an_open_session(&host);
    let withdrawn = share(&host, withdrawn_session, record.device_id).await;
    assert_eq!(all_of_it(&connection).await.offers.len(), 1);
    revoke(withdrawn.grant.grant_id).await;
    assert!(
        all_of_it(&connection).await.offers.is_empty(),
        "a withdrawn invitation is not offered"
    );

    let (revoked_session, _) = an_open_session(&host);
    let revoked = share(&host, revoked_session, record.device_id).await;
    redeem(&host, &connection, revoked.preview.invitation_id).await;
    assert_eq!(all_of_it(&connection).await.shares.len(), 1);
    revoke(revoked.grant.grant_id).await;
    assert!(
        all_of_it(&connection).await.shares.is_empty(),
        "a revoked share is not held"
    );

    let (short_session, _) = an_open_session(&host);
    let short = share_with(
        &host,
        short_session,
        record.device_id,
        RoleSelection::plain(SessionRole::Viewer),
        Some(60_000),
    )
    .await
    .expect("a short share is written");
    let (kept_session, _) = an_open_session(&host);
    let kept = share(&host, kept_session, record.device_id).await;
    let before = all_of_it(&connection).await;
    assert_eq!(before.offers.len(), 2);
    wall.advance(Duration::from_secs(5 * 60));
    let after = all_of_it(&connection).await;
    assert_eq!(
        after
            .offers
            .iter()
            .map(|offer| offer.invitation_id)
            .collect::<Vec<_>>(),
        vec![kept.preview.invitation_id],
        "the invitation that ran out is not offered and the other still is: {:?} {:?}",
        short.preview.invitation_id,
        after
    );
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: what is shared about a session that has closed is not told: an offer for it and a
/// share of it are dropped, and the session's number goes with them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_closed_sessions_offers_and_shares_are_not_told() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let connection = RawDevice::connect(&host, &device, &record).await;
    let (offered_session, _) = an_open_session(&host);
    let (held_session, _) = an_open_session(&host);
    share(&host, offered_session, record.device_id).await;
    let held_share = share(&host, held_session, record.device_id).await;
    redeem(&host, &connection, held_share.preview.invitation_id).await;
    let before = all_of_it(&connection).await;
    assert_eq!((before.offers.len(), before.shares.len()), (1, 1));

    end_session(&host, offered_session);
    end_session(&host, held_session);
    let after = all_of_it(&connection).await;
    assert!(
        after.offers.is_empty() && after.shares.is_empty(),
        "a closed session is not told of: {after:?}"
    );
    connection.close();
    host.stop().await;
}

/// KR-REQ-18.12: the owner is refused an invitation for a session that has closed, as closed, even
/// when it names a question only the session's worker could preview; and for one that never ran or
/// whose launch failed, as unknown, before the invitation exists: nothing is written for any of
/// them, and the same share of an open session is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_12_a_session_that_is_not_open_is_refused_before_an_invitation_exists() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) = recipient(&host, &owner).await;
    let offers = || {
        host.controller()
            .sharing()
            .grants()
            .offers_after(record.device_id, None, 16)
            .expect("the offers are read")
            .len()
    };
    let (closed, _) = an_open_session(&host);
    end_session(&host, closed);
    let (failed, _) = an_open_session(&host);
    fail_session(&host, failed);
    let (open, _) = an_open_session(&host);
    let never_ran = SessionId::new(kr_ipc::new_uuid());
    let names_a_question = RoleSelection {
        named_questions: [QuestionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        ..RoleSelection::plain(SessionRole::Viewer)
    };

    for (session_id, selection, refusal) in [
        (
            closed,
            RoleSelection::plain(SessionRole::Viewer),
            ErrorCode::SessionClosed,
        ),
        (closed, names_a_question, ErrorCode::SessionClosed),
        (
            failed,
            RoleSelection::plain(SessionRole::Viewer),
            ErrorCode::UnknownSession,
        ),
        (
            never_ran,
            RoleSelection::plain(SessionRole::Viewer),
            ErrorCode::UnknownSession,
        ),
    ] {
        let refused = share_with(&host, session_id, record.device_id, selection, None)
            .await
            .expect_err("a session that is not open is not shared");
        assert_eq!(refused.code, refusal, "{refused:?}");
    }
    assert_eq!(offers(), 0, "no invitation was written");

    share(&host, open, record.device_id).await;
    assert_eq!(offers(), 1, "an open session is shared");
    host.stop().await;
}

/// KR-REQ-18.12: the check where the share is written reads the session's reservation again. The
/// request found the session open, is held before its transaction, and the session is recorded as
/// closed while it is held: the write refuses it as closed and no invitation is written. The
/// control is the same request released with the session still open, which is written. (The
/// closure is recorded through a second handle of the registry, as `end_session` does; a daemon
/// records one under its registry's lock, which this request holds from its second look to the
/// write, so what the check covers is a closure recorded between the first look and the second.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_12_a_session_that_closes_while_the_share_waits_takes_no_invitation() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) = recipient(&host, &owner).await;
    let offers = || {
        host.controller()
            .sharing()
            .grants()
            .offers_after(record.device_id, None, 16)
            .expect("the offers are read")
            .len()
    };
    let held_share = |session_id: SessionId, mut client: kr_ipc::client::LocalClient| {
        let target = net_support::on_the_session(&host, session_id);
        let selection = RoleSelection::plain(SessionRole::Viewer);
        let params = GrantCreateParams {
            session_id,
            recipient_device_id: record.device_id,
            parent_grant_id: Nullable::null(),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: Nullable::null(),
            owner_confirmation: Nullable::null(),
        };
        tokio::spawn(async move {
            client
                .mutate(
                    Method::GrantCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &params,
                )
                .await
                .expect("the call reaches the daemon")
        })
    };
    let at_the_store = || {
        let (arrived, go) = host.controller().sharing().grants().pause_before_effect();
        let arrived =
            tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(60)));
        (arrived, go)
    };

    let (standing, _) = an_open_session(&host);
    let (arrived, go) = at_the_store();
    let request = held_share(standing, host.client().await);
    arrived
        .await
        .expect("the wait ran")
        .expect("the request is held at the store");
    go.send(()).expect("the request is let go");
    request
        .await
        .expect("the request ran")
        .expect("a session that is still open takes the share");
    assert_eq!(offers(), 1);

    let (ending, _) = an_open_session(&host);
    let (arrived, go) = at_the_store();
    let request = held_share(ending, host.client().await);
    arrived
        .await
        .expect("the wait ran")
        .expect("the request is held at the store");
    end_session(&host, ending);
    go.send(()).expect("the request is let go");
    let refused = request
        .await
        .expect("the request ran")
        .expect_err("a session that closed while the request waited takes no invitation");
    assert_eq!(refused.code, ErrorCode::SessionClosed, "{refused:?}");
    assert_eq!(
        offers(),
        1,
        "no invitation was written for the closed session"
    );
    host.stop().await;
}

/// KR-REQ-25.10: a list longer than a page is read in pages without losing or repeating an entry,
/// though every share was issued at one moment, and an offer that is redeemed between two pages is
/// neither listed twice nor allowed to hide another.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_long_list_is_paged_by_its_key_and_survives_a_redemption_between_pages() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let connection = RawDevice::connect(&host, &device, &record).await;
    let (session_id, _) = an_open_session(&host);
    let now_ms = kr_ipc::now_ms().get();

    // Seventy offers, all issued at one moment, so that the order between them is the identifier's.
    let issued: Vec<GrantCreateResult> = (0..70)
        .map(|_| written(&host, session_id, record.device_id, now_ms, 3_600_000))
        .collect();
    let first = all_of_it(&connection).await;
    assert_eq!(first.offers.len(), 64, "a page is at most sixty-four");
    assert!(first.offers_more, "and says that more follow");
    let last = first.offers.last().expect("a last offer");
    let next_key = OfferKey {
        issued_at_ms: last.issued_at_ms,
        invitation_id: last.invitation_id,
    };

    // One offer of the second page is redeemed between the pages, and so is one the first page
    // listed: neither may come back, and no other may be lost.
    let second_page: Vec<InvitationId> = {
        let listed: Vec<InvitationId> = first.offers.iter().map(|o| o.invitation_id).collect();
        issued
            .iter()
            .map(|created| created.preview.invitation_id)
            .filter(|id| !listed.contains(id))
            .collect()
    };
    assert_eq!(second_page.len(), 6);
    redeem(&host, &connection, second_page[0]).await;
    redeem(&host, &connection, first.offers[0].invitation_id).await;
    let second = held(&connection, Some(next_key), None).await;
    let mut seen: Vec<InvitationId> = first.offers.iter().map(|o| o.invitation_id).collect();
    let on_second: Vec<InvitationId> = second.offers.iter().map(|o| o.invitation_id).collect();
    assert!(!second.offers_more, "the second page is the last");
    assert!(
        !on_second.contains(&second_page[0]),
        "an offer redeemed between pages is not listed"
    );
    assert_eq!(on_second.len(), 5, "and the other five of them are");
    seen.extend(on_second);
    for created in &issued {
        let id = created.preview.invitation_id;
        let redeemed = id == second_page[0] || id == first.offers[0].invitation_id;
        assert!(
            seen.contains(&id) || redeemed,
            "no offer is lost between pages"
        );
    }
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "and none is listed twice");

    // Seventy shares held once the rest are redeemed too, again all issued at one moment.
    for created in &issued {
        if created.preview.invitation_id != second_page[0]
            && created.preview.invitation_id != first.offers[0].invitation_id
        {
            redeem(&host, &connection, created.preview.invitation_id).await;
        }
    }
    let page = held(&connection, None, None).await;
    assert_eq!(page.shares.len(), 64);
    assert!(page.shares_more);
    let last = page.shares.last().expect("a last share");
    let rest = held(
        &connection,
        None,
        Some(ShareKey {
            issued_at_ms: last.issued_at_ms,
            grant_id: last.grant.grant_id,
        }),
    )
    .await;
    assert_eq!(rest.shares.len(), 6, "the 70 shares held are 64 and 6");
    assert!(!rest.shares_more);
    let mut ids: Vec<GrantId> = page
        .shares
        .iter()
        .chain(rest.shares.iter())
        .map(|share| share.grant.grant_id)
        .collect();
    let listed = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), listed, "no share is listed twice");
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: a voice grant a device holds is never listed, and the rows a page leaves out do
/// not make the page they were read in look like the last: every share after them is still told.
/// The store is read in chunks of 128 rows, and a chunk whose rows are all left out, a voice grant
/// and shares that have run out among them, must not end the list while rows follow it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_rows_left_out_of_the_first_chunk_do_not_hide_the_shares_after_it() {
    use kr_controller::grants::store::GrantRecord;
    use kr_protocol::grant::GrantExpiry;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::TimestampMs;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let connection = RawDevice::connect(&host, &device, &record).await;
    let (session_id, _) = an_open_session(&host);
    let template = share(&host, session_id, record.device_id).await.grant;

    // A hundred and thirty-one rows the store holds as active shares of the session. The first is a
    // voice grant, the next hundred and twenty-seven have run out, and three are told: so the
    // first chunk of 128 rows has nothing to tell, and the three follow it.
    let base = kr_ipc::now_ms().get();
    let mut told = Vec::new();
    for index in 0..131_u64 {
        let mut grant = template.clone();
        grant.grant_id = GrantId::new(kr_ipc::new_uuid());
        if index == 0 {
            grant.actions.insert(ActionRight::VoiceUse);
        } else if index < 128 {
            grant.expiry = GrantExpiry::At {
                expires_at_ms: TimestampMs::new(base - 1),
            };
        } else {
            told.push(grant.grant_id);
        }
        host.controller()
            .sharing()
            .grants()
            .issue(
                &GrantRecord {
                    grant,
                    session_id: Some(session_id),
                    issued_at_ms: base + index,
                    activated_at_ms: Some(base + index),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the row is written");
    }

    let mut listed: Vec<GrantId> = Vec::new();
    let mut after = None;
    loop {
        let page = held(&connection, None, after.take()).await;
        listed.extend(page.shares.iter().map(|share| share.grant.grant_id));
        if !page.shares_more {
            break;
        }
        let last = page.shares.last().expect("a full page has a last share");
        after = Some(ShareKey {
            issued_at_ms: last.issued_at_ms,
            grant_id: last.grant.grant_id,
        });
    }
    listed.sort();
    told.sort();
    assert_eq!(
        listed, told,
        "the three shares after the first chunk are told, and nothing else is"
    );
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: the end a device is told is the earlier of the share's and its own pairing's,
/// for an offer and for a share it holds, so a share written before the host refused one that
/// outlasts the pairing is told with the end it will have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_the_end_told_is_the_earlier_of_the_share_and_the_pairing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient_ending_in(&host, &owner, Duration::from_secs(30 * 60)).await;
    let pairing_ends = match record.grant.expiry {
        kr_protocol::grant::GrantExpiry::At { expires_at_ms } => expires_at_ms,
        kr_protocol::grant::GrantExpiry::Never => panic!("this pairing ends"),
    };
    let (offered_session, _) = an_open_session(&host);
    let (held_session, _) = an_open_session(&host);
    let now_ms = kr_ipc::now_ms().get();
    written(&host, offered_session, record.device_id, now_ms, 3_600_000);
    let held_share = written(&host, held_session, record.device_id, now_ms, 3_600_000);
    let connection = RawDevice::connect(&host, &device, &record).await;
    redeem(&host, &connection, held_share.preview.invitation_id).await;

    let told = all_of_it(&connection).await;
    assert_eq!(told.offers.len(), 1);
    assert_eq!(told.offers[0].ends_at_ms, pairing_ends);
    assert_eq!(told.shares.len(), 1);
    assert_eq!(told.shares[0].ends_at_ms, Nullable::some(pairing_ends));
    connection.close();
    host.stop().await;
}
