use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::ids::{
    ActionId, ActionWindowId, EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

fn attach(claim_geometry: bool, requested: &[AttachmentCapability]) -> MutationRequest {
    let session_id = SessionId::new(Uuid::from_bytes([3; 16]));
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionAttach.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(Uuid::from_bytes([4; 16])),
        target: ActionTarget {
            environment_id: EnvironmentId::new(Uuid::from_bytes([5; 16])),
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        params: ParamsValue::from_typed(&SessionAttachParams {
            session_id,
            mode: AttachMode::Terminal,
            claim_geometry,
            dimensions: Nullable::null(),
            terminal_profile_id: Nullable::null(),
            requested: requested.iter().copied().collect(),
        })
        .expect("encodes"),
        grant_id: Nullable::null(),
        expected: ParamsValue::from_typed(&std::collections::BTreeMap::<String, u64>::new())
            .expect("encodes"),
        action_window_id: ActionWindowId::new("window").expect("a window identifier"),
        requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
    }
}

/// KR-REQ-08.68: registering a claim is what needs the geometry right, and asking is not
/// registering.
#[test]
fn a_requested_capability_is_not_a_geometry_claim() {
    assert!(
        super::decision::claims_geometry(&attach(true, &[])),
        "the flag that registers a claim is a claim"
    );
    assert!(
        !super::decision::claims_geometry(&attach(false, &[AttachmentCapability::Geometry])),
        "asking for the capability is a request the host intersects, not a claim"
    );
    assert!(
        !super::decision::claims_geometry(&attach(
            false,
            &[
                AttachmentCapability::ObserveTerminal,
                AttachmentCapability::Input
            ]
        )),
        "and an ordinary observing attachment claims nothing"
    );
}

/// No frame a worker receives carries a voice right, whichever way work reaches it, which is
/// why a voice grant's withdrawal owes no fence. The device's pairing grant carries every
/// right, `voice.use` included, and it holds a live voice grant; its session's worker records
/// every frame it is sent and refuses each.
///
/// - Every method this door decides for it (`check_grant`, the decision a forwarded mutation's
///   rights are cut from) carries `voice.use` only when the method requires it, and each such
///   method is a voice method the daemon serves itself.
/// - Its forwarded mutation and its close, sent through the door's own `mutate`, reach the
///   worker carrying exactly the rights decided for them, and a local close carries none.
/// - Both builders of a forwarded mutation, the proxy link and the local client, refuse a set
///   that holds `voice.use` before anything is sent, and a frame built under another name and
///   written straight to a link is not encoded.
/// - Every voice effect is performed here or not at all: the one the daemon performs, a
///   session read, succeeds and reaches the worker as the daemon's own request, which carries
///   no rights, and nothing else reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_frame_a_worker_receives_carries_a_voice_right() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::authority::RequiredAuthority;
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::voice::VoiceAction;

    use crate::service::a_close_a_worker_never_answers as fake;

    let recorded: fake::Recorded = Arc::default();
    let world = fake::fake_worker(Some(Arc::clone(&recorded))).await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let revision = controller.policy().authority_revision();

    // A device paired under `actions`, holding a live voice grant of its own.
    let pair = |byte: u8, actions: kr_protocol::scalars::CanonicalSet<ActionRight>| {
        let (mut paired, _) =
            crate::service::net::tests::granted(kr_protocol::grant::GrantExpiry::Never, revision);
        paired.actions = actions;
        let device = crate::service::net::devices::DeviceRecord {
            device_id: paired.recipient_device_id,
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([byte; 32]),
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
            authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
            stored_envelope: None,
            notification_preview: None,
            device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
            platform: kr_protocol::pairing::DevicePlatform::Ios,
            grant: paired.clone(),
            paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            revoked_at_ms: None,
            committed_invitation_id: None,
            expired_at_ms: None,
        };
        controller.devices().commit(&device).expect("paired");
        let voice_grant = kr_protocol::grant::Grant {
            grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
            issuer_device_id: controller.sharing().host_device_id(),
            actions: [ActionRight::VoiceUse, ActionRight::SessionView]
                .into_iter()
                .collect(),
            ..paired
        };
        controller
            .sharing()
            .grants()
            .issue(
                &crate::grants::GrantRecord {
                    grant: voice_grant.clone(),
                    session_id: None,
                    issued_at_ms: 1,
                    activated_at_ms: Some(1),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("a live voice grant");
        (device, voice_grant)
    };
    // For the door, a pairing grant that carries every right, `voice.use` included.
    let (device, _) = pair(7, ActionRight::ALL.iter().copied().collect());
    // For the voice module, whose ordinary authority is a grant that carries no voice right.
    let (voice_device, voice_grant) = pair(
        8,
        ActionRight::ALL
            .iter()
            .copied()
            .filter(|right| *right != ActionRight::VoiceUse)
            .collect(),
    );
    let connection = super::RemoteConnection::for_test(controller, device.clone());

    // Every method, as this door decides it.
    let mut decided_with_voice = 0;
    for method in Method::ALL {
        let entry = method.entry();
        if !entry.ingress.contains(&ActorIngress::PairedDevice) {
            continue;
        }
        let Ok(decision) = connection.check_grant(Some(world.session_id), entry, false) else {
            continue;
        };
        if decision
            .decided
            .permitted
            .rights
            .contains(&ActionRight::VoiceUse)
        {
            decided_with_voice += 1;
            assert!(
                entry.required_rights.iter().any(|required| matches!(
                    required.authority,
                    RequiredAuthority::Right {
                        right: ActionRight::VoiceUse
                    }
                )),
                "{method:?} is decided with voice.use although it does not require it"
            );
            assert!(
                crate::voice::VoiceModule::serves(*method),
                "{method:?} is decided with voice.use and is not served here"
            );
        }
    }
    assert!(
        decided_with_voice > 0,
        "the device holds voice.use for the methods that need it"
    );

    // A forwarded mutation and a device's close, as the device sends them, through this
    // door's own path from its window to the worker.
    let decided = |method: Method| {
        connection
            .check_grant(Some(world.session_id), method.entry(), false)
            .expect("decided")
            .decided
            .permitted
            .rights
    };
    let submit_rights = decided(Method::AgentPromptSubmit);
    let close_rights = decided(Method::SessionClose);
    let window = connection
        .windows
        .issue(connection.connection_id, controller.boot_epoch)
        .expect("a window");
    let sent = |method: Method, request_id: u64, params: ParamsValue| MutationRequest {
        request_id: RequestId::new(request_id),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::some(device.grant.grant_id),
        target: ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(world.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: window.action_window_id.clone(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params,
    };
    let _ = connection
        .mutate(&sent(Method::AgentPromptSubmit, 11, ParamsValue::empty()))
        .await;
    let _ = connection
        .mutate(&sent(
            Method::SessionClose,
            12,
            ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
                session_id: world.session_id,
            })
            .expect("encodes"),
        ))
        .await;

    // Rights that hold a voice right are refused by both builders of a forwarded mutation,
    // before anything is sent.
    let with_voice: kr_protocol::scalars::CanonicalSet<ActionRight> =
        [ActionRight::VoiceUse, ActionRight::SessionView]
            .into_iter()
            .collect();
    let sent_before = recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    let refused = connection
        .proxied_mutation(
            &sent(Method::AgentPromptSubmit, 13, ParamsValue::empty()),
            world.accepted,
            revision,
            with_voice.clone(),
            &mut None,
        )
        .await;
    assert!(
        matches!(
            &refused,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Error(error),
                ..
            }) if error.message.contains("never travels to a worker")
        ),
        "the proxy refuses a voice right: {refused:?}"
    );
    let mut held = controller
        .worker_client(&world.worker)
        .await
        .expect("the daemon's own link");
    let link = held.client();
    let local = link
        .forward(
            &fake::close_request(world.environment_id, world.session_id),
            &world.actor,
            &with_voice,
            kr_protocol::scalars::U64::new(u64::MAX),
        )
        .await;
    assert!(
        matches!(
            local,
            Err(kr_ipc::IpcError::RightNotForwarded(ActionRight::VoiceUse))
        ),
        "the local client refuses a voice right: {local:?}"
    );
    // And a frame built under another name and written straight to the link, past both
    // builders, is not encoded.
    {
        use kr_protocol::local::ForwardedMutation as Built;

        let written = link
            .writer()
            .write_message(&ControlFrame::Forwarded(Box::new(Built {
                mutation: fake::close_request(world.environment_id, world.session_id),
                actor: world.actor.clone(),
                grant_rights: with_voice.clone(),
                accepted_deadline_boot_ms: kr_protocol::scalars::U64::new(u64::MAX),
                history: None,
            })))
            .await;
        assert!(
            written.is_err(),
            "a frame carrying voice.use is not encoded, however it is built and sent"
        );
    }
    held.give_back();
    drop(held);
    assert_eq!(
        recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        sent_before,
        "nothing reached the worker"
    );

    // A local close.
    let carried = fake::admission(controller, world.accepted).await;
    let _ = controller
        .session_close(
            &fake::close_request(world.environment_id, world.session_id),
            &world.actor,
            Some(world.accepted),
            carried,
        )
        .await;

    // Every voice effect. What reaches the worker from here on is the voice module's.
    let before_voice = recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    let voice_session_id = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let delegation_id =
        kr_protocol::voice::VoiceDelegationId::new("a-delegation").expect("an identifier");
    for action in VoiceAction::ALL {
        let Some(method) = crate::voice::method_for(*action) else {
            continue;
        };
        let proposal = kr_voice::Proposal {
            voice_session_id,
            device_id: voice_device.device_id,
            voice_grant_id: voice_grant.grant_id,
            environment_id: world.environment_id,
            action: *action,
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            session_id: Some(world.session_id),
            delegation_id: delegation_id.clone(),
            plan: kr_protocol::voice::VoiceActionPlan {
                voice_session_id,
                action: *action,
                session_id: kr_protocol::scalars::Nullable::some(world.session_id),
                delegation_id: kr_protocol::scalars::Nullable::some(delegation_id.clone()),
                payload_digest: kr_protocol::scalars::Digest256::from_bytes([3; 32]),
            },
            approval: None,
            turn_id: None,
            destination: None,
        };
        let performed = controller.voice_perform(method, &proposal).await;
        if method == Method::SessionRead {
            assert!(
                performed.as_ref().is_ok_and(|receipt| receipt.performed),
                "the daemon performs the read: {performed:?}"
            );
        }
    }

    let frames = recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let forwarded: Vec<kr_protocol::local::ForwardedMutation> = frames
        .iter()
        .filter_map(|frame| match frame {
            ControlFrame::Forwarded(mutation) => Some(mutation.as_ref().clone()),
            _ => None,
        })
        .collect();
    for mutation in &forwarded {
        assert!(
            !mutation.grant_rights.contains(&ActionRight::VoiceUse),
            "{:?} reached the worker carrying voice.use",
            mutation.mutation.method
        );
    }
    assert!(
        !frames
            .iter()
            .any(|frame| matches!(frame, ControlFrame::ForwardedRead(_))),
        "nothing here forwards a read"
    );

    // The door's paths: exactly the rights decided for each, and none for a local close.
    let rights_of = |method: Method| {
        forwarded
            .iter()
            .filter(|mutation| mutation.mutation.method == method.into())
            .map(|mutation| mutation.grant_rights.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        rights_of(Method::AgentPromptSubmit),
        vec![submit_rights],
        "the forwarded mutation carries exactly the rights decided for it"
    );
    let closes = rights_of(Method::SessionClose);
    assert_eq!(
        closes.len(),
        2,
        "the device's close and the local one: {closes:?}"
    );
    assert!(
        closes.contains(&close_rights),
        "the device's close: {closes:?}"
    );
    assert!(
        closes
            .iter()
            .any(kr_protocol::scalars::CanonicalSet::is_empty),
        "the local close carries no rights: {closes:?}"
    );

    // The voice module's: no forwarded work at all, and its session read as the daemon's own
    // request.
    let mut session_reads = 0;
    for frame in &frames[before_voice..] {
        match frame {
            ControlFrame::Forwarded(_) | ControlFrame::ForwardedRead(_) => {
                panic!("a voice effect reached the worker as forwarded work: {frame:?}");
            }
            ControlFrame::Request(request) => {
                assert_eq!(
                    request.method,
                    Method::SessionRead.into(),
                    "the daemon's own request is its session read"
                );
                session_reads += 1;
            }
            _ => {}
        }
    }
    assert!(
        session_reads >= 1,
        "the voice read reached the worker as the daemon's own request"
    );
    world.serving.abort();
}

/// A device committed to `controller`'s records, paired under the grant `shape` makes of one
/// that sees every session and nothing else: `session.view`, no retained history, no live
/// screen and no expiry.
fn paired(
    controller: &crate::service::Controller,
    byte: u8,
    shape: impl FnOnce(&mut kr_protocol::grant::Grant),
) -> crate::service::net::devices::DeviceRecord {
    let revision = controller.policy().authority_revision();
    let (mut paired, _) =
        crate::service::net::tests::granted(kr_protocol::grant::GrantExpiry::Never, revision);
    shape(&mut paired);
    let device = crate::service::net::devices::DeviceRecord {
        device_id: paired.recipient_device_id,
        endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([byte; 32]),
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
        stored_envelope: None,
        notification_preview: None,
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: paired,
        paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    };
    controller.devices().commit(&device).expect("paired");
    device
}

/// A device whose grant admits every read the method table lets a paired device make: every
/// right, every environment and session, the whole retained history and the live screen, and a
/// live voice grant beside it. What such a device is answered is the routing's decision rather
/// than its grant's.
fn paired_with_every_right(
    controller: &crate::service::Controller,
    byte: u8,
) -> crate::service::net::devices::DeviceRecord {
    use kr_protocol::rights::ActionRight;

    let device = paired(controller, byte, |grant| {
        grant.actions = ActionRight::ALL.iter().copied().collect();
        grant.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
        grant.history.include_live_screen = true;
    });
    let voice_grant = kr_protocol::grant::Grant {
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id: controller.sharing().host_device_id(),
        actions: [ActionRight::VoiceUse, ActionRight::SessionView]
            .into_iter()
            .collect(),
        ..device.grant.clone()
    };
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: voice_grant,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a live voice grant");
    device
}

/// The receipt a voice read of the session a fake worker serves is answered with, after `prepare`
/// has put into the daemon whatever the test says the description host holds of it.
///
/// The read is made as a device paired under every right but the voice right, and a voice grant of
/// its own: the ordinary grant a voice grant narrows.
async fn receipt_of_a_voice_read<Prepared: std::future::Future<Output = ()>>(
    prepare: impl FnOnce(
        std::sync::Arc<crate::service::Controller>,
        kr_protocol::ids::SessionId,
    ) -> Prepared,
) -> String {
    use std::sync::Arc;

    use crate::service::a_close_a_worker_never_answers as fake;

    let recorded: fake::Recorded = Arc::default();
    let world = fake::fake_worker(Some(recorded)).await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let device = paired(controller, 8, |grant| {
        grant.actions = kr_protocol::rights::ActionRight::ALL
            .iter()
            .copied()
            .filter(|right| *right != kr_protocol::rights::ActionRight::VoiceUse)
            .collect();
        grant.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
    });
    let voice_grant = kr_protocol::grant::Grant {
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id: controller.sharing().host_device_id(),
        actions: [
            kr_protocol::rights::ActionRight::VoiceUse,
            kr_protocol::rights::ActionRight::SessionView,
        ]
        .into_iter()
        .collect(),
        ..device.grant.clone()
    };
    let voice_grant_id = voice_grant.grant_id;
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: voice_grant,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a live voice grant");
    prepare(Arc::clone(controller), world.session_id).await;
    let voice_session_id = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let delegation_id =
        kr_protocol::voice::VoiceDelegationId::new("a-delegation").expect("an identifier");
    let action = kr_protocol::voice::VoiceAction::Status;
    let proposal = kr_voice::Proposal {
        voice_session_id,
        device_id: device.device_id,
        voice_grant_id,
        environment_id: world.environment_id,
        action,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        session_id: Some(world.session_id),
        delegation_id: delegation_id.clone(),
        plan: kr_protocol::voice::VoiceActionPlan {
            voice_session_id,
            action,
            session_id: Nullable::some(world.session_id),
            delegation_id: Nullable::some(delegation_id),
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([3; 32]),
        },
        approval: None,
        turn_id: None,
        destination: None,
    };
    let receipt = controller
        .voice_perform(Method::SessionRead, &proposal)
        .await
        .expect("the daemon performs the read");
    assert!(receipt.performed);
    world.serving.abort();
    receipt.summary
}

/// KR-REQ-15.20: the receipt of a voice read of a session names the session with the name a person
/// pinned, under the bound the voice grant's device has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_receipt_of_a_voice_read_names_the_pin_the_host_holds() {
    let summary = receipt_of_a_voice_read(|controller, session_id| async move {
        controller
            .descriptions()
            .rename(
                session_id,
                Some("Release prep"),
                "local:501",
                &kr_describe::metadata::SessionFacts::default(),
                kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
                &|write| write(),
            )
            .expect("a name is pinned");
    })
    .await;
    assert!(summary.contains("named \"Release prep\""), "{summary}");
}

/// KR-REQ-15.20 and KR-REQ-24.11: a receipt says what was done and names the session by what a
/// person chose and what the daemon holds of it, and nothing a model wrote of it and nothing the
/// description host observed, so no read of it can carry either out after privacy mode removes
/// them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_receipt_of_a_voice_read_carries_nothing_a_model_wrote_or_the_host_observed() {
    use kr_protocol::describe::{DescriptionFacts, DescriptionFactsPage};
    use kr_protocol::scalars::U64;

    let summary = receipt_of_a_voice_read(|controller, session_id| async move {
        controller
            .descriptions()
            .store()
            .publish(
                &session_id,
                &crate::describe::tests::generated(
                    "Pairing check",
                    kr_worker::privacy::PrivacyGeneration::new(0),
                ),
                900,
            )
            .expect("a description");
        // The description host observes the session running in another directory than the one it
        // started in.
        let host = controller.descriptions().host().expect("a host").clone();
        host.session_opened(
            session_id,
            kr_protocol::ids::SessionEpoch::V1,
            kr_describe::context::ContextBinding::new("test"),
        );
        host.page(
            session_id,
            Box::new(DescriptionFactsPage {
                request_id: RequestId::new(1),
                session_id,
                privacy_generation: Nullable::some(U64::new(0)),
                private: false,
                facts: Nullable::some(DescriptionFacts {
                    revision: U64::new(1),
                    generation: U64::new(0),
                    directory: Nullable::some("observed-directory".to_owned()),
                    repository: Nullable::null(),
                    application: Nullable::some("cargo".to_owned()),
                    completion: Nullable::null(),
                    intent: Nullable::null(),
                    thread: Nullable::null(),
                    events: Vec::new(),
                }),
            }),
            false,
        );
        controller
            .descriptions()
            .until_host_has_taken_what_was_posted()
            .await;
        assert!(
            host.snapshot().seen.contains_key(&session_id),
            "the host observed the session"
        );
    })
    .await;
    assert_eq!(summary, "session 1 running /bin/zsh is live in /work");
}

/// Every read the method table admits for a paired device is served, or refused by name for a
/// reason the device can act on. None reaches the refusal the routing keeps for a method the
/// table does not admit for a device, which names no reason.
///
/// The routing's decision is walked over the whole table: every read a paired device may make
/// has one, raw input has one, and no other method does. Then each read is sent through a
/// paired device's own connection, naming the session this host's worker serves, by a device
/// whose grant admits every one of them, so what answers is the routing rather than the grant.
/// A read the routing forwards reaches the worker, which records it and refuses it; a read the
/// daemon answers itself is answered or refused by its own service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_read_the_method_table_admits_for_a_device_is_served_or_refused_by_name() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::authority::EffectClass;
    use kr_protocol::envelope::{ControlFrame, Outcome, Request, Response};
    use kr_protocol::error::ErrorCode;

    use crate::service::a_close_a_worker_never_answers as fake;

    let mut undecided = Vec::new();
    for method in Method::ALL {
        let entry = method.entry();
        let request = entry.effect == EffectClass::Read || *method == Method::InputWrite;
        let admitted = request && entry.ingress.contains(&ActorIngress::PairedDevice);
        if super::routes::DeviceRead::of(*method).is_some() != admitted {
            undecided.push((entry.name, admitted));
        }
    }
    assert!(
        undecided.is_empty(),
        "methods whose routing decision does not match whether the method table admits them \
         as a paired device's request, with that admission: {undecided:?}"
    );

    let recorded: fake::Recorded = Arc::default();
    let world = fake::fake_worker(Some(Arc::clone(&recorded))).await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let device = paired_with_every_right(controller, 9);
    let connection = super::RemoteConnection::for_test(controller, device);
    let params = ParamsValue::from_typed(&kr_protocol::session::SessionReadParams {
        session_id: world.session_id,
    })
    .expect("encodes");

    let mut reads = 0_u64;
    let mut unrouted = Vec::new();
    for method in Method::ALL {
        let entry = method.entry();
        if entry.effect != EffectClass::Read || !entry.ingress.contains(&ActorIngress::PairedDevice)
        {
            continue;
        }
        reads += 1;
        let answer = connection
            .read(&Request {
                request_id: RequestId::new(reads),
                method: (*method).into(),
                method_version: MethodVersion::V1,
                params: params.clone(),
            })
            .await;
        if let ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) = &answer
            && error.code == ErrorCode::InvalidArgument
            && error.message == format!("{} is not a read this host serves", entry.name)
        {
            unrouted.push(entry.name);
        }
    }
    assert!(
        reads > 0,
        "the method table admits reads for a paired device"
    );
    assert!(
        unrouted.is_empty(),
        "reads the method table admits for a paired device that reach the refusal kept for \
         methods it does not admit: {unrouted:?}"
    );
    world.serving.abort();
}

/// What a test's worker answers a forwarded read with, by the request; `None` refuses it.
type Answers =
    std::sync::Arc<dyn Fn(&kr_protocol::envelope::Request) -> Option<ParamsValue> + Send + Sync>;

/// A daemon whose one worker answers each read a device's connection forwards to it with what
/// `answers` makes of the request, and refuses one `answers` has nothing for. Like the recording
/// worker, it installs any authority revision it is told of, answers the daemon's own
/// `session.read` with a live session and refuses every other request and forwarded mutation;
/// every frame it is sent after its handshake is kept in `recorded`.
async fn answering_worker(
    answers: Answers,
    recorded: crate::service::a_close_a_worker_never_answers::Recorded,
    stated: CanonicalSet<kr_protocol::ids::CapabilityId>,
) -> crate::service::a_close_a_worker_never_answers::Silent {
    use std::sync::Arc;

    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::{ErrorCode, ProtocolError};

    use crate::service::a_close_a_worker_never_answers as fake;

    let refused = |request_id: RequestId| {
        ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "this worker answers only the reads its test gave it",
            )),
        })
    };
    fake::fake_world(move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let answers = Arc::clone(&answers);
                let recorded = Arc::clone(&recorded);
                let stated = stated.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let replies = match fake::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &stated,
                        ) {
                            Some(replies) => replies,
                            None => {
                                let reply = match &frame {
                                    ControlFrame::AuthorityRevision(notice) => {
                                        Some(ControlFrame::AuthorityRevisionAck(
                                            kr_protocol::worker::AuthorityRevisionAck {
                                                session_id: identity.session_id(),
                                                revision: notice.revision,
                                                fence: None,
                                            },
                                        ))
                                    }
                                    ControlFrame::Request(request)
                                        if request.method == Method::SessionRead.into() =>
                                    {
                                        Some(ControlFrame::Response(Response {
                                            request_id: request.request_id,
                                            outcome: Outcome::Ok(
                                                ParamsValue::from_typed(&fake::read_result(
                                                    identity.session_id(),
                                                ))
                                                .expect("encodes"),
                                            ),
                                        }))
                                    }
                                    ControlFrame::Request(request) => {
                                        Some(refused(request.request_id))
                                    }
                                    ControlFrame::Forwarded(forwarded) => {
                                        Some(refused(forwarded.mutation.request_id))
                                    }
                                    ControlFrame::ForwardedRead(forwarded) => {
                                        Some(match answers(&forwarded.request) {
                                            Some(value) => ControlFrame::Response(Response {
                                                request_id: forwarded.request.request_id,
                                                outcome: Outcome::Ok(value),
                                            }),
                                            None => refused(forwarded.request.request_id),
                                        })
                                    }
                                    _ => None,
                                };
                                recorded
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .push(frame);
                                reply.into_iter().collect()
                            }
                        };
                        for reply in replies {
                            if writer.write_message(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        })
    })
    .await
}

/// What a worker of this build states in its answer to a hello: that it reads the history scope
/// a forwarded read carries.
fn reads_scopes() -> CanonicalSet<kr_protocol::ids::CapabilityId> {
    [
        kr_protocol::ids::CapabilityId::new(kr_protocol::local::FORWARDED_HISTORY_SCOPE)
            .expect("a capability identifier"),
    ]
    .into_iter()
    .collect()
}

/// What a worker of this build states in its answer to a hello about a forwarded read's scope: it
/// reads one, and it holds a question read to it.
fn holds_question_reads() -> CanonicalSet<kr_protocol::ids::CapabilityId> {
    [
        kr_protocol::local::FORWARDED_HISTORY_SCOPE,
        kr_protocol::local::FORWARDED_QUESTION_SCOPE,
    ]
    .into_iter()
    .map(|capability| {
        kr_protocol::ids::CapabilityId::new(capability).expect("a capability identifier")
    })
    .collect()
}

/// The reads a worker was forwarded, in the order they arrived.
fn forwarded_reads(
    recorded: &crate::service::a_close_a_worker_never_answers::Recorded,
) -> Vec<kr_protocol::local::ForwardedRequest> {
    recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(|frame| match frame {
            kr_protocol::envelope::ControlFrame::ForwardedRead(forwarded) => {
                Some(forwarded.as_ref().clone())
            }
            _ => None,
        })
        .collect()
}

/// One request of `method` from a device, with `params`.
fn device_request<P: serde::Serialize>(
    request_id: u64,
    method: Method,
    params: &P,
) -> kr_protocol::envelope::Request {
    kr_protocol::envelope::Request {
        request_id: RequestId::new(request_id),
        method: method.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(params).expect("encodes"),
    }
}

/// The result an answer carries, or a panic naming the refusal it carries instead.
fn answered<T: kr_protocol::wire::WireMessage>(answer: kr_protocol::envelope::ControlFrame) -> T {
    match answer {
        kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
            outcome: kr_protocol::envelope::Outcome::Ok(value),
            ..
        }) => value.to_typed().expect("a result of the declared shape"),
        other => panic!("the read was not answered: {other:?}"),
    }
}

/// The refusal an answer carries, or a panic naming what it carries instead.
fn refusal(answer: kr_protocol::envelope::ControlFrame) -> kr_protocol::error::ProtocolError {
    match answer {
        kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
            outcome: kr_protocol::envelope::Outcome::Error(error),
            ..
        }) => error,
        other => panic!("the read was not refused: {other:?}"),
    }
}

/// One question the application inside `session_id` asked, as that session's worker holds it.
fn asked(session_id: SessionId, byte: u8, created_at_ms: u64) -> kr_protocol::question::Question {
    use kr_protocol::question::{
        Question, QuestionChoice, QuestionKind, QuestionSource, QuestionState,
    };

    Question {
        question_id: kr_protocol::ids::QuestionId::new(Uuid::from_bytes([byte; 16])),
        revision: kr_protocol::ids::QuestionRevision::new(1),
        state: QuestionState::Pending,
        session_id,
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Confirm,
        context: "two tests fail".to_owned(),
        question: "push anyway?".to_owned(),
        choices: vec![QuestionChoice::something_else()],
        source: QuestionSource {
            application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                Uuid::from_bytes([3; 16]),
            ),
            process: kr_protocol::identity::ProcessStartIdentity::new(
                42,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                7,
            ),
            executable: Nullable::some("/usr/bin/some-agent".to_owned()),
            agent_label: Nullable::null(),
            connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([4; 16])),
            launch_channel: false,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: kr_protocol::scalars::TimestampMs::new(created_at_ms),
        expires_at_ms: kr_protocol::scalars::TimestampMs::new(
            created_at_ms.saturating_add(86_400_000),
        ),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

/// `question.read` from a paired device is answered by the worker of the session it names, which
/// is asked under the device's own envelope and with its grant's history scope. The worker holds
/// its answer to that scope through section 10's shared filter, so what it answers is what the
/// device is told: this daemon keeps no filter of its own to disagree with it. A device whose grant
/// does not admit the session is refused before anything reaches the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_the_questions_its_grant_reaches_from_the_sessions_worker() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::QuestionId;
    use kr_protocol::question::{QuestionReadParams, QuestionReadResult};

    use crate::service::a_close_a_worker_never_answers as fake;

    // The questions the session's worker answers with, whatever the read's scope: the worker
    // decides what a scope admits, and this worker's answer stands for that decision.
    const EARLIER: u8 = 0x21;
    const NAMED: u8 = 0x22;
    const LATER: u8 = 0x23;
    let question = |byte: u8| QuestionId::new(Uuid::from_bytes([byte; 16]));
    let recorded: fake::Recorded = Arc::default();
    let world = answering_worker(
        Arc::new(|request: &kr_protocol::envelope::Request| {
            if request.method != Method::QuestionRead.into() {
                return None;
            }
            let params: QuestionReadParams = request.params.to_typed().ok()?;
            let questions = [
                asked(params.session_id, EARLIER, 1_000),
                asked(params.session_id, NAMED, 1_000),
                asked(params.session_id, LATER, 5_000),
            ]
            .into_iter()
            .filter(|asked| {
                params
                    .question_id
                    .as_ref()
                    .is_none_or(|wanted| asked.question_id == *wanted)
            })
            .collect();
            ParamsValue::from_typed(&QuestionReadResult { questions }).ok()
        }),
        Arc::clone(&recorded),
        holds_question_reads(),
    )
    .await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let read = |request_id: u64, question_id: Option<QuestionId>| {
        device_request(
            request_id,
            Method::QuestionRead,
            &QuestionReadParams {
                session_id: world.session_id,
                question_id: Nullable(question_id),
                include_resolved: true,
            },
        )
    };
    let shown = |answer| {
        answered::<QuestionReadResult>(answer)
            .questions
            .into_iter()
            .map(|asked| asked.question_id)
            .collect::<Vec<_>>()
    };

    // A device that sees this session, reaching back to 2 000 and naming one earlier question, is
    // told what the worker answered, all of it.
    let reaching = paired(controller, 10, |grant| {
        grant.history.lower_bound_ms =
            Nullable::some(kr_protocol::scalars::TimestampMs::new(2_000));
        grant.history.named_questions = [question(NAMED)].into_iter().collect();
    });
    let connection = super::RemoteConnection::for_test(controller, reaching.clone());
    assert_eq!(
        shown(connection.read(&read(1, None)).await),
        vec![question(EARLIER), question(NAMED), question(LATER)],
        "the worker's answer, as the worker gave it"
    );
    assert_eq!(
        shown(connection.read(&read(2, Some(question(EARLIER)))).await),
        vec![question(EARLIER)]
    );

    // Each read reached the worker under this device's own envelope, with its grant's history
    // scope for the worker to hold the answer to.
    let forwarded = forwarded_reads(&recorded);
    assert_eq!(forwarded.len(), 2, "{forwarded:?}");
    for read in &forwarded {
        assert_eq!(read.request.method, Method::QuestionRead.into());
        assert_eq!(read.actor.ingress, ActorIngress::PairedDevice);
        assert_eq!(read.actor.device_id, Nullable::some(reaching.device_id));
        assert_eq!(read.actor.grant_id, Nullable::some(reaching.grant.grant_id));
        assert_eq!(read.history.as_ref(), Some(&reaching.grant.history));
    }

    // A device whose grant sees another session is refused, and nothing reaches the worker.
    let elsewhere = paired(controller, 12, |grant| {
        grant.session_selector = kr_protocol::grant::SessionSelector::These {
            session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        };
    });
    let connection = super::RemoteConnection::for_test(controller, elsewhere);
    let outside = refusal(connection.read(&read(3, None)).await);
    assert_eq!(outside.code, ErrorCode::PermissionDenied, "{outside:?}");
    assert_eq!(
        forwarded_reads(&recorded).len(),
        2,
        "a read the grant does not admit reaches no worker"
    );
    world.serving.abort();
}

/// `agent.capabilities` and `agent.commands` from a paired device are answered by the worker of
/// the session their subject names, which is asked under the device's own envelope, and they
/// come back as the worker answered them. The session a subject names is the one the grant is
/// checked against: a device whose grant does not admit it is refused before anything reaches
/// the worker, as it is for a read that names its session at the top of its parameters.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_an_agents_capabilities_and_commands_from_the_sessions_worker() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::agent::{
        AgentBindingState, AgentCapabilitiesParams, AgentCapabilitiesResult, AgentCommand,
        AgentCommandsParams, AgentCommandsResult, AgentSubject,
    };
    use kr_protocol::error::ErrorCode;

    use crate::service::a_close_a_worker_never_answers as fake;

    let binding = AgentBindingState {
        binding_revision: kr_protocol::ids::AgentBindingRevision::new(3),
        thread_id: Nullable::null(),
        turn_id: Nullable::null(),
        profile_id: Nullable::null(),
        mode: kr_protocol::broker::IntegrationMode::Gateway,
        rich_mutations_suspended: false,
        suspension_reason: Nullable::null(),
    };
    let capabilities = AgentCapabilitiesResult {
        binding: binding.clone(),
        capabilities: kr_protocol::broker::CapabilityMap {
            records: Vec::new(),
        },
    };
    let commands = AgentCommandsResult {
        binding,
        commands: vec![AgentCommand {
            name: "new".to_owned(),
            summary: "start a new conversation".to_owned(),
            parameter_encoding: "none".to_owned(),
        }],
    };
    let recorded: fake::Recorded = Arc::default();
    let world = answering_worker(
        {
            let capabilities = capabilities.clone();
            let commands = commands.clone();
            Arc::new(move |request: &kr_protocol::envelope::Request| {
                match request.method.method()? {
                    Method::AgentCapabilities => ParamsValue::from_typed(&capabilities).ok(),
                    Method::AgentCommands => ParamsValue::from_typed(&commands).ok(),
                    _ => None,
                }
            })
        },
        Arc::clone(&recorded),
        reads_scopes(),
    )
    .await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let subject = AgentSubject {
        session_id: world.session_id,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(Uuid::from_bytes(
            [5; 16],
        )),
    };

    // A device that sees every session.
    let viewer = paired(controller, 13, |_| {});
    let connection = super::RemoteConnection::for_test(controller, viewer.clone());
    let read = device_request(
        1,
        Method::AgentCapabilities,
        &AgentCapabilitiesParams { subject },
    );
    assert_eq!(
        answered::<AgentCapabilitiesResult>(connection.read(&read).await),
        capabilities
    );
    let read = device_request(2, Method::AgentCommands, &AgentCommandsParams { subject });
    assert_eq!(
        answered::<AgentCommandsResult>(connection.read(&read).await),
        commands
    );
    let forwarded = forwarded_reads(&recorded);
    assert_eq!(
        forwarded
            .iter()
            .map(|read| read.request.method.clone())
            .collect::<Vec<_>>(),
        vec![
            Method::AgentCapabilities.into(),
            Method::AgentCommands.into()
        ]
    );
    for read in &forwarded {
        assert_eq!(read.actor.ingress, ActorIngress::PairedDevice);
        assert_eq!(read.actor.device_id, Nullable::some(viewer.device_id));
        assert_eq!(read.actor.grant_id, Nullable::some(viewer.grant.grant_id));
    }

    // A device whose grant sees another session is refused the subject in this one, and
    // nothing reaches the worker.
    let elsewhere = paired(controller, 14, |grant| {
        grant.session_selector = kr_protocol::grant::SessionSelector::These {
            session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        };
    });
    let connection = super::RemoteConnection::for_test(controller, elsewhere);
    for read in [
        device_request(
            4,
            Method::AgentCapabilities,
            &AgentCapabilitiesParams { subject },
        ),
        device_request(5, Method::AgentCommands, &AgentCommandsParams { subject }),
    ] {
        let outside = refusal(connection.read(&read).await);
        assert_eq!(
            outside.code,
            ErrorCode::PermissionDenied,
            "{}: {outside:?}",
            read.method.as_str()
        );
    }
    assert_eq!(
        forwarded_reads(&recorded).len(),
        2,
        "a read the grant does not admit reaches no worker"
    );
    world.serving.abort();
}

/// KR-REQ-23.39 and KR-REQ-11.26 for the paired-device ingress: `agent.snapshot` and
/// `agent.approval.inspect` from a paired device go to the worker of the session their subject
/// names, under the device's own envelope and with the history scope of the grant the read was
/// decided under, and come back as the worker answered them: the worker is what narrows them.
/// A device whose grant lacks `session.view`, and one whose grant does not admit the subject's
/// session, are refused before anything reaches a worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_an_agents_history_and_an_approval_record_under_its_grants_scope() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::agent::{
        AgentApprovalInspectParams, AgentBindingState, AgentSnapshotEntry, AgentSnapshotParams,
        AgentSnapshotResult, AgentSubject,
    };
    use kr_protocol::error::ErrorCode;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{TimestampMs, U64};

    use crate::service::a_close_a_worker_never_answers as fake;

    let snapshot = AgentSnapshotResult {
        binding: AgentBindingState {
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(3),
            thread_id: Nullable::null(),
            turn_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::Gateway,
            rich_mutations_suspended: false,
            suspension_reason: Nullable::null(),
        },
        entries: vec![AgentSnapshotEntry {
            node: U64::new(2),
            kind: "message".to_owned(),
            text: "said under the grant".to_owned(),
            omitted_text_bytes: U64::ZERO,
            observed_at: TimestampMs::new(2_500),
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(3),
            turn_id: Nullable::null(),
        }],
        continuation: Nullable::null(),
        history_gap: false,
        withheld_entries: U64::new(1),
    };
    let recorded: fake::Recorded = Arc::default();
    let world = answering_worker(
        {
            let snapshot = snapshot.clone();
            Arc::new(move |request: &kr_protocol::envelope::Request| {
                match request.method.method()? {
                    Method::AgentSnapshot => ParamsValue::from_typed(&snapshot).ok(),
                    // The daemon passes a worker's answer on as it came, so any answer
                    // stands for the record here.
                    Method::AgentApprovalInspect => Some(ParamsValue::empty()),
                    _ => None,
                }
            })
        },
        Arc::clone(&recorded),
        reads_scopes(),
    )
    .await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let subject = AgentSubject {
        session_id: world.session_id,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(Uuid::from_bytes(
            [5; 16],
        )),
    };
    let reads = |first: u64| {
        [
            device_request(
                first,
                Method::AgentSnapshot,
                &AgentSnapshotParams {
                    subject,
                    from_node: Nullable::null(),
                },
            ),
            device_request(
                first + 1,
                Method::AgentApprovalInspect,
                &AgentApprovalInspectParams {
                    subject,
                    resource_id: kr_protocol::ids::PendingResourceId::new(Uuid::from_bytes(
                        [6; 16],
                    )),
                },
            ),
        ]
    };

    // A device whose grant reaches back to one moment and names nothing.
    let viewer = paired(controller, 15, |grant| {
        grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(2_000));
        grant.history.include_live_screen = false;
    });
    let connection = super::RemoteConnection::for_test(controller, viewer.clone());
    let [snapshot_read, record_read] = reads(1);
    assert_eq!(
        answered::<AgentSnapshotResult>(connection.read(&snapshot_read).await),
        snapshot
    );
    match connection.read(&record_read).await {
        kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
            outcome: kr_protocol::envelope::Outcome::Ok(value),
            ..
        }) => assert_eq!(value, ParamsValue::empty()),
        other => panic!("the record read was not answered: {other:?}"),
    }
    let forwarded = forwarded_reads(&recorded);
    assert_eq!(
        forwarded
            .iter()
            .map(|read| read.request.method.clone())
            .collect::<Vec<_>>(),
        vec![
            Method::AgentSnapshot.into(),
            Method::AgentApprovalInspect.into()
        ]
    );
    for read in &forwarded {
        assert_eq!(read.actor.ingress, ActorIngress::PairedDevice);
        assert_eq!(read.actor.device_id, Nullable::some(viewer.device_id));
        assert_eq!(read.actor.grant_id, Nullable::some(viewer.grant.grant_id));
        assert_eq!(
            read.history.as_ref(),
            Some(&viewer.grant.history),
            "the grant's scope travels with {}",
            read.request.method.as_str()
        );
    }

    // Without session.view, and for a session the grant does not admit, nothing reaches the
    // worker.
    let blind = paired(controller, 16, |grant| {
        grant.actions = grant
            .actions
            .iter()
            .copied()
            .filter(|right| *right != ActionRight::SessionView)
            .collect();
    });
    let elsewhere = paired(controller, 17, |grant| {
        grant.session_selector = kr_protocol::grant::SessionSelector::These {
            session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        };
    });
    for (device, first) in [(blind, 3), (elsewhere, 5)] {
        let connection = super::RemoteConnection::for_test(controller, device);
        for read in reads(first) {
            let refused = refusal(connection.read(&read).await);
            assert_eq!(
                refused.code,
                ErrorCode::PermissionDenied,
                "{}: {refused:?}",
                read.method.as_str()
            );
        }
    }
    assert_eq!(
        forwarded_reads(&recorded).len(),
        2,
        "a read the grant does not admit reaches no worker"
    );
    world.serving.abort();
}

/// A worker of an earlier build does not say that it reads a forwarded read's history scope,
/// and a frame with a member it does not know would end the link. So it is sent none: a
/// device's snapshot reaches it without a scope, which it refuses by itself, and the same link
/// serves the device's next read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_does_not_read_scopes_is_sent_none_and_serves_the_next_read() {
    use std::sync::Arc;

    use kr_protocol::agent::{
        AgentBindingState, AgentCapabilitiesParams, AgentCapabilitiesResult, AgentSnapshotParams,
        AgentSubject,
    };

    use crate::service::a_close_a_worker_never_answers as fake;

    let capabilities = AgentCapabilitiesResult {
        binding: AgentBindingState {
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(3),
            thread_id: Nullable::null(),
            turn_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::Gateway,
            rich_mutations_suspended: false,
            suspension_reason: Nullable::null(),
        },
        capabilities: kr_protocol::broker::CapabilityMap {
            records: Vec::new(),
        },
    };
    let recorded: fake::Recorded = Arc::default();
    let world = answering_worker(
        {
            let capabilities = capabilities.clone();
            Arc::new(move |request: &kr_protocol::envelope::Request| {
                match request.method.method()? {
                    Method::AgentCapabilities => ParamsValue::from_typed(&capabilities).ok(),
                    _ => None,
                }
            })
        },
        Arc::clone(&recorded),
        CanonicalSet::new(),
    )
    .await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    let subject = AgentSubject {
        session_id: world.session_id,
        application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(Uuid::from_bytes(
            [5; 16],
        )),
    };
    let viewer = paired(controller, 18, |_| {});
    let connection = super::RemoteConnection::for_test(controller, viewer);

    let snapshot = device_request(
        1,
        Method::AgentSnapshot,
        &AgentSnapshotParams {
            subject,
            from_node: Nullable::null(),
        },
    );
    refusal(connection.read(&snapshot).await);
    let next = device_request(
        2,
        Method::AgentCapabilities,
        &AgentCapabilitiesParams { subject },
    );
    assert_eq!(
        answered::<AgentCapabilitiesResult>(connection.read(&next).await),
        capabilities,
        "the link serves the next read"
    );
    let forwarded = forwarded_reads(&recorded);
    assert_eq!(forwarded.len(), 2);
    assert!(
        forwarded.iter().all(|read| read.history.is_none()),
        "a worker that does not read scopes is sent none"
    );
    world.serving.abort();
}

/// A device whose grant lets it close and read every session.
fn closing_and_viewing(
    controller: &crate::service::Controller,
    byte: u8,
) -> crate::service::net::devices::DeviceRecord {
    use kr_protocol::rights::ActionRight;

    paired(controller, byte, |grant| {
        grant.actions = [ActionRight::SessionView, ActionRight::SessionClose]
            .into_iter()
            .collect();
    })
}

/// Closes a session through the daemon for a device, as its connection's close does, and returns
/// what the close settled as.
async fn close_for_a_device(
    world: &crate::service::a_close_a_worker_never_answers::Silent,
    connection: &super::RemoteConnection,
    close: &MutationRequest,
    rights: &[kr_protocol::rights::ActionRight],
) -> crate::service::net::ClosedRemotely {
    close_for_a_device_of(&world.controller, world.accepted, connection, close, rights).await
}

/// The same for a daemon and the deadline its close was accepted under.
async fn close_for_a_device_of(
    controller: &std::sync::Arc<crate::service::Controller>,
    accepted: kr_transport::window::AcceptedDeadline,
    connection: &super::RemoteConnection,
    close: &MutationRequest,
    rights: &[kr_protocol::rights::ActionRight],
) -> crate::service::net::ClosedRemotely {
    let rights: CanonicalSet<_> = rights.iter().copied().collect();
    let envelope = connection.envelope(controller.policy().authority_revision());
    let (answer, answered) = tokio::sync::oneshot::channel();
    // Nothing holds the link for a delivery: the acceptance is taken as delivered at once.
    let (_, delivered) = tokio::sync::oneshot::channel();
    controller
        .close_remote_session(
            close,
            crate::service::net::proxy::Vouched {
                actor: &envelope,
                grant_rights: &rights,
                history: Some(&connection.device.grant.history),
            },
            accepted,
            &connection.expiry_observer(),
            answer,
            delivered,
        )
        .await;
    answered
        .await
        .expect("the close settles")
        .expect("the worker answers the close")
}

/// KR-REQ-09.12: a device's close that a closure overtakes between the daemon's reading of the
/// session's worker and its opening of the link the close goes over is answered from the closure
/// record, which the device is told is a record and not the worker's own answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_devices_close_that_a_closure_overtakes_is_answered_from_the_closure() {
    use kr_protocol::rights::ActionRight;
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_link_that_is_not_given_back::Served;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = Served::start().await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 23));
    let close = fake::close_request(controller.paths().environment_id(), world.session_id);
    let accepted = kr_transport::window::AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: kr_transport::window::DeadlineBound::RequestedTtl,
    };
    let (arrived, go) = controller.before_a_proxy_is_opened.arm();

    let (closed, ()) = tokio::join!(
        close_for_a_device_of(
            controller,
            accepted,
            &connection,
            &close,
            &[ActionRight::SessionView, ActionRight::SessionClose],
        ),
        async {
            arrived.await.expect("the close reaches the worker's door");
            controller
                .retire(&closure_of(world.session_id))
                .await
                .expect("the closure is recorded");
            go.send(()).expect("the close is waiting");
        }
    );
    assert_eq!(closed.retained, crate::service::net::Retained::Record);
    let answered: SessionCloseResult = closed.value.to_typed().expect("a close result");
    assert_eq!(answered.state, SessionState::Closed);
    assert_eq!(
        answered.closure.as_ref().map(|record| record.session_id),
        Some(world.session_id)
    );
}

/// KR-REQ-09.12: a paired device that reads a session that has closed is told that it closed,
/// whether its read names the session or only an action it performed there, and not that the
/// session is unknown: the closure is on record. A session this host never held is unknown, which
/// is the control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_reads_a_closed_session_is_told_it_closed_and_not_that_it_is_unknown() {
    use kr_protocol::error::ErrorCode;
    use kr_protocol::question::QuestionReadParams;
    use kr_protocol::receipt::ActionReadParams;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_link_that_is_not_given_back::Served;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = Served::start().await;
    let controller = &world.controller;
    let device = paired_with_every_right(controller, 71);
    // The route of an action the device performed in the session, which a read of that action
    // follows to the session.
    let close = fake::close_request(controller.paths().environment_id(), world.session_id);
    assert!(
        super::RemoteConnection::for_test(controller, device.clone())
            .claim_route(&close, Some(world.session_id))
            .is_ok(),
        "the route of the close is on record"
    );
    controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");

    let question_read = |session_id: SessionId| {
        device_request(
            1,
            Method::QuestionRead,
            &QuestionReadParams {
                session_id,
                question_id: Nullable::null(),
                include_resolved: true,
            },
        )
    };
    let action_read = device_request(
        2,
        Method::ActionRead,
        &ActionReadParams {
            action_id: close.action_id,
            session_id: None,
        },
    );
    // Each on a connection of its own, as a device that connects after the closure asks.
    for request in [question_read(world.session_id), action_read] {
        let connection = super::RemoteConnection::for_test(controller, device.clone());
        let refused = refusal(connection.read(&request).await);
        assert_eq!(refused.code, ErrorCode::SessionClosed, "{refused:?}");
    }
    let connection = super::RemoteConnection::for_test(controller, device);
    let unknown = refusal(
        connection
            .read(&question_read(SessionId::new(kr_ipc::new_uuid())))
            .await,
    );
    assert_eq!(unknown.code, ErrorCode::UnknownSession, "{unknown:?}");
}

/// KR-REQ-23.34: a daemon that replaced the one a device's close went through, and admitted the
/// session's worker without a description, answers the device's exact retry of that close from
/// the receipt the worker kept, and settles that answer as it settles one given now. Once the
/// worker stops answering, a read is answered closing from the description the kept acceptance
/// carried, and a list includes the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_daemon_settles_a_devices_retried_close_from_the_workers_receipt() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    script.refuse_reads(true);
    let world = scripted::restarted(world).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 21));
    // The close went through the daemon this one replaced: its route is on record, and the
    // worker kept the acceptance it gave.
    let close = fake::close_request(world.environment_id, world.session_id);
    assert!(
        connection
            .claim_route(&close, Some(world.session_id))
            .is_ok(),
        "the route of the close is on record"
    );
    let accepted = script.acceptance(world.session_id);
    script.kept(
        close.action_id,
        ParamsValue::from_typed(&accepted).expect("encodes"),
    );

    let answered = connection
        .answer(ControlFrame::Mutation(Box::new(close)))
        .await
        .expect("the retry is answered");
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answered.frame()
    else {
        panic!(
            "the retry is answered with the kept acceptance: {:?}",
            answered.frame()
        );
    };
    assert_eq!(
        value
            .to_typed::<SessionCloseResult>()
            .expect("a close answer"),
        accepted
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = scripted::read(&world)
        .await
        .expect("a closing session is answered from the acceptance the worker kept");
    assert_eq!(Some(answer.session), accepted.session);
    assert_eq!(
        scripted::list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    assert!(!scripted::recorded(&world).await);
    world.serving.abort();
}

/// KR-REQ-23.34: the same for a device's close dispatched again, which the worker answers from
/// what it kept: the daemon passes the kept answer on as it came and settles it on the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_daemon_settles_a_close_the_worker_answers_again_from_what_it_kept() {
    use kr_protocol::rights::ActionRight;
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    script.refuse_reads(true);
    let world = scripted::restarted(world).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 22));
    let close = fake::close_request(world.environment_id, world.session_id);
    let accepted = script.acceptance(world.session_id);
    script.kept(
        close.action_id,
        ParamsValue::from_typed(&accepted).expect("encodes"),
    );

    let closed = close_for_a_device(
        &world,
        &connection,
        &close,
        &[ActionRight::SessionView, ActionRight::SessionClose],
    )
    .await;
    assert!(
        matches!(
            closed.retained,
            crate::service::net::Retained::Worker { .. }
        ),
        "the worker answered from what it kept"
    );
    assert_eq!(
        closed
            .value
            .to_typed::<SessionCloseResult>()
            .expect("a close answer"),
        accepted,
        "and the kept answer is passed on as it came"
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = scripted::read(&world)
        .await
        .expect("a closing session is answered from the acceptance the worker kept");
    assert_eq!(Some(answer.session), accepted.session);
    assert_eq!(
        scripted::list(&world, false).await,
        vec![(world.session_id, SessionState::Closing)]
    );
    world.serving.abort();
}

/// KR-REQ-23.34: the daemon keeps the description a worker's acceptance of a device's close
/// carries whatever the device may read. What the device is shown of it is decided where its
/// answer is written; what the daemon keeps is what it answers a read with once the worker has
/// stopped answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_devices_close_is_kept_by_the_daemon_whatever_the_device_may_read() {
    use kr_protocol::rights::ActionRight;
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    script.refuse_reads(true);
    let world = scripted::restarted(world).await;
    let controller = &world.controller;
    let closer = paired(controller, 23, |grant| {
        grant.actions = [ActionRight::SessionClose].into_iter().collect();
    });
    let connection = super::RemoteConnection::for_test(controller, closer);

    let closed = close_for_a_device(
        &world,
        &connection,
        &fake::close_request(world.environment_id, world.session_id),
        &[ActionRight::SessionClose],
    )
    .await;
    assert_eq!(closed.retained, crate::service::net::Retained::Not);
    let accepted: SessionCloseResult = closed.value.to_typed().expect("a close answer");
    assert_eq!(accepted.state, SessionState::Closing);
    assert!(
        accepted.session.is_some(),
        "the worker's acceptance reaches the daemon with its description"
    );

    let (_arrived, go) = script.end_at_next_read();
    drop(go);
    let answer = scripted::read(&world)
        .await
        .expect("a closing session is answered from the acceptance");
    assert_eq!(Some(answer.session), accepted.session);
    world.serving.abort();
}

/// A device's mutation of `method` to the scripted session, with params `params`.
fn device_mutation(
    world: &crate::service::a_close_a_worker_never_answers::Silent,
    connection: &super::RemoteConnection,
    method: Method,
    request_id: u64,
    params: ParamsValue,
) -> MutationRequest {
    let window = connection
        .windows
        .issue(connection.connection_id, world.controller.boot_epoch)
        .expect("a window");
    MutationRequest {
        request_id: RequestId::new(request_id),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(world.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: window.action_window_id,
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params,
    }
}

/// The error an answer carries, when it is one.
fn error_of(answer: &kr_protocol::envelope::ControlFrame) -> &kr_protocol::error::ProtocolError {
    let kr_protocol::envelope::ControlFrame::Response(kr_protocol::envelope::Response {
        outcome: kr_protocol::envelope::Outcome::Error(error),
        ..
    }) = answer
    else {
        panic!("an error was expected: {answer:?}");
    };
    error
}

/// KR-REQ-10.49: a mutation carries the history scope of the grant a device acts under to a worker
/// that holds what it retains to one, and carries none to a worker of an earlier build, which ends
/// the link a frame with a member it does not know arrived on: a device's close is made either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_mutation_carries_the_devices_scope_only_to_a_worker_that_holds_results_to_one()
 {
    use kr_protocol::rights::ActionRight;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [true, false] {
        let script = Scripted::new();
        if !holds {
            script.built_before_results_were_held_to_scopes();
        }
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let connection =
            super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 31));
        let closed = close_for_a_device(
            &world,
            &connection,
            &fake::close_request(world.environment_id, world.session_id),
            &[ActionRight::SessionView, ActionRight::SessionClose],
        )
        .await;
        assert_eq!(
            closed.retained,
            crate::service::net::Retained::Not,
            "{holds}"
        );
        let forwarded = script.forwarded();
        assert_eq!(forwarded.len(), 1, "{holds}");
        assert_eq!(
            forwarded[0].history,
            holds.then(|| connection.device.grant.history.clone()),
            "a worker that holds results to a scope is sent it, and no other is: {holds}"
        );
        // On the wire the member is absent for a worker that does not state the capability, not
        // null: a null member is one an earlier worker's closed frame refuses all the same.
        assert_eq!(
            script.forwarded_with_history(),
            vec![holds],
            "the bytes the proxy wrote carry a history member only for a capable worker: {holds}"
        );
        world.serving.abort();
    }
}

/// Publishes one small attachment for `actor`.
fn a_published_attachment(
    controller: &crate::service::Controller,
    environment_id: kr_protocol::ids::EnvironmentId,
    actor: &kr_protocol::ids::ActorId,
    name: &str,
) -> kr_protocol::transfer::AttachmentHandle {
    a_published_attachment_for(controller, environment_id, actor, name, None)
}

/// Publishes one small attachment for `actor`, begun for `session_id` where there is one.
fn a_published_attachment_for(
    controller: &crate::service::Controller,
    environment_id: kr_protocol::ids::EnvironmentId,
    actor: &kr_protocol::ids::ActorId,
    name: &str,
    session_id: Option<kr_protocol::ids::SessionId>,
) -> kr_protocol::transfer::AttachmentHandle {
    use kr_protocol::scalars::{Bytes, Digest256, U64};
    use kr_protocol::transfer::{
        ChunkDescriptor, UploadBeginParams, UploadChunkParams, UploadFinishParams,
    };

    let service = controller.transfer().service();
    let bytes = name.as_bytes().to_vec();
    let digest = Digest256::from_bytes(kr_cbor::sha256(&bytes));
    let begun = service
        .upload_begin(
            actor,
            &UploadBeginParams {
                environment_id,
                session_id: Nullable(session_id),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest,
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: name.to_owned(),
            },
            None,
        )
        .expect("reserves the upload");
    service
        .upload_chunk(
            actor,
            &UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk: ChunkDescriptor {
                    index: U64::new(0),
                    byte_len: U64::new(bytes.len() as u64),
                    digest,
                },
                bytes: Bytes::new(bytes.clone()),
            },
            None,
        )
        .expect("takes the chunk");
    service
        .upload_finish(
            actor,
            &UploadFinishParams {
                transfer_id: begun.transfer_id,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: digest,
            },
            None,
        )
        .expect("publishes the attachment")
        .handle
}

/// Binds a published attachment to a draft, and returns the draft as it stands then.
fn bound_to_a_draft(
    controller: &crate::service::Controller,
    actor: &kr_protocol::ids::ActorId,
    draft: &kr_protocol::transfer::DraftRecord,
    handle: &kr_protocol::transfer::AttachmentHandle,
) -> kr_protocol::transfer::DraftRecord {
    use kr_protocol::scalars::U64;
    use kr_protocol::transfer::{
        AgentDraftAddAttachmentParams, AttachmentContribution, InsertionMethod,
    };

    controller
        .transfer()
        .service()
        .draft_add_attachment(
            actor,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec![handle.declared_media_type.clone()],
                    max_byte_len: U64::new(1024),
                    max_count: U64::new(4),
                    insertion_method: InsertionMethod::TypedSubmission,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
            None,
        )
        .expect("binds the attachment");
    controller
        .transfer()
        .service()
        .draft(actor, draft.draft_id)
        .expect("reads the draft")
}

/// A new draft that names no session and holds nothing.
fn an_empty_draft(
    controller: &crate::service::Controller,
    environment_id: kr_protocol::ids::EnvironmentId,
    actor: &kr_protocol::ids::ActorId,
) -> kr_protocol::transfer::DraftRecord {
    controller
        .transfer()
        .service()
        .draft_create(
            actor,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id,
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "look at this".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft
}

/// A new draft that names no session and holds one published attachment.
fn a_draft_holding_an_attachment(
    controller: &crate::service::Controller,
    environment_id: kr_protocol::ids::EnvironmentId,
    actor: &kr_protocol::ids::ActorId,
    name: &str,
) -> kr_protocol::ids::DraftId {
    let handle = a_published_attachment(controller, environment_id, actor, name);
    let draft = an_empty_draft(controller, environment_id, actor);
    bound_to_a_draft(controller, actor, &draft, &handle).draft_id
}

/// A prompt a device makes to the scripted session, naming `draft_id`.
fn a_prompt_naming(
    world: &crate::service::a_close_a_worker_never_answers::Silent,
    connection: &super::RemoteConnection,
    method: Method,
    request_id: u64,
    draft_id: kr_protocol::ids::DraftId,
) -> MutationRequest {
    let params = kr_protocol::agent::AgentPromptParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_protocol::agent::AgentSubject {
                session_id: world.session_id,
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                    kr_ipc::new_uuid(),
                ),
            },
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
        },
        draft_id: Nullable::some(draft_id),
        text: Nullable::null(),
    };
    device_mutation(
        world,
        connection,
        method,
        request_id,
        ParamsValue::from_typed(&params).expect("encodes"),
    )
}

/// A device that may view a session and prompt its agent, paired with `controller`.
fn prompting_and_viewing(
    controller: &crate::service::Controller,
    byte: u8,
) -> crate::service::net::devices::DeviceRecord {
    use kr_protocol::rights::ActionRight;

    paired(controller, byte, |grant| {
        grant.actions = [ActionRight::SessionView, ActionRight::AgentPrompt]
            .into_iter()
            .collect();
    })
}

/// The attachments of a draft, as the transfer service holds them.
fn the_attachments_of(
    controller: &crate::service::Controller,
    actor: &kr_protocol::ids::ActorId,
    draft_id: kr_protocol::ids::DraftId,
) -> Vec<kr_protocol::transfer::AttachmentHandle> {
    controller
        .transfer()
        .service()
        .draft(actor, draft_id)
        .expect("reads the draft")
        .attachments
        .into_iter()
        .map(|attachment| attachment.handle)
        .collect()
}

/// Whether the attachment of a draft that holds one has been submitted.
fn is_submitted(
    controller: &crate::service::Controller,
    actor: &kr_protocol::ids::ActorId,
    draft_id: kr_protocol::ids::DraftId,
) -> bool {
    the_attachments_of(controller, actor, draft_id)[0].submitted
}

/// KR-REQ-14.11: a prompt a device sends or queues with a draft puts the draft's attachments under
/// the session's retention from the moment it is forwarded, whatever the worker then does.
///
/// The draft names no session, so the session the prompt goes to is what holds the attachment. The
/// record is made before the worker is asked, so a worker that is still deciding, one that refuses
/// and a connection that has ended all leave it in place: a file this host was asked to hand to a
/// session is never left on the seven-day window of an unused attachment. What the draft gets
/// after that is held too. A prompt that is refused before it is forwarded, for want of the right
/// to prompt, records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_naming_a_draft_puts_its_attachments_under_the_sessions_retention_when_forwarded()
{
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::rights::ActionRight;

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, prompting_and_viewing(controller, 41));
    let actor = connection.device.principal();
    let answered_ok = |answer: &super::Answered| {
        matches!(
            answer.frame(),
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        )
    };

    // A device that may not prompt is refused before anything is forwarded, and nothing is
    // recorded for the draft it named.
    let viewer = super::RemoteConnection::for_test(
        controller,
        paired(controller, 44, |grant| {
            grant.actions = [ActionRight::SessionView].into_iter().collect();
        }),
    );
    let viewer_actor = viewer.device.principal();
    let withheld = a_draft_holding_an_attachment(
        controller,
        world.environment_id,
        &viewer_actor,
        "viewer.bin",
    );
    script.accepts_prompts(true);
    let answer = viewer
        .answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &viewer,
            Method::AgentPromptSubmit,
            1,
            withheld,
        ))))
        .await
        .expect("the prompt is answered");
    assert!(!answered_ok(&answer), "{:?}", answer.frame());
    assert!(!is_submitted(controller, &viewer_actor, withheld));

    // The worker is still deciding, and the connection ends while it does: the record is already
    // there, and stays.
    let held = a_draft_holding_an_attachment(controller, world.environment_id, &actor, "held.bin");
    let (arrived, go) = script.hold_the_next_prompt();
    {
        let answering = connection.answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &connection,
            Method::AgentPromptSubmit,
            2,
            held,
        ))));
        tokio::pin!(answering);
        tokio::select! {
            _ = &mut answering => panic!("the worker was holding the prompt"),
            reached = arrived => reached.expect("the prompt reaches the worker"),
        }
        assert!(
            is_submitted(controller, &actor, held),
            "recorded before the worker has answered"
        );
        // The connection ends here: nothing is left to hear the answer.
    }
    let _ = go.send(());
    let handle = the_attachments_of(controller, &actor, held).remove(0);
    assert!(handle.submitted);
    assert_eq!(handle.session_id, Nullable::some(world.session_id));

    // An attachment belongs to one session. A prompt to another is refused before anything is
    // forwarded, and records nothing.
    let sent_before = script.forwarded().len();
    let foreign = a_published_attachment_for(
        controller,
        world.environment_id,
        &actor,
        "foreign.bin",
        Some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())),
    );
    let foreign_draft = an_empty_draft(controller, world.environment_id, &actor);
    let foreign_draft = bound_to_a_draft(controller, &actor, &foreign_draft, &foreign).draft_id;
    let answer = connection
        .answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &connection,
            Method::AgentPromptSubmit,
            6,
            foreign_draft,
        ))))
        .await
        .expect("the prompt is answered");
    assert!(!answered_ok(&answer), "{:?}", answer.frame());
    assert_eq!(script.forwarded().len(), sent_before, "nothing was sent");
    assert!(!is_submitted(controller, &actor, foreign_draft));

    // A worker that refuses the prompt leaves the attachment with that session: it was sent one.
    let refused =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "refused.bin");
    script.accepts_prompts(false);
    let answer = connection
        .answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &connection,
            Method::AgentPromptSubmit,
            3,
            refused,
        ))))
        .await
        .expect("the prompt is answered");
    assert!(!answered_ok(&answer), "{:?}", answer.frame());
    assert!(is_submitted(controller, &actor, refused));

    // A queued prompt is held by the session's agent from the moment the worker takes it.
    let queued =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "queued.bin");
    script.accepts_prompts(true);
    let answer = connection
        .answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &connection,
            Method::AgentPromptQueue,
            4,
            queued,
        ))))
        .await
        .expect("the queued prompt is answered");
    assert!(answered_ok(&answer), "{:?}", answer.frame());
    assert!(is_submitted(controller, &actor, queued));

    // The session's agent reads the draft when it does, so an attachment bound after the draft was
    // sent is held as well.
    let later = a_published_attachment(controller, world.environment_id, &actor, "later.bin");
    let sent = controller
        .transfer()
        .service()
        .draft(&actor, queued)
        .expect("reads the draft");
    bound_to_a_draft(controller, &actor, &sent, &later);
    let held = the_attachments_of(controller, &actor, queued);
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|handle| handle.submitted));
    assert!(
        held.iter()
            .all(|handle| handle.session_id == Nullable::some(world.session_id))
    );

    // A draft this device does not hold has nothing for this host to retain, and is no failure of
    // a prompt the worker takes.
    let answer = connection
        .answer(ControlFrame::Mutation(Box::new(a_prompt_naming(
            &world,
            &connection,
            Method::AgentPromptSubmit,
            5,
            kr_protocol::ids::DraftId::new(kr_ipc::new_uuid()),
        ))))
        .await
        .expect("the prompt is answered");
    assert!(answered_ok(&answer), "{:?}", answer.frame());
    world.serving.abort();
}

/// KR-REQ-14.11: a prompt that names a draft, made by a caller at this machine, is recorded as the
/// draft sent to the session before the worker is asked, exactly as a paired device's is, and
/// reaches the worker through this daemon as the local owner's own action.
///
/// The worker is still deciding when the check is made, so the record cannot be something the
/// worker's answer, or the connection that hears it, decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_naming_a_draft_is_recorded_before_the_worker_is_asked() {
    use kr_protocol::envelope::ControlFrame;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "local.bin");

    let mutation = a_local_prompt(
        &world,
        &admission,
        ActionId::new(kr_ipc::new_uuid()),
        Nullable::some(draft_id),
        Nullable::null(),
    );

    let (arrived, go) = script.hold_the_next_prompt();
    let mut performing = tokio::spawn({
        let controller = std::sync::Arc::clone(controller);
        let actor = actor.clone();
        async move {
            controller
                .perform(&actor, admission.connection_id, None, mutation)
                .await
        }
    });
    tokio::select! {
        answered = &mut performing => panic!("the worker was holding the prompt: {answered:?}"),
        reached = arrived => reached.expect("the prompt reaches the worker"),
    }
    assert!(
        is_submitted(controller, &actor, draft_id),
        "recorded before the worker has answered"
    );
    let handle = the_attachments_of(controller, &actor, draft_id).remove(0);
    assert_eq!(handle.session_id, Nullable::some(world.session_id));
    let _ = go.send(());
    let answer = performing.await.expect("the prompt is answered");
    assert!(
        matches!(
            answer,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: kr_protocol::envelope::Outcome::Ok(_),
                ..
            })
        ),
        "{answer:?}"
    );
    let sent = prompts_the_worker_was_asked_to_take(&script);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].actor.ingress,
        kr_protocol::actor::ActorIngress::LocalIpc
    );
    world.serving.abort();
}

/// KR-REQ-14.11: a prompt made under an action identifier the worker has already used for another
/// payload is refused as a reused identifier before the draft it names is recorded or anything is
/// sent, whichever way the first prompt reached the worker, so one prompt's identifier cannot put
/// another draft's attachments under the session's retention.
///
/// The first prompt carries its text inline, so nothing here ever recorded or claimed it: only the
/// worker knows it holds the action.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_reusing_an_action_for_a_draft_is_refused_before_it_is_recorded() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "reused.bin");
    let action_id = ActionId::new(kr_ipc::new_uuid());

    let inline = a_local_prompt(
        &world,
        &admission,
        action_id,
        Nullable::null(),
        Nullable::some(kr_protocol::agent::PromptText::new("run the tests").expect("text")),
    );
    let sent = controller
        .perform(&actor, admission.connection_id, None, inline)
        .await;
    assert!(
        matches!(
            sent,
            ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            })
        ),
        "{sent:?}"
    );

    let reused = controller
        .perform(
            &actor,
            admission.connection_id,
            None,
            a_local_prompt(
                &world,
                &admission,
                action_id,
                Nullable::some(draft_id),
                Nullable::null(),
            ),
        )
        .await;
    let ControlFrame::Response(Response {
        outcome: Outcome::Error(error),
        ..
    }) = reused
    else {
        panic!("a reused identifier is refused: {reused:?}");
    };
    assert_eq!(error.code, kr_protocol::error::ErrorCode::IdConflict);
    assert!(
        !is_submitted(controller, &actor, draft_id),
        "the draft was recorded under an identifier that is not its own"
    );
    assert_eq!(prompts_the_worker_was_asked_to_take(&script).len(), 1);
    world.serving.abort();
}

/// KR-REQ-14.11: a repeat of a prompt whose first attempt reached the worker is answered from the
/// receipt the worker holds, and nothing about the draft is recorded or sent again, so a record
/// that would now be refused cannot replace the answer the caller is owed.
///
/// The draft's attachment belongs to another session, so recording it for this one is refused. The
/// worker holds a receipt for this actor and this exact request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_the_worker_holds_a_receipt_for_is_answered_from_it_and_not_recorded_again() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::{ErrorCode, ProtocolError};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "repeat.bin");
    record_directly(
        &world,
        &actor,
        draft_id,
        kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect("records the submission to another session");
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let mutation = a_local_prompt(
        &world,
        &admission,
        action_id,
        Nullable::some(draft_id),
        Nullable::null(),
    );
    script.holds_a_refused_prompt(
        &mutation,
        &actor,
        ProtocolError::new(
            ErrorCode::UnsupportedCapability,
            "no upstream takes prompts",
        ),
    );

    let repeated = controller
        .perform(&actor, admission.connection_id, None, mutation)
        .await;
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = repeated
    else {
        panic!("the worker answers the repeat from its receipt: {repeated:?}");
    };
    let receipt: kr_protocol::receipt::ReceiptResponse = value.to_typed().expect("a receipt");
    assert_eq!(receipt.receipt.action_id, action_id);
    assert_eq!(receipt.receipt.actor_id, actor);
    assert_eq!(
        receipt.receipt.error.0.map(|error| error.code),
        Some(ErrorCode::UnsupportedCapability)
    );
    assert!(
        prompts_the_worker_was_asked_to_take(&script).is_empty(),
        "nothing is sent again"
    );
    world.serving.abort();
}

/// KR-REQ-14.11: a prompt the worker cannot say whether it holds a receipt for is refused with
/// what the worker said, and the draft it names is not recorded, because the worker may hold a
/// receipt that makes this a reused identifier or a repeat.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_the_worker_cannot_look_up_is_refused_and_its_draft_is_not_recorded() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    script.cannot_read_its_receipts();
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "unknown.bin");

    let answered = controller
        .perform(
            &actor,
            admission.connection_id,
            None,
            a_local_prompt(
                &world,
                &admission,
                ActionId::new(kr_ipc::new_uuid()),
                Nullable::some(draft_id),
                Nullable::null(),
            ),
        )
        .await;
    let ControlFrame::Response(Response {
        outcome: Outcome::Error(error),
        ..
    }) = answered
    else {
        panic!("the worker's refusal is the answer: {answered:?}");
    };
    assert_eq!(
        error.code,
        kr_protocol::error::ErrorCode::StorageUnavailable
    );
    assert!(
        !is_submitted(controller, &actor, draft_id),
        "the draft was recorded though the worker could not say whether it held a receipt"
    );
    assert!(prompts_the_worker_was_asked_to_take(&script).is_empty());
    world.serving.abort();
}

/// KR-REQ-09.12: a prompt a caller at this machine makes to a session that has closed is answered
/// that the session closed, from the closure the host recorded, as a paired device's read of it is,
/// and not that the session is unknown, which is the answer for a session this daemon holds neither
/// a worker nor a closure for. The prompt names a draft, and nothing is recorded for a session that
/// is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_for_a_session_that_closed_is_told_it_closed_and_not_that_it_is_unknown() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::ErrorCode;
    use kr_transport::window::{AcceptedDeadline, DeadlineBound};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_link_that_is_not_given_back::Served;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = Served::start().await;
    let controller = &world.controller;
    let environment_id = controller.paths().environment_id();
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let admission = fake::admission(controller, accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id = a_draft_holding_an_attachment(controller, environment_id, &actor, "closed.bin");
    controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");

    let code_of = |answered: ControlFrame| match answered {
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => error.code,
        other => panic!("the prompt is refused: {other:?}"),
    };
    let closed = controller
        .perform(
            &actor,
            admission.connection_id,
            None,
            a_local_prompt_to(
                controller,
                environment_id,
                world.session_id,
                &admission,
                ActionId::new(kr_ipc::new_uuid()),
                Nullable::some(draft_id),
                Nullable::null(),
            ),
        )
        .await;
    assert_eq!(code_of(closed), ErrorCode::SessionClosed);
    assert!(
        !is_submitted(controller, &actor, draft_id),
        "a draft was recorded as sent to a session that is gone"
    );

    let unknown = controller
        .perform(
            &actor,
            admission.connection_id,
            None,
            a_local_prompt_to(
                controller,
                environment_id,
                SessionId::new(kr_ipc::new_uuid()),
                &admission,
                ActionId::new(kr_ipc::new_uuid()),
                Nullable::some(draft_id),
                Nullable::null(),
            ),
        )
        .await;
    assert_eq!(code_of(unknown), ErrorCode::UnknownSession);
}

/// KR-REQ-09.12: a prompt a caller at this machine makes to a session the registry lists as live,
/// whose worker the daemon had not reached when it started, is put to that worker, as a device's
/// attach to the session and a read of it are, and is not refused as for a session nobody holds.
/// The daemon looks for the worker again before it says there is none.
///
/// The control is a reservation the host has fenced: looking again does not undo the fence, so the
/// worker is never connected to and the prompt is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_for_a_live_session_whose_worker_was_not_reached_at_start_finds_it_first() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for fenced in [false, true] {
        let script = Scripted::new();
        script.accepts_prompts(true);
        let world = scripted::recorded_unreached(&script).await;
        let controller = &world.controller;
        if fenced {
            let mut registry = controller.registry.lock().await;
            let reservation = registry
                .reservation_for_session(world.session_id)
                .expect("the registry answers")
                .expect("the create's reservation");
            registry
                .fence(reservation.reservation_id)
                .expect("fences the reservation");
        }
        assert!(
            controller
                .directory
                .lock()
                .await
                .get(world.session_id)
                .is_none(),
            "the daemon has not reached the worker"
        );
        let admission = fake::admission(controller, world.accepted).await;
        let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let answered = controller
            .perform(
                &actor,
                admission.connection_id,
                None,
                a_local_prompt(
                    &world,
                    &admission,
                    ActionId::new(kr_ipc::new_uuid()),
                    Nullable::null(),
                    Nullable::some(
                        kr_protocol::agent::PromptText::new("run the tests").expect("text"),
                    ),
                ),
            )
            .await;
        if fenced {
            assert!(
                matches!(
                    answered,
                    ControlFrame::Response(Response {
                        outcome: Outcome::Error(_),
                        ..
                    })
                ),
                "a fenced reservation's worker is not reached: {answered:?}"
            );
            assert_eq!(script.connections(), 0, "nothing reached the worker");
            assert!(prompts_the_worker_was_asked_to_take(&script).is_empty());
        } else {
            assert!(
                matches!(
                    answered,
                    ControlFrame::Response(Response {
                        outcome: Outcome::Ok(_),
                        ..
                    })
                ),
                "{answered:?}"
            );
            assert_eq!(prompts_the_worker_was_asked_to_take(&script).len(), 1);
            assert!(
                controller
                    .directory
                    .lock()
                    .await
                    .get(world.session_id)
                    .is_some(),
                "the worker the prompt reached is in the directory"
            );
        }
        world.serving.abort();
    }
}

/// KR-REQ-09.12: a prompt a caller at this machine makes while another exchange holds the daemon's
/// one link to the worker waits for its turn, and a session that closes meanwhile is closed to it:
/// it is answered that the session closed, from the closure the host recorded, and nothing is
/// recorded, and nothing the worker could take is sent, for a session that is gone. It is not
/// answered as a failure of the worker, whether the link it then gets still reaches the worker or
/// the worker has ended and the daemon cannot open another.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_waiting_for_the_workers_link_while_the_session_closes_is_told_it_closed() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::ErrorCode;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{
        self as scripted, Scripted, closure_of,
    };

    for worker_ended in [false, true] {
        let script = Scripted::new();
        script.accepts_prompts(true);
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let admission = fake::admission(controller, world.accepted).await;
        let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let draft_id =
            a_draft_holding_an_attachment(controller, world.environment_id, &actor, "waiting.bin");

        // Another exchange holds the link, and the prompt queues behind it.
        let mut held = controller
            .worker_client(&world.worker)
            .await
            .expect("the daemon's own link");
        let mutation = a_local_prompt(
            &world,
            &admission,
            ActionId::new(kr_ipc::new_uuid()),
            Nullable::some(draft_id),
            Nullable::null(),
        );
        let prompting = tokio::spawn({
            let controller = std::sync::Arc::clone(controller);
            let actor = actor.clone();
            async move {
                controller
                    .perform(&actor, admission.connection_id, None, mutation)
                    .await
            }
        });
        // The prompt is waiting for the slot once something besides the table and the holder has
        // taken it: the slot is shared by all three.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        while controller
            .connections
            .lock()
            .await
            .get(&world.session_id)
            .map(std::sync::Arc::strong_count)
            != Some(3)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the prompt did not queue for the worker's link"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        controller
            .retire(&closure_of(world.session_id))
            .await
            .expect("the closure is recorded");
        if worker_ended {
            // The worker has gone and its link with it, so the daemon has none to hand over and
            // none it can open.
            world.serving.abort();
            drop(held);
        } else {
            held.give_back();
            drop(held);
        }

        let answered = prompting.await.expect("the prompt's task ends");
        let ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) = answered
        else {
            panic!("a prompt for a session that closed was taken: {answered:?}");
        };
        assert_eq!(
            error.code,
            ErrorCode::SessionClosed,
            "worker ended: {worker_ended}: {error}"
        );
        assert!(
            !is_submitted(controller, &actor, draft_id),
            "a draft was recorded as sent to a session that is gone"
        );
        assert!(
            prompts_the_worker_was_asked_to_take(&script).is_empty(),
            "nothing was sent to the worker of a session that closed"
        );
        world.serving.abort();
    }
}

/// KR-REQ-09.12: an exact repeat of a prompt, made while another exchange holds the daemon's one
/// link to the worker, is answered from the receipt the worker holds for its first attempt even when
/// the session closes while it waits: the closure is recorded and the worker still answers, and what
/// a duplicate is owed is the existing receipt. Nothing is recorded, and nothing the worker could
/// take is sent, whether the repeat carries the window of the connection it is made on or one this
/// connection never issued, and whether it carries its text or names a draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_waiting_for_the_workers_link_while_the_session_closes_is_answered_from_its_receipt()
 {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::error::{ErrorCode, ProtocolError};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{
        self as scripted, Scripted, closure_of,
    };

    for (own_window, names_a_draft) in [(true, false), (false, false), (true, true), (false, true)]
    {
        let script = Scripted::new();
        script.accepts_prompts(true);
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let admission = fake::admission(controller, world.accepted).await;
        // The window a repeat from a replacement connection carries is one this connection never
        // issued, so it arrives with no deadline.
        let other_connection = fake::admission(controller, world.accepted).await;
        let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let draft_id =
            a_draft_holding_an_attachment(controller, world.environment_id, &actor, "repeat.bin");
        let (draft, text) = if names_a_draft {
            (Nullable::some(draft_id), Nullable::null())
        } else {
            (
                Nullable::null(),
                Nullable::some(kr_protocol::agent::PromptText::new("run the tests").expect("text")),
            )
        };
        let mutation = a_local_prompt(
            &world,
            if own_window {
                &admission
            } else {
                &other_connection
            },
            action_id,
            draft,
            text,
        );
        script.holds_a_refused_prompt(
            &mutation,
            &actor,
            ProtocolError::new(
                ErrorCode::UnsupportedCapability,
                "no upstream takes prompts",
            ),
        );

        let mut held = controller
            .worker_client(&world.worker)
            .await
            .expect("the daemon's own link");
        let repeating = tokio::spawn({
            let controller = std::sync::Arc::clone(controller);
            let actor = actor.clone();
            async move {
                controller
                    .perform(&actor, admission.connection_id, None, mutation)
                    .await
            }
        });
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        while controller
            .connections
            .lock()
            .await
            .get(&world.session_id)
            .map(std::sync::Arc::strong_count)
            != Some(3)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the repeat did not queue for the worker's link"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        controller
            .retire(&closure_of(world.session_id))
            .await
            .expect("the closure is recorded");
        held.give_back();
        drop(held);

        let repeated = repeating.await.expect("the repeat's task ends");
        let ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) = repeated
        else {
            panic!(
                "the worker answers the repeat from its receipt (own window {own_window}, draft \
                 {names_a_draft}): {repeated:?}"
            );
        };
        let receipt: kr_protocol::receipt::ReceiptResponse = value.to_typed().expect("a receipt");
        assert_eq!(receipt.receipt.action_id, action_id);
        assert!(prompts_the_worker_was_asked_to_take(&script).is_empty());
        assert!(
            !is_submitted(controller, &actor, draft_id),
            "nothing is recorded for a session that is gone"
        );
        world.serving.abort();
    }
}

/// KR-REQ-14.11: the first time a daemon of this build starts over a transfer journal an earlier
/// build wrote it notes every session the host knows, because each was started by a daemon of an
/// earlier build whose worker may take a draft prompt this host is not told of. A daemon that starts
/// again over the same journal notes nothing: a session started since has a worker that refuses such
/// a prompt. A journal this build makes has no earlier session to note.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sessions_a_daemon_knows_at_its_first_start_over_an_earlier_builds_journal_are_noted() {
    use std::collections::BTreeSet;

    use kr_transfer::Noting;

    use crate::service::a_close_a_worker_never_answers::Silent;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{
        self as scripted, Scripted, restarted,
    };

    let noted = |world: &Silent| -> BTreeSet<kr_protocol::ids::SessionId> {
        world
            .controller
            .transfer()
            .service()
            .unseen_prompt_sessions()
            .expect("reads the journal")
    };
    let noting = |world: &Silent| {
        world
            .controller
            .transfer()
            .service()
            .noting()
            .expect("reads the journal")
    };

    // A journal this build made has nothing to note, whatever session the host comes to know.
    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    assert_eq!(noting(&world), Noting::Done);
    let world = restarted(world).await;
    assert_eq!(noting(&world), Noting::Done);
    assert!(noted(&world).is_empty());

    // A journal an earlier build wrote has never been noted, and its start notes the session.
    rusqlite::Connection::open(kr_transfer::staging::StagingArea::store_path(
        &world._temp.environment(),
    ))
    .expect("opens the transfer journal")
    .execute("UPDATE schema_version SET version = 2", [])
    .expect("makes the journal one an earlier build wrote");
    let world = restarted(world).await;
    assert_eq!(noting(&world), Noting::Held);
    assert_eq!(noted(&world), BTreeSet::from([world.session_id]));

    // A start after that notes nothing more.
    let world = restarted(world).await;
    assert_eq!(noted(&world), BTreeSet::from([world.session_id]));
    world.serving.abort();
}

/// KR-REQ-14.11: the sessions noted at a first start are settled once none of them can run a worker,
/// and not before. Settling puts what a noted session names under that session's retention, as if
/// it had been submitted to it, and forgets the sessions, so the sweep no longer reads them. A start
/// that follows notes nothing again, and an attachment that names no noted session is not touched.
///
/// A noted session that is live keeps the noting, and so does a fenced launch whose process still
/// runs: the host never reaches its worker and has no closure for it. A session that closed, a launch
/// that failed and a fenced launch whose process has ended do not, though only the first has a
/// closure record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sessions_noted_at_a_first_start_are_settled_once_none_of_them_can_run_a_worker() {
    use std::collections::BTreeSet;

    use crate::registry::LaunchPhase;
    use crate::service::a_close_a_worker_never_answers::Silent;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{
        self as scripted, Scripted, closure_of, restarted,
    };

    let noted = |world: &Silent| -> BTreeSet<kr_protocol::ids::SessionId> {
        world
            .controller
            .transfer()
            .service()
            .unseen_prompt_sessions()
            .expect("reads the journal")
    };
    let sweep = |world: &Silent| {
        let swept = world
            .controller
            .transfer()
            .sweep(&std::sync::Arc::downgrade(&world.controller));
        async move { swept.await.expect("the sweep runs") }
    };
    let submitted = |world: &Silent,
                     actor: &kr_protocol::ids::ActorId,
                     handle: &kr_protocol::transfer::AttachmentHandle| {
        world
            .controller
            .transfer()
            .service()
            .attachment_handle(actor, handle.transfer_id)
            .expect("reads the attachment")
            .submitted
    };

    // A start over a journal no earlier build noted finds a live session and two launches that
    // never started, and notes all three.
    let script = Scripted::new();
    let world = scripted::reported_late(&script).await;
    let failed = scripted::reserved(&world, None, "/").await;
    let fenced = scripted::reserved(&world, None, "/").await;
    let path = kr_transfer::staging::StagingArea::store_path(&world._temp.environment());
    let journal = || rusqlite::Connection::open(&path).expect("opens the transfer journal");
    let tables = |journal: &rusqlite::Connection| -> i64 {
        journal
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN
                     ('unseen_prompt_sessions', 'unseen_prompts_noted')",
                [],
                |row| row.get(0),
            )
            .expect("reads the journal's tables")
    };
    assert_eq!(
        tables(&journal()),
        0,
        "a journal this build made has neither"
    );
    journal()
        .execute("UPDATE schema_version SET version = 2", [])
        .expect("makes the journal one an earlier build wrote");
    let world = restarted(world).await;
    let controller = &world.controller;
    let all = BTreeSet::from([world.session_id, failed.session_id, fenced.session_id]);
    assert_eq!(noted(&world), all);
    assert_eq!(tables(&journal()), 2, "the noting is kept in two tables");
    for launch in [&failed, &fenced] {
        assert_eq!(
            controller
                .registry
                .lock()
                .await
                .reservation(launch.reservation_id)
                .expect("the registry answers")
                .expect("the launch's reservation")
                .phase,
            LaunchPhase::Failed,
            "the start resolved a launch that never started"
        );
    }

    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let belonging = a_published_attachment_for(
        controller,
        world.environment_id,
        &actor,
        "belonging.bin",
        Some(world.session_id),
    );
    let loose = a_published_attachment(controller, world.environment_id, &actor, "loose.bin");

    // The session runs, so nothing is settled.
    sweep(&world).await;
    assert_eq!(noted(&world), all);
    assert_eq!(tables(&journal()), 2);
    assert!(!submitted(&world, &actor, &belonging));

    // It closes, but one launch was fenced after all, and its process runs.
    controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    {
        let mut registry = controller.registry.lock().await;
        registry
            .fence(fenced.reservation_id)
            .expect("fences the reservation");
        registry
            .record_launch(
                fenced.reservation_id,
                &kr_ipc::identity::current_process_start_identity().expect("a process identity"),
            )
            .expect("records the launcher");
    }
    sweep(&world).await;
    assert_eq!(noted(&world), all);
    assert_eq!(tables(&journal()), 2);
    assert!(!submitted(&world, &actor, &belonging));

    // Its process has ended, and nothing noted can run a worker.
    controller
        .registry
        .lock()
        .await
        .record_launch(
            fenced.reservation_id,
            &kr_ipc::identity::ended_process_identity(4_000_001),
        )
        .expect("records the launcher");
    sweep(&world).await;
    assert!(noted(&world).is_empty(), "the sessions are forgotten");
    assert_eq!(tables(&journal()), 0, "and both tables are gone");
    assert!(
        submitted(&world, &actor, &belonging),
        "what a noted session names is under its retention"
    );
    assert!(
        !submitted(&world, &actor, &loose),
        "what names no noted session is on its own window"
    );

    // A start after that notes nothing: the sessions are in the registry still, and what was
    // settled stays settled.
    let world = restarted(world).await;
    assert!(noted(&world).is_empty());
    assert_eq!(tables(&journal()), 0);
    world.serving.abort();
}

/// Records that a draft is sent to a session as the daemon does for a prompt, under an admission
/// that stands.
async fn record_directly(
    world: &crate::service::a_close_a_worker_never_answers::Silent,
    actor: &kr_protocol::ids::ActorId,
    draft_id: kr_protocol::ids::DraftId,
    session_id: kr_protocol::ids::SessionId,
) -> Result<usize, kr_protocol::error::ProtocolError> {
    let admission = crate::service::a_close_a_worker_never_answers::admission(
        &world.controller,
        world.accepted,
    )
    .await;
    world
        .controller
        .transfer()
        .record_submission(
            actor,
            draft_id,
            session_id,
            crate::transfer::TransferAdmission::new(
                std::sync::Arc::clone(&world.controller),
                admission,
            ),
        )
        .await
}

/// Stops the record of a draft where it has passed the daemon's own check and not yet entered the
/// transfer service, brings `lapse` about there, and lets the record go on.
async fn lapsing_before_the_record(
    controller: &std::sync::Arc<crate::service::Controller>,
    lapse: impl FnOnce(),
    prompt: impl std::future::Future<Output = ()>,
) {
    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let lapsing = async {
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the waiting thread finishes")
        .expect("the record reaches the place it is stopped at");
        lapse();
        release.send(()).expect("the record goes on");
    };
    tokio::join!(prompt, lapsing);
}

/// KR-REQ-14.11, KR-REQ-09.09: the record of the draft a local prompt names is made under the
/// admission the prompt arrived under, asked where the transfer service writes. A registration
/// withdrawn after the daemon's own check and before the service's lock leaves the draft as it was,
/// and the prompt is refused and not sent.
///
/// The control is the same prompt with its registration standing, which the neighbouring tests
/// carry: it is recorded and sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_prompt_whose_admission_lapses_before_its_draft_is_recorded_records_nothing() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "lapsed.bin");
    let mutation = a_local_prompt(
        &world,
        &admission,
        ActionId::new(kr_ipc::new_uuid()),
        Nullable::some(draft_id),
        Nullable::null(),
    );

    let mut answered = None;
    lapsing_before_the_record(
        controller,
        || {
            controller.admitted_table().remove(&admission.connection_id);
        },
        async {
            answered = Some(
                controller
                    .perform(&actor, admission.connection_id, None, mutation)
                    .await,
            );
        },
    )
    .await;
    let Some(ControlFrame::Response(Response {
        outcome: Outcome::Error(error),
        ..
    })) = answered
    else {
        panic!("the prompt is refused: {answered:?}");
    };
    assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    assert!(
        !is_submitted(controller, &actor, draft_id),
        "the draft was recorded after its admission had lapsed"
    );
    assert!(
        prompts_the_worker_was_asked_to_take(&script).is_empty(),
        "and the prompt was sent"
    );
    world.serving.abort();
}

/// KR-REQ-14.11, KR-REQ-09.09: the same for a paired device's prompt. The record is made under the
/// admission the prompt arrived under, so a device whose registration is withdrawn while the
/// prompt waits for its worker's link records nothing and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_prompt_whose_admission_lapses_before_its_draft_is_recorded_records_nothing() {
    use kr_protocol::envelope::ControlFrame;

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, prompting_and_viewing(controller, 45));
    let actor = connection.device.principal();
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "paired.bin");
    let prompt = a_prompt_naming(&world, &connection, Method::AgentPromptSubmit, 7, draft_id);

    let mut answered = None;
    lapsing_before_the_record(
        controller,
        || {
            controller
                .admitted_table()
                .remove(&connection.connection_id());
        },
        async {
            answered = Some(
                connection
                    .answer(ControlFrame::Mutation(Box::new(prompt)))
                    .await
                    .expect("the prompt is answered"),
            );
        },
    )
    .await;
    let answered = answered.expect("the prompt was answered");
    let ControlFrame::Response(kr_protocol::envelope::Response {
        outcome: kr_protocol::envelope::Outcome::Error(error),
        ..
    }) = answered.frame()
    else {
        panic!("the prompt is refused: {:?}", answered.frame());
    };
    assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    assert!(
        !is_submitted(controller, &actor, draft_id),
        "the draft was recorded after its admission had lapsed"
    );
    assert!(
        prompts_the_worker_was_asked_to_take(&script).is_empty(),
        "and the prompt was sent"
    );
    world.serving.abort();
}

/// KR-REQ-14.11, KR-REQ-09.09: the deadline a prompt was admitted under is asked again where its
/// draft is recorded. The clock is moved past the deadline at the place the record is stopped,
/// with the registration standing, so it is the deadline that refuses: nothing is recorded and
/// nothing is sent, on both routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_whose_deadline_passes_before_its_draft_is_recorded_records_nothing() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let (continuous, _wall, clocks) = crate::service::net::tests::manual_clocks();
    let script = Scripted::new();
    script.accepts_prompts(true);
    let world = scripted::scripted_on(&script, Some(clocks)).await;
    let controller = &world.controller;
    let past_it = || continuous.advance(std::time::Duration::from_secs(3_600));

    // A caller at this machine.
    let admission = fake::admission(controller, world.accepted).await;
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "late.bin");
    let mutation = a_local_prompt(
        &world,
        &admission,
        ActionId::new(kr_ipc::new_uuid()),
        Nullable::some(draft_id),
        Nullable::null(),
    );
    let mut answered = None;
    lapsing_before_the_record(controller, past_it, async {
        answered = Some(
            controller
                .perform(&actor, admission.connection_id, None, mutation)
                .await,
        );
    })
    .await;
    let Some(ControlFrame::Response(Response {
        outcome: Outcome::Error(error),
        ..
    })) = answered
    else {
        panic!("the local prompt is refused: {answered:?}");
    };
    assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    assert!(
        error.message.contains("deadline"),
        "it is the deadline that refused: {}",
        error.message
    );
    assert!(!is_submitted(controller, &actor, draft_id));

    // A paired device.
    let connection =
        super::RemoteConnection::for_test(controller, prompting_and_viewing(controller, 47));
    let device = connection.device.principal();
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &device, "later.bin");
    let prompt = a_prompt_naming(&world, &connection, Method::AgentPromptSubmit, 8, draft_id);
    let mut answered = None;
    lapsing_before_the_record(controller, past_it, async {
        answered = Some(
            connection
                .answer(ControlFrame::Mutation(Box::new(prompt)))
                .await
                .expect("the prompt is answered"),
        );
    })
    .await;
    let answered = answered.expect("the prompt was answered");
    let ControlFrame::Response(Response {
        outcome: Outcome::Error(error),
        ..
    }) = answered.frame()
    else {
        panic!("the paired prompt is refused: {:?}", answered.frame());
    };
    assert_eq!(error.code, kr_protocol::error::ErrorCode::PermissionDenied);
    assert!(
        error.message.contains("deadline"),
        "it is the deadline that refused: {}",
        error.message
    );
    assert!(!is_submitted(controller, &device, draft_id));
    assert!(
        prompts_the_worker_was_asked_to_take(&script).is_empty(),
        "and neither prompt was sent"
    );
    world.serving.abort();
}

/// A prompt a caller at this machine makes to the scripted session as `action_id`, naming a draft
/// or carrying its text inline, under a window issued to `admission`'s connection.
fn a_local_prompt(
    world: &crate::service::a_close_a_worker_never_answers::Silent,
    admission: &crate::authority::AdmittedMutation,
    action_id: ActionId,
    draft_id: Nullable<kr_protocol::ids::DraftId>,
    text: Nullable<kr_protocol::agent::PromptText>,
) -> MutationRequest {
    a_local_prompt_to(
        &world.controller,
        world.environment_id,
        world.session_id,
        admission,
        action_id,
        draft_id,
        text,
    )
}

/// A prompt a caller at this machine makes to `session_id` as `action_id`, naming a draft or
/// carrying its text inline, under a window issued to `admission`'s connection.
fn a_local_prompt_to(
    controller: &crate::service::Controller,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: SessionId,
    admission: &crate::authority::AdmittedMutation,
    action_id: ActionId,
    draft_id: Nullable<kr_protocol::ids::DraftId>,
    text: Nullable<kr_protocol::agent::PromptText>,
) -> MutationRequest {
    let window = controller
        .windows
        .issue(admission.connection_id, controller.boot_epoch)
        .expect("a window");
    let params = kr_protocol::agent::AgentPromptParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_protocol::agent::AgentSubject {
                session_id,
                application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                    kr_ipc::new_uuid(),
                ),
            },
            binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
        },
        draft_id,
        text,
    };
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::AgentPromptSubmit.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::some(params.target.subject.application_instance_id),
            agent_binding_revision: Nullable::some(params.target.binding_revision),
        },
        expected: ParamsValue::empty(),
        action_window_id: window.action_window_id,
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    }
}

/// The prompts a scripted worker was asked to take, which are the ones forwarded with a lifetime:
/// a prompt forwarded with none is only asked whether the worker holds a receipt for it.
fn prompts_the_worker_was_asked_to_take(
    script: &crate::service::a_read_that_meets_a_worker_on_its_way_out::Scripted,
) -> Vec<kr_protocol::local::ForwardedMutation> {
    script
        .forwarded()
        .into_iter()
        .filter(|forwarded| forwarded.accepted_deadline_boot_ms.get() != 0)
        .collect()
}

/// KR-REQ-14.11: a sweep judges an attachment only against a view of retention taken after the
/// attachment was read, so a draft sent to a session that began while the sweep was asking is left
/// for the next sweep and is not expired as the attachment of a session nobody knew.
///
/// The sweep stops once it has asked which sessions retain. A session this host did not know
/// then receives the draft, and the sweep, let go, expires nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sweep_leaves_a_draft_sent_to_a_session_that_began_after_it_asked() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let actor = prompting_and_viewing(controller, 61).principal();
    let draft_id =
        a_draft_holding_an_attachment(controller, world.environment_id, &actor, "began.bin");

    let (arrived, go, swept) = controller
        .transfer()
        .sweep_paused(&std::sync::Arc::downgrade(controller));
    tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
        .await
        .expect("the sweep reaches the question in time")
        .expect("the sweep says it has arrived");

    // A session the sweep's question did not cover begins, and the draft is sent to it.
    let began = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    record_directly(&world, &actor, draft_id, began)
        .await
        .expect("records the submission");
    assert!(is_submitted(controller, &actor, draft_id));
    let _ = go.send(());

    let swept = swept.await.expect("the sweep runs");
    assert_eq!(
        swept.expired_attachments, 0,
        "an attachment submitted after the sweep asked is not judged by its answer"
    );
    world.serving.abort();
}

/// KR-REQ-10.49: the daemon's own link to a worker, the one a close made at the local door and a
/// supervised action go through, carries no history scope on the wire whatever the worker states:
/// it acts as the owner, whom no scope bounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_the_daemons_own_link_forwards_no_history_member() {
    use kr_protocol::rights::ActionRight;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [true, false] {
        let script = Scripted::new();
        if !holds {
            script.built_before_results_were_held_to_scopes();
        }
        let world = scripted::scripted(&script).await;
        let mut client = world
            .controller
            .worker_client(&world.worker)
            .await
            .expect("the daemon's own link");
        let rights: CanonicalSet<ActionRight> = [ActionRight::SessionClose].into_iter().collect();
        let answered = client
            .client()
            .forward(
                &fake::close_request(world.environment_id, world.session_id),
                &world.actor,
                &rights,
                kr_protocol::scalars::U64::new(u64::MAX),
            )
            .await
            .expect("the worker answers the daemon's own close");
        assert!(answered.is_ok(), "the close is accepted: {answered:?}");
        drop(client);
        assert_eq!(script.forwarded().len(), 1, "{holds}");
        assert_eq!(
            script.forwarded_with_history(),
            vec![false],
            "no history member reaches the worker, stated capability or not: {holds}"
        );
        world.serving.abort();
    }
}

/// KR-REQ-10.49: an answer to a question, for a device that has a history scope, is not sent to a
/// worker that does not hold what it retains to one: it would answer with the whole question. The
/// refusal is `UNSUPPORTED_CAPABILITY`, before anything is sent. A worker that does is sent it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_question_is_not_resolved_for_a_device_at_a_worker_that_cannot_hold_the_answer_to_its_scope()
 {
    use kr_protocol::rights::ActionRight;

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [false, true] {
        let script = Scripted::new();
        if !holds {
            script.built_before_results_were_held_to_scopes();
        }
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let connection = super::RemoteConnection::for_test(
            controller,
            paired(controller, 32, |grant| {
                grant.actions = [ActionRight::SessionView, ActionRight::QuestionRespond]
                    .into_iter()
                    .collect();
                grant.history.lower_bound_ms =
                    Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
            }),
        );
        let params = kr_protocol::question::QuestionAnswerParams {
            session_id: world.session_id,
            question_id: kr_protocol::ids::QuestionId::new(kr_ipc::new_uuid()),
            expected_revision: kr_protocol::ids::QuestionRevision::new(1),
            answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
        };
        for (index, method) in [Method::QuestionAnswer, Method::QuestionCancel]
            .into_iter()
            .enumerate()
        {
            let params = if method == Method::QuestionAnswer {
                ParamsValue::from_typed(&params).expect("encodes")
            } else {
                ParamsValue::from_typed(&kr_protocol::question::QuestionCancelParams {
                    session_id: params.session_id,
                    question_id: params.question_id,
                    expected_revision: params.expected_revision,
                })
                .expect("encodes")
            };
            let mutation = device_mutation(&world, &connection, method, 41, params);
            let answer = connection.mutate(&mutation).await;
            if holds {
                // It reached the worker, which refuses what it does not perform.
                assert_eq!(script.forwarded().len(), index + 1, "{method:?}");
                assert_eq!(
                    error_of(&answer).code,
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    "{answer:?}"
                );
            } else {
                assert_eq!(
                    script.forwarded().len(),
                    0,
                    "nothing was sent for {method:?}"
                );
                assert_eq!(
                    error_of(&answer).code,
                    kr_protocol::error::ErrorCode::UnsupportedCapability,
                    "{answer:?}"
                );
            }
        }
        world.serving.abort();
    }
}

/// KR-REQ-10.49: a device's retry of a close whose answer a worker of an earlier build kept is
/// refused by name, and the daemon settles the kept answer first, as it settles one given now: the
/// worker keeps the answer whole, which the daemon uses for its own record and does not show. The
/// refusal says the host holds the answer and that a close under a new action identifier stops the
/// session, and never that the first close did not happen. The control, a worker that holds
/// results to a scope, answers the retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_retried_close_at_an_earlier_worker_is_settled_and_refused_by_name() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::session::SessionState;

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [false, true] {
        let script = Scripted::new();
        if !holds {
            script.built_before_results_were_held_to_scopes();
        }
        let world = scripted::scripted(&script).await;
        script.refuse_reads(true);
        let world = scripted::restarted(world).await;
        let controller = &world.controller;
        let connection =
            super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 33));
        let close = fake::close_request(world.environment_id, world.session_id);
        assert!(
            connection
                .claim_route(&close, Some(world.session_id))
                .is_ok(),
            "the route of the close is on record"
        );
        let accepted = script.acceptance(world.session_id);
        script.kept(
            close.action_id,
            ParamsValue::from_typed(&accepted).expect("encodes"),
        );

        let answered = connection
            .answer(ControlFrame::Mutation(Box::new(close)))
            .await
            .expect("the retry is answered");
        if holds {
            let ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            }) = answered.frame()
            else {
                panic!(
                    "a worker that holds results to a scope answers: {:?}",
                    answered.frame()
                );
            };
        } else {
            let error = error_of(answered.frame());
            assert_eq!(
                error.code,
                kr_protocol::error::ErrorCode::UnsupportedCapability,
                "{error}"
            );
            assert!(
                error.message.contains("holds what this action produced"),
                "{error}"
            );
            assert!(error.message.contains("new action identifier"), "{error}");
            assert!(!error.message.contains("not done"), "{error}");
        }

        // Either way the daemon kept what the worker said of the session, so a read answers
        // closing once the worker has stopped answering.
        let (_arrived, go) = script.end_at_next_read();
        drop(go);
        let read = scripted::read(&world)
            .await
            .expect("a closing session is answered from the acceptance the worker kept");
        assert_eq!(Some(read.session), accepted.session, "{holds}");
        assert_eq!(
            scripted::list(&world, false).await,
            vec![(world.session_id, SessionState::Closing)]
        );
        world.serving.abort();
    }
}

/// KR-REQ-10.49: the receipt a worker of an earlier build keeps for a refused action holds no
/// result and an error whose text it did not hold to anything, and a device is not shown it: the
/// retry is refused by name, with none of the worker's words in it. A worker that holds results to
/// a scope is the control: it answers with the receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_49_a_receipt_an_earlier_worker_kept_is_not_shown_to_a_device() {
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::rights::ActionRight;

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [false, true] {
        let script = Scripted::new();
        if !holds {
            script.built_before_results_were_held_to_scopes();
        }
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let connection = super::RemoteConnection::for_test(
            controller,
            paired(controller, 34, |grant| {
                grant.actions = [ActionRight::SessionView, ActionRight::AgentPrompt]
                    .into_iter()
                    .collect();
            }),
        );
        let prompt = device_mutation(
            &world,
            &connection,
            Method::AgentPromptSubmit,
            51,
            ParamsValue::empty(),
        );
        assert!(
            connection
                .claim_route(&prompt, Some(world.session_id))
                .is_ok(),
            "the route of the prompt is on record"
        );
        script.kept_without_a_result(
            prompt.action_id,
            Method::AgentPromptSubmit,
            kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::InvalidArgument,
                "the agent said the prompt quoted /home/person/secret-notes",
            ),
        );
        let answered = connection
            .answer(ControlFrame::Mutation(Box::new(prompt)))
            .await
            .expect("the retry is answered");
        if holds {
            assert!(
                matches!(answered.frame(), ControlFrame::Receipt(_)),
                "{:?}",
                answered.frame()
            );
        } else {
            let error = error_of(answered.frame());
            assert_eq!(
                error.code,
                kr_protocol::error::ErrorCode::UnsupportedCapability,
                "{error}"
            );
            assert!(!error.message.contains("secret-notes"), "{error}");
            assert!(!error.message.contains("the agent said"), "{error}");
        }
        world.serving.abort();
    }
}

/// KR-REQ-23.34: a caller that may close a session and may not read its receipts has the close
/// made, whether or not its route was already on record: section 7 lets an authorised stop go
/// ahead, and what a worker answers a retried close with is checked on its way back. The route is
/// recorded before the close is sent, and a link that fails after that leaves a route and no
/// receipt, which is not a reason to refuse a close the caller may make. A close the worker
/// already kept is made again and not shown, and the daemon settles what the worker kept. Both
/// contracts of worker are tried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_a_close_is_made_for_a_caller_that_may_not_read_its_receipt() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for holds in [true, false] {
        for kept in [false, true] {
            let script = Scripted::new();
            if !holds {
                script.built_before_results_were_held_to_scopes();
            }
            let world = scripted::scripted(&script).await;
            script.refuse_reads(true);
            let world = scripted::restarted(world).await;
            let controller = &world.controller;
            let connection = super::RemoteConnection::for_test(
                controller,
                paired(controller, 35, |grant| {
                    grant.actions = [ActionRight::SessionClose].into_iter().collect();
                }),
            );
            let close = device_mutation(
                &world,
                &connection,
                Method::SessionClose,
                1,
                ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
                    session_id: world.session_id,
                })
                .expect("encodes"),
            );
            assert!(
                connection
                    .claim_route(&close, Some(world.session_id))
                    .is_ok(),
                "the route of the close is on record"
            );
            let accepted = script.acceptance(world.session_id);
            if kept {
                script.kept(
                    close.action_id,
                    ParamsValue::from_typed(&accepted).expect("encodes"),
                );
            }
            let answered = connection
                .answer(ControlFrame::Mutation(Box::new(close)))
                .await
                .expect("the close is answered");
            assert_eq!(
                script.forwarded().len(),
                1,
                "the close reaches the worker once, whatever it kept and whatever it holds: \
                 holds {holds}, kept {kept}: {:?}",
                answered.frame()
            );
            if kept {
                let error = error_of(answered.frame());
                assert!(
                    matches!(
                        error.code,
                        kr_protocol::error::ErrorCode::PermissionDenied
                            | kr_protocol::error::ErrorCode::UnsupportedCapability
                    ),
                    "{error}"
                );
                // What it kept is settled all the same.
                let (_arrived, go) = script.end_at_next_read();
                drop(go);
                let read = scripted::read(&world)
                    .await
                    .expect("a closing session is answered from the acceptance the worker kept");
                assert_eq!(Some(read.session), accepted.session);
                assert_eq!(
                    scripted::list(&world, false).await,
                    vec![(world.session_id, SessionState::Closing)]
                );
            } else {
                let ControlFrame::Response(Response {
                    outcome: Outcome::Ok(value),
                    ..
                }) = answered.frame()
                else {
                    panic!("the close is made: {:?}", answered.frame());
                };
                let made: SessionCloseResult = value.to_typed().expect("a close answer");
                assert_eq!(made.state, SessionState::Closing);
            }
            world.serving.abort();
        }
    }
}

/// KR-REQ-23.34: a retained answer of this daemon's own is written under the read that is its
/// authority. A mutation that names a session is decided as a read of a receipt over that session,
/// which needs `session.view`; a create, whose request names none, is decided over the session its
/// answer names; an owner confirmation's challenge is decided under the right to read challenges,
/// which is `host.manage`; and an answer about the environment is left under the decision its own
/// right gave, which goes on checking where the answer is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_a_retained_answer_of_the_daemons_own_is_decided_as_the_read_it_is() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::rights::ActionRight;

    use crate::service::a_close_a_worker_never_answers as fake;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let with = |byte: u8, actions: &[ActionRight]| {
        super::RemoteConnection::for_test(
            controller,
            paired(controller, byte, |grant| {
                grant.actions = actions.iter().copied().collect();
            }),
        )
    };
    let viewer = with(61, &[ActionRight::SessionView]);
    let blind = with(62, &[ActionRight::SessionRename]);
    let owner = with(63, &[ActionRight::HostManage]);
    let nothing_to_manage = with(64, &[ActionRight::SessionView]);
    let on_the_session = |connection: &super::RemoteConnection, method: Method| {
        device_mutation(&world, connection, method, 71, ParamsValue::empty())
    };
    let empty = ControlFrame::Response(Response {
        request_id: RequestId::new(71),
        outcome: Outcome::Ok(ParamsValue::empty()),
    });

    // A mutation that names a session: a rename, a review, a visit.
    for method in [
        Method::SessionRename,
        Method::ReviewAcknowledge,
        Method::VisitAcknowledge,
    ] {
        let read = viewer
            .read_of_retained(method, &on_the_session(&viewer, method), &empty)
            .expect("a device that may view is answered")
            .expect("under the read of the receipt");
        assert_eq!(read.shown_as, method);
        let denied = blind
            .read_of_retained(method, &on_the_session(&blind, method), &empty)
            .expect_err("a device that may not view is not");
        assert_eq!(denied.code, kr_protocol::error::ErrorCode::PermissionDenied);
    }

    // A create names no session in its request, and the answer names the one it made.
    let mut create = on_the_session(&viewer, Method::SessionCreate);
    create.target.session_id = Nullable::null();
    let made = ControlFrame::Response(Response {
        request_id: RequestId::new(71),
        outcome: Outcome::Ok(
            ParamsValue::from_typed(&kr_protocol::session::SessionCreateResult {
                session: crate::service::a_close_a_worker_never_answers::read_result(
                    world.session_id,
                )
                .session,
                endpoint: Nullable::null(),
                deduplicated: true,
                presentation_error: Nullable::null(),
            })
            .expect("encodes"),
        ),
    });
    assert!(
        viewer
            .read_of_retained(Method::SessionCreate, &create, &made)
            .expect("answered")
            .is_some(),
        "decided over the session the create made"
    );
    assert!(
        blind
            .read_of_retained(Method::SessionCreate, &create, &made)
            .is_err(),
        "and refused to a device that may not view it"
    );

    // An owner confirmation's challenge: the right to read the challenges.
    for method in [
        Method::OwnerConfirmationRequest,
        Method::OwnerConfirmationComplete,
    ] {
        let mut asked = on_the_session(&owner, method);
        asked.target.session_id = Nullable::null();
        let read = owner
            .read_of_retained(method, &asked, &empty)
            .expect("a device that may manage the host is shown its challenge")
            .expect("under the read of the challenges");
        assert_eq!(read.shown_as, method);
        let mut refused = on_the_session(&nothing_to_manage, method);
        refused.target.session_id = Nullable::null();
        let denied = nothing_to_manage
            .read_of_retained(method, &refused, &empty)
            .expect_err("a device that no longer holds the right is not");
        assert_eq!(denied.code, kr_protocol::error::ErrorCode::PermissionDenied);

        // Whatever session the record's target names, which an owner confirmation is not
        // admitted with now but a record kept before that may carry: a device that may view
        // that session and no longer manages the host is not shown its challenge.
        let named = on_the_session(&nothing_to_manage, method);
        assert!(named.target.session_id.is_present());
        let denied = nothing_to_manage
            .read_of_retained(method, &named, &empty)
            .expect_err("the session its target names does not decide it");
        assert_eq!(denied.code, kr_protocol::error::ErrorCode::PermissionDenied);
        let named = on_the_session(&owner, method);
        let read = owner
            .read_of_retained(method, &named, &empty)
            .expect("a device that may manage the host is shown its challenge")
            .expect("under the read of the challenges");
        assert_eq!(read.shown_as, method);
    }

    // An answer about the environment stays under the decision its own right gave.
    let mut environment = on_the_session(&owner, Method::CatalogueAdd);
    environment.target.session_id = Nullable::null();
    assert!(
        owner
            .read_of_retained(Method::CatalogueAdd, &environment, &empty)
            .expect("no read is asked of it")
            .is_none()
    );
}

/// KR-REQ-23.34: an owner confirmation acts on this host and names no session at a paired door, as
/// it names none at the local one, so a request that names one is refused before it is decided
/// and cannot be kept with a target its retried answer would be decided over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_an_owner_confirmation_names_no_session_at_a_paired_door() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};
    use kr_protocol::rights::ActionRight;

    use crate::service::a_close_a_worker_never_answers as fake;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let connection = super::RemoteConnection::for_test(
        controller,
        paired(controller, 66, |grant| {
            grant.actions = [ActionRight::HostManage, ActionRight::SessionView]
                .into_iter()
                .collect();
        }),
    );
    for method in [
        Method::OwnerConfirmationRequest,
        Method::OwnerConfirmationComplete,
    ] {
        let named = device_mutation(&world, &connection, method, 72, ParamsValue::empty());
        assert!(named.target.session_id.is_present());
        let answered = connection
            .answer(ControlFrame::Mutation(Box::new(named)))
            .await
            .expect("answered");
        let ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) = answered.frame()
        else {
            panic!("{method:?} with a session in its target is refused: {answered:?}");
        };
        assert_eq!(
            error.code,
            kr_protocol::error::ErrorCode::InvalidArgument,
            "{method:?}: {error}"
        );
        assert!(error.message.contains("names no session"), "{error}");
    }
}

/// KR-REQ-23.34: an `action.read` that names an action only is about the session the daemon
/// recorded the action's route to, which is the subject the read is decided over and the authority
/// its answer is written under. One that names a session is about that session, and one for an
/// action this host holds no route for is about none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_an_action_read_by_identifier_is_about_the_session_its_route_names() {
    use crate::service::a_close_a_worker_never_answers as fake;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 65));
    let read =
        |action_id: ActionId, session_id: Option<SessionId>| kr_protocol::envelope::Request {
            request_id: RequestId::new(5),
            method: Method::ActionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id,
            })
            .expect("encodes"),
        };
    let close = fake::close_request(world.environment_id, world.session_id);
    assert_eq!(
        connection.receipt_session(&read(close.action_id, None)),
        None,
        "an action this host holds no route for is about no session"
    );
    assert!(
        connection
            .claim_route(&close, Some(world.session_id))
            .is_ok(),
        "the route of the close is on record"
    );
    assert_eq!(
        connection.receipt_session(&read(close.action_id, None)),
        Some(world.session_id),
        "the route names the session the action was performed on"
    );
    let other = SessionId::new(kr_ipc::new_uuid());
    assert_eq!(
        connection.receipt_session(&read(close.action_id, Some(other))),
        Some(other),
        "a read that names a session is about it"
    );
}

/// KR-REQ-23.34: a device that may not read a session's receipts is refused its retry of an action
/// other than a close, and nothing reaches the worker: only a close is made for a caller that may
/// not read what it produced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_a_retry_of_an_action_other_than_a_close_is_refused_to_a_caller_that_may_not_view()
 {
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::rights::ActionRight;

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    let connection = super::RemoteConnection::for_test(
        controller,
        paired(controller, 66, |grant| {
            grant.actions = [ActionRight::AgentPrompt].into_iter().collect();
        }),
    );
    let prompt = device_mutation(
        &world,
        &connection,
        Method::AgentPromptSubmit,
        52,
        ParamsValue::empty(),
    );
    assert!(
        connection
            .claim_route(&prompt, Some(world.session_id))
            .is_ok(),
        "the route of the prompt is on record"
    );
    script.kept_without_a_result(
        prompt.action_id,
        Method::AgentPromptSubmit,
        kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::InvalidArgument,
            "the agent said the prompt quoted /home/person/secret-notes",
        ),
    );
    let answered = connection
        .answer(ControlFrame::Mutation(Box::new(prompt)))
        .await
        .expect("the retry is answered");
    let error = error_of(answered.frame());
    assert_eq!(
        error.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{error}"
    );
    assert!(!error.message.contains("secret-notes"), "{error}");
    assert_eq!(script.forwarded().len(), 0, "nothing reached the worker");
    world.serving.abort();
}

/// KR-REQ-23.34: a retried close of a session this daemon recorded the closure of is answered from
/// that record, which no worker gave and which therefore is not a worker's whole answer: it is the
/// daemon's own, and a device that may read it is shown it, whichever contract the session's worker
/// kept. It carries no description, because no worker is left to describe the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_34_a_close_answered_from_the_closure_record_is_the_daemons_own() {
    use kr_protocol::rights::ActionRight;
    use kr_protocol::session::{SessionCloseResult, SessionState};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    script.built_before_results_were_held_to_scopes();
    let world = scripted::scripted(&script).await;
    let controller = &world.controller;
    controller
        .registry
        .lock()
        .await
        .record_closure(&scripted::closure_of(world.session_id))
        .expect("the closure is recorded");
    controller.directory.lock().await.remove(world.session_id);
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 67));

    let closed = close_for_a_device(
        &world,
        &connection,
        &fake::close_request(world.environment_id, world.session_id),
        &[ActionRight::SessionView, ActionRight::SessionClose],
    )
    .await;
    assert_eq!(closed.retained, crate::service::net::Retained::Record);
    let answer: SessionCloseResult = closed.value.to_typed().expect("a close answer");
    assert_eq!(answer.state, SessionState::Closed);
    assert!(answer.session.is_none(), "no worker is left to describe it");
    assert_eq!(script.forwarded().len(), 0, "no worker was asked");
    world.serving.abort();
}

/// A device whose pairing grant carries `session.view` and no voice right, and a voice grant of its
/// own that stands until `expires_at_ms` in UTC. Returns the device.
fn paired_with_a_voice_grant_until(
    controller: &crate::service::Controller,
    byte: u8,
    expires_at_ms: u64,
) -> crate::service::net::devices::DeviceRecord {
    use kr_protocol::rights::ActionRight;

    let device = paired(controller, byte, |grant| {
        grant.actions = [ActionRight::SessionView].into_iter().collect();
    });
    let voice_grant = kr_protocol::grant::Grant {
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id: controller.sharing().host_device_id(),
        actions: [ActionRight::VoiceUse, ActionRight::SessionView]
            .into_iter()
            .collect(),
        expiry: kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires_at_ms),
        },
        ..device.grant.clone()
    };
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: voice_grant,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a live voice grant");
    device
}

/// KR-REQ-09.09: a voice grant that ran out stays out when this host's wall clock is wound back,
/// because the lapse is decided on the reading this host's floor holds and not on the raw clock.
/// The control: the same grant is held while the clock has not reached its expiry, and the
/// method that needs it is decided with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_grant_that_ran_out_does_not_come_back_when_the_wall_clock_is_wound_back() {
    use std::sync::atomic::Ordering;

    use kr_protocol::rights::ActionRight;

    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
    let controller = crate::service::net::tests::daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired_with_a_voice_grant_until(&controller, 31, now + 60_000);
    let connection = super::RemoteConnection::for_test(&controller, device);
    let entry = Method::VoiceStart.entry();
    let decides_with_voice = || {
        connection
            .check_grant(None, entry, false)
            .map(|decision| {
                decision
                    .decided
                    .permitted
                    .rights
                    .contains(&ActionRight::VoiceUse)
            })
            .map_err(|error| error.message)
    };

    assert_eq!(
        decides_with_voice(),
        Ok(true),
        "the voice grant stands until it expires"
    );

    // Past its expiry: this host's reading raises the floor, and the grant is out.
    wall.store(now + 120_000, Ordering::SeqCst);
    let refused = decides_with_voice().expect_err("a voice grant that ran out holds nothing");
    assert!(refused.contains("voice"), "{refused}");

    // Wound back to before the expiry: the floor holds the reading, so the grant stays out.
    wall.store(now + 10_000, Ordering::SeqCst);
    let refused = decides_with_voice().expect_err("a clock wound back does not lend it a life");
    assert!(refused.contains("voice"), "{refused}");
}

/// KR-REQ-09.09: while the floor an end of the voice grant was found on is not on record, the
/// method that needs it is refused as the floor's own refusal, and not as a device that holds no
/// voice grant: a daemon started in a new boot could decide the other way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_grant_whose_end_is_not_on_record_is_refused_as_unrecorded() {
    use std::sync::atomic::Ordering;

    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
    let controller = crate::service::net::tests::daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired_with_a_voice_grant_until(&controller, 32, now + 60_000);
    let connection = super::RemoteConnection::for_test(&controller, device);
    let entry = Method::VoiceStart.entry();
    connection
        .check_grant(None, entry, false)
        .expect("the voice grant stands until it expires");

    // The store takes no record of an expiry, as on a full disk.
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_expiry BEFORE UPDATE ON grants
             WHEN NEW.expired_at_ms IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    wall.store(now + 120_000, Ordering::SeqCst);
    let refused = connection
        .check_grant(None, entry, false)
        .expect_err("a lapse this host cannot record is not stated");
    assert_eq!(
        refused.message,
        crate::grants::Refusal::FloorUnrecorded.detail(),
        "{refused:?}"
    );
    registry
        .execute_batch("DROP TRIGGER refuse_expiry;")
        .expect("the fault is cleared");
}

/// KR-REQ-09.12: a device's retry that the worker answers from the receipt it kept goes back only
/// under the admission asked after that lookup, which the worker's own answer waits for. A fence
/// this host comes to owe while the lookup is under way stops the answer.
///
/// The retry is stopped at the place its answer has been found and has not been given, so the
/// fence lands there and not before: the admission the retry arrived under stood when the lookup
/// began, which is what a check made before the lookup would have asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_answered_from_the_workers_receipt_is_refused_when_a_fence_lands_during_the_lookup()
{
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    use crate::service::a_close_a_worker_never_answers as fake;
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    let script = Scripted::new();
    let world = scripted::scripted(&script).await;
    script.refuse_reads(true);
    let world = scripted::restarted(world).await;
    let controller = &world.controller;
    let connection =
        super::RemoteConnection::for_test(controller, closing_and_viewing(controller, 24));
    let close = fake::close_request(world.environment_id, world.session_id);
    assert!(
        connection
            .claim_route(&close, Some(world.session_id))
            .is_ok(),
        "the route of the close is on record"
    );
    let accepted = script.acceptance(world.session_id);
    script.kept(
        close.action_id,
        ParamsValue::from_typed(&accepted).expect("encodes"),
    );

    let (arrived, release) = controller.pause_retained_lookup();
    let (answered, ()) = tokio::join!(
        connection.answer(ControlFrame::Mutation(Box::new(close))),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
                .await
                .expect("the retry reaches the place it is stopped at")
                .expect("the pause is armed");
            controller.hold_fence(true);
            release.send(()).expect("the retry goes on");
        }
    );
    let answered = answered.expect("the retry is answered");
    let ControlFrame::Response(Response {
        outcome: Outcome::Error(refused),
        ..
    }) = answered.frame()
    else {
        panic!(
            "a fence owed while the receipt was found stops the answer: {:?}",
            answered.frame()
        );
    };
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(refused.message.contains("fence"), "{refused:?}");
    world.serving.abort();
}
