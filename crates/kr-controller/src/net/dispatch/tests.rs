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
        super::claims_geometry(&attach(true, &[])),
        "the flag that registers a claim is a claim"
    );
    assert!(
        !super::claims_geometry(&attach(false, &[AttachmentCapability::Geometry])),
        "asking for the capability is a request the host intersects, not a claim"
    );
    assert!(
        !super::claims_geometry(&attach(
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
    let mut client = controller
        .worker_client(&world.worker)
        .await
        .expect("the daemon's own link");
    let link = client.as_mut().expect("the connection is open");
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
            })))
            .await;
        assert!(
            written.is_err(),
            "a frame carrying voice.use is not encoded, however it is built and sent"
        );
    }
    drop(client);
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
        if super::DeviceRead::of(*method).is_some() != admitted {
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

/// `question.read` from a paired device is answered by the worker of the session it names,
/// which is asked under the device's own envelope. What comes back is narrowed to the grant's
/// history scope: a question the grant names explicitly, and any asked at or after the moment
/// the grant reaches back to. A question the device names that the scope does not reach is
/// refused rather than answered empty, and a grant that retains no history and names no
/// question reads none. A device whose grant does not admit the session is refused before
/// anything reaches the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_the_questions_its_grant_reaches_from_the_sessions_worker() {
    use std::sync::Arc;

    use kr_protocol::actor::ActorIngress;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::QuestionId;
    use kr_protocol::question::{QuestionReadParams, QuestionReadResult};

    use crate::service::a_close_a_worker_never_answers as fake;

    // Three questions the session's worker holds: two asked before the moment the grant
    // reaches back to, one of which the grant names, and one asked after it.
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
        reads_scopes(),
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

    // A device that sees this session, reaching back to 2 000 and naming one earlier question.
    let reaching = paired(controller, 10, |grant| {
        grant.history.lower_bound_ms =
            Nullable::some(kr_protocol::scalars::TimestampMs::new(2_000));
        grant.history.named_questions = [question(NAMED)].into_iter().collect();
    });
    let connection = super::RemoteConnection::for_test(controller, reaching.clone());
    assert_eq!(
        shown(connection.read(&read(1, None)).await),
        vec![question(NAMED), question(LATER)],
        "the question the grant names and the one asked after its lower bound, and not the one \
         asked before it"
    );
    assert_eq!(
        shown(connection.read(&read(2, Some(question(NAMED)))).await),
        vec![question(NAMED)]
    );
    let hidden = refusal(connection.read(&read(3, Some(question(EARLIER)))).await);
    assert_eq!(hidden.code, ErrorCode::PermissionDenied, "{hidden:?}");

    // Each read reached the worker, and under this device's own envelope.
    let forwarded = forwarded_reads(&recorded);
    assert_eq!(forwarded.len(), 3, "{forwarded:?}");
    for read in &forwarded {
        assert_eq!(read.request.method, Method::QuestionRead.into());
        assert_eq!(read.actor.ingress, ActorIngress::PairedDevice);
        assert_eq!(read.actor.device_id, Nullable::some(reaching.device_id));
        assert_eq!(read.actor.grant_id, Nullable::some(reaching.grant.grant_id));
    }

    // A grant that retains no history and names no question reads none of them.
    let current_only = paired(controller, 11, |_| {});
    let connection = super::RemoteConnection::for_test(controller, current_only);
    assert!(shown(connection.read(&read(4, None)).await).is_empty());
    assert_eq!(forwarded_reads(&recorded).len(), 4);

    // A device whose grant sees another session is refused, and nothing reaches the worker.
    let elsewhere = paired(controller, 12, |grant| {
        grant.session_selector = kr_protocol::grant::SessionSelector::These {
            session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
        };
    });
    let connection = super::RemoteConnection::for_test(controller, elsewhere);
    let outside = refusal(connection.read(&read(5, None)).await);
    assert_eq!(outside.code, ErrorCode::PermissionDenied, "{outside:?}");
    assert_eq!(
        forwarded_reads(&recorded).len(),
        4,
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
