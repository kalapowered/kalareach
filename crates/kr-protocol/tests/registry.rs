//! Invariants of the method and authority table.

use std::collections::BTreeSet;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{
    AuthorityDecision, CapabilityRequirement, ConfirmationRequirement, DenialReason, EffectClass,
    FreshnessRequirement, HistoryFilter, IdempotencyBehaviour, RequiredAuthority, RequiredRight,
    RightCondition,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::method::{
    Method, MethodGroup, MethodName, MethodVersion, REGISTRY, decide, lookup,
};
use kr_protocol::rights::ActionRight;

#[test]
fn every_method_has_exactly_one_entry_in_declaration_order() {
    assert_eq!(REGISTRY.len(), Method::ALL.len());
    for (index, method) in Method::ALL.iter().enumerate() {
        let entry = &REGISTRY[index];
        assert_eq!(entry.method, *method, "registry order at index {index}");
        assert_eq!(entry.name, method.as_str());
        assert_eq!(entry.group, method.group());
        assert_eq!(method.entry().name, method.as_str());
    }
}

#[test]
fn method_names_are_unique_and_well_formed() {
    let mut seen = BTreeSet::new();
    for method in Method::ALL {
        let name = method.as_str();
        assert!(seen.insert(name), "duplicate method name {name}");
        let parsed = MethodName::new(name).unwrap_or_else(|_| panic!("{name} is not well formed"));
        assert_eq!(parsed.method(), Some(*method));
        assert_eq!(Method::from_wire(name), Some(*method));
    }
}

#[test]
fn every_group_in_the_specification_table_has_methods() {
    let groups: BTreeSet<MethodGroup> = Method::ALL.iter().map(|method| method.group()).collect();
    for group in [
        MethodGroup::HostAndEnvironment,
        MethodGroup::Pairing,
        MethodGroup::Devices,
        MethodGroup::PluginCatalogues,
        MethodGroup::Plugins,
        MethodGroup::PluginActions,
        MethodGroup::QuestionSource,
        MethodGroup::QuestionUserInterface,
        MethodGroup::SkillSetup,
        MethodGroup::Sessions,
        MethodGroup::Attachments,
        MethodGroup::Input,
        MethodGroup::RootIntegration,
        MethodGroup::ShellLaunch,
        MethodGroup::AgentState,
        MethodGroup::AgentMutations,
        MethodGroup::DraftsAndMedia,
        MethodGroup::ProjectRepositories,
        MethodGroup::Workspaces,
        MethodGroup::ChangesAndDiffs,
        MethodGroup::ReviewAndAttention,
        MethodGroup::PendingActionControl,
        MethodGroup::OwnerConfirmation,
        MethodGroup::StateRecovery,
        MethodGroup::Sharing,
        MethodGroup::Services,
        MethodGroup::Voice,
        MethodGroup::Automation,
    ] {
        assert!(groups.contains(&group), "no methods in {group:?}");
    }
    assert_eq!(groups.len(), 28, "the specification lists 28 method groups");
}

#[test]
fn the_required_methods_of_the_specification_table_are_all_listed() {
    // Every method named in the section 23 method-groups table, plus the transfer methods named in
    // section 14 under "upload/download methods".
    let required = [
        "host.info",
        "environment.list",
        "environment.capabilities",
        "host.doctor",
        "pair.invite",
        "pair.redeem",
        "pair.finish",
        "pair.confirm",
        "pair.cancel",
        "pair.status",
        "device.list",
        "device.revoke",
        "device.preview_key.update",
        "catalogue.list",
        "catalogue.add",
        "catalogue.sync",
        "catalogue.pin",
        "catalogue.remove",
        "plugin.list",
        "plugin.install",
        "plugin.remove",
        "plugin.pin",
        "plugin.enable",
        "plugin.disable",
        "plugin.grant",
        "plugin.capabilities",
        "plugin.action.invoke",
        "question.create",
        "question.read_own",
        "question.cancel_own",
        "alert.create",
        "question.read",
        "question.answer",
        "question.cancel",
        "agent_tools.install",
        "agent_tools.status",
        "agent_tools.remove",
        "session.list",
        "session.create",
        "session.read",
        "session.close",
        "session.describe",
        "session.rename",
        "session.attach",
        "session.detach",
        "attachment.configure",
        "attachment.viewport",
        "terminal.resize",
        "terminal.geometry.transfer",
        "terminal.palette.set",
        "input.acquire",
        "input.release",
        "input.interrupt",
        "input.write",
        "root.editor.enter",
        "root.editor.leave",
        "root.editor.fence",
        "root.eof.detach",
        "root.command.accepted",
        "shell.launch",
        "agent.capabilities",
        "agent.snapshot",
        "agent.commands",
        "agent.prompt.submit",
        "agent.prompt.queue",
        "agent.turn.steer",
        "agent.turn.cancel",
        "agent.approval.respond",
        "draft.create",
        "draft.update",
        "agent.draft.add_attachment",
        "upload.begin",
        "upload.status",
        "upload.chunk",
        "upload.finish",
        "upload.cancel",
        "download.begin",
        "download.chunk",
        "project.list",
        "project.read",
        "project.init",
        "project.clone",
        "project.adopt",
        "project.operation.cancel",
        "workspace.list",
        "workspace.create",
        "workspace.read",
        "workspace.remove",
        "diff.read",
        "diff.apply",
        "diff.revert",
        "changeset.capture",
        "changeset.read",
        "changeset.materialize",
        "review.read",
        "review.acknowledge",
        "attention.read",
        "attention.acknowledge",
        "visit.acknowledge",
        "action.cancel",
        "owner.confirmation.request",
        "owner.confirmation.complete",
        "events.subscribe",
        "events.snapshot",
        "history.page",
        "action.read",
        "grant.create",
        "grant.revoke",
        "grant.list",
        "push.installation.register",
        "push.sender.issue",
        "push.sender.renew",
        "push.sender.revoke",
        "mailbox.read",
        "authority.sync",
        "sync.compare_exchange",
        "backup.manifest",
        "voice.start",
        "voice.stop",
        "voice.grant",
        "voice.delegate",
        "voice.context",
        "workflow.install",
        "workflow.enable",
        "workflow.pause",
        "workflow.run",
        "workflow.read",
    ];
    for name in required {
        assert!(
            lookup(name).is_some(),
            "{name} is missing from the registry"
        );
    }

    // Section 23's table is the minimum public surface, and the entries below are the whole of
    // what this build adds to it. Each is a managed-service method whose credential names the
    // method it was signed for, so a surface section 17 describes and section 23's table does not
    // list still needs an entry here: without one there is no name to sign, and a signature made
    // for one operation would serve for another. Section 23 also requires each effect to carry its
    // own exhaustive entry with its own effect class, so a write never travels under a read entry:
    // the mailbox is written and acknowledged as well as read, and managed storage reads objects
    // and its own status apart from everything it writes. Every other method is the
    // specification's own; a further addition changes this list and is noticed here.
    let added = [
        ("mailbox.deliver", EffectClass::Write),
        ("mailbox.acknowledge", EffectClass::Write),
        ("storage.status", EffectClass::Read),
        ("storage.retention.set", EffectClass::Write),
        ("storage.upload.create", EffectClass::Write),
        ("storage.upload.part", EffectClass::Write),
        ("storage.upload.complete", EffectClass::Write),
        ("storage.upload.abort", EffectClass::Write),
        ("storage.object.read", EffectClass::Read),
        ("storage.object.delete", EffectClass::Write),
    ];
    for (name, effect) in added {
        let entry = lookup(name).unwrap_or_else(|| panic!("{name} is missing from the registry"));
        assert_eq!(entry.effect, effect, "{name} carries its own effect class");
        assert_eq!(
            entry.group,
            MethodGroup::Services,
            "{name} is a service method"
        );
        assert_eq!(
            entry.freshness,
            FreshnessRequirement::ServiceCredential,
            "{name} is proven by a service credential"
        );
    }

    // Section 25 gives the review and attention group two operations that section 23's row does
    // not name: a quiet-hours window has to be set before it can defer anything, and the
    // changed-since-last-visit view has to be readable without moving the visit cursor that
    // defines it. Both carry their own exhaustive entry under the group's own scoped-view right,
    // and neither can mutate code: section 23's rule for this group is that no review method does,
    // and the rights below are the whole of what they require.
    let attention = [
        ("attention.quiet_hours", EffectClass::Write),
        ("visit.changed", EffectClass::Read),
    ];
    for (name, effect) in attention {
        let entry = lookup(name).unwrap_or_else(|| panic!("{name} is missing from the registry"));
        assert_eq!(entry.effect, effect, "{name} carries its own effect class");
        assert_eq!(
            entry.group,
            MethodGroup::ReviewAndAttention,
            "{name} is a review and attention method"
        );
        assert_eq!(
            entry.required_rights,
            &[RequiredRight::right(ActionRight::SessionView)],
            "{name} asks for scoped view authority and nothing that mutates code"
        );
    }

    assert_eq!(
        REGISTRY.len(),
        required.len() + added.len() + attention.len(),
        "the registry holds the required methods and the named additions"
    );
}

#[test]
fn anything_unlisted_is_denied() {
    for name in [
        "host.shutdown",
        "session.evict",
        "terminal.input",
        "",
        "AGENT.PROMPT.SUBMIT",
    ] {
        assert!(lookup(name).is_none(), "{name} must not be listed");
        assert_eq!(
            decide(name, MethodVersion::V1, ActorIngress::PairedDevice),
            AuthorityDecision::Denied(DenialReason::UnlistedMethod)
        );
    }
    assert_eq!(
        DenialReason::UnlistedMethod.error_code(),
        ErrorCode::PermissionDenied
    );
}

#[test]
fn an_unsupported_method_version_is_a_schema_failure() {
    let decision = decide("host.info", MethodVersion(2), ActorIngress::PairedDevice);
    assert_eq!(
        decision,
        AuthorityDecision::Denied(DenialReason::UnsupportedVersion {
            supported: MethodVersion::V1
        })
    );
    assert_eq!(
        DenialReason::UnsupportedVersion {
            supported: MethodVersion::V1
        }
        .error_code(),
        ErrorCode::UnsupportedSchema
    );
}

#[test]
fn private_ipc_groups_are_unreachable_from_the_network_or_a_plugin() {
    for entry in REGISTRY {
        if matches!(
            entry.group,
            MethodGroup::RootIntegration | MethodGroup::QuestionSource
        ) {
            assert_eq!(
                entry.ingress,
                &[ActorIngress::LocalIpc],
                "{} must be private IPC only",
                entry.name
            );
        }
        assert!(
            !entry.permits_ingress(ActorIngress::Plugin),
            "{} must not be reachable from the plugin runtime; plugin effects carry their own \
             authority entries",
            entry.name
        );
    }
    for name in [
        "root.editor.enter",
        "root.editor.leave",
        "root.editor.fence",
        "root.eof.detach",
        "root.command.accepted",
        "question.create",
        "question.read_own",
        "question.cancel_own",
        "alert.create",
    ] {
        let entry = lookup(name).expect("listed");
        assert_eq!(
            decide(name, MethodVersion::V1, ActorIngress::PairedDevice),
            AuthorityDecision::Denied(DenialReason::ForbiddenIngress {
                ingress: ActorIngress::PairedDevice
            }),
            "{name} must reject a network caller"
        );
        assert!(entry.permits_ingress(ActorIngress::LocalIpc));
    }
}

#[test]
fn only_the_pre_authorisation_pairing_surface_accepts_an_unpaired_peer() {
    let open: Vec<&str> = REGISTRY
        .iter()
        .filter(|entry| entry.permits_ingress(ActorIngress::UnpairedPeer))
        .map(|entry| entry.name)
        .collect();
    assert_eq!(open, ["pair.redeem", "pair.finish", "pair.status"]);
}

#[test]
fn reads_and_writes_carry_the_freshness_and_idempotency_their_class_requires() {
    for entry in REGISTRY {
        match entry.effect {
            EffectClass::Read => {
                assert!(
                    matches!(
                        entry.idempotency,
                        IdempotencyBehaviour::IdempotentRead | IdempotencyBehaviour::Keyed { .. }
                    ),
                    "{}: a read is idempotent",
                    entry.name
                );
                assert!(
                    matches!(
                        entry.freshness,
                        FreshnessRequirement::CurrentAuthority
                            | FreshnessRequirement::InvitationDeadline
                            | FreshnessRequirement::ServiceCredential
                    ),
                    "{}: a read does not carry an action window",
                    entry.name
                );
                assert_eq!(
                    entry.confirmation,
                    ConfirmationRequirement::None,
                    "{}: a read never requires owner confirmation",
                    entry.name
                );
            }
            EffectClass::Write => {
                assert!(
                    !matches!(entry.idempotency, IdempotencyBehaviour::IdempotentRead),
                    "{}: a write is not an idempotent read",
                    entry.name
                );
                assert!(
                    matches!(
                        entry.freshness,
                        FreshnessRequirement::ActionWindow
                            | FreshnessRequirement::InputLease
                            | FreshnessRequirement::InvitationDeadline
                            | FreshnessRequirement::ServiceCredential
                    ),
                    "{}: a write carries a freshness context",
                    entry.name
                );
            }
        }
    }
}

#[test]
fn only_raw_input_uses_the_ordered_stream_contract() {
    let streamed: Vec<&str> = REGISTRY
        .iter()
        .filter(|entry| matches!(entry.idempotency, IdempotencyBehaviour::OrderedStream))
        .map(|entry| entry.name)
        .collect();
    assert_eq!(streamed, ["input.write"]);
    let entry = lookup("input.write").expect("listed");
    assert_eq!(entry.freshness, FreshnessRequirement::InputLease);
}

#[test]
fn history_bearing_reads_apply_the_grant_filter() {
    for name in [
        "session.read",
        "session.describe",
        "agent.snapshot",
        "events.subscribe",
        "events.snapshot",
        "history.page",
        "diff.read",
        "changeset.read",
        "review.read",
        "attention.read",
        "download.begin",
        "download.chunk",
        "voice.context",
    ] {
        let entry = lookup(name).expect("listed");
        assert_eq!(
            entry.history_filter,
            HistoryFilter::GrantLowerBound,
            "{name} must apply the shared history filter"
        );
    }
    assert_eq!(
        lookup("session.attach").expect("listed").history_filter,
        HistoryFilter::LiveViewOnly
    );
    assert_eq!(
        lookup("question.read").expect("listed").history_filter,
        HistoryFilter::NamedCurrentResources
    );
}

#[test]
fn every_entry_that_names_a_capability_names_a_revision() {
    for entry in REGISTRY {
        if let CapabilityRequirement::Required { capability_id, .. } = entry.capability {
            assert!(
                !capability_id.is_empty(),
                "{}: capability id is empty",
                entry.name
            );
        }
    }
}

#[test]
fn every_conditional_right_is_one_the_specification_states() {
    let conditional: Vec<(&str, RightCondition)> = REGISTRY
        .iter()
        .flat_map(|entry| {
            entry
                .required_rights
                .iter()
                .filter(|required| required.when != RightCondition::Always)
                .map(move |required| (entry.name, required.when))
        })
        .collect();
    assert_eq!(
        conditional,
        [
            // Either the candidate's transcript proof or the issuing owner's context.
            ("pair.status", RightCondition::CandidateEndpoint),
            ("pair.status", RightCondition::IssuingOwner),
            // A geometry claim needs terminal.geometry; observing does not.
            ("session.attach", RightCondition::GeometryClaim),
            ("attachment.configure", RightCondition::GeometryClaim),
            // Own undispatched intent, or explicit host-owner authority.
            ("action.cancel", RightCondition::OwnSubject),
            ("action.cancel", RightCondition::OtherActor),
            // A device may broaden its own voice grant; another device's needs host.manage.
            ("voice.grant", RightCondition::OwnSubject),
            ("voice.grant", RightCondition::OtherActor),
        ]
    );
}

#[test]
fn a_conditional_pair_is_a_choice_and_not_an_intersection() {
    // OwnSubject and OtherActor are mutually exclusive, so exactly one branch applies to any
    // request. An entry that lists one must list the other, otherwise one case is unauthorised.
    for entry in REGISTRY {
        let has_own = entry
            .required_rights
            .iter()
            .any(|required| required.when == RightCondition::OwnSubject);
        let has_other = entry
            .required_rights
            .iter()
            .any(|required| required.when == RightCondition::OtherActor);
        assert_eq!(has_own, has_other, "{}: one branch is missing", entry.name);

        let has_candidate = entry
            .required_rights
            .iter()
            .any(|required| required.when == RightCondition::CandidateEndpoint);
        let has_issuer = entry
            .required_rights
            .iter()
            .any(|required| required.when == RightCondition::IssuingOwner);
        assert_eq!(
            has_candidate, has_issuer,
            "{}: one pairing branch is missing",
            entry.name
        );
    }
}

#[test]
fn reading_a_retained_receipt_needs_present_view_authority() {
    // Owning an action identifier is not permission to read what the receipt exposes. The
    // requirement resolves against the subject the receipt names, so a receipt for a host effect
    // such as device.revoke is reachable under host scope rather than under session.view.
    let entry = lookup("action.read").expect("listed");
    assert!(
        entry
            .required_rights
            .iter()
            .any(|required| matches!(required.authority, RequiredAuthority::PresentViewAuthority)),
        "action.read must require present view authority"
    );
    assert!(
        !entry
            .unconditional_rights()
            .any(|right| right == ActionRight::SessionView),
        "a receipt for a host effect has no session to view"
    );
    assert!(
        entry
            .resource_selectors
            .contains(&kr_protocol::authority::ResourceSelectorKind::Environment),
        "the subject may be an environment rather than a session"
    );
    assert_eq!(entry.history_filter, HistoryFilter::GrantLowerBound);
}

#[test]
fn sharing_needs_issuer_or_delegation_authority() {
    for name in ["grant.create", "grant.revoke", "grant.list"] {
        let entry = lookup(name).expect("listed");
        assert!(
            entry
                .required_rights
                .iter()
                .any(|required| matches!(required.authority, RequiredAuthority::IssuerDelegation)),
            "{name} must require issuer or delegation authority over the grant itself"
        );
    }
}

#[test]
fn host_management_methods_require_the_host_manage_right() {
    for name in [
        "device.list",
        "device.revoke",
        "catalogue.add",
        "catalogue.sync",
        "catalogue.pin",
        "catalogue.remove",
        "plugin.install",
        "plugin.remove",
        "plugin.pin",
        "plugin.enable",
        "plugin.disable",
        "plugin.grant",
        "agent_tools.install",
        "agent_tools.remove",
    ] {
        let entry = lookup(name).expect("listed");
        assert!(
            entry
                .unconditional_rights()
                .any(|right| right == ActionRight::HostManage),
            "{name} must require host.manage"
        );
    }
}

#[test]
fn owner_confirmation_covers_the_sensitive_operations() {
    for name in [
        "pair.invite",
        "pair.confirm",
        "catalogue.add",
        "plugin.grant",
        "owner.confirmation.complete",
    ] {
        assert_eq!(
            lookup(name).expect("listed").confirmation,
            ConfirmationRequirement::Always,
            "{name} always needs a fresh owner confirmation"
        );
    }
    for name in [
        "grant.create",
        "catalogue.sync",
        "plugin.install",
        "workflow.install",
        "voice.grant",
    ] {
        assert_eq!(
            lookup(name).expect("listed").confirmation,
            ConfirmationRequirement::WhenEnlargingAuthority,
            "{name} needs confirmation when it enlarges authority"
        );
    }
    // Revocation and restriction never need a rights-enlarging confirmation.
    for name in [
        "device.revoke",
        "grant.revoke",
        "session.close",
        "action.cancel",
    ] {
        assert_eq!(
            lookup(name).expect("listed").confirmation,
            ConfirmationRequirement::None,
            "{name} must not require a new confirmation"
        );
    }
}

#[test]
fn service_methods_use_a_service_credential() {
    for entry in REGISTRY {
        if entry.group == MethodGroup::Services {
            assert_eq!(
                entry.ingress,
                &[ActorIngress::ServiceClient],
                "{}",
                entry.name
            );
            assert_eq!(entry.freshness, FreshnessRequirement::ServiceCredential);
            assert!(
                entry.required_rights.iter().any(|required| matches!(
                    required.authority,
                    RequiredAuthority::ServiceCredential
                )),
                "{}: a service method presents a service credential",
                entry.name
            );
        }
    }
}

#[test]
fn voice_methods_require_a_voice_grant() {
    for name in [
        "voice.start",
        "voice.stop",
        "voice.delegate",
        "voice.context",
    ] {
        let entry = lookup(name).expect("listed");
        assert!(
            entry
                .required_rights
                .iter()
                .any(|required| matches!(required.authority, RequiredAuthority::VoiceGrant)),
            "{name} must intersect a voice grant"
        );
    }
}

#[test]
fn a_listed_method_on_a_permitted_ingress_resolves_to_its_entry() {
    let decision = decide(
        "session.read",
        MethodVersion::V1,
        ActorIngress::PairedDevice,
    );
    match decision {
        AuthorityDecision::Listed(entry) => {
            assert_eq!(entry.method, Method::SessionRead);
            assert_eq!(entry.effect, EffectClass::Read);
        }
        AuthorityDecision::Denied(reason) => panic!("unexpected denial: {reason:?}"),
    }
}
