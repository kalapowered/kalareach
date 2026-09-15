//! Invariants of the method and authority table.

use std::collections::BTreeSet;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{
    AuthorityDecision, CapabilityRequirement, ConfirmationRequirement, DenialReason, EffectClass,
    FreshnessRequirement, HistoryFilter, IdempotencyBehaviour, RequiredAuthority, RightCondition,
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
    assert_eq!(
        REGISTRY.len(),
        required.len(),
        "the registry holds exactly the required methods"
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
fn geometry_claims_are_the_only_conditional_terminal_rights() {
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
            ("pair.status", RightCondition::CandidateEndpoint),
            ("pair.status", RightCondition::IssuingOwner),
            ("session.attach", RightCondition::GeometryClaim),
            ("attachment.configure", RightCondition::GeometryClaim),
            ("action.cancel", RightCondition::OtherActor),
        ]
    );
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
