//! What version 1 does not offer an agent.
//!
//! Section 19 keeps stable session identifiers, event cursors, binding revisions, typed actions and
//! scoped grants as extension points for a later release, and says version 1 neither advertises
//! nor implements agent capabilities for live-session discovery or observation, previous-session
//! search, messages or swarm orchestration. The method table is the whole of what a host answers,
//! so what an agent can reach through the protocol is a property of that table, and these tests
//! read it.
//!
//! An agent's own authority in the table is the verified originating application and its caller
//! token on private IPC. Arbitrary code running under the same operating-system account remains
//! part of that account's trust boundary, as section 11 says; what is checked here is that nothing
//! is offered to an agent as an agent.

use std::collections::BTreeSet;

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{RequiredAuthority, ResourceSelectorKind};
use kr_protocol::method::{MethodGroup, REGISTRY};

/// KR-REQ-19.07: the method table declares the caller authority a process inside a session can
/// hold for two private groups and nothing else: the four question-source methods an agent's
/// helper uses, and the root shell's own editor bridge. Every one is local IPC only, and each
/// names one session, one question or one attachment rather than a listing or a search, so the
/// table offers an agent no method that enumerates sessions. That a helper's calls reach only the
/// session it runs in is the host's to enforce, and the contact tests exercise it with two
/// sessions.
#[test]
fn the_caller_authority_is_declared_for_single_session_methods_only() {
    let sourced: BTreeSet<&str> = REGISTRY
        .iter()
        .filter(|entry| {
            entry
                .required_rights
                .iter()
                .any(|required| required.authority == RequiredAuthority::LocalCallerToken)
        })
        .map(|entry| entry.name)
        .collect();
    let private: BTreeSet<&str> = REGISTRY
        .iter()
        .filter(|entry| {
            matches!(
                entry.group,
                MethodGroup::QuestionSource | MethodGroup::RootIntegration
            )
        })
        .map(|entry| entry.name)
        .collect();
    assert_eq!(
        sourced, private,
        "a caller authority reaches the question-source methods and the root shell's bridge only"
    );
    let questions: BTreeSet<&str> = REGISTRY
        .iter()
        .filter(|entry| entry.group == MethodGroup::QuestionSource)
        .map(|entry| entry.name)
        .collect();
    assert_eq!(
        questions,
        BTreeSet::from([
            "question.create",
            "question.read_own",
            "question.cancel_own",
            "alert.create"
        ]),
        "an agent's helper has exactly the four question-source methods"
    );

    for entry in REGISTRY.iter().filter(|entry| sourced.contains(entry.name)) {
        assert_eq!(
            entry.ingress,
            &[ActorIngress::LocalIpc],
            "{} is private IPC only",
            entry.name
        );
        for selector in entry.resource_selectors {
            let own = match entry.group {
                MethodGroup::QuestionSource => matches!(
                    selector,
                    ResourceSelectorKind::Session | ResourceSelectorKind::Question
                ),
                _ => matches!(
                    selector,
                    ResourceSelectorKind::Session | ResourceSelectorKind::Attachment
                ),
            };
            assert!(
                own,
                "{} names {selector:?}, which is not one session or a resource inside one",
                entry.name
            );
        }
    }
}

/// KR-REQ-19.07: the methods a person uses to find and page sessions, `session.list`,
/// `history.page` and `events.subscribe`, need a person's rights and are never reachable under an
/// agent's caller authority, and no method at all is reachable from the plugin runtime. No method
/// name belongs to a family section 19 keeps out of version 1; that part reads names, so it catches
/// such a method being added under its obvious name rather than proving there is none.
#[test]
fn no_method_discovers_searches_or_routes_between_agent_sessions() {
    const OUTSIDE_V1: &[&str] = &[
        "search",
        "message",
        "swarm",
        "orchestrat",
        "route",
        "discover",
        "observe",
        "agent.session",
        "agent.history",
        "session.search",
    ];
    for entry in REGISTRY {
        for family in OUTSIDE_V1 {
            assert!(
                !entry.name.contains(family),
                "{} looks like an agent capability section 19 keeps out of version 1",
                entry.name
            );
        }
        assert!(
            !entry.permits_ingress(ActorIngress::Plugin),
            "{} is reachable from the plugin runtime",
            entry.name
        );
    }

    // The human navigation version 1 keeps is a person's, not an agent's: listing sessions and
    // paging a session's history need `session.view` from a paired device or the local owner, or
    // a workflow's own declared grant, and never the caller authority an agent's helper holds.
    for name in ["session.list", "history.page", "events.subscribe"] {
        let entry = REGISTRY
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert!(
            entry
                .required_rights
                .iter()
                .all(|required| required.authority != RequiredAuthority::LocalCallerToken),
            "{name} is not reachable under an agent's caller authority"
        );
        assert!(!entry.permits_ingress(ActorIngress::Plugin));
    }
}
