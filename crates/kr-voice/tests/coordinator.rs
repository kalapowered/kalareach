//! The coordinator, driven through its three seams and two providers.
//!
//! No test here makes a live provider call. The provider seam is filled twice — once by a fake
//! managed broker and once by a backend of the person's own — which is what proves the interface
//! stays modular rather than asserting it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.01 | `a_call_runs_on_either_provider_through_one_interface`, `an_unknown_creation_is_a_state_and_leaves_no_grant` |
//! | KR-REQ-15.02 | `stopping_a_voice_session_leaves_the_terminal_sessions_running` |
//! | KR-REQ-15.11 | `a_delegation_runs_under_the_intersection_of_both_grants`, `a_delegation_the_provider_never_announced_is_refused`, `a_delegation_carries_no_task_text` |
//! | KR-REQ-15.13 | `the_five_unlocked_screen_classes_are_refused_without_a_confirmation`, `provider_text_cannot_create_a_confirmation`, `a_confirmation_for_one_action_does_not_authorise_another` |
//! | KR-REQ-15.14 | `stopping_a_voice_session_revokes_its_grant_before_the_broker_is_told` |
//! | KR-REQ-15.17 | `a_result_that_was_admitted_and_not_performed_is_reported_as_admitted` |
//! | KR-REQ-15.20 | `context_selection_uses_the_requesting_devices_scope_and_nothing_wider` |
//! | KR-REQ-15.21 | `the_default_voice_grant_permits_four_things_and_names_them`, `submitting_a_prompt_needs_the_spoken_destination` |
//! | KR-REQ-15.22 | `cancelling_a_turn_needs_the_typed_request_and_the_current_turn` |
//! | KR-REQ-23.51 | `every_voice_method_needs_the_voice_grant` |

use std::sync::{Arc, Mutex};

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceRateQuote, VoiceSession,
    VoiceSessionRequest, VoiceStart, VoiceStartLatency,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ActionId, AgentTurnId, ApprovalRequestId, AuthorityRevision, DeviceId, EnvironmentId, GrantId,
    SessionId, VoiceSessionId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, Nullable, TimestampMs, U64, Uuid,
};
use kr_protocol::voice::{
    SpokenDestination, VerifiedApprovalAnswer, VoiceAction, VoiceActionPlan, VoiceContextClass,
    VoiceContextParams, VoiceDelegateParams, VoiceDelegationId, VoiceDelegationOutcome,
    VoiceGrantParams, VoiceRefusal, VoiceStartOutcome, VoiceStartParams, VoiceStopParams,
};
use kr_voice::seams::{
    ActionSubmitter, ContextItem, ContextRequest, ContextSource, GatheredContext, HostReceipt,
    SelectedItem, VoiceAuthority, VoiceFuture, WithheldRun,
};
use kr_voice::{Coordinator, Proposal, VoiceGrantPlan, sign_confirmation};

// ---------------------------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------------------------

fn device(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn session(byte: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([byte; 16]))
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([0xe0; 16]))
}

fn action(byte: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([byte; 16]))
}

const HOST: u8 = 0xf0;
const PHONE: u8 = 0xf1;
const SESSION_A: u8 = 0xa1;
const SESSION_B: u8 = 0xa2;

// ---------------------------------------------------------------------------------------------
// The host's three seams, filled in memory
// ---------------------------------------------------------------------------------------------

/// A grant store with the cascade the real one has.
#[derive(Debug, Default)]
struct Store {
    grants: Vec<Grant>,
    revoked: Vec<GrantId>,
    revoked_at_ms: Vec<u64>,
    next: u8,
}

#[derive(Debug)]
struct Authority {
    store: Mutex<Store>,
    device_grant: Mutex<Option<Grant>>,
    identity: AuthorisationKey,
}

impl Authority {
    fn new(device_grant: Grant, identity: AuthorisationKey) -> Self {
        Self {
            store: Mutex::new(Store {
                next: 0x10,
                ..Store::default()
            }),
            device_grant: Mutex::new(Some(device_grant)),
            identity,
        }
    }

    /// Narrows the device's ordinary grant, the way revoking and reissuing one does.
    fn narrow_device_grant(&self, actions: &[ActionRight]) {
        let mut held = self.device_grant.lock().expect("the device grant");
        if let Some(grant) = held.as_mut() {
            grant.actions = actions.iter().copied().collect();
        }
    }

    fn is_revoked(&self, grant_id: GrantId) -> bool {
        self.store
            .lock()
            .expect("the store")
            .revoked
            .contains(&grant_id)
    }

    fn revoked_at(&self, grant_id: GrantId) -> Option<u64> {
        let store = self.store.lock().expect("the store");
        store
            .revoked
            .iter()
            .position(|held| *held == grant_id)
            .map(|index| store.revoked_at_ms[index])
    }
}

impl VoiceAuthority for Authority {
    fn device_grant(
        &self,
        device_id: DeviceId,
        session_id: Option<SessionId>,
        _now_ms: u64,
    ) -> kr_voice::Result<Option<Grant>> {
        let held = self.device_grant.lock().expect("the device grant").clone();
        Ok(held.filter(|grant| {
            grant.recipient_device_id == device_id
                && session_id.is_none_or(|id| grant.session_selector.admits(id))
        }))
    }

    fn grant(&self, grant_id: GrantId, _now_ms: u64) -> kr_voice::Result<Option<Grant>> {
        let store = self.store.lock().expect("the store");
        if store.revoked.contains(&grant_id) {
            return Ok(None);
        }
        Ok(store
            .grants
            .iter()
            .find(|grant| grant.grant_id == grant_id)
            .cloned())
    }

    fn standing_voice_grant(
        &self,
        device_id: DeviceId,
        _now_ms: u64,
    ) -> kr_voice::Result<Option<Grant>> {
        let store = self.store.lock().expect("the store");
        Ok(store
            .grants
            .iter()
            .rev()
            .find(|grant| {
                grant.recipient_device_id == device_id
                    && grant.parent_grant_id.0.is_none()
                    && grant.permits(ActionRight::VoiceUse)
                    && !store.revoked.contains(&grant.grant_id)
            })
            .cloned())
    }

    fn issue(&self, plan: &VoiceGrantPlan) -> kr_voice::Result<Grant> {
        let mut store = self.store.lock().expect("the store");
        let grant_id = GrantId::new(Uuid::from_bytes([store.next; 16]));
        store.next = store.next.wrapping_add(1);
        let grant = plan.grant(grant_id);
        store.grants.push(grant.clone());
        Ok(grant)
    }

    fn revoke(&self, grant_id: GrantId, now_ms: u64) -> kr_voice::Result<u64> {
        let mut store = self.store.lock().expect("the store");
        // The cascade: a revoked parent takes its descendants with it.
        let mut going = vec![grant_id];
        let mut index = 0;
        while index < going.len() {
            let parent = going[index];
            let children: Vec<GrantId> = store
                .grants
                .iter()
                .filter(|grant| grant.parent_grant_id.0 == Some(parent))
                .map(|grant| grant.grant_id)
                .collect();
            going.extend(children);
            index += 1;
        }
        for going in going {
            if !store.revoked.contains(&going) {
                store.revoked.push(going);
                store.revoked_at_ms.push(now_ms);
            }
        }
        Ok(now_ms)
    }

    fn device_identity_key(
        &self,
        _device_id: DeviceId,
    ) -> kr_voice::Result<Option<AuthorisationKey>> {
        Ok(Some(self.identity))
    }
}

/// A context source that answers with items it was given, already filtered.
#[derive(Debug)]
struct Context {
    gathered: Mutex<GatheredContext>,
    seen: Mutex<Vec<ContextRequest>>,
    approval: Mutex<Option<(ApprovalRequestId, Digest256)>>,
}

impl Context {
    fn new(gathered: GatheredContext) -> Self {
        Self {
            gathered: Mutex::new(gathered),
            seen: Mutex::new(Vec::new()),
            approval: Mutex::new(None),
        }
    }

    fn holds_approval(&self, approval_request_id: ApprovalRequestId, digest: Digest256) {
        *self.approval.lock().expect("the approval") = Some((approval_request_id, digest));
    }

    fn last_request(&self) -> ContextRequest {
        self.seen
            .lock()
            .expect("what was asked")
            .last()
            .cloned()
            .expect("one gathering")
    }
}

impl ContextSource for Context {
    fn gather<'a>(&'a self, request: &'a ContextRequest) -> VoiceFuture<'a, GatheredContext> {
        self.seen
            .lock()
            .expect("what was asked")
            .push(request.clone());
        let gathered = self.gathered.lock().expect("the content").clone();
        Box::pin(async move { Ok(gathered) })
    }

    fn approval_details<'a>(
        &'a self,
        _session_id: SessionId,
        approval_request_id: &'a ApprovalRequestId,
    ) -> VoiceFuture<'a, Option<Digest256>> {
        let held = self.approval.lock().expect("the approval").clone();
        let approval_request_id = approval_request_id.clone();
        Box::pin(async move {
            Ok(held.and_then(|(held, digest)| (held == approval_request_id).then_some(digest)))
        })
    }
}

/// A submitter that records what it was asked to do.
#[derive(Debug)]
struct Submitter {
    proposals: Mutex<Vec<Proposal>>,
    performed: Mutex<bool>,
}

impl Submitter {
    fn new() -> Self {
        Self {
            proposals: Mutex::new(Vec::new()),
            performed: Mutex::new(true),
        }
    }

    /// Makes the host admit the next proposal without performing it.
    fn admits_without_performing(&self) {
        *self.performed.lock().expect("the flag") = false;
    }

    fn proposals(&self) -> Vec<Proposal> {
        self.proposals.lock().expect("the proposals").clone()
    }
}

impl ActionSubmitter for Submitter {
    fn submit<'a>(&'a self, proposal: &'a Proposal) -> VoiceFuture<'a, HostReceipt> {
        self.proposals
            .lock()
            .expect("the proposals")
            .push(proposal.clone());
        let performed = *self.performed.lock().expect("the flag");
        let action_id = proposal.action_id;
        Box::pin(async move {
            Ok(HostReceipt {
                action_id,
                performed,
                summary: "the host answered".to_owned(),
            })
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Two providers behind one interface
// ---------------------------------------------------------------------------------------------

/// What a fake provider answers a creation with.
#[derive(Clone, Debug)]
enum Answer {
    Started,
    /// The answer an earlier attempt already produced, which the service repeats rather than
    /// starting a second metered call.
    Replayed,
    CreationUnknown,
    Capacity,
}

/// A stand-in for the managed broker. It makes no network call.
#[derive(Debug)]
struct ManagedFake {
    answer: Mutex<Answer>,
    closed: Mutex<Vec<String>>,
    offers: Mutex<Vec<String>>,
}

impl ManagedFake {
    fn new(answer: Answer) -> Self {
        Self {
            answer: Mutex::new(answer),
            closed: Mutex::new(Vec::new()),
            offers: Mutex::new(Vec::new()),
        }
    }

    fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    fn offers(&self) -> Vec<String> {
        self.offers.lock().expect("the offers").clone()
    }
}

fn running_call(name: &str) -> VoiceSession {
    VoiceSession {
        call_id: format!("call-{name}"),
        attempt_id: format!("attempt-{name}"),
        provider_session_id: format!("sess_{name}"),
        answer_sdp: "v=0\r\n".to_owned(),
        model: "gpt-live-1".to_owned(),
        closes_at: "2026-09-20T01:00:00Z".to_owned(),
        reservation_ends_at: "2026-09-20T01:00:15Z".to_owned(),
        control_path: format!("/api/voice/sessions/call-{name}/control"),
        heartbeat_seconds: 20,
        sideband_ready: true,
        hold: VoiceHold {
            reservation_id: "hold-1".to_owned(),
            reserved: "600".to_owned(),
            ceiling: "500".to_owned(),
            deadline: "2026-09-20T01:00:15Z".to_owned(),
        },
        reasoning_hold: None,
        rate: VoiceRateQuote {
            version: "2026-09".to_owned(),
            minor_units_per_second: "1".to_owned(),
            minimum_seconds: 15,
            currency: "USD".to_owned(),
        },
        latency: VoiceStartLatency {
            creation_to_answer_ms: 400,
            sideband_ready_ms: 120,
        },
        replayed: false,
        disclosure: vec!["The managed service can read this call.".to_owned()],
    }
}

impl ManagedVoiceService for ManagedFake {
    fn start<'a>(&'a self, request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        self.offers
            .lock()
            .expect("the offers")
            .push(request.offer_sdp.clone());
        let answer = self.answer.lock().expect("the answer").clone();
        Box::pin(async move {
            Ok(match answer {
                Answer::Started => VoiceStart::Started(Box::new(running_call("managed"))),
                Answer::Replayed => VoiceStart::Started(Box::new(VoiceSession {
                    replayed: true,
                    ..running_call("managed")
                })),
                Answer::CreationUnknown => VoiceStart::CreationUnknown {
                    attempt_id: Some("attempt-unknown".to_owned()),
                    message: "The provider may hold a session for that attempt.".to_owned(),
                },
                Answer::Capacity => {
                    VoiceStart::Refused(Box::new(kr_client::services::voice::VoiceRefusal {
                        reason: kr_client::services::voice::VoiceRefusalReason::ServiceCapacity,
                        message: "Managed capacity is spent.".to_owned(),
                        alternatives: vec!["Use your own provider credential.".to_owned()],
                        attempt_id: None,
                        call_id: None,
                    }))
                }
            })
        })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        self.closed
            .lock()
            .expect("what was closed")
            .push(call_id.to_owned());
        let call_id = call_id.to_owned();
        Box::pin(async move {
            Ok(VoiceClosure {
                call_id,
                state: "finalised".to_owned(),
                usage_seconds: 42,
                usage_provisional: false,
            })
        })
    }
}

/// A backend of the person's own, reached with their own credential.
///
/// It is the second implementation of the same interface, which is what "the provider interface
/// stays modular for BYOK, local voice and other providers" means in practice. Nothing above it
/// knows which one answered.
#[derive(Debug, Default)]
struct OwnBackend {
    closed: Mutex<Vec<String>>,
}

impl ManagedVoiceService for OwnBackend {
    fn start<'a>(&'a self, _request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        Box::pin(async move { Ok(VoiceStart::Started(Box::new(running_call("byok")))) })
    }

    fn close<'a>(&'a self, call_id: &'a str) -> ServiceFuture<'a, VoiceClosure> {
        self.closed
            .lock()
            .expect("what was closed")
            .push(call_id.to_owned());
        let call_id = call_id.to_owned();
        Box::pin(async move {
            Ok(VoiceClosure {
                call_id,
                state: "finalised".to_owned(),
                usage_seconds: 0,
                usage_provisional: true,
            })
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------------

fn device_grant(actions: &[ActionRight]) -> Grant {
    Grant {
        grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: device(HOST),
        recipient_device_id: device(PHONE),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [environment()].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session(SESSION_A), session(SESSION_B)]
                .into_iter()
                .collect(),
        },
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1_000)),
            include_live_screen: true,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

fn gathered() -> GatheredContext {
    GatheredContext {
        session_description: Some(ContextItem::new("the voice coordinator", 2_000)),
        working_directory: Some(ContextItem::new("/work", 2_000)),
        active_application: Some(ContextItem::new("an editor", 2_000)),
        pending_decisions: vec![ContextItem::new("apply the diff?", 2_100)],
        recent_messages: vec![
            ContextItem::new("before the bound", 500),
            ContextItem::new("after the bound", 2_200),
        ],
        selected: vec![SelectedItem {
            class: VoiceContextClass::FileContents,
            item: ContextItem::new("sk-abcdefghijklmnopqrstuvwxyz01 in a file", 2_300),
        }],
        resources: vec!["session:a1".to_owned()],
        withheld: vec![WithheldRun {
            reason: "before the grant's lower bound".to_owned(),
            count: 3,
        }],
    }
}

struct Fixture {
    coordinator: Coordinator,
    authority: Arc<Authority>,
    context: Arc<Context>,
    submitter: Arc<Submitter>,
    broker: Arc<ManagedFake>,
    key: AuthorisationKeyPair,
}

fn fixture_with(actions: &[ActionRight], answer: Answer) -> Fixture {
    let key = AuthorisationKeyPair::generate().expect("a device identity key");
    let authority = Arc::new(Authority::new(device_grant(actions), *key.public()));
    let context = Arc::new(Context::new(gathered()));
    let submitter = Arc::new(Submitter::new());
    let broker = Arc::new(ManagedFake::new(answer));
    let coordinator = Coordinator::new(
        Arc::clone(&context) as Arc<dyn ContextSource>,
        Arc::clone(&authority) as Arc<dyn VoiceAuthority>,
        Arc::clone(&submitter) as Arc<dyn ActionSubmitter>,
        Some(Arc::clone(&broker) as Arc<dyn ManagedVoiceService>),
        device(HOST),
        environment(),
        "https://reach.example",
    );
    Fixture {
        coordinator,
        authority,
        context,
        submitter,
        broker,
        key,
    }
}

fn fixture() -> Fixture {
    fixture_with(
        &[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::AgentCancel,
            ActionRight::AgentApprovalRespond,
            ActionRight::TerminalInput,
            ActionRight::FilesApplyDiff,
            ActionRight::SessionClose,
            ActionRight::SessionShare,
        ],
        Answer::Started,
    )
}

fn grant_params(actions: Option<&[VoiceAction]>) -> VoiceGrantParams {
    VoiceGrantParams {
        device_id: device(PHONE),
        session_ids: [session(SESSION_A)].into_iter().collect(),
        actions: Nullable(actions.map(|actions| actions.iter().copied().collect())),
    }
}

fn start_params() -> VoiceStartParams {
    VoiceStartParams {
        session_ids: [session(SESSION_A)].into_iter().collect(),
        offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
        duration_seconds: 600,
        reasoning_budget_minor: Nullable::some(U64::new(100)),
    }
}

fn delegation(name: &str) -> VoiceDelegationId {
    VoiceDelegationId::new(format!("item_{name}")).expect("an opaque identifier")
}

fn delegate_params(
    voice_session_id: VoiceSessionId,
    delegation_id: VoiceDelegationId,
    voice_action: VoiceAction,
) -> VoiceDelegateParams {
    VoiceDelegateParams {
        voice_session_id,
        delegation_id,
        offset_ms: U64::new(1_000),
        action: voice_action,
        session_id: Nullable::some(session(SESSION_A)),
        spoken_destination: Nullable::null(),
        approval: Nullable::null(),
        turn_id: Nullable::null(),
        confirmation: Nullable::null(),
    }
}

/// Starts a call with `actions` in the standing grant and returns the voice session.
async fn started(fixture: &Fixture, actions: Option<&[VoiceAction]>) -> VoiceSessionId {
    fixture
        .coordinator
        .grant(&grant_params(actions), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect("a call");
    let VoiceStartOutcome::Started { session } = result.outcome else {
        panic!("the call runs");
    };
    session.voice_session_id
}

fn refusal(outcome: &VoiceDelegationOutcome) -> (VoiceRefusal, String) {
    match outcome {
        VoiceDelegationOutcome::Refused { reason, message } => (*reason, message.clone()),
        other => panic!("this delegation is refused, not {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.21: the default voice grant
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.21: the default voice grant permits section 15 ¶13's four actions, the change states
/// which actions it permits, and broadening beyond the device's own grant narrows instead.
#[tokio::test]
async fn the_default_voice_grant_permits_four_things_and_names_them() {
    let fixture = fixture();
    let result = fixture
        .coordinator
        .grant(&grant_params(None), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant");

    let names: Vec<&str> = result
        .statement
        .actions
        .iter()
        .map(|action| action.as_str())
        .collect();
    assert_eq!(names, vec!["brief", "compose_prompt", "navigate", "status"]);
    assert_eq!(result.statement.statements.len(), 4);
    assert!(
        result.statement.unlocked_screen_actions.is_empty(),
        "nothing in the default scope needs an unlocked screen"
    );

    // Broadening beyond what the device's own grant carries narrows and says so.
    fixture
        .authority
        .narrow_device_grant(&[ActionRight::SessionView]);
    let broadened = fixture
        .coordinator
        .grant(
            &grant_params(Some(&[VoiceAction::Navigate, VoiceAction::ShellInput])),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect("a narrowed voice grant");
    assert!(
        broadened
            .not_held_by_device
            .contains(&VoiceAction::ShellInput)
    );
    assert!(
        !broadened
            .statement
            .actions
            .contains(&VoiceAction::ShellInput)
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.01 and 23.51: the call, its provider and the authority it runs under
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.01: the coordinator starts a call through one provider interface, and a second
/// implementation of that interface carries the same call without anything above it changing.
#[tokio::test]
async fn a_call_runs_on_either_provider_through_one_interface() {
    let managed = fixture();
    let voice_session_id = started(&managed, None).await;
    assert_eq!(managed.coordinator.live_sessions(), 1);
    assert_eq!(
        managed.broker.offers(),
        vec![start_params().offer_sdp],
        "the caller's own offer is forwarded unchanged"
    );

    // The same coordinator over a backend of the person's own.
    let key = AuthorisationKeyPair::generate().expect("a device identity key");
    let authority = Arc::new(Authority::new(
        device_grant(&[ActionRight::SessionView]),
        *key.public(),
    ));
    let own = Arc::new(OwnBackend::default());
    let coordinator = Coordinator::new(
        Arc::new(Context::new(gathered())) as Arc<dyn ContextSource>,
        Arc::clone(&authority) as Arc<dyn VoiceAuthority>,
        Arc::new(Submitter::new()) as Arc<dyn ActionSubmitter>,
        Some(Arc::clone(&own) as Arc<dyn ManagedVoiceService>),
        device(HOST),
        environment(),
        "https://voice.example",
    );
    coordinator
        .grant(&grant_params(None), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant");
    let result = coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect("a call");
    let VoiceStartOutcome::Started { session } = result.outcome else {
        panic!("the call runs on the person's own backend");
    };
    assert_eq!(session.call_id, "call-byok");
    assert_ne!(session.voice_session_id, voice_session_id);
}

/// KR-REQ-15.01: an unknown creation is a typed state, nothing is retried, and no authority is
/// written for a call that may not exist.
#[tokio::test]
async fn an_unknown_creation_is_a_state_and_leaves_no_grant() {
    let fixture = fixture_with(&[ActionRight::SessionView], Answer::CreationUnknown);
    fixture
        .coordinator
        .grant(&grant_params(None), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect("an answer");
    let VoiceStartOutcome::CreationUnknown { attempt_id, .. } = result.outcome else {
        panic!("an unknown creation is its own state");
    };
    assert_eq!(attempt_id, "attempt-unknown");
    assert_eq!(
        fixture.coordinator.live_sessions(),
        0,
        "nothing is running, so nothing holds authority"
    );
    assert_eq!(
        fixture.broker.offers().len(),
        1,
        "an unknown creation is never retried"
    );
}

/// KR-REQ-15.01 and 15.14: a replayed answer is the call this account already holds, so no second
/// grant is written for it and the call is not left unbound.
#[tokio::test]
async fn a_replayed_answer_does_not_become_a_second_grant() {
    let fixture = fixture();
    started(&fixture, None).await;
    *fixture.broker.answer.lock().expect("the answer") = Answer::Replayed;

    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_100,
        )
        .await
        .expect("an answer");
    assert!(
        matches!(result.outcome, VoiceStartOutcome::Unavailable { .. }),
        "{:?}",
        result.outcome
    );
    assert_eq!(
        fixture.coordinator.live_sessions(),
        1,
        "the call this device already holds is the only one"
    );
    assert!(
        fixture.broker.closed().is_empty(),
        "the call a live voice session is running under is not closed by a repeated start"
    );
}

/// KR-REQ-15.01: a replayed answer for a call nothing holds is closed rather than left metering.
#[tokio::test]
async fn a_replayed_answer_for_a_call_nothing_holds_is_closed() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;
    fixture
        .coordinator
        .stop(device(PHONE), &VoiceStopParams { voice_session_id }, 10_050)
        .await
        .expect("the call stops");
    *fixture.broker.answer.lock().expect("the answer") = Answer::Replayed;

    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_100,
        )
        .await
        .expect("an answer");
    assert!(matches!(
        result.outcome,
        VoiceStartOutcome::Unavailable { .. }
    ));
    assert_eq!(
        fixture.broker.closed(),
        vec!["call-managed".to_owned(), "call-managed".to_owned()],
        "the stop closed it once and the unbound replay closed it again"
    );
}

/// KR-REQ-15.14: replacing a standing voice grant finalises the calls it withdrew.
#[tokio::test]
async fn replacing_a_standing_grant_closes_the_calls_it_withdrew() {
    let fixture = fixture();
    started(&fixture, None).await;
    assert_eq!(fixture.coordinator.live_sessions(), 1);

    fixture
        .coordinator
        .grant(
            &grant_params(Some(&[VoiceAction::Navigate])),
            AuthorityRevision::new(1),
            10_200,
        )
        .await
        .expect("a narrower standing voice grant");
    assert_eq!(
        fixture.coordinator.live_sessions(),
        0,
        "the calls under the grant this one replaces have ended"
    );
    assert_eq!(
        fixture.broker.closed(),
        vec!["call-managed".to_owned()],
        "and the broker was told to finalise them"
    );
}

/// KR-REQ-15.21: replacing a standing voice grant withdraws the one it replaces, so two scopes
/// never stand at once.
#[tokio::test]
async fn a_replaced_standing_grant_is_withdrawn_with_the_calls_under_it() {
    let fixture = fixture();
    let first = fixture
        .coordinator
        .grant(&grant_params(None), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant")
        .grant_id;
    let second = fixture
        .coordinator
        .grant(
            &grant_params(Some(&[VoiceAction::Navigate])),
            AuthorityRevision::new(1),
            10_100,
        )
        .await
        .expect("a narrower standing voice grant")
        .grant_id;
    assert_ne!(first, second);
    assert!(
        fixture.authority.is_revoked(first),
        "the grant this one replaces is withdrawn"
    );
}

/// KR-REQ-15.01: exhausted managed capacity is reported with the paths that still work, and never
/// as a failure of the host.
#[tokio::test]
async fn exhausted_capacity_reports_what_still_works() {
    let fixture = fixture_with(&[ActionRight::SessionView], Answer::Capacity);
    fixture
        .coordinator
        .grant(&grant_params(None), AuthorityRevision::new(1), 10_000)
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect("an answer");
    let VoiceStartOutcome::Unavailable {
        reason,
        alternatives,
        ..
    } = result.outcome
    else {
        panic!("capacity is an answer about the service");
    };
    assert_eq!(reason, "service_capacity");
    assert!(!alternatives.is_empty());
}

/// KR-REQ-23.51: every voice method needs the voice grant at the host, and a device with none gets
/// nothing.
#[tokio::test]
async fn every_voice_method_needs_the_voice_grant() {
    let fixture = fixture();

    // Starting without one.
    let error = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
        )
        .await
        .expect_err("no voice grant, no call");
    assert_eq!(error.reason(), Some(VoiceRefusal::OutsideVoiceGrant));

    // With one, but for a voice session nobody started.
    let voice_session_id = started(&fixture, None).await;
    let invented = VoiceSessionId::new(Uuid::from_bytes([0x99; 16]));
    let error = fixture
        .coordinator
        .context(
            device(PHONE),
            &VoiceContextParams {
                voice_session_id: invented,
                session_id: session(SESSION_A),
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            11_000,
        )
        .await
        .expect_err("no such voice session");
    assert_eq!(error.reason(), Some(VoiceRefusal::UnknownVoiceSession));

    // And another device's call is not this device's.
    let error = fixture
        .coordinator
        .stop(device(0x55), &VoiceStopParams { voice_session_id }, 11_000)
        .await
        .expect_err("another device gets nothing");
    assert_eq!(error.reason(), Some(VoiceRefusal::UnknownVoiceSession));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.02 and 15.14: the voice session's own life
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.14: stopping a voice session revokes its grant immediately, and the revocation does
/// not wait for the broker.
///
/// KR-REQ-15.02: the terminal sessions it reached keep running, and the answer names them.
#[tokio::test]
async fn stopping_a_voice_session_revokes_its_grant_before_the_broker_is_told() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;
    let result = fixture
        .coordinator
        .stop(device(PHONE), &VoiceStopParams { voice_session_id }, 12_000)
        .await
        .expect("the call stops");

    assert!(fixture.authority.is_revoked(result.revoked_grant_id));
    assert_eq!(
        fixture.authority.revoked_at(result.revoked_grant_id),
        Some(12_000)
    );
    assert_eq!(result.revoked_at_ms.get(), 12_000);
    assert!(result.broker_notified);
    assert_eq!(fixture.broker.closed(), vec!["call-managed".to_owned()]);
    assert_eq!(fixture.coordinator.live_sessions(), 0);

    // Nothing runs under the revoked grant afterwards.
    let error = fixture
        .coordinator
        .stop(device(PHONE), &VoiceStopParams { voice_session_id }, 12_500)
        .await
        .expect_err("it is over");
    assert_eq!(error.reason(), Some(VoiceRefusal::UnknownVoiceSession));
}

/// KR-REQ-15.02: a voice session is not a shell session. Stopping one names the terminal sessions
/// it reached and closes none of them; nothing in the coordinator can.
#[tokio::test]
async fn stopping_a_voice_session_leaves_the_terminal_sessions_running() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;
    let result = fixture
        .coordinator
        .stop(device(PHONE), &VoiceStopParams { voice_session_id }, 12_000)
        .await
        .expect("the call stops");
    assert_eq!(
        result.sessions_left_running,
        [session(SESSION_A)].into_iter().collect()
    );
    assert!(
        fixture.submitter.proposals().is_empty(),
        "stopping a voice session proposes no host effect at all"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.11: the delegation path
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.11: a delegation runs under the device's ordinary grant intersected with the voice
/// grant, and narrowing either one stops it.
#[tokio::test]
async fn a_delegation_runs_under_the_intersection_of_both_grants() {
    let fixture = fixture();
    let voice_session_id = started(
        &fixture,
        Some(&[VoiceAction::Navigate, VoiceAction::Status]),
    )
    .await;

    let result = fixture
        .coordinator
        .delegate(
            device(PHONE),
            action(1),
            &delegate_params(voice_session_id, delegation("one"), VoiceAction::Status),
            11_000,
        )
        .await
        .expect("an answer");
    assert!(matches!(
        result.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));

    // An action the voice grant does not carry.
    let result = fixture
        .coordinator
        .delegate(
            device(PHONE),
            action(2),
            &delegate_params(
                voice_session_id,
                delegation("two"),
                VoiceAction::SubmitPrompt,
            ),
            11_100,
        )
        .await
        .expect("an answer");
    let (reason, message) = refusal(&result.outcome);
    assert_eq!(reason, VoiceRefusal::DestinationNotNamed, "{message}");

    // Narrowing the device's own grant stops what the voice grant still lists.
    fixture.authority.narrow_device_grant(&[]);
    let result = fixture
        .coordinator
        .delegate(
            device(PHONE),
            action(3),
            &delegate_params(voice_session_id, delegation("three"), VoiceAction::Status),
            11_200,
        )
        .await
        .expect("an answer");
    let (reason, _) = refusal(&result.outcome);
    assert_eq!(reason, VoiceRefusal::OutsideDeviceGrant);
}

/// KR-REQ-15.11: a delegation identifier is correlation data. One that is not on this call's
/// timeline, and one that has already been submitted, are both refused.
#[tokio::test]
async fn a_delegation_the_provider_never_announced_is_refused() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::Status])).await;

    let mut params = delegate_params(voice_session_id, delegation("late"), VoiceAction::Status);
    params.offset_ms = U64::new(10_000_000);
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::UnannouncedDelegation
    );

    // One delegation is one action: submitting the same identifier twice is refused.
    let params = delegate_params(voice_session_id, delegation("once"), VoiceAction::Status);
    let first = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &params, 11_000)
        .await
        .expect("an answer");
    assert!(matches!(
        first.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));
    let again = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &params, 11_100)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&again.outcome).0,
        VoiceRefusal::UnannouncedDelegation
    );
}

/// KR-REQ-15.11: the delegation event supplies an identifier and a timeline offset, not task text.
/// What the coordinator proposes is built from the host's own state.
#[tokio::test]
async fn a_delegation_carries_no_task_text() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::Status])).await;
    fixture
        .coordinator
        .delegate(
            device(PHONE),
            action(1),
            &delegate_params(voice_session_id, delegation("one"), VoiceAction::Status),
            11_000,
        )
        .await
        .expect("an answer");

    let proposals = fixture.submitter.proposals();
    assert_eq!(proposals.len(), 1);
    let proposal = &proposals[0];
    assert_eq!(proposal.action, VoiceAction::Status);
    assert_eq!(proposal.delegation_id, delegation("one"));
    assert_eq!(proposal.session_id, Some(session(SESSION_A)));
    // The proposal carries the identifier, the action the device named and the host's own plan.
    // There is no field on it for anything the model said, which is the point.
    assert_eq!(proposal.plan.action, VoiceAction::Status);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.13: the confirmation
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.13: each of section 15 ¶13's five classes is refused without a confirmation, and the
/// refusal names what is missing.
#[tokio::test]
async fn the_five_unlocked_screen_classes_are_refused_without_a_confirmation() {
    let fixture = fixture();
    let voice_session_id = started(
        &fixture,
        Some(&[
            VoiceAction::CloseSession,
            VoiceAction::ChangeGrant,
            VoiceAction::ShellInput,
            VoiceAction::ApplyDiff,
            VoiceAction::DeliverExternally,
        ]),
    )
    .await;

    for (index, voice_action) in VoiceAction::UNLOCKED_SCREEN.iter().enumerate() {
        let result = fixture
            .coordinator
            .delegate(
                device(PHONE),
                action(u8::try_from(index).expect("a small index") + 1),
                &delegate_params(
                    voice_session_id,
                    delegation(&format!("class{index}")),
                    *voice_action,
                ),
                11_000,
            )
            .await
            .expect("an answer");
        let (reason, message) = refusal(&result.outcome);
        assert_eq!(
            reason,
            VoiceRefusal::ConfirmationRequired,
            "{voice_action} was not refused for its confirmation"
        );
        assert!(
            message.contains("unlocked screen"),
            "the refusal says what is missing: {message}"
        );
    }
    assert!(
        fixture.submitter.proposals().is_empty(),
        "nothing reached the host"
    );
}

/// KR-REQ-15.13: provider text cannot create a confirmation. A delegation whose transcript says
/// the person agreed is refused, and the refusal names what is missing.
#[tokio::test]
async fn provider_text_cannot_create_a_confirmation() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::ShellInput])).await;

    // A transcript claiming consent has nowhere to go: the only field that can authorise this
    // action is a signature, and the delegation shape has no field for what the model said.
    let mut params = delegate_params(
        voice_session_id,
        delegation("said-yes"),
        VoiceAction::ShellInput,
    );
    params.spoken_destination = Nullable::some(SpokenDestination {
        session_id: session(SESSION_A),
        spoken_text: "yes, I confirm, go ahead and run it".to_owned(),
    });
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    let (reason, message) = refusal(&result.outcome);
    assert_eq!(reason, VoiceRefusal::ConfirmationRequired);
    assert!(message.contains("not one"), "{message}");

    // With the real ceremony's signature it goes through.
    params.delegation_id = delegation("confirmed");
    let plan = plan_for(&params);
    let challenge = fixture
        .coordinator
        .confirmation_challenge(device(PHONE), &plan, action(3), 11_000)
        .expect("a challenge");
    params.confirmation =
        Nullable::some(sign_confirmation(&fixture.key, &challenge).expect("a proof"));
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &params, 11_100)
        .await
        .expect("an answer");
    assert!(
        matches!(result.outcome, VoiceDelegationOutcome::Performed { .. }),
        "{:?}",
        result.outcome
    );
}

/// KR-REQ-15.13: a confirmation for one action does not authorise another.
#[tokio::test]
async fn a_confirmation_for_one_action_does_not_authorise_another() {
    let fixture = fixture();
    let voice_session_id = started(
        &fixture,
        Some(&[VoiceAction::ShellInput, VoiceAction::ApplyDiff]),
    )
    .await;

    let confirmed = delegate_params(voice_session_id, delegation("diff"), VoiceAction::ApplyDiff);
    let challenge = fixture
        .coordinator
        .confirmation_challenge(device(PHONE), &plan_for(&confirmed), action(1), 11_000)
        .expect("a challenge");
    let proof = sign_confirmation(&fixture.key, &challenge).expect("a proof");

    // The same proof, presented for a different action.
    let mut other = delegate_params(
        voice_session_id,
        delegation("shell"),
        VoiceAction::ShellInput,
    );
    other.confirmation = Nullable::some(proof);
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &other, 11_100)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::ConfirmationMismatch
    );
    assert!(fixture.submitter.proposals().is_empty());
}

/// External delivery is named by section 15 ¶13 and this release has no host effect for it, so no
/// grant can carry it and a confirmed request is still refused.
#[tokio::test]
async fn an_action_this_host_has_no_effect_for_is_refused_even_when_confirmed() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::DeliverExternally])).await;
    let mut params = delegate_params(
        voice_session_id,
        delegation("deliver"),
        VoiceAction::DeliverExternally,
    );
    let challenge = fixture
        .coordinator
        .confirmation_challenge(device(PHONE), &plan_for(&params), action(1), 11_000)
        .expect("a challenge");
    params.confirmation =
        Nullable::some(sign_confirmation(&fixture.key, &challenge).expect("a proof"));
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_100)
        .await
        .expect("an answer");
    assert_eq!(refusal(&result.outcome).0, VoiceRefusal::NoSuchEffect);
}

/// The plan a confirmation binds to, built the way the coordinator builds it.
fn plan_for(params: &VoiceDelegateParams) -> VoiceActionPlan {
    let material = VoiceDelegateParams {
        confirmation: Nullable::null(),
        ..params.clone()
    };
    VoiceActionPlan {
        voice_session_id: params.voice_session_id,
        action: params.action,
        session_id: params.session_id,
        delegation_id: Nullable::some(params.delegation_id.clone()),
        payload_digest: Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &kr_cbor::to_canonical_value(&material).expect("canonical parameters"),
        ))),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.21 and 15.22: the three actions with their own requirement
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.21: submitting a prompt requires a clear spoken confirmation naming the destination
/// session, and one that names another session is refused.
#[tokio::test]
async fn submitting_a_prompt_needs_the_spoken_destination() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::SubmitPrompt])).await;

    let params = delegate_params(
        voice_session_id,
        delegation("p1"),
        VoiceAction::SubmitPrompt,
    );
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::DestinationNotNamed
    );

    let mut wrong = delegate_params(
        voice_session_id,
        delegation("p2"),
        VoiceAction::SubmitPrompt,
    );
    wrong.spoken_destination = Nullable::some(SpokenDestination {
        session_id: session(SESSION_B),
        spoken_text: "send it to the other session".to_owned(),
    });
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &wrong, 11_100)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::DestinationNotNamed
    );

    let mut right = delegate_params(
        voice_session_id,
        delegation("p3"),
        VoiceAction::SubmitPrompt,
    );
    right.spoken_destination = Nullable::some(SpokenDestination {
        session_id: session(SESSION_A),
        spoken_text: "send it to the build session".to_owned(),
    });
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &right, 11_200)
        .await
        .expect("an answer");
    assert!(matches!(
        result.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));
}

/// KR-REQ-15.21: an approval decision needs the verified request's details and an explicit answer,
/// and details the host does not hold are refused rather than believed.
#[tokio::test]
async fn an_approval_needs_the_verified_request_and_an_explicit_answer() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::AnswerApproval])).await;
    let approval_request_id = ApprovalRequestId::new("approval-1").expect("an identifier");
    fixture
        .context
        .holds_approval(approval_request_id.clone(), Digest256::from_bytes([9; 32]));

    let params = delegate_params(
        voice_session_id,
        delegation("a1"),
        VoiceAction::AnswerApproval,
    );
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::ApprovalNotVerified
    );

    let mut invented = delegate_params(
        voice_session_id,
        delegation("a2"),
        VoiceAction::AnswerApproval,
    );
    invented.approval = Nullable::some(VerifiedApprovalAnswer {
        approval_request_id: approval_request_id.clone(),
        details_digest: Digest256::from_bytes([1; 32]),
        approved: true,
    });
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &invented, 11_100)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&result.outcome).0,
        VoiceRefusal::ApprovalNotVerified
    );

    let mut verified = delegate_params(
        voice_session_id,
        delegation("a3"),
        VoiceAction::AnswerApproval,
    );
    verified.approval = Nullable::some(VerifiedApprovalAnswer {
        approval_request_id,
        details_digest: Digest256::from_bytes([9; 32]),
        approved: true,
    });
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &verified, 11_200)
        .await
        .expect("an answer");
    assert!(matches!(
        result.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));
}

/// KR-REQ-15.22: cancelling a coding task uses the agent's typed request and its current turn
/// identifier. Nothing that stops playback can reach this path, because interruption is not in
/// this vocabulary at all.
#[tokio::test]
async fn cancelling_a_turn_needs_the_typed_request_and_the_current_turn() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::CancelTurn])).await;

    let params = delegate_params(voice_session_id, delegation("c1"), VoiceAction::CancelTurn);
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    let (reason, message) = refusal(&result.outcome);
    assert_eq!(reason, VoiceRefusal::TurnNotNamed);
    assert!(message.contains("playback"), "{message}");

    let mut named = delegate_params(voice_session_id, delegation("c2"), VoiceAction::CancelTurn);
    named.turn_id = Nullable::some(AgentTurnId::new("turn-7").expect("a turn identifier"));
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &named, 11_100)
        .await
        .expect("an answer");
    assert!(matches!(
        result.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));
    let proposals = fixture.submitter.proposals();
    assert_eq!(
        proposals.last().expect("a proposal").turn_id,
        Some(AgentTurnId::new("turn-7").expect("a turn identifier"))
    );

    // Every voice action this vocabulary has, and not one of them is an interruption.
    assert!(
        !VoiceAction::ALL
            .iter()
            .any(|action| action.as_str().contains("interrupt")),
        "speech interruption has no voice action, so it cannot reach cancellation"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.17: admission is not execution
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.17: a proposal the host admitted and did not perform is reported as admitted only,
/// with the note that says host action receipts are the authority.
#[tokio::test]
async fn a_result_that_was_admitted_and_not_performed_is_reported_as_admitted() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::Status])).await;
    fixture.submitter.admits_without_performing();

    let result = fixture
        .coordinator
        .delegate(
            device(PHONE),
            action(1),
            &delegate_params(voice_session_id, delegation("one"), VoiceAction::Status),
            11_000,
        )
        .await
        .expect("an answer");
    let VoiceDelegationOutcome::Admitted { note, .. } = result.outcome else {
        panic!("an admitted proposal is reported as admitted, not performed");
    };
    assert!(
        note.contains("not evidence that a host action ran"),
        "{note}"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.20: context selection
// ---------------------------------------------------------------------------------------------

/// KR-REQ-15.20: the selection is built under the requesting device's own grant, carries section
/// 15 ¶12's five things, excludes the rest until the person selects it, names its interval and
/// says what stripping does not establish.
#[tokio::test]
async fn context_selection_uses_the_requesting_devices_scope_and_nothing_wider() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;

    let result = fixture
        .coordinator
        .context(
            device(PHONE),
            &VoiceContextParams {
                voice_session_id,
                session_id: session(SESSION_A),
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            11_000,
        )
        .await
        .expect("a selection");

    // Built from the device's own grant, which is the only scope the seam can be given.
    let asked = fixture.context.last_request();
    assert_eq!(asked.grant.recipient_device_id, device(PHONE));
    assert_eq!(
        asked.grant.history.lower_bound_ms.0.map(TimestampMs::get),
        Some(1_000)
    );

    assert_eq!(
        result.selection.session_description,
        "the voice coordinator"
    );
    assert_eq!(result.selection.working_directory, "/work");
    assert_eq!(result.selection.active_application, "an editor");
    assert_eq!(result.selection.pending_decisions.len(), 1);
    assert_eq!(
        result.selection.recent_messages,
        vec!["after the bound".to_owned()],
        "content older than the grant's bound never reaches the selection"
    );
    assert!(
        result.selection.selected.is_empty(),
        "file contents stay out until the person selects them"
    );
    assert!(result.selection.text_tokens <= 8_000);
    assert!(result.selection.stripping_note.contains("does not prove"));
    assert!(result.provenance.from_ms.get() >= 1_000);
    assert!(!result.provenance.resources.is_empty());
    assert!(
        result
            .withheld
            .iter()
            .any(|run| run.reason.contains("lower bound"))
    );
    assert!(
        result
            .disclosure
            .iter()
            .any(|line| line.contains("transcripts")),
        "the host states what the managed operator can see"
    );

    // Selecting the class brings it in, and the secret pattern inside it is replaced.
    let chosen = fixture
        .coordinator
        .context(
            device(PHONE),
            &VoiceContextParams {
                voice_session_id,
                session_id: session(SESSION_A),
                selected: [VoiceContextClass::FileContents].into_iter().collect(),
                delegation_id: Nullable::null(),
            },
            11_100,
        )
        .await
        .expect("a selection");
    assert_eq!(chosen.selection.selected.len(), 1);
    assert!(
        !chosen.selection.selected[0].text.contains("abcdefghij"),
        "a recognised credential is replaced: {}",
        chosen.selection.selected[0].text
    );
    assert_eq!(chosen.selection.secrets_stripped, 1);
}

/// KR-REQ-15.20: a session this voice session does not reach is refused, whatever the device's own
/// grant covers.
#[tokio::test]
async fn context_cannot_reach_a_session_outside_the_voice_session() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;
    let error = fixture
        .coordinator
        .context(
            device(PHONE),
            &VoiceContextParams {
                voice_session_id,
                session_id: session(SESSION_B),
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            11_000,
        )
        .await
        .expect_err("outside this call");
    assert_eq!(
        error.reason(),
        Some(VoiceRefusal::SessionOutsideVoiceSession)
    );
}
