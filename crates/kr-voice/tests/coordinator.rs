//! The coordinator, driven through its three seams and two providers.
//!
//! No test here makes a live provider call. The provider seam is filled twice — once by a fake
//! managed broker and once by a backend of the person's own — which is what proves the interface
//! stays modular rather than asserting it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-15.01 | `a_call_runs_on_either_provider_through_one_interface`, `an_unknown_creation_is_a_state_and_leaves_no_grant`, `a_start_names_the_rate_the_person_was_shown`, `a_changed_rate_leaves_nothing_behind_and_carries_the_new_rate` |
//! | KR-REQ-15.02 | `stopping_a_voice_session_leaves_the_terminal_sessions_running` |
//! | KR-REQ-15.09 | `the_terms_a_person_reads_before_a_call_are_the_services_own`, `the_context_for_a_call_goes_under_the_services_words_for_it` |
//! | KR-REQ-15.11 | `a_delegation_runs_under_the_intersection_of_both_grants`, `a_delegation_outside_this_calls_timeline_or_already_spent_is_refused`, `a_delegation_carries_no_task_text` |
//! | KR-REQ-15.13 | `the_five_unlocked_screen_classes_are_refused_without_a_confirmation`, `provider_text_cannot_create_a_confirmation`, `a_confirmation_for_one_action_does_not_authorise_another` |
//! | KR-REQ-15.14 | `stopping_a_voice_session_revokes_its_grant_before_the_broker_is_told` |
//! | KR-REQ-15.17 | `a_result_that_was_admitted_and_not_performed_is_reported_as_admitted` |
//! | KR-REQ-15.19 | `the_terms_a_person_reads_before_a_call_are_the_services_own`, `a_host_without_the_services_terms_says_why`, `a_preparation_is_refused_where_a_start_would_be` |
//! | KR-REQ-15.20 | `context_selection_uses_the_requesting_devices_scope_and_nothing_wider` |
//! | KR-REQ-15.21 | `the_default_voice_grant_permits_four_things_and_names_them`, `submitting_a_prompt_needs_the_spoken_destination` |
//! | KR-REQ-15.22 | `cancelling_a_turn_needs_the_typed_request_and_the_current_turn` |
//! | KR-REQ-23.51 | `every_voice_method_needs_the_voice_grant` |

use std::sync::{Arc, Mutex};

use kr_client::services::ServiceFuture;
use kr_client::services::voice::{
    ManagedVoiceService, VoiceClosure, VoiceHold, VoiceMetadata, VoiceRateQuote, VoiceSession,
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
    VoiceGrantParams, VoicePrepareParams, VoiceRefusal, VoiceStartOutcome, VoiceStartParams,
    VoiceStopParams,
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
    lookups: Lookups,
    /// This host's clock, as a test moves it.
    now: std::sync::atomic::AtomicU64,
}

/// A standing-grant lookup a test can hold open, and the number that have begun.
///
/// A real lookup reads a store, so it takes time, and that time is the window two changes to one
/// device's voice grant can meet in. Holding the first one open puts them both in that window on
/// purpose rather than hoping the scheduler interleaves two fast calls.
#[derive(Debug, Default)]
struct Lookups {
    started: std::sync::atomic::AtomicU64,
    armed: std::sync::atomic::AtomicBool,
    holding: Mutex<bool>,
    resumed: std::sync::Condvar,
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
            lookups: Lookups::default(),
            now: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Moves this host's clock to `now_ms`.
    fn clock_reaches(&self, now_ms: u64) {
        self.now.store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Holds the next revocation open until [`Authority::release_lookup`].
    ///
    /// Only the next one: everything after it runs straight through, which is what puts a second
    /// caller inside the window the first one is being held in.
    fn hold_next_lookup(&self) {
        *self.lookups.holding.lock().expect("the held lookup") = true;
        self.lookups
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Lets the held lookup finish.
    fn release_lookup(&self) {
        *self.lookups.holding.lock().expect("the held lookup") = false;
        self.lookups.resumed.notify_all();
    }

    /// How many standing-grant lookups have begun.
    fn lookups_started(&self) -> u64 {
        self.lookups
            .started
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Narrows the device's ordinary grant, the way revoking and reissuing one does.
    fn narrow_device_grant(&self, actions: &[ActionRight]) {
        let mut held = self.device_grant.lock().expect("the device grant");
        if let Some(grant) = held.as_mut() {
            grant.actions = actions.iter().copied().collect();
        }
    }

    /// How many grants have been written, standing and session-bound alike.
    fn issued(&self) -> usize {
        self.store.lock().expect("the store").grants.len()
    }

    fn is_revoked(&self, grant_id: GrantId) -> bool {
        self.store
            .lock()
            .expect("the store")
            .revoked
            .contains(&grant_id)
    }

    /// The standing voice grants this device holds that nothing has revoked.
    ///
    /// More than one is the failure the atomic replacement exists to prevent: two scopes standing
    /// at once, only one of which the person was shown.
    fn standing_grants(&self, device_id: DeviceId) -> Vec<GrantId> {
        let store = self.store.lock().expect("the store");
        store
            .grants
            .iter()
            .filter(|grant| {
                grant.recipient_device_id == device_id
                    && grant.parent_grant_id.0.is_none()
                    && grant.permits(ActionRight::VoiceUse)
                    && !store.revoked.contains(&grant.grant_id)
            })
            .map(|grant| grant.grant_id)
            .collect()
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
        self.lookups
            .started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

    fn issue(
        &self,
        plan: &VoiceGrantPlan,
        admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<Grant> {
        assert!(admission.still_admitted(), "a write inside its admission");
        let mut store = self.store.lock().expect("the store");
        let grant_id = GrantId::new(Uuid::from_bytes([store.next; 16]));
        store.next = store.next.wrapping_add(1);
        let grant = plan.grant(grant_id);
        store.grants.push(grant.clone());
        Ok(grant)
    }

    fn revoke(
        &self,
        grant_id: GrantId,
        now_ms: u64,
        _admission: &dyn kr_voice::Admission,
    ) -> kr_voice::Result<u64> {
        // Held here, after the grant to replace has been read and before it is withdrawn: that is
        // the window a second change would read the same grant in.
        if self
            .lookups
            .armed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let mut holding = self.lookups.holding.lock().expect("the held lookup");
            while *holding {
                holding = self
                    .lookups
                    .resumed
                    .wait(holding)
                    .expect("the held lookup is released");
            }
        }
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

    fn now_ms(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
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
    /// A host whose clock moves while this gathering runs, and where it moves to.
    ///
    /// A read waits for the host, and what a test needs to put inside that wait is time passing.
    during: Mutex<Option<(Arc<Authority>, u64)>>,
}

impl Context {
    fn new(gathered: GatheredContext) -> Self {
        Self {
            gathered: Mutex::new(gathered),
            seen: Mutex::new(Vec::new()),
            approval: Mutex::new(None),
            during: Mutex::new(None),
        }
    }

    /// Moves `authority`'s clock to `now_ms` while the next gathering runs.
    fn clock_moves_during_the_read(&self, authority: &Arc<Authority>, now_ms: u64) {
        *self.during.lock().expect("the clock move") = Some((Arc::clone(authority), now_ms));
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
        let during = self.during.lock().expect("the clock move").take();
        Box::pin(async move {
            // Inside the read, which is where the time this coordinator has to notice passes.
            if let Some((authority, now_ms)) = during {
                authority.clock_reaches(now_ms);
            }
            Ok(gathered)
        })
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
    /// The turn the agent is on, when this host is one that knows.
    ///
    /// Whether a turn identifier is the current one is the worker's answer, not the coordinator's:
    /// the coordinator carries the typed request to the host and reports what the host said about
    /// it. A host that holds a current turn is what makes that reporting checkable.
    current_turn: Mutex<Option<kr_protocol::ids::AgentTurnId>>,
}

impl Submitter {
    fn new() -> Self {
        Self {
            proposals: Mutex::new(Vec::new()),
            performed: Mutex::new(true),
            current_turn: Mutex::new(None),
        }
    }

    /// Makes the host admit the next proposal without performing it.
    fn admits_without_performing(&self) {
        *self.performed.lock().expect("the flag") = false;
    }

    /// Gives this host a current turn, which it refuses to cancel anything else against.
    fn agent_is_on_turn(&self, turn_id: &str) {
        *self.current_turn.lock().expect("the current turn") =
            Some(kr_protocol::ids::AgentTurnId::new(turn_id).expect("a turn identifier"));
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
        let stale = {
            let current = self.current_turn.lock().expect("the current turn");
            current.is_some() && current.as_ref() != proposal.turn_id.as_ref()
        };
        Box::pin(async move {
            if stale {
                return Err(kr_voice::VoiceError::Host(
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::StaleSession,
                        "that turn is not the one this agent is on".to_owned(),
                    ),
                ));
            }
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
    /// The rate moved on after the person was shown it.
    RateChanged,
}

/// A stand-in for the managed broker. It makes no network call.
#[derive(Debug)]
struct ManagedFake {
    answer: Mutex<Answer>,
    closed: Mutex<Vec<String>>,
    offers: Mutex<Vec<String>>,
    /// The rate version each start named.
    versions: Mutex<Vec<Option<String>>>,
    /// Whether the terms read fails, as it does when the service cannot be reached.
    terms_unreachable: Mutex<bool>,
    /// Held creations, for a test that needs one start to still be waiting while another arrives.
    ///
    /// A real creation takes as long as a network round trip, and the window this opens is that
    /// round trip rather than an invention of the test.
    holding: tokio::sync::Semaphore,
    held: Mutex<bool>,
}

impl ManagedFake {
    fn new(answer: Answer) -> Self {
        Self {
            answer: Mutex::new(answer),
            closed: Mutex::new(Vec::new()),
            offers: Mutex::new(Vec::new()),
            versions: Mutex::new(Vec::new()),
            terms_unreachable: Mutex::new(false),
            holding: tokio::sync::Semaphore::new(0),
            held: Mutex::new(false),
        }
    }

    /// Makes every creation wait until [`ManagedFake::release`] lets one through.
    fn hold_creations(&self) {
        *self.held.lock().expect("the hold") = true;
    }

    /// Lets one held creation answer.
    fn release(&self) {
        self.holding.add_permits(1);
    }

    fn closed(&self) -> Vec<String> {
        self.closed.lock().expect("what was closed").clone()
    }

    fn offers(&self) -> Vec<String> {
        self.offers.lock().expect("the offers").clone()
    }

    fn versions(&self) -> Vec<Option<String>> {
        self.versions.lock().expect("the versions").clone()
    }
}

/// The terms the fake service publishes, in words no host keeps a copy of.
fn published_terms() -> VoiceMetadata {
    VoiceMetadata {
        enabled: true,
        model: "gpt-live-1".to_owned(),
        disclosure: vec![
            "Audio travels directly between this device and the provider.".to_owned(),
            "This service's own channel still receives transcripts.".to_owned(),
        ],
        admission_note: "The model received this context, and nothing more.".to_owned(),
        delegation_note: "Submit the delegation to the host over the device connection.".to_owned(),
        alternatives: vec!["The coding agent already running on the host.".to_owned()],
        rate: VoiceRateQuote {
            version: "2026-09".to_owned(),
            minor_units_per_second: "1".to_owned(),
            minimum_seconds: 15,
            currency: "usd".to_owned(),
        },
        maximum_session_seconds: 1_800,
        minimum_request_seconds: 60,
        heartbeat_seconds: 20,
        context_bytes: 500,
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
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        let unreachable = *self.terms_unreachable.lock().expect("the switch");
        Box::pin(async move {
            if unreachable {
                return Err(kr_client::error::ClientError::Host(
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::UpstreamUnavailable,
                        "the managed service did not answer".to_owned(),
                    ),
                ));
            }
            Ok(Some(published_terms()))
        })
    }

    fn provider(&self) -> String {
        "the managed broker".to_owned()
    }

    fn start<'a>(&'a self, request: &'a VoiceSessionRequest) -> ServiceFuture<'a, VoiceStart> {
        self.offers
            .lock()
            .expect("the offers")
            .push(request.offer_sdp.clone());
        self.versions
            .lock()
            .expect("the versions")
            .push(request.expected_rate_version.clone());
        let answer = self.answer.lock().expect("the answer").clone();
        let held = *self.held.lock().expect("the hold");
        Box::pin(async move {
            if held {
                self.holding
                    .acquire()
                    .await
                    .expect("the hold is never closed")
                    .forget();
            }
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
                Answer::RateChanged => VoiceStart::RateChanged {
                    rate: VoiceRateQuote {
                        version: "2026-10".to_owned(),
                        minor_units_per_second: "3".to_owned(),
                        minimum_seconds: 15,
                        currency: "usd".to_owned(),
                    },
                    message: "The rate changed after it was shown.".to_owned(),
                    call_id: None,
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
    fn metadata(&self) -> ServiceFuture<'_, Option<VoiceMetadata>> {
        // Not the managed service: it quotes no managed rate and publishes no managed terms.
        Box::pin(async move { Ok(None) })
    }

    fn provider(&self) -> String {
        "a backend of the person's own".to_owned()
    }

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
        expected_rate_version: Nullable::some("2026-09".to_owned()),
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
        .grant(
            &grant_params(actions),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
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
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
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
            &kr_voice::Unbounded,
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
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let result = coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
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
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
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

/// An admission that stands until the store has been read for a standing voice grant, and has
/// lapsed from then on: the way a fence owed or a deadline passed while a start was reading lands.
#[derive(Debug)]
struct LapsesOnceRead {
    authority: Arc<Authority>,
    before: u64,
}

impl kr_voice::Admission for LapsesOnceRead {
    fn still_admitted(&self) -> bool {
        self.authority.lookups_started() == self.before
    }
}

/// A start whose admission lapsed while it read the store asks the broker for nothing.
///
/// The broker's call is the first thing a start does that costs anything, so the admission is asked
/// after the start's reads and immediately before the broker. Asked only once the broker had
/// answered, a call would already have been created and would then have to be closed; asked before
/// the reads, the answer would be out of date by the time the broker was asked.
#[tokio::test]
async fn a_start_whose_admission_lapsed_while_it_read_asks_the_broker_for_nothing() {
    let fixture = fixture();
    fixture
        .coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let admission = LapsesOnceRead {
        authority: Arc::clone(&fixture.authority),
        before: fixture.authority.lookups_started(),
    };

    let refused = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &admission,
        )
        .await
        .expect_err("the start is refused");

    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        fixture.broker.offers().is_empty(),
        "the broker was asked for nothing"
    );
    assert!(
        fixture.broker.closed().is_empty(),
        "so there was no call to close"
    );
    assert_eq!(fixture.coordinator.live_sessions(), 0);
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
            &kr_voice::Unbounded,
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
            &kr_voice::Unbounded,
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

/// KR-REQ-15.01 and 23.51: one device starts one call at a time, so two starts cannot each decide
/// about the call the other is creating.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_start_while_the_first_is_still_waiting_is_told_so() {
    let fixture = fixture();
    fixture
        .coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    fixture.broker.hold_creations();

    let coordinator = Arc::new(fixture.coordinator);
    let first = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .start(
                    device(PHONE),
                    &start_params(),
                    AuthorityRevision::new(1),
                    10_010,
                    &kr_voice::Unbounded,
                )
                .await
                .expect("an answer")
        }
    });
    // The first start is inside the creation the broker is holding, which is the window two starts
    // would otherwise cross in.
    while fixture.broker.offers().is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    let second = coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_020,
            &kr_voice::Unbounded,
        )
        .await
        .expect("an answer");
    let VoiceStartOutcome::Unavailable { reason, .. } = &second.outcome else {
        panic!("the second start is told one is running, not {second:?}");
    };
    assert_eq!(reason, "session_in_progress");
    assert_eq!(
        fixture.broker.offers().len(),
        1,
        "the second start never reached the broker, so it created nothing to race over"
    );

    fixture.broker.release();
    let first = first.await.expect("the first start finishes");
    assert!(
        matches!(first.outcome, VoiceStartOutcome::Started { .. }),
        "{:?}",
        first.outcome
    );
    assert_eq!(coordinator.live_sessions(), 1);
    assert!(
        fixture.broker.closed().is_empty(),
        "nothing closed the call the first start was creating"
    );
}

/// KR-REQ-15.21: two changes to one device's standing voice grant leave one grant standing,
/// whichever order they run in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_changes_to_a_standing_grant_leave_one_of_them_standing() {
    let fixture = fixture();
    let coordinator = Arc::new(fixture.coordinator);
    coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let before = fixture.authority.lookups_started();
    // The first change is held after it has read the grant it replaces and before it withdraws
    // it, which is the window the second one would otherwise read the same grant in.
    fixture.authority.hold_next_lookup();

    let narrow = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .grant(
                    &grant_params(Some(&[VoiceAction::Navigate])),
                    AuthorityRevision::new(1),
                    10_100,
                    &kr_voice::Unbounded,
                )
                .await
                .expect("a narrower standing voice grant")
                .grant_id
        }
    });
    while fixture.authority.lookups_started() == before {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let wider = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .grant(
                    &grant_params(Some(&[VoiceAction::Navigate, VoiceAction::Status])),
                    AuthorityRevision::new(1),
                    10_100,
                    &kr_voice::Unbounded,
                )
                .await
                .expect("a wider standing voice grant")
                .grant_id
        }
    });
    // Long enough for the second change to get as far as it can while the first is held.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    fixture.authority.release_lookup();

    let narrow = narrow.await.expect("the narrower change finishes");
    let wider = wider.await.expect("the wider change finishes");
    assert_ne!(narrow, wider);

    let standing = fixture.authority.standing_grants(device(PHONE));
    assert_eq!(
        standing.len(),
        1,
        "one standing voice grant stands, not two scopes at once: {standing:?}"
    );
    assert!(
        standing == vec![narrow] || standing == vec![wider],
        "the one standing is one of the two that were written: {standing:?}"
    );
}

/// KR-REQ-15.14 and 15.21: a voice grant replaced while a call is being created does not leave
/// that call holding authority the replacement withdrew.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_created_under_a_grant_that_was_replaced_is_not_kept() {
    let fixture = fixture();
    let coordinator = Arc::new(fixture.coordinator);
    coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    fixture.broker.hold_creations();

    let start = tokio::spawn({
        let coordinator = Arc::clone(&coordinator);
        async move {
            coordinator
                .start(
                    device(PHONE),
                    &start_params(),
                    AuthorityRevision::new(1),
                    10_010,
                    &kr_voice::Unbounded,
                )
                .await
                .expect("an answer")
        }
    });
    while fixture.broker.offers().is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // The person narrows their voice grant while the broker is still answering.
    coordinator
        .grant(
            &grant_params(Some(&[VoiceAction::Navigate])),
            AuthorityRevision::new(1),
            10_020,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a narrower standing voice grant");
    fixture.broker.release();

    let started = start.await.expect("the start finishes");
    let VoiceStartOutcome::Unavailable { reason, .. } = &started.outcome else {
        panic!(
            "a call planned under a withdrawn grant is not kept: {:?}",
            started.outcome
        );
    };
    assert_eq!(reason, "voice_grant_changed");
    assert_eq!(
        coordinator.live_sessions(),
        0,
        "no voice session is holding authority the replacement withdrew"
    );
    assert_eq!(
        fixture.broker.closed(),
        vec!["call-managed".to_owned()],
        "and the call it created was closed rather than left metering"
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
            &kr_voice::Unbounded,
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
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant")
        .grant_id;
    let second = fixture
        .coordinator
        .grant(
            &grant_params(Some(&[VoiceAction::Navigate])),
            AuthorityRevision::new(1),
            10_100,
            &kr_voice::Unbounded,
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
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
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
            &kr_voice::Unbounded,
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

/// KR-REQ-15.11: a delegation identifier is correlation data. One whose offset is not on this
/// call's timeline, and one that has already been submitted, are both refused.
///
/// What this host can check about an identifier is its timeline and whether it has been spent: the
/// provider's data channel is the device's, so an identifier this host has never seen before, at
/// an offset inside the call, is one it accepts and spends. It carries no authority either way.
#[tokio::test]
async fn a_delegation_outside_this_calls_timeline_or_already_spent_is_refused() {
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

/// KR-REQ-23.51 and 15.11: one delegation is one action, whichever call carries it and whatever
/// action identifier it arrives under, so the effect happens once whatever a caller submits
/// twice.
#[tokio::test]
async fn one_action_identifier_carries_one_delegation() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::Status])).await;
    let params = delegate_params(voice_session_id, delegation("one"), VoiceAction::Status);
    let first = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    assert!(matches!(
        first.outcome,
        VoiceDelegationOutcome::Performed { .. }
    ));

    // The same delegation again, whatever identifier carries it: refused, and nothing dispatched
    // a second time. A repeat of the same *action* is answered from the record this host retained
    // for it, which is the daemon's own and is proved where that record lives.
    let again = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &params, 11_200)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&again.outcome).0,
        VoiceRefusal::UnannouncedDelegation
    );
    assert_eq!(
        fixture.submitter.proposals().len(),
        1,
        "the effect happened once"
    );

    // And the same delegation through another call this device is holding reaches nothing, because
    // one delegation is one action whichever call carries it.
    let second = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            11_300,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a second call");
    let VoiceStartOutcome::Started { session: second } = second.outcome else {
        panic!("the second call runs");
    };
    let second = second.voice_session_id;
    let elsewhere = delegate_params(second, delegation("one"), VoiceAction::Status);
    let refused_again = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &elsewhere, 11_400)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&refused_again.outcome).0,
        VoiceRefusal::UnannouncedDelegation
    );
    assert_eq!(
        fixture.submitter.proposals().len(),
        1,
        "the effect still happened once"
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
        let VoiceDelegationOutcome::ConfirmationRequired { request, message } = &result.outcome
        else {
            panic!(
                "{voice_action} was admitted without its confirmation: {:?}",
                result.outcome
            );
        };
        assert_eq!(request.action, *voice_action);
        assert_eq!(request.voice_session_id, voice_session_id);
        assert!(
            message.contains("unlocked screen"),
            "the answer says what is missing: {message}"
        );
    }
    assert!(
        fixture.submitter.proposals().is_empty(),
        "nothing reached the host"
    );
}

/// KR-REQ-15.13: the challenge comes back on the wire, and the delegation it belongs to is not
/// spent by asking for it: the same delegation returns carrying the signature and becomes one
/// action.
#[tokio::test]
async fn the_challenge_comes_back_and_the_delegation_survives_it() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, Some(&[VoiceAction::ApplyDiff])).await;
    let mut params = delegate_params(voice_session_id, delegation("diff"), VoiceAction::ApplyDiff);

    let asked = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_000)
        .await
        .expect("an answer");
    let VoiceDelegationOutcome::ConfirmationRequired { request, .. } = asked.outcome else {
        panic!("the first submission answers with the challenge");
    };
    assert_eq!(request.action_id, action(1));
    assert_eq!(request.device_id, device(PHONE));

    // The device signs the challenge this host issued and submits the same delegation again.
    params.confirmation =
        Nullable::some(sign_confirmation(&fixture.key, &request).expect("a proof"));
    let performed = fixture
        .coordinator
        .delegate(device(PHONE), action(1), &params, 11_050)
        .await
        .expect("an answer");
    assert!(
        matches!(performed.outcome, VoiceDelegationOutcome::Performed { .. }),
        "{:?}",
        performed.outcome
    );

    // And it is one action: the delegation is spent now.
    let again = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &params, 11_100)
        .await
        .expect("an answer");
    assert_eq!(
        refusal(&again.outcome).0,
        VoiceRefusal::UnannouncedDelegation
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
    let VoiceDelegationOutcome::ConfirmationRequired { message, .. } = &result.outcome else {
        panic!(
            "a transcript saying yes is not a confirmation: {:?}",
            result.outcome
        );
    };
    assert!(message.contains("not one"), "{message}");
    assert!(
        fixture.submitter.proposals().is_empty(),
        "the transcript admitted nothing"
    );

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

    // A turn identifier that is not the one the agent is on is the host's to refuse, and the
    // coordinator reports what the host said rather than deciding for it.
    fixture.submitter.agent_is_on_turn("turn-7");
    let mut stale = delegate_params(voice_session_id, delegation("c1b"), VoiceAction::CancelTurn);
    stale.turn_id = Nullable::some(AgentTurnId::new("turn-6").expect("a turn identifier"));
    let error = fixture
        .coordinator
        .delegate(device(PHONE), action(2), &stale, 11_050)
        .await
        .expect_err("a stale turn cancels nothing");
    assert!(error.reason().is_none(), "the host refused it: {error}");

    let mut named = delegate_params(voice_session_id, delegation("c2"), VoiceAction::CancelTurn);
    named.turn_id = Nullable::some(AgentTurnId::new("turn-7").expect("a turn identifier"));
    let result = fixture
        .coordinator
        .delegate(device(PHONE), action(3), &named, 11_100)
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

/// KR-REQ-15.20 and 15.14: a call whose own deadline passes while the host is reading does not
/// have that read served to it.
#[tokio::test]
async fn a_selection_is_not_served_after_the_call_it_was_read_for_ran_out() {
    let fixture = fixture();
    let voice_session_id = started(&fixture, None).await;
    // The clock passes the call's own deadline **inside** the read, so the check that notices is
    // the one taken after it: the request still carries the moment it arrived, and the first
    // check passes on that.
    fixture
        .context
        .clock_moves_during_the_read(&fixture.authority, 10_000 + 600_000 + 1);

    let error = fixture
        .coordinator
        .context(
            device(PHONE),
            &VoiceContextParams {
                voice_session_id,
                session_id: session(SESSION_A),
                selected: CanonicalSet::from_iter([]),
                delegation_id: Nullable::null(),
            },
            10_100,
        )
        .await
        .expect_err("a call that ran out is served nothing");
    assert_eq!(error.reason(), Some(VoiceRefusal::OutsideVoiceGrant));
}

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
    assert_eq!(
        result.disclosure,
        running_call("managed").disclosure,
        "the selection goes under the service's own statement of what it can see"
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

// ---------------------------------------------------------------------------------------------
// KR-REQ-15.19 and 15.09: what a person reads before a call, and the rate a start accepts
// ---------------------------------------------------------------------------------------------

fn prepare_params(selected: &[VoiceContextClass]) -> VoicePrepareParams {
    VoicePrepareParams {
        session_ids: [session(SESSION_A)].into_iter().collect(),
        selected: selected.iter().copied().collect(),
    }
}

/// KR-REQ-15.19 and 15.09: before any call exists, the host answers with its own scope and the
/// managed service's terms in the service's own words, and creates nothing to do it.
#[tokio::test]
async fn the_terms_a_person_reads_before_a_call_are_the_services_own() {
    let fixture = fixture();
    fixture
        .coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let written = fixture.authority.issued();

    let prepared = fixture
        .coordinator
        .prepare(
            device(PHONE),
            &prepare_params(&[
                VoiceContextClass::FileContents,
                VoiceContextClass::TerminalScrollback,
            ]),
            10_000,
        )
        .await
        .expect("a preparation");

    let published = published_terms();
    let terms = prepared.managed.0.expect("the managed service's terms");
    assert_eq!(terms.disclosure, published.disclosure, "carried verbatim");
    assert_eq!(terms.admission_note, published.admission_note);
    assert_eq!(terms.delegation_note, published.delegation_note);
    assert_eq!(terms.alternatives, published.alternatives);
    assert_eq!(terms.model, "gpt-live-1");
    assert_eq!(terms.rate.version, "2026-09");
    assert_eq!(terms.rate.minor_units_per_second.get(), 1);
    assert_eq!(terms.maximum_session_seconds, 1_800);
    assert!(prepared.managed_unavailable.0.is_none());

    assert_eq!(
        prepared.session_ids,
        [session(SESSION_A)].into_iter().collect()
    );
    assert_eq!(prepared.broker_origin, "https://reach.example");
    // This device's grant carries no file right, so file contents would not be carried whatever
    // the person selected; scrollback needs none and would be.
    assert_eq!(
        prepared.selected,
        [VoiceContextClass::TerminalScrollback]
            .into_iter()
            .collect()
    );
    assert_eq!(prepared.excluded.len(), VoiceContextClass::ALL.len());

    // Nothing was created to answer it.
    assert!(fixture.broker.offers().is_empty(), "no call was asked for");
    assert_eq!(fixture.coordinator.live_sessions(), 0);
    assert_eq!(fixture.authority.issued(), written, "no grant was written");
}

/// KR-REQ-15.19: a host that has no managed terms to show says why, and offers none in their
/// place: no service at all, a provider that is not the managed one, and a service that could not
/// be read are three different things to tell a person.
#[tokio::test]
async fn a_host_without_the_services_terms_says_why() {
    async fn prepared(
        provider: Option<Arc<dyn ManagedVoiceService>>,
    ) -> kr_protocol::voice::VoicePrepareResult {
        let key = AuthorisationKeyPair::generate().expect("a device identity key");
        let authority = Arc::new(Authority::new(
            device_grant(&[ActionRight::SessionView]),
            *key.public(),
        ));
        let coordinator = Coordinator::new(
            Arc::new(Context::new(gathered())) as Arc<dyn ContextSource>,
            Arc::clone(&authority) as Arc<dyn VoiceAuthority>,
            Arc::new(Submitter::new()) as Arc<dyn ActionSubmitter>,
            provider,
            device(HOST),
            environment(),
            "https://reach.example",
        );
        coordinator
            .grant(
                &grant_params(None),
                AuthorityRevision::new(1),
                10_000,
                &kr_voice::Unbounded,
            )
            .await
            .expect("a standing voice grant");
        coordinator
            .prepare(device(PHONE), &prepare_params(&[]), 10_000)
            .await
            .expect("a preparation")
    }

    let none = prepared(None).await;
    assert!(none.managed.0.is_none());
    let said = none.managed_unavailable.0.clone().expect("a reason");
    assert!(said.starts_with("This host has no voice service"), "{said}");

    let own = prepared(Some(
        Arc::new(OwnBackend::default()) as Arc<dyn ManagedVoiceService>
    ))
    .await;
    assert!(own.managed.0.is_none());
    let said = own.managed_unavailable.0.clone().expect("a reason");
    assert!(said.contains("not the managed service"), "{said}");

    let silent = Arc::new(ManagedFake::new(Answer::Started));
    *silent.terms_unreachable.lock().expect("the switch") = true;
    let unread = prepared(Some(silent as Arc<dyn ManagedVoiceService>)).await;
    assert!(unread.managed.0.is_none());
    let said = unread.managed_unavailable.0.clone().expect("a reason");
    assert!(
        said.contains("could not read the managed service's terms"),
        "{said}"
    );
    assert!(said.contains("did not answer"), "{said}");

    // Whatever the service did, the scope is still this host's to state.
    for answer in [&none, &own, &unread] {
        assert_eq!(
            answer.session_ids,
            [session(SESSION_A)].into_iter().collect()
        );
    }
}

/// KR-REQ-15.19: the preparation refuses where a start would, so a person is never shown a call
/// that could not be made.
#[tokio::test]
async fn a_preparation_is_refused_where_a_start_would_be() {
    let fixture = fixture();
    let error = fixture
        .coordinator
        .prepare(device(PHONE), &prepare_params(&[]), 10_000)
        .await
        .expect_err("no voice grant, nothing to describe");
    assert_eq!(error.reason(), Some(VoiceRefusal::OutsideVoiceGrant));
    assert!(fixture.broker.offers().is_empty());
}

/// KR-REQ-15.01: a start names the rate version the person was shown, and the host passes it on
/// unchanged.
#[tokio::test]
async fn a_start_names_the_rate_the_person_was_shown() {
    let fixture = fixture();
    started(&fixture, None).await;
    assert_eq!(fixture.broker.versions(), vec![Some("2026-09".to_owned())]);
}

/// KR-REQ-15.01: a start the service refuses for a changed rate is a typed answer carrying the
/// rate as it is now, and leaves no call, no grant and nothing to close behind it.
#[tokio::test]
async fn a_changed_rate_leaves_nothing_behind_and_carries_the_new_rate() {
    let fixture = fixture_with(&[ActionRight::SessionView], Answer::RateChanged);
    fixture
        .coordinator
        .grant(
            &grant_params(None),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("a standing voice grant");
    let written = fixture.authority.issued();

    let result = fixture
        .coordinator
        .start(
            device(PHONE),
            &start_params(),
            AuthorityRevision::new(1),
            10_000,
            &kr_voice::Unbounded,
        )
        .await
        .expect("an answer");
    let VoiceStartOutcome::RateChanged { rate, message } = result.outcome else {
        panic!("a changed rate is its own answer: {:?}", result.outcome);
    };
    assert_eq!(rate.version, "2026-10");
    assert_eq!(rate.minor_units_per_second.get(), 3);
    assert_eq!(message, "The rate changed after it was shown.");
    assert_eq!(fixture.coordinator.live_sessions(), 0);
    assert_eq!(fixture.authority.issued(), written, "no grant was written");
    assert!(
        fixture.broker.closed().is_empty(),
        "nothing was created to close"
    );
}

/// KR-REQ-15.09: the context selected for a call goes under the statement the service gave that
/// call, not under a second wording this host keeps.
#[tokio::test]
async fn the_context_for_a_call_goes_under_the_services_words_for_it() {
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
            10_100,
        )
        .await
        .expect("a selection");
    assert_eq!(result.disclosure, running_call("managed").disclosure);
}
