//! The default context of a voice call, whole: what the daemon holds of a session and what the
//! session's worker holds of it, under one selection.
//!
//! The daemon is the real one, on a real worker it adopted (`net_support::worker`), and a voice
//! module over the same stores as `voice.rs` builds, with a provider that makes no network call.
//! The device's `voice.context` frame is the one the daemon's dispatch hands the voice module, so
//! what is read here is what a paired phone is answered. No case here starts a live call, and
//! none proves that a model receives the answer: that is the phone's half
//! (`apps/companion/src-tauri/tests/voice_call.rs`).
//!
//! No case waits on a time. The moments an entry is stamped with are chosen against the moment the
//! session was created, which the grant's history bound is also set at.

#![cfg(unix)]

mod net_support;
mod voice_provider;

use std::sync::Arc;

use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::ids::{ApplicationInstanceId, DeviceId, RequestId, SessionId, VoiceSessionId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::U64;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::voice::{
    FragmentText, TranscriptFragment, VoiceContextClass, VoiceContextParams, VoiceContextResult,
    VoiceDelegateParams, VoiceDelegationId, VoiceDelegationOutcome, VoiceGrantParams,
    VoicePrepareParams, VoiceStartOutcome, VoiceStartParams,
};
use net_support::worker::{Adopted, Upstream};
use voice_provider::OfflineProvider;

/// How long a case waits for the daemon or a worker to reach a state it reads.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// What the cap and the bound are stated against: the reasons the selection reports.
const OVER_CAP: &str = "beyond the 8,000-token context cap";
const OUTSIDE_BOUND: &str = "outside the grant's history lower bound";

/// A daemon with one session, a paired device that may be told about it, and a call that device
/// started over it.
struct World {
    adopted: Adopted,
    voice: Arc<kr_controller::voice::VoiceModule>,
    device_id: DeviceId,
    voice_session_id: VoiceSessionId,
    session_id: SessionId,
    /// The moment the session was created, which the device's history bound is set at: what the
    /// daemon holds of the session is produced then, and an entry stamped earlier is outside it.
    started_ms: u64,
}

impl World {
    async fn start() -> Self {
        Self::start_over(Adopted::start(1).await).await
    }

    async fn start_over(adopted: Adopted) -> Self {
        let controller = Arc::clone(adopted.host.controller());
        let session_id = adopted.workers[0].session_id;
        let environment_id = adopted.environment_id();
        let started_ms = {
            let read: kr_protocol::session::SessionReadResult = adopted
                .host
                .client()
                .await
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams { session_id },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the session reads")
                .to_typed()
                .expect("decodes");
            read.session.created_at_ms.get()
        };

        // A device paired with the right to view, whose history begins when the session did.
        let device = net_support::Device::create().await;
        let mut ordinary = net_support::proposal(&[ActionRight::SessionView]);
        ordinary.history.lower_bound_ms = Nullable::some(TimestampMs::new(started_ms));
        let device_id = net_support::pair_with(&adopted.host, &device, &adopted.owner, ordinary)
            .await
            .device_id;

        let voice = Arc::new(kr_controller::voice::VoiceModule::new(
            Arc::new(kr_controller::voice::ControllerFacts::new(Arc::downgrade(
                &controller,
            ))),
            Arc::new(kr_controller::voice::GrantAuthority::new(
                Arc::clone(controller.sharing()),
                Arc::clone(controller.devices()),
                controller.sharing().host_device_id(),
                Arc::downgrade(&controller),
            )),
            Arc::new(kr_controller::voice::ControllerDispatch::new(
                Arc::downgrade(&controller),
            )),
            Some(Arc::new(OfflineProvider::default())),
            controller.sharing().host_device_id(),
            environment_id,
            "https://reach.example".to_owned(),
        ));
        let revision = controller.policy().authority_revision();
        voice
            .coordinator()
            .grant(
                &VoiceGrantParams {
                    device_id,
                    session_ids: [session_id].into_iter().collect(),
                    actions: Nullable(None),
                },
                revision,
                kr_ipc::now_ms().get(),
                &kr_voice::Unbounded,
            )
            .await
            .expect("a standing voice grant");
        let prepared = voice
            .coordinator()
            .prepare(
                device_id,
                &VoicePrepareParams {
                    session_ids: [session_id].into_iter().collect(),
                    selected: CanonicalSet::from_iter([]),
                },
            )
            .await
            .expect("a preparation")
            .prepared;
        let started = voice
            .coordinator()
            .start(
                device_id,
                &VoiceStartParams {
                    session_ids: [session_id].into_iter().collect(),
                    offer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".to_owned(),
                    duration_seconds: 600,
                    reasoning_budget_minor: Nullable::null(),
                    prepared,
                    expected_rate_version: Nullable::some("2026-09".to_owned()),
                },
                revision,
                kr_ipc::now_ms().get(),
                &kr_voice::Unbounded,
            )
            .await
            .expect("a call");
        let VoiceStartOutcome::Started { session } = started.outcome else {
            panic!("the call runs");
        };
        Self {
            adopted,
            voice,
            device_id,
            voice_session_id: session.voice_session_id,
            session_id,
            started_ms,
        }
    }

    fn worker(&self) -> &net_support::worker::Worker {
        &self.adopted.workers[0]
    }

    /// Registers an agent on the session's worker and returns its instance.
    fn agent(&self) -> ApplicationInstanceId {
        self.worker().register_agent(Arc::new(Upstream::default()))
    }

    /// What the agent `instance` was observed to say, stamped at `at`.
    fn said(&self, instance: ApplicationInstanceId, text: &str, at: u64) {
        self.worker()
            .service
            .broker()
            .observe(instance, "message", text, TimestampMs::new(at))
            .expect("the agent has said something");
    }

    /// What `voice.context` answered, as the device that asked reads it.
    async fn context_of(&self, selected: &[VoiceContextClass]) -> Outcome {
        let request = Request {
            request_id: RequestId::new(1),
            method: Method::VoiceContext.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&VoiceContextParams {
                voice_session_id: self.voice_session_id,
                session_id: self.session_id,
                selected: selected.iter().copied().collect(),
                delegation_id: Nullable::null(),
            })
            .expect("encodes"),
        };
        let ControlFrame::Response(response) =
            self.voice.read_frame(self.device_id, &request).await
        else {
            panic!("a read is answered with a response");
        };
        response.outcome
    }

    async fn context(&self) -> VoiceContextResult {
        self.context_selecting(&[]).await
    }

    async fn context_selecting(&self, selected: &[VoiceContextClass]) -> VoiceContextResult {
        let Outcome::Ok(value) = self.context_of(selected).await else {
            panic!("the read was refused");
        };
        value.to_typed().expect("decodes")
    }

    /// Pins `name` on the session, as the person at this machine does.
    async fn pin(&self, name: &str) {
        self.adopted
            .host
            .client()
            .await
            .mutate(
                Method::SessionRename,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                self.worker().target(self.adopted.environment_id()),
                &kr_protocol::describe::SessionRenameParams {
                    session_id: self.session_id,
                    title: Nullable::some(name.to_owned()),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the session is renamed");
    }

    /// What the host says to a device that asks for the session's status: the summary of the
    /// receipt of the read it performs.
    async fn status_receipt(&self) -> String {
        let answered = self
            .voice
            .coordinator()
            .delegate(
                self.device_id,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                &VoiceDelegateParams {
                    voice_session_id: self.voice_session_id,
                    delegation_id: VoiceDelegationId::new("item_status").expect("an identifier"),
                    offset_ms: U64::new(0),
                    fragments: vec![TranscriptFragment {
                        start_ms: U64::new(0),
                        end_ms: U64::new(0),
                        text: FragmentText::new("What's the status?").expect("a fragment"),
                    }],
                    confirmation: Nullable::null(),
                },
                kr_ipc::now_ms().get(),
                &(Arc::new(kr_voice::Unbounded) as Arc<dyn kr_voice::Admission>),
            )
            .await
            .expect("the words are read as the status of the session");
        let VoiceDelegationOutcome::Performed { summary, .. } = answered.outcome else {
            panic!("the host performs the read: {:?}", answered.outcome);
        };
        summary
    }

    /// Waits until the session's retained terminal output holds `marker`, read at the worker.
    async fn until_the_output_holds(&self, marker: &str) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let page: kr_protocol::recovery::HistoryPageResult = self
                .worker()
                .client()
                .await
                .request(
                    Method::HistoryPage,
                    &kr_protocol::recovery::HistoryPageParams {
                        session_id: self.session_id,
                        from_cursor: U64::new(0),
                        max_bytes: U64::new(65_536),
                    },
                )
                .await
                .expect("the call reaches the worker")
                .expect("the output is paged")
                .to_typed()
                .expect("decodes");
            if String::from_utf8_lossy(page.bytes.as_slice()).contains(marker) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the output never held {marker}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// When privacy mode last changed, on the host's clock.
    async fn privacy_changed_at(&self) -> u64 {
        let report: kr_protocol::privacy::PrivacyReport = self
            .adopted
            .host
            .client()
            .await
            .request(
                Method::PrivacyStatus,
                &kr_protocol::privacy::PrivacyStatusParams {},
            )
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode's report")
            .to_typed()
            .expect("decodes");
        report.changed_at_ms.get()
    }

    /// Waits until the host's clock reads a later millisecond than `moment`, so that what is
    /// produced next is produced after it.
    async fn until_after(&self, moment: u64) {
        while kr_ipc::now_ms().get() <= moment {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    async fn stop(self) {
        self.adopted.stop().await;
    }
}

/// Waits until the file the session's shell wrote holds `marker`.
async fn until_the_file_holds(path: &std::path::Path, marker: &str) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !std::fs::read_to_string(path).is_ok_and(|text| text.contains(marker)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} never held {marker}",
            path.display()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Every string a selection carries, as a model is given them.
fn texts(result: &VoiceContextResult) -> Vec<&str> {
    let selection = &result.selection;
    let mut all = vec![
        selection.session_description.as_str(),
        selection.working_directory.as_str(),
        selection.active_application.as_str(),
    ];
    all.extend(selection.pending_decisions.iter().map(String::as_str));
    all.extend(selection.recent_messages.iter().map(String::as_str));
    all.extend(selection.selected.iter().map(|chosen| chosen.text.as_str()));
    all
}

fn withheld(result: &VoiceContextResult, reason: &str) -> Option<u64> {
    result
        .withheld
        .iter()
        .find(|run| run.reason == reason)
        .map(|run| run.count.get())
}

/// KR-REQ-15.20: the default context carries both halves of a session through one selection: what
/// the daemon holds of it (its description and its directory) and what its worker holds (the last
/// twenty semantic messages of its agents, oldest first, and the decisions waiting on a person),
/// under the requesting device's own history bound, which the shared filter applies and reports.
///
/// Narrower than the specification: a pending decision created before the grant's history bound
/// stays withheld, though section 10 would admit a current decision the grant names. This case
/// names none, so the narrowing is not exercised; it is stated in `docs/voice/README.md`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_context_carries_both_halves_of_a_session_under_the_devices_bound() {
    let world = World::start().await;
    let (first, second) = (
        world.agent(),
        world
            .worker()
            .register_agent_numbered(3, Arc::new(Upstream::default())),
    );
    let started = world.started_ms;

    // Thirty entries across two agents. The six oldest are stamped before the device's bound.
    for i in 0..30u64 {
        let agent = if i % 2 == 0 { first } else { second };
        let at = if i < 6 {
            started - 1_000 + i
        } else {
            started + 1 + i
        };
        world.said(agent, &format!("note {i:02}"), at);
    }
    let question = world.worker().ask("r1");
    world.worker().offer_approval_at(
        first,
        Arc::new(Upstream::default()),
        None,
        TimestampMs::new(started + 100),
    );

    let result = world.context().await;
    let selection = &result.selection;

    // The daemon's half.
    assert!(
        selection.session_description.contains("session 1"),
        "{selection:?}"
    );
    assert!(!selection.working_directory.is_empty(), "{selection:?}");

    // The worker's half: the last twenty of the twenty-four the bound admits, oldest first, and
    // the decisions waiting.
    let expected: Vec<String> = (10..30).map(|i| format!("message: note {i:02}")).collect();
    assert_eq!(selection.recent_messages, expected);
    assert_eq!(selection.pending_decisions.len(), 2, "{selection:?}");
    assert!(
        selection
            .pending_decisions
            .iter()
            .any(|decision| decision.contains(&question.question)),
        "{selection:?}"
    );
    assert!(
        selection
            .pending_decisions
            .iter()
            .any(|decision| decision.contains("session/request_permission")),
        "{selection:?}"
    );

    // The six entries before the bound were kept out by the shared filter, which says how many,
    // and the selection's own second check had nothing left to drop.
    let filter_run = result
        .withheld
        .iter()
        .find(|run| run.reason.contains("bound") && run.reason != OUTSIDE_BOUND)
        .unwrap_or_else(|| panic!("the shared filter reports what it kept out: {result:?}"));
    assert_eq!(filter_run.count.get(), 6, "{result:?}");
    assert_eq!(withheld(&result, OUTSIDE_BOUND), None, "{result:?}");
    assert!(result.provenance.from_ms.get() >= started, "{result:?}");
    world.stop().await;
}

/// KR-REQ-15.20: one cap covers the whole default context. Each half fits eight thousand text
/// tokens alone and together they do not; the selection keeps whole items to the cap, says what it
/// dropped, and its count of tokens is exactly what the items it carries cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cap_covers_both_halves_together() {
    let world = World::start().await;
    let agent = world.agent();
    let started = world.started_ms;

    // The daemon's half alone.
    let base = world.context().await;
    let base_tokens = u64::from(base.selection.text_tokens);
    assert!(base_tokens > 0 && base_tokens < 400, "{base:?}");

    // Twenty messages of four hundred bytes each as the selection renders them: eight thousand
    // between them, which fits alone and does not fit beside the daemon's half.
    for i in 0..20u64 {
        let body = format!("{i:02}-{}", "x".repeat(391 - 3));
        world.said(agent, &body, started + 1 + i);
    }
    let result = world.context().await;
    let selection = &result.selection;

    assert_eq!(selection.recent_messages.len(), 19, "{selection:?}");
    assert!(
        selection
            .recent_messages
            .iter()
            .enumerate()
            .all(|(i, text)| text.starts_with(&format!("message: {i:02}-"))),
        "the oldest nineteen are kept, whole: the twentieth did not fit"
    );
    assert_eq!(withheld(&result, OVER_CAP), Some(1), "{result:?}");
    assert!(selection.truncated);
    let costed: u64 = texts(&result)
        .iter()
        .map(|text| u64::from(kr_voice::token_bound(text)))
        .sum();
    assert_eq!(costed, u64::from(selection.text_tokens), "{result:?}");
    assert!(selection.text_tokens <= 8_000, "{result:?}");
    assert_eq!(
        u64::from(selection.text_tokens),
        base_tokens + 19 * 400,
        "{result:?}"
    );
    world.stop().await;
}

/// KR-REQ-15.20: a secret in either half is replaced and counted, whichever half it came from: a
/// recognised credential in what an agent said, in a question's context and in a name a person
/// pinned. The built-in patterns do it; the note beside every selection says that stripping is a
/// secondary measure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_in_either_half_is_replaced_and_counted() {
    let world = World::start().await;
    let agent = world.agent();
    let started = world.started_ms;
    let (token, pinned, key) = (
        "ghp_Zr8Qm3Kd9Lw2Xv7Nb5Tc1Hs",
        "AKIAZR8QM3KD9LW2XV7N",
        "api_key=Qm3Kd9Lw2Xv7Nb5Tc",
    );

    world.said(agent, &format!("deploy with {token}"), started + 1);
    world
        .worker()
        .ask_with_context("r1", &format!("the release uses {key}"));
    world.pin(pinned).await;

    let result = world.context().await;
    let carried = texts(&result).join("\n");
    for secret in [token, pinned, "Qm3Kd9Lw2Xv7Nb5Tc"] {
        assert!(
            !carried.contains(secret),
            "{secret} reached the model: {carried}"
        );
    }
    assert_eq!(
        carried.matches("[redacted]").count(),
        3,
        "each of the three is replaced: {carried}"
    );
    assert_eq!(result.selection.secrets_stripped, 3, "{result:?}");
    assert!(
        carried.contains("deploy with") && carried.contains("the release uses"),
        "what surrounds a secret stays: {carried}"
    );
    assert!(
        result.selection.stripping_note.contains("does not prove"),
        "{result:?}"
    );
    world.stop().await;
}

/// KR-REQ-15.20: the receipt of a voice read of a session is stated through the same selection:
/// a secret in the name a person pinned is replaced there too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_receipt_of_a_voice_read_passes_the_same_stripping() {
    let world = World::start().await;
    world.pin("AKIAZR8QM3KD9LW2XV7N").await;

    let summary = world.status_receipt().await;
    assert!(!summary.contains("AKIAZR8QM3KD9LW2XV7N"), "{summary}");
    assert!(summary.contains("[redacted]"), "{summary}");
    assert!(summary.contains("session 1"), "{summary}");
    world.stop().await;
}

/// A session whose shell plants one marker in each place the default context leaves out: its
/// environment, a file in its directory, and its terminal output.
fn planted_in(directory: &std::path::Path) -> String {
    format!(
        "export KR_VOICE_ENV_MARKER=env-marker-5c1e; \
         cd '{}' && printf 'file-marker-9d2a\\n' > notes.txt; \
         printf 'scrollback-marker-3b7f\\n'; \
         exec cat",
        directory.display()
    )
}

/// KR-REQ-15.20: what the default leaves out (file contents, environment variables, raw terminal
/// scrollback and attachment bytes) never reaches the context, whether nothing is selected or
/// every class a person may select is. The control is a marker in what an agent said, which does.
///
/// The environment and attachment legs show that no path leads in: this daemon has no read of a
/// session's environment or of its attachments for a call, and the two classes a person may
/// select (environment variables and terminal scrollback) have no collection behind them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_default_leaves_out_never_reaches_the_context_selected_or_not() {
    let directory = tempfile::tempdir().expect("a directory");
    let world =
        World::start_over(Adopted::start_running(&planted_in(directory.path())).await).await;
    // The markers are where they were planted: in the file and in the terminal's retained output.
    until_the_file_holds(&directory.path().join("notes.txt"), "file-marker-9d2a").await;
    world.until_the_output_holds("scrollback-marker-3b7f").await;

    let agent = world.agent();
    world.said(agent, "control-marker-entry", world.started_ms + 1);

    for selected in [
        Vec::new(),
        vec![
            VoiceContextClass::EnvironmentVariables,
            VoiceContextClass::TerminalScrollback,
        ],
    ] {
        let result = world.context_selecting(&selected).await;
        let carried = texts(&result).join("\n");
        assert!(
            carried.contains("control-marker-entry"),
            "{selected:?}: {carried}"
        );
        for marker in [
            "env-marker-5c1e",
            "file-marker-9d2a",
            "scrollback-marker-3b7f",
        ] {
            assert!(
                !carried.contains(marker),
                "{selected:?}: {marker} reached the model: {carried}"
            );
        }
    }
    world.stop().await;
}

/// How many of the three reads that gather the worker's half the worker has been sent.
fn worker_half_reads(world: &World) -> usize {
    world
        .worker()
        .service
        .received()
        .iter()
        .filter(|(method, _)| {
            matches!(
                method.method(),
                Some(Method::AgentInstances | Method::AgentSnapshot | Method::QuestionRead)
            )
        })
        .count()
}

/// KR-REQ-15.20 and KR-REQ-24.27: the worker's half follows privacy mode. While it is on the
/// context carries none of it and the worker is asked for none; what was retained before is gone
/// when it is turned off, what happened while it was on is not brought back, and what happens
/// after is carried. The control is the same read before the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_workers_half_follows_privacy_mode() {
    let world = World::start().await;
    let agent = world.agent();
    let started = world.started_ms;
    world.said(agent, "before the change", started + 1);

    let control = world.context().await;
    assert_eq!(
        control.selection.recent_messages,
        vec!["message: before the change".to_owned()]
    );

    world.adopted.set_privacy(true).await;
    let asked = worker_half_reads(&world);
    let private = world.context().await;
    assert!(
        private.selection.recent_messages.is_empty()
            && private.selection.pending_decisions.is_empty(),
        "{private:?}"
    );
    assert_eq!(
        worker_half_reads(&world),
        asked,
        "the worker is asked for none of it while privacy mode is on"
    );
    world.said(agent, "during privacy mode", started + 2);

    world.adopted.set_privacy(false).await;
    world.said(agent, "after the change", kr_ipc::now_ms().get() + 5);

    let after = world.context().await;
    assert_eq!(
        after.selection.recent_messages,
        vec!["message: after the change".to_owned()],
        "{after:?}"
    );
    world.stop().await;
}

/// KR-REQ-15.20 and KR-REQ-24.27: nothing produced before privacy mode last changed is carried
/// after it, whatever the worker still holds. The worker removes its history when privacy mode is
/// enabled, but a worker of an earlier release keeps it, and a decision that was pending across the
/// change is not a body to export as history: so the daemon carries only what was produced after
/// the change. What it kept out is counted, and what is produced after is carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_produced_before_privacy_mode_last_changed_is_carried_after_it() {
    let world = World::start().await;
    let agent = world.agent();
    world.worker().ask("before");

    world.adopted.set_privacy(true).await;
    world.adopted.set_privacy(false).await;
    let changed = world.privacy_changed_at().await;
    world.until_after(changed).await;

    // What a worker that kept its history through the change would still hold: an entry stamped
    // before it.
    world.said(agent, "kept from before the change", changed - 1);
    world.said(agent, "after the change", changed + 1);
    world.worker().ask("after");

    let result = world.context().await;
    assert_eq!(
        result.selection.recent_messages,
        vec!["message: after the change".to_owned()],
        "{result:?}"
    );
    assert_eq!(result.selection.pending_decisions.len(), 1, "{result:?}");
    assert!(
        result.selection.pending_decisions[0].contains("(after)"),
        "{result:?}"
    );
    assert_eq!(
        withheld(&result, kr_controller::voice::BEFORE_PRIVACY_CHANGE),
        Some(2),
        "the entry and the decision from before are counted: {result:?}"
    );
    world.stop().await;
}
