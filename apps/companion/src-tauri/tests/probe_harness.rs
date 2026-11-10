//! The checks a debug build runs for a whole call on a phone, run against the in-process daemon.
//!
//! The device run (`scripts/e2e-voice-call-device.sh`) judges a phone by these checks, so a check
//! that cannot fail would make that run prove nothing. Here the daemon is kr-controller's
//! in-process host, the voice service is the stand-in the device run uses, and only the call's
//! media is scripted. The checks pair with the host from a direct invitation, follow a started call
//! and read its end.
//!
//! | What | What proves it |
//! | --- | --- |
//! | A call is followed from the invitation to its end, and every check reads it as healthy | `a_call_is_followed_from_the_invitation_to_the_end_native_code_tells` |
//! | A call the person ends is not read as one native code ended | `a_call_the_person_ends_fails_the_check_that_reads_native_codes_end` |
//! | Each leg of the connected run is played against the real gate and a real host's session, and the host is sent exactly the requests the leg expects | `the_positive_leg_...` and the cases after it |

// The probe is in debug builds only, so a release build of this crate's tests has nothing to run.
#![cfg(debug_assertions)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;
#[path = "../../../../crates/kr-controller/tests/voice_support/mod.rs"]
mod voice_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use companion_platform::call::{CallEvent, Media};
use companion_tauri::probe::delegating::{Driver, DriverFuture, Leg};
use companion_tauri::probe::harness::{Harness, Mode, call_check, call_check_with};
use companion_tauri::voice::{Calls, Kept, Timings};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing::{self as calls, Signer};
use net_support::worker::{Adopted, Worker};
use net_support::{Host, proposal};
use support::call::ScriptedCalls;
use support::{Companion, LinkControl, NoOwner, StubIntake, WATCHDOG, govern, parts};
use tauri::Manager as _;
use voice_support::StandIn;

/// The token the phone's account holds, which the stand-in's control accepts.
const TOKEN: &str = "harness-account-token";

/// How the counters the scripted platform reports move.
#[derive(Clone, Copy)]
enum Moves {
    /// They grow all the time.
    Always,
    /// They stand still.
    Never,
    /// They grow until the voice service is gone and stand still after.
    UntilTheServiceIsGone,
}

/// A host, a stand-in voice service and a phone that is paired with nothing and is given the
/// stand-in's origin and token, as the device run gives them.
struct Scene {
    host: Host,
    owner: DeviceKeys,
    /// The real sessions the host holds, which a run of spoken requests reads.
    workers: Vec<Worker>,
    /// The connections the phone makes to the host, which count what it sends.
    link: Arc<LinkControl>,
    stand_in: StandIn,
    platform: Arc<ScriptedCalls>,
    companion: Companion,
    harness: Harness,
    /// Set when the checks have looked at the running call.
    looked: Arc<AtomicBool>,
    /// Set when the outage mode has read the figure of the first audio played out, after which the
    /// script takes the voice service away.
    figure_read: Arc<AtomicBool>,
    /// Set when the script is about to take the voice service away, before it does.
    service_gone: Arc<AtomicBool>,
    /// Set when the task that moves the counters exists, and when it has carried a value after it
    /// saw `service_gone`, so that none is carried after the service drops.
    producer: Arc<AtomicBool>,
    producer_saw_the_service_gone: Arc<AtomicBool>,
    /// The checks reported so far, by name.
    reported: Arc<std::sync::Mutex<Vec<&'static str>>>,
    _data: tempfile::TempDir,
}

async fn scene() -> Scene {
    scene_over(
        0,
        Timings {
            tick: Duration::from_millis(100),
            ..Timings::default()
        },
    )
    .await
}

/// A host that holds `sessions` real sessions, a stand-in voice service and a phone with `timings`.
async fn scene_over(sessions: u64, timings: Timings) -> Scene {
    let stand_in = StandIn::start().await;
    stand_in.accept_control_token(TOKEN);
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(stand_in.origin().to_owned());
    let (host, owner, workers) = if sessions == 0 {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_with_document(&owner, &document).await;
        (host, owner, Vec::new())
    } else {
        let adopted = Adopted::start_with_document(sessions, &document).await;
        (adopted.host, adopted.owner, adopted.workers)
    };
    host.controller()
        .host_account()
        .keep_for_test(stand_in.host_grant())
        .await;

    let harness = Harness {
        origin: stand_in.origin().to_owned(),
        token: TOKEN.to_owned(),
        invitation: String::new(),
        mode: Mode::NativeFailure,
        media_seconds: 60,
        leg: Leg::Positive,
        session_ids: workers
            .iter()
            .map(|worker| worker.session_id.to_string())
            .collect(),
    };
    let platform = ScriptedCalls::new();
    let data = tempfile::tempdir().expect("a directory");
    let calls = Calls::on_phone(
        Arc::clone(&platform) as Arc<dyn companion_platform::call::CallPlatform>,
        harness.service().expect("the stand-in's service"),
        timings,
        Kept::at(data.path()),
    );
    let link = LinkControl::new();
    let mut governed = parts(Arc::new(MemoryStore::new()), Arc::new(host.room.clone()));
    govern(&mut governed, &link);
    let companion = Companion::start_with_voice(
        data.path(),
        governed,
        Arc::new(NoOwner),
        StubIntake::holding("", false),
        calls,
        harness.account(),
    );
    Scene {
        host,
        owner,
        workers,
        link,
        stand_in,
        platform,
        companion,
        harness,
        looked: Arc::default(),
        figure_read: Arc::default(),
        service_gone: Arc::default(),
        producer: Arc::default(),
        producer_saw_the_service_gone: Arc::default(),
        reported: Arc::default(),
        _data: data,
    }
}

impl Scene {
    /// What a run is given: the stand-in, the token, the invitation's text and what the run is for.
    fn harness_for(&self, invitation: &str, mode: Mode) -> Harness {
        Harness {
            origin: self.harness.origin.clone(),
            token: self.harness.token.clone(),
            invitation: invitation.to_owned(),
            mode,
            media_seconds: 3,
            leg: Leg::Positive,
            session_ids: self.harness.session_ids.clone(),
        }
    }

    /// A direct invitation to the host, as the device run's host issues one.
    async fn invitation(&self) -> (String, kr_protocol::ids::InvitationId) {
        let mut client = self.host.client().await;
        // Paired with the history of a session from its start where the run reads one, as the
        // device run's host issues it.
        let mut proposed = proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]);
        if !self.workers.is_empty() {
            proposed.history.lower_bound_ms =
                Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
        }
        let invited = calls::invite_direct(
            self.host.environment_id,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &proposed,
            &Signer::OwnerDevice(&self.owner),
        )
        .await
        .expect("a direct invitation");
        let InviteEntry::Direct { qr_text } = &invited.entry else {
            panic!("a direct invitation");
        };
        (qr_text.as_str().to_owned(), invited.invitation_id)
    }

    /// Approves the device that redeems the invitation, as the device run's host does.
    async fn approve(&self, invitation: kr_protocol::ids::InvitationId) {
        let mut client = self.host.client().await;
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let status = calls::owner_status(&mut client, invitation)
                    .await
                    .expect("the invitation's status");
                if status.owner.0.and_then(|view| view.approval.0).is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the phone redeemed the invitation");
        calls::confirm_candidate(
            self.host.environment_id,
            &mut client,
            invitation,
            &Signer::OwnerDevice(&self.owner),
        )
        .await
        .expect("the owner approves the phone");
    }

    /// Reports each check, and notes that the running call was looked at.
    fn reporting(&self) -> impl FnMut(&companion_tauri::probe::Check) + Send + 'static {
        let (looked, reported) = (Arc::clone(&self.looked), Arc::clone(&self.reported));
        let figure_read = Arc::clone(&self.figure_read);
        move |check| {
            if check.name == "the first audio played out" {
                figure_read.store(true, Ordering::SeqCst);
            }
            reported
                .lock()
                .expect("the list of reports")
                .push(check.name);
            if check.name == "native code holds the call" {
                looked.store(true, Ordering::SeqCst);
            }
        }
    }

    /// Waits until the call runs with its control attached and the checks have looked at it, as
    /// they do well before a connection that leads nowhere fails.
    async fn call_runs(&self) {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let state = self
                    .companion
                    .call("voice_call_state", serde_json::json!({}))
                    .expect("the call's state");
                if state["running"] == true
                    && state["control"] == "connected"
                    && self.looked.load(Ordering::SeqCst)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the call runs");
    }

    /// What native code's statistics say the media carried, and, when `playout` says so, the news
    /// that audio was played out, once the call runs; the counters move as `moves` says. Returns the
    /// task that moves them.
    async fn carry_audio_once_the_call_runs(
        &self,
        moves: Moves,
        from: u64,
        playout: bool,
    ) -> tokio::task::JoinHandle<()> {
        self.call_runs().await;
        let platform = Arc::clone(&self.platform);
        if playout {
            platform.tell(CallEvent::Playout);
        }
        let gone = Arc::clone(&self.service_gone);
        let saw = Arc::clone(&self.producer_saw_the_service_gone);
        self.producer.store(true, Ordering::SeqCst);
        let mut counted = from;
        tokio::spawn(async move {
            loop {
                // The flag is read once for the round: a round that saw it carries a value that
                // no later round moves, and says so after it has carried it.
                let leaving = gone.load(Ordering::SeqCst);
                let grows = match moves {
                    Moves::Always => true,
                    Moves::Never => false,
                    Moves::UntilTheServiceIsGone => !leaving,
                };
                if grows {
                    counted += 100;
                }
                platform.carry(Media {
                    packets_received: Some(counted),
                    packets_sent: Some(counted),
                    played_samples: Some(counted * 480),
                });
                if leaving {
                    saw.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }

    /// Takes the voice service away once the figure of the first audio has been read, as the device
    /// script does when it sees that check.
    async fn take_the_service_away_once_the_figure_is_read(&self) {
        tokio::time::timeout(WATCHDOG, async {
            while !self.figure_read.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the figure was read");
        // The counters stop first, and the service drops after the task that moves them has said it
        // carried its last value.
        self.service_gone.store(true, Ordering::SeqCst);
        if self.producer.load(Ordering::SeqCst) {
            tokio::time::timeout(WATCHDOG, async {
                while !self.producer_saw_the_service_gone.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the counters were frozen");
        }
        self.stand_in.go_down();
    }

    /// Ends the call once it runs, the way a connection that leads nowhere does.
    async fn fail_the_connection_once_the_call_runs(&self) {
        self.call_runs().await;
        self.platform.fail_the_connection();
    }

    /// Ends the call once it runs, the way the person does.
    async fn stop_the_call_once_it_runs(&self) {
        self.call_runs().await;
        self.companion
            .call("voice_stop", serde_json::json!({}))
            .expect("the call ends");
    }
}

/// The names of the checks that measured what they ask about and found it wrong; a check that could
/// not measure is not among them.
fn measured_failures(checks: &[companion_tauri::probe::Check]) -> Vec<&'static str> {
    checks
        .iter()
        .filter(|check| check.measured && !check.ok)
        .map(|check| check.name)
        .collect()
}

fn failed(checks: &[companion_tauri::probe::Check]) -> Vec<String> {
    checks
        .iter()
        .filter(|check| !check.ok)
        .map(companion_tauri::probe::Check::line)
        .collect()
}

/// The checks pair with the host from the invitation's text, follow the call the host made
/// through the stand-in to the end native code tells, and find every step as it should be.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_is_followed_from_the_invitation_to_the_end_native_code_tells() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::NativeFailure);
    let (checks, (), ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.fail_the_connection_once_the_call_runs(),
    );

    assert!(failed(&checks).is_empty(), "{:#?}", failed(&checks));
    let reported = scene.reported.lock().expect("the list of reports").clone();
    assert_eq!(
        reported,
        checks.iter().map(|check| check.name).collect::<Vec<_>>(),
        "each check is reported as it is made, in order"
    );
    assert!(
        checks
            .iter()
            .any(|check| check.name == "the voice service was told the call is over"),
        "the last step of the call was read: {reported:?}"
    );
    assert_eq!(scene.stand_in.count("/api/voice/sessions"), 1);
    assert!(scene.stand_in.count("/api/voice/sessions/call-1/close") >= 1);
    assert_eq!(
        scene.stand_in.control().report().upgrades[0]
            .authorization
            .as_deref(),
        Some(format!("Bearer {}", scene.harness.token).as_str())
    );
    scene.host.stop().await;
}

/// A call the person ends is not read as one that native code ended because its connection
/// failed: the check that reads native code's end fails, and the steps around it still pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_the_person_ends_fails_the_check_that_reads_native_codes_end() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::NativeFailure);
    let (checks, (), ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.stop_the_call_once_it_runs(),
    );

    assert_eq!(
        checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect::<Vec<_>>(),
        ["native code ends a call whose connection fails"]
    );
    scene.host.stop().await;
}

/// In the outage mode the checks read the audio each end received from the counters, find the
/// voice service unreachable once the script takes it away, exercise the local mute and silence,
/// stop the call without the service and read that its closure is not confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_that_carries_audio_is_followed_through_the_loss_of_the_voice_service() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    let (checks, (), moving, ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.carry_audio_once_the_call_runs(Moves::Always, 100, true),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    moving.abort();

    assert!(failed(&checks).is_empty(), "{:#?}", failed(&checks));
    for name in [
        "audio reaches the call from the peer",
        "audio leaves the call for the peer",
        "the call takes audio to the speaker side",
        "the first audio played out",
        "the control reads unreachable when the service is gone",
        "the microphone mutes with the service gone",
        "the speaker is silenced with the service gone",
        "the media stays connected with the service gone",
        "the closure of the call at the service is not confirmed",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| check.name == name && check.measured),
            "{name} was not made and measured: {:#?}",
            checks.iter().map(|check| check.line()).collect::<Vec<_>>()
        );
    }
    scene.host.stop().await;
}

/// A counter that stands still is not a connection that carries audio, and a counter native code
/// did not report is not measured: neither passes for a pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_that_does_not_move_fails_the_checks_and_audio_nobody_counted_is_not_measured() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    // Counters that cross their floors and stand still: the media does not stay connected.
    let (checks, (), moving, ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.carry_audio_once_the_call_runs(Moves::Never, 100, true),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    moving.abort();

    assert_eq!(
        failed(&checks)
            .iter()
            .filter_map(|line| line.strip_prefix("check="))
            .filter_map(|line| line.split(" ok=").next())
            .collect::<Vec<_>>(),
        ["the media stays connected with the service gone"],
        "{:#?}",
        failed(&checks)
    );
    scene.host.stop().await;

    // Counters below their floors that do not move: no direction carried audio, and the media does
    // not stay connected.
    let scene = self::scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    let (checks, (), moving, ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.carry_audio_once_the_call_runs(Moves::Never, 10, true),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    moving.abort();
    let below: Vec<&str> = checks
        .iter()
        .filter(|check| check.measured && !check.ok)
        .map(|check| check.name)
        .collect();
    assert_eq!(
        below,
        [
            "audio reaches the call from the peer",
            "audio leaves the call for the peer",
            "the call takes audio to the speaker side",
            "the media stays connected with the service gone",
        ],
        "{:#?}",
        checks.iter().map(|check| check.line()).collect::<Vec<_>>()
    );
    scene.host.stop().await;

    // No counters at all: every audio check says it could not measure, and none fails.
    let scene = self::scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    let (checks, (), (), ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.call_runs(),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    let not_measured: Vec<&str> = checks
        .iter()
        .filter(|check| !check.measured)
        .map(|check| check.name)
        .collect();
    assert_eq!(
        not_measured,
        [
            "audio reaches the call from the peer",
            "audio leaves the call for the peer",
            "the call takes audio to the speaker side",
            "the first audio played out",
            "the media stays connected with the service gone",
        ],
        "{:#?}",
        checks.iter().map(|check| check.line()).collect::<Vec<_>>()
    );
    assert!(
        checks
            .iter()
            .filter(|check| check.measured)
            .all(|check| check.ok),
        "{:#?}",
        failed(&checks)
    );
    scene.host.stop().await;
}

/// Packets that arrived before the service went away do not make the media go on without it: a
/// counter that stood still from the loss on fails the check, whatever it had grown to before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn media_that_stops_when_the_service_goes_away_does_not_stay_connected() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    let (checks, (), moving, ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.carry_audio_once_the_call_runs(Moves::UntilTheServiceIsGone, 100, true),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    moving.abort();

    assert_eq!(
        measured_failures(&checks),
        ["the media stays connected with the service gone"],
        "{:#?}",
        failed(&checks)
    );
    scene.host.stop().await;
}

/// Audio that arrived and samples that were played, with no news of audio played out, are a
/// detector that did not tell: the figure's check fails and is not said to be unmeasured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_that_played_with_no_news_of_it_fails_the_figure_check() {
    let scene = scene().await;
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let run = scene.harness_for(&text, Mode::Outage);
    let (checks, (), moving, ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &run,
            &mut report,
        ),
        scene.approve(invitation),
        scene.carry_audio_once_the_call_runs(Moves::Always, 100, false),
        scene.take_the_service_away_once_the_figure_is_read(),
    );
    moving.abort();

    assert_eq!(
        measured_failures(&checks),
        ["the first audio played out"],
        "{:#?}",
        failed(&checks)
    );
    scene.host.stop().await;
}

/* ---------------------------------------------------------------------------------------------- */
/* The legs of the connected run                                                                  */
/* ---------------------------------------------------------------------------------------------- */
//
// The device run plays each leg through the peer in the application and the stand-in voice service
// on the machine. Here the same legs are played against the same gate and a real host's session,
// with native code scripted: the provider's data channel is the scripted platform's, the service's
// announcements the stand-in's, the drop hook a gap in what native code's record shows. What a leg
// asserts of the host is read at the phone's connection to it, where each `voice.delegate` is
// counted, and what the model was told is read at the stand-in's control.

/// Timings of a call that hands spoken requests to the host: a wait for what was said before a
/// delegation that the announcement and the data channel both come inside, a proof that stays young
/// long enough that a loaded machine does not age it, and the watchdog for what is held.
fn delegating_timings() -> Timings {
    Timings {
        tick: Duration::from_millis(100),
        delegation_wait: Duration::from_millis(500),
        proof_age: Duration::from_secs(10),
        drain_within: WATCHDOG,
        host_within: WATCHDOG,
        ..Timings::default()
    }
}

/// The provider's data channel, the voice service's announcements and the recorder's drop, played
/// through the scripted platform and the stand-in. The device run plays them through the peer.
struct Scripted<'a> {
    platform: Arc<ScriptedCalls>,
    stand_in: &'a StandIn,
    /// The phone's calls, whose owner says when it has read a voice service announcement, when the
    /// call hands delegations to the host. The shipped configuration keeps no such record.
    calls: tauri::State<'a, Calls>,
    owner_records_announcements: bool,
    drops: std::sync::atomic::AtomicU64,
    /// Whether native code's record shows a gap from the moment the leg starts.
    gap_from_the_start: bool,
    /// Whether native code's record shows a gap once the leg says its first word, as a recorder
    /// that stalls while the leg runs does.
    gap_at_the_first_word: bool,
}

impl Driver for Scripted<'_> {
    fn provider<'a>(&'a self, bytes: &'a [u8]) -> DriverFuture<'a, ()> {
        Box::pin(async move {
            if self.gap_at_the_first_word && self.drops.load(Ordering::SeqCst) == 0 {
                self.platform.show_a_gap_in_progress();
            }
            self.platform.tell_provider_bytes(bytes.to_vec());
            Ok(())
        })
    }

    fn announce<'a>(&'a self, id: &'a str, offset_ms: u64) -> DriverFuture<'a, ()> {
        Box::pin(async move {
            self.stand_in.control().announce(id, offset_ms);
            // The announcement and the provider's delegation come on paths that nothing orders, and
            // the model is told what became of a delegation that is refused at once by a request
            // the control turns away when it has not heard the announcement. The owner says when it
            // has, and the provider's delegation is written after.
            if !self.owner_records_announcements {
                return Ok(());
            }
            tokio::time::timeout(WATCHDOG, async {
                while !self.calls.has_read_announcement(id, offset_ms) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| "the owner never read the voice service's announcement".to_owned())
        })
    }

    fn drop_recorder(&self, _milliseconds: u64) -> DriverFuture<'_, ()> {
        Box::pin(async move {
            self.platform.show_a_gap_in_progress();
            self.drops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn drops_made(&self) -> DriverFuture<'_, u64> {
        Box::pin(async move { Ok(self.drops.load(Ordering::SeqCst)) })
    }

    fn recorder_stops_with_the_mute(&self) -> bool {
        false
    }

    fn after_a_mute(&self, muted: bool) -> DriverFuture<'_, ()> {
        Box::pin(async move {
            // Native code tells the news of a mute, and the recorder's progress starts afresh once
            // the microphone is back, as a device's does.
            let state = if muted {
                companion_platform::call::CaptureState::MutedByPerson
            } else {
                companion_platform::call::CaptureState::Capturing
            };
            self.platform.tell(CallEvent::Capture { state });
            if !muted {
                self.platform.show_progress_age(Some(10));
            }
            Ok(())
        })
    }

    fn events_open(&self) -> DriverFuture<'_, bool> {
        Box::pin(async move {
            // Asked once the call runs: native code's record then shows the recorder delivering, as
            // a device's does, and a gap from the start where the case wants one.
            self.platform.show_progress_age(Some(10));
            if self.gap_from_the_start {
                self.platform.show_a_gap_in_progress();
            }
            Ok(true)
        })
    }
}

/// What native code's statistics say of the audio the call has received.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Counters {
    /// More packets than the floor a leg needs.
    #[default]
    Counted,
    /// Native code reads no media at all.
    NoMedia,
    /// Native code reads media but no count of packets received.
    NoPacketCount,
}

/// What `scene.platform` shows before the leg starts.
#[derive(Clone, Copy, Default)]
struct Before {
    /// What the audio counters say.
    counters: Counters,
    /// The answer turns discontinuous transmission on.
    dtx: bool,
    /// Native code's record shows a gap from the start, which makes the gate refuse every set.
    gap: bool,
    /// Native code's record shows a gap once the leg's first word is said.
    gap_at_the_first_word: bool,
}

/// Plays one leg of the connected run on a call over one real session, and gives the scene and the
/// checks.
async fn play(leg: Leg, before: Before) -> (Scene, Vec<companion_tauri::probe::Check>) {
    let scene = scene_over(1, delegating_timings()).await;
    if before.dtx {
        scene.platform.answer_with_dtx(true);
    }
    match before.counters {
        Counters::Counted => scene.platform.carry(Media {
            packets_received: Some(100),
            packets_sent: Some(100),
            played_samples: Some(48_000),
        }),
        Counters::NoMedia => {}
        Counters::NoPacketCount => scene.platform.carry(Media {
            packets_received: None,
            packets_sent: Some(100),
            played_samples: Some(48_000),
        }),
    }
    let (text, invitation) = scene.invitation().await;
    let mut report = scene.reporting();
    let mut run = scene.harness_for(&text, Mode::Delegating);
    run.leg = leg;
    let checks = {
        let driver = Scripted {
            platform: Arc::clone(&scene.platform),
            stand_in: &scene.stand_in,
            calls: scene.companion.app.state::<Calls>(),
            owner_records_announcements: !matches!(leg, Leg::Production),
            drops: std::sync::atomic::AtomicU64::new(0),
            gap_from_the_start: before.gap,
            gap_at_the_first_word: before.gap_at_the_first_word,
        };
        let (checks, ()) = tokio::join!(
            call_check_with(
                scene.companion.app.handle(),
                &*scene.platform,
                &run,
                Ok(&driver),
                &mut report,
            ),
            scene.approve(invitation),
        );
        checks
    };
    (scene, checks)
}

/// Stops the host and the workers it ran over.
async fn stop(scene: Scene) {
    let Scene { host, workers, .. } = scene;
    host.stop().await;
    for worker in workers {
        worker.stop().await;
    }
}

/// The attach words the model was told: the instructions the control carried that name no
/// delegation.
fn attach_words(scene: &Scene) -> Vec<String> {
    scene
        .stand_in
        .control()
        .report()
        .sent
        .iter()
        .filter(|sent| sent.command == "instructions" && sent.delegation.is_none())
        .filter_map(|sent| sent.content.clone())
        .collect()
}

/// What the model was told of the delegation `id`.
fn told_of(scene: &Scene, id: &str) -> Vec<String> {
    scene
        .stand_in
        .control()
        .report()
        .sent
        .iter()
        .filter(|sent| sent.delegation.as_deref() == Some(id))
        .filter_map(|sent| sent.content.clone())
        .collect()
}

/// How many `voice.delegate` the phone sent the host.
fn at_the_host(scene: &Scene) -> usize {
    scene.link.sent(kr_protocol::method::Method::VoiceDelegate)
}

/// What every leg shows: every check it made passed, and the host was sent `at_the_host` requests.
fn assert_leg(scene: &Scene, checks: &[companion_tauri::probe::Check], at_the_host_is: usize) {
    assert!(
        failed(checks).is_empty(),
        "{:#?}\nall the checks: {:#?}\nwhat the control refused: {:?}\nwhat it carried: {:?}",
        failed(checks),
        checks
            .iter()
            .map(companion_tauri::probe::Check::line)
            .collect::<Vec<_>>(),
        scene.stand_in.control().report().refusals,
        scene
            .stand_in
            .control()
            .report()
            .sent
            .iter()
            .map(|sent| format!(
                "{} {:?} {}",
                sent.command,
                sent.delegation,
                sent.content
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(30)
                    .collect::<String>()
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        at_the_host(scene),
        at_the_host_is,
        "the host was sent that many requests: {:#?}",
        checks.iter().map(|check| check.line()).collect::<Vec<_>>()
    );
}

/// The shipped configuration: a delegation the service announces is answered that nothing was done,
/// what the data channel says changes nothing, and the host is sent nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_production_leg_answers_nothing_was_done_and_reaches_no_host() {
    let (scene, checks) = play(Leg::Production, Before::default()).await;

    assert_leg(&scene, &checks, 0);
    let attach = attach_words(&scene);
    assert!(
        attach.iter().any(|words| words.contains("cannot act")),
        "{attach:?}"
    );
    assert!(!attach.iter().any(|words| words.contains("can ask")));
    stop(scene).await;
}

/// No break and not the first utterance: the host is sent one request and performs it, and the
/// model is told the attach words for the constant on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_positive_leg_hands_a_status_to_the_host_and_tells_the_model_what_it_reports() {
    let (scene, checks) = play(Leg::Positive, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    let attach = attach_words(&scene);
    assert!(
        attach.iter().any(|words| words.contains("can ask")),
        "{attach:?}"
    );
    assert!(!attach.iter().any(|words| words.contains("cannot act")));
    assert!(
        told_of(&scene, "d-1")
            .iter()
            .any(|words| words.starts_with("The person's computer read it.")),
        "{:?}",
        told_of(&scene, "d-1")
    );
    stop(scene).await;
}

/// A call whose record of capture shows a gap before the leg begins is not the leg's to judge: the
/// leg reads the record first, names the break as the recorder's own for the device script to play
/// the leg again on a new call, and says nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_whose_capture_broke_before_the_leg_is_not_played() {
    let (scene, checks) = play(
        Leg::Positive,
        Before {
            gap: true,
            ..Before::default()
        },
    )
    .await;

    assert_eq!(
        measured_failures(&checks),
        ["the recorder delivered without a break before the leg began"],
        "{:#?}",
        failed(&checks)
    );
    assert!(
        failed(&checks)
            .iter()
            .any(|check| check.contains("the recorder broke by itself")),
        "{:#?}",
        failed(&checks)
    );
    assert_eq!(at_the_host(&scene), 0);
    stop(scene).await;
}

/// A call whose native code reads no media, or no count of the audio packets received, has shown
/// nothing about audio: the leg fails on the audio check and says nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_whose_native_code_reads_no_audio_counters_is_not_played() {
    for counters in [Counters::NoMedia, Counters::NoPacketCount] {
        let (scene, checks) = play(
            Leg::Positive,
            Before {
                counters,
                ..Before::default()
            },
        )
        .await;

        assert_eq!(
            measured_failures(&checks),
            ["the call carries audio before the leg begins"],
            "{:#?}",
            failed(&checks)
        );
        assert!(
            failed(&checks)
                .iter()
                .any(|check| check.contains("native code reads no")),
            "{:#?}",
            failed(&checks)
        );
        assert_eq!(at_the_host(&scene), 0);
        stop(scene).await;
    }
}

/// A call whose record of capture shows a gap once the leg is under way is one the gate refuses for
/// good, so the first sentence is refused for the gap and not as the first of the call. The positive
/// leg fails on it, which a leg that cannot fail would not, and names the break as one it did not
/// make, which is what has the device script play the leg again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_whose_capture_breaks_during_the_positive_leg_names_the_break() {
    let (scene, checks) = play(
        Leg::Positive,
        Before {
            gap_at_the_first_word: true,
            ..Before::default()
        },
    )
    .await;

    assert_eq!(
        measured_failures(&checks),
        ["the first utterance is refused"],
        "{:#?}",
        failed(&checks)
    );
    assert!(
        failed(&checks)
            .iter()
            .any(|check| check.contains("the recorder broke by itself")),
        "{:#?}",
        failed(&checks)
    );
    assert_eq!(at_the_host(&scene), 0);
    stop(scene).await;
}

/// The command is the first thing said in the call: refused, with nothing at the host; the same
/// command said after it is performed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_utterance_leg_refuses_the_first_command_and_performs_the_second() {
    let (scene, checks) = play(Leg::FirstUtterance, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    stop(scene).await;
}

/// A mute and an unmute between two parts of a command refuse it, and every later command, after a
/// read that was performed: the host is sent the one request of the control and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mute_leg_refuses_the_command_and_every_later_one() {
    let (scene, checks) = play(Leg::Mute, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    stop(scene).await;
}

/// A gap in what the recorder hands the call refuses the next command, which native code tells no
/// news of: its record shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gap_leg_refuses_the_command_after_a_drop_in_the_recorder() {
    let (scene, checks) = play(Leg::Gap, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    stop(scene).await;
}

/// An answer that turns discontinuous transmission on refuses every command of the call, and the
/// host is sent nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_dtx_leg_refuses_the_command_of_a_call_that_may_hold_back_quiet_speech() {
    let (scene, checks) = play(
        Leg::Dtx,
        Before {
            dtx: true,
            ..Before::default()
        },
    )
    .await;

    assert_leg(&scene, &checks, 0);
    stop(scene).await;
}

/// A required event on the data channel that fails its schema refuses the next command, after a read
/// that was performed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_malformed_leg_refuses_the_command_after_a_required_event_that_fails_its_schema() {
    let (scene, checks) = play(Leg::Malformed, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    stop(scene).await;
}

/// A fragment that belongs to a request and arrives after the request was read taints the call: the
/// read that was performed stands, the call is told, and the next command is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_late_fragment_leg_keeps_the_earlier_read_and_refuses_the_next_command() {
    let (scene, checks) = play(Leg::LateFragment, Before::default()).await;

    assert_leg(&scene, &checks, 1);
    stop(scene).await;
}

/// A delegation the voice service does not announce at the provider's offset is refused and does not
/// taint the call: the commands before and after it are performed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_broker_leg_refuses_the_delegation_the_service_does_not_vouch_for() {
    let (scene, checks) = play(Leg::BrokerDisagrees, Before::default()).await;

    assert_leg(&scene, &checks, 2);
    stop(scene).await;
}
