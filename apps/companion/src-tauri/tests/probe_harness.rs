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

use companion_tauri::probe::harness::{Harness, call_check};
use companion_tauri::voice::{Calls, Kept, Timings};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use support::call::ScriptedCalls;
use support::{Companion, NoOwner, StubIntake, WATCHDOG, parts};
use voice_support::StandIn;

/// The token the phone's account holds, which the stand-in's control accepts.
const TOKEN: &str = "harness-account-token";

/// A host, a stand-in voice service and a phone that is paired with nothing and is given the
/// stand-in's origin and token, as the device run gives them.
struct Scene {
    host: Host,
    owner: DeviceKeys,
    stand_in: StandIn,
    platform: Arc<ScriptedCalls>,
    companion: Companion,
    harness: Harness,
    /// Set when the checks have looked at the running call.
    looked: Arc<AtomicBool>,
    /// The checks reported so far, by name.
    reported: Arc<std::sync::Mutex<Vec<&'static str>>>,
    _data: tempfile::TempDir,
}

async fn scene() -> Scene {
    let stand_in = StandIn::start().await;
    stand_in.accept_control_token(TOKEN);
    let owner = DeviceKeys::generate().expect("owner keys");
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(stand_in.origin().to_owned());
    let host = Host::start_with_document(&owner, &document).await;
    host.controller()
        .host_account()
        .keep_for_test(stand_in.host_grant())
        .await;

    let harness = Harness {
        origin: stand_in.origin().to_owned(),
        token: TOKEN.to_owned(),
        invitation: String::new(),
    };
    let platform = ScriptedCalls::new();
    let data = tempfile::tempdir().expect("a directory");
    let calls = Calls::on_phone(
        Arc::clone(&platform) as Arc<dyn companion_platform::call::CallPlatform>,
        harness.service().expect("the stand-in's service"),
        Timings {
            tick: Duration::from_millis(100),
            ..Timings::default()
        },
        Kept::at(data.path()),
    );
    let companion = Companion::start_with_voice(
        data.path(),
        parts(Arc::new(MemoryStore::new()), Arc::new(host.room.clone())),
        Arc::new(NoOwner),
        StubIntake::holding("", false),
        calls,
        harness.account(),
    );
    Scene {
        host,
        owner,
        stand_in,
        platform,
        companion,
        harness,
        looked: Arc::default(),
        reported: Arc::default(),
        _data: data,
    }
}

impl Scene {
    /// A direct invitation to the host, as the device run's host issues one.
    async fn invitation(&self) -> (String, kr_protocol::ids::InvitationId) {
        let mut client = self.host.client().await;
        let invited = calls::invite_direct(
            self.host.environment_id,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
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
        move |check| {
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

    let (checks, (), ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &text,
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

    let (checks, (), ()) = tokio::join!(
        call_check(
            scene.companion.app.handle(),
            &*scene.platform,
            &text,
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
