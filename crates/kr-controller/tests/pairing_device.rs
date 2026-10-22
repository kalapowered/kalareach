//! The host a phone pairs with on a simulator or an emulator: it issues the invitations the phone
//! scans, reads what the phone redeemed and approves it, asks for the confirmations the phone
//! answers and reads the host's own record of each answer.
//!
//! This is the machine side of a device run, not a test of the product by itself: a script starts
//! it (`scripts/e2e-pairing-device.sh`) beside the installed application, so it is ignored in an
//! ordinary run. The daemon is the real one, on the loopback interface. The phone's side is the
//! installed application, driven through its own screens by the platform's UI automation; this suite
//! never sees the phone except through what the host records.
//!
//! The script and this suite talk through files in `KR_HARNESS_DIR`, on the internal disk (a file
//! holds an invitation's secret, so it is written for its owner alone). The suite works through the
//! phases the script asks for, each started by a `go-<phase>` file, in any order and any number of
//! times, and ends when `finish` appears. Every phase says when it is done with `done-<phase>`.
//!
//! | Phase | The script's file | The suite writes |
//! | --- | --- | --- |
//! | `control` | `go-control`, then `control-done` | `control.png`: a direct invitation's QR with one bit of its secret flipped; `control-result.txt`: whether the host locked a candidate |
//! | `direct` | `go-direct`, then `approve` | `direct.png`: the invitation's QR; `host-value.txt`: the value the host shows once a candidate redeemed; `paired.txt` once approved |
//! | `code` | `go-code`, then `code-done` | `code.png`: a code QR naming another service, which is a listener this suite owns; `connections.txt`: how many connections that listener has taken |
//! | `confirm` | `go-confirm`, then `confirm-cancelled`, then `confirm-go` | `challenge.txt` once the host asks; `challenge-open.txt` once the cancelled prompt left it unanswered; `confirm-result.txt` with the record of the phone's answer |
//! | `device` | `go-device` | `device-value.txt`: the value of a second device the host asks the phone to confirm; `device-result.txt` once the phone's answer paired it |
//!
//! `KR_HARNESS_PEER` is the name the phone reaches this machine by: `127.0.0.1` for a simulator,
//! which shares the machine's network, and `10.0.2.2` for an emulator. `KR_HARNESS_SERVICE_PEER` is
//! the name it reaches the other service of the `code` phase by, which is `KR_HARNESS_PEER` unless
//! the script gives that port another way in (an emulator's own loopback interface, through a
//! tunnel); `ready.json` says the port. `KR_HARNESS_SECONDS` bounds the whole run. It is for the machines a simulator or an emulator runs on, which are Unix. No
//! test here calls a live service.

#![cfg(unix)]

mod net_support;

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use image::{GrayImage, ImageFormat};
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_pairing::grants::personal_owner_grant;
use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::ids::{ConfirmationId, EnvironmentId, InvitationId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairConfirmParams, PairConfirmResult,
    PairInviteParams, PairInviteResult,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    CodeQrPayload, NetworkHint, QrPayload, RendezvousOrigin, group_verification_value,
};
use kr_protocol::scalars::{Nullable, SecretBytes32};
use net_support::pairing::{self as calls, Signer};
use net_support::worker::Adopted;
use net_support::{Device, Host};

/// How long the script is given to take each step the suite waits for.
const STEP: Duration = Duration::from_secs(300);

/// The smallest side of a QR picture, in pixels: a poster in the emulator's scene and a photo in the
/// simulator's library are read at their own resolution.
const PICTURE: u32 = 1024;

/// The fixture's code invitation, whose code a phone's scanner reads. Only its origin is replaced.
const FIXTURES: &str = include_str!("../../../fixtures/pairing/codes.json");

/// Waits until `file` exists, or `within` passes, or the script says the run is finished.
async fn appears(file: &Path, within: Duration) -> bool {
    let finish = file.parent().map(|directory| directory.join("finish"));
    let end = Instant::now() + within;
    while !file.exists() {
        if Instant::now() >= end || finish.as_ref().is_some_and(|finish| finish.exists()) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    true
}

/// An invitation's text and its secret in the forms a log could print them in, one to a line: what
/// no log of a phone may hold. The script searches the phone's logs for every line.
fn secret_forms(text: &str, secret: &[u8; 32]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use std::fmt::Write as _;

    let mut hex = String::new();
    for byte in secret {
        let _ = write!(hex, "{byte:02x}");
    }
    format!(
        "{text}\n{hex}\n{}\n{}\n",
        URL_SAFE_NO_PAD.encode(secret),
        STANDARD.encode(secret)
    )
}

/// A code invitation's text and the code's secret half in the forms a log could print them in, one to
/// a line: the code is ten characters, the first four of which name the invitation and are not secret.
fn code_forms(text: &str, code: &str) -> String {
    let secret = &code[5..];
    format!(
        "{text}\n{code}\n{}\n{secret}\n{}\n",
        code.replace('-', ""),
        secret.replace('-', "")
    )
}

/// Writes `bytes` to `file` where only this user can read it, whole: the script reads a file the
/// moment it appears, so it appears only when it is complete.
fn write_private(file: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let staging = file.with_extension("partial");
    let mut open = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staging)
        .expect("a file in the harness directory");
    open.write_all(bytes).expect("the file is written");
    std::fs::rename(&staging, file).expect("the file is put in place");
}

/// A QR code of `text` as a picture: low error correction and a quiet zone of four modules, which is
/// what the host's own terminal drawing makes, at a scale that gives it at least [`PICTURE`] pixels.
fn qr_picture(text: &str) -> Vec<u8> {
    let code = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Low)
        .expect("a payload that fits a QR code");
    let border = 4;
    let modules = code.size() + 2 * border;
    let scale = u32::try_from(modules)
        .map(|modules| PICTURE.div_ceil(modules))
        .expect("a small code");
    let edge = u32::try_from(modules).expect("a small code") * scale;
    let mut picture = GrayImage::from_pixel(edge, edge, image::Luma([255]));
    for y in 0..code.size() {
        for x in 0..code.size() {
            if !code.get_module(x, y) {
                continue;
            }
            let (left, top) = (
                u32::try_from(x + border).expect("inside") * scale,
                u32::try_from(y + border).expect("inside") * scale,
            );
            for dy in 0..scale {
                for dx in 0..scale {
                    picture.put_pixel(left + dx, top + dy, image::Luma([0]));
                }
            }
        }
    }
    let mut out = Cursor::new(Vec::new());
    picture
        .write_to(&mut out, ImageFormat::Png)
        .expect("a picture");
    out.into_inner()
}

/// A direct invitation's payload, with the host reachable at `peer`: the port the host bound, on the
/// name the phone reaches this machine by. The hint is only where to dial; the host's endpoint
/// identity is what authenticates it.
fn payload_for(invited: &PairInviteResult, peer: &str) -> kr_protocol::pairing::DirectQrPayload {
    let mut payload = calls::direct_payload(invited);
    let port = payload
        .network_config
        .direct_addresses
        .first()
        .and_then(|hint| hint.as_str().rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .expect("the host names an address to dial");
    payload.network_config.direct_addresses =
        vec![NetworkHint::new(format!("{peer}:{port}")).expect("an address that is a hint")];
    payload
}

fn text_of(payload: kr_protocol::pairing::DirectQrPayload) -> String {
    QrPayload::Direct(Box::new(payload))
        .to_text()
        .expect("a payload that is text")
        .to_string()
}

/// KR-REQ-10.38: the pictures of the fixtures' two QR codes are committed beside them
/// (`fixtures/pairing/qr-*.png`), drawn as the host's own terminal drawing draws a code: low error
/// correction and a quiet zone of four modules. The phones' decoders read these pictures in their
/// own tests (Vision on a Mac, ZXing on a JVM) and must give back the fixtures' text, which makes
/// them the decoders' check against what a host shows. Set `KR_WRITE_FIXTURES=1` to draw them again.
#[test]
fn the_committed_qr_pictures_are_the_fixtures_drawn_the_way_the_host_draws_them() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pairing");
    let texts: serde_json::Value = serde_json::from_str(FIXTURES).expect("the fixtures");
    for mode in ["code", "direct"] {
        let text = texts["qr"][mode]["text"]
            .as_str()
            .expect("the fixture text");
        let drawn = qr_picture(text);
        let file = fixtures.join(format!("qr-{mode}.png"));
        if std::env::var_os("KR_WRITE_FIXTURES").is_some() {
            std::fs::write(&file, &drawn).expect("the picture is written");
        }
        let committed =
            image::load_from_memory(&std::fs::read(&file).expect("a committed picture"))
                .expect("a picture")
                .to_luma8();
        let now = image::load_from_memory(&drawn)
            .expect("a picture")
            .to_luma8();
        assert_eq!(committed.dimensions(), now.dimensions(), "{mode}");
        assert!(
            committed.as_raw() == now.as_raw(),
            "the {mode} picture is not what the fixture draws; set KR_WRITE_FIXTURES=1 to draw it again"
        );
    }
}

/// One daemon and the owner the run bootstraps it with.
struct Run {
    directory: PathBuf,
    peer: String,
    /// The name the phone reaches the other service of the `code` phase by.
    service_peer: String,
    owner: DeviceKeys,
    host: Host,
    environment: EnvironmentId,
}

impl Run {
    fn say(&self, file: &str, text: &str) {
        write_private(&self.directory.join(file), text.as_bytes());
    }

    /// Issues a direct invitation for a personal owner, which the owner confirms here.
    async fn invite(&self, client: &mut LocalClient) -> PairInviteResult {
        let signer = Signer::OwnerDevice(&self.owner);
        calls::invite_direct(
            self.environment,
            client,
            InviteGrantKind::PersonalOwner,
            &personal_owner_grant(),
            &signer,
        )
        .await
        .expect("a direct invitation")
    }

    /// Waits for the candidate of `invitation` to bind and says its value.
    async fn candidate_value(
        &self,
        client: &mut LocalClient,
        invitation: InvitationId,
    ) -> Option<String> {
        let end = Instant::now() + STEP;
        while Instant::now() < end {
            let status = calls::owner_status(client, invitation)
                .await
                .expect("the invitation's status");
            if let Some(candidate) = status.owner.0.and_then(|view| view.candidate.0) {
                return Some(group_verification_value(&candidate.verification_value));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        None
    }

    /// Waits for the host to hold an answer to `confirmation`, and says its record.
    async fn answered(&self, confirmation: ConfirmationId) -> Option<String> {
        let end = Instant::now() + STEP;
        while Instant::now() < end {
            if let Some(record) = self
                .host
                .network()
                .pairing()
                .rows()
                .acceptance(confirmation)
                .expect("readable")
            {
                return Some(format!(
                    "channel={} consumed={}",
                    record.channel,
                    record.consumed_at_ms.is_some()
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        None
    }

    /// Whether the host still lists `confirmation` as waiting for an answer.
    async fn unanswered(&self, client: &mut LocalClient, confirmation: ConfirmationId) -> bool {
        let pending = calls::pending(client)
            .await
            .expect("the owner's pending list");
        pending
            .pending
            .iter()
            .any(|each| each.request.confirmation_id == confirmation && !each.answered)
    }

    /// A direct invitation whose secret has one bit flipped: nothing a host holds opens it. It is
    /// offered as `<name>.png`, and its text, for a phase that pastes it, is the first line of
    /// `secrets-<name>.txt`; the script says it is done with `<name>-done`.
    async fn control(&self, name: &str) {
        let mut client = self.host.client().await;
        let client = &mut client;
        let invited = self.invite(client).await;
        let mut payload = payload_for(&invited, &self.peer);
        let mut secret = *payload.secret.expose();
        secret[0] ^= 1;
        payload.secret = SecretBytes32::from_bytes(secret);
        let text = text_of(payload);
        write_private(
            &self.directory.join(format!("secrets-{name}.txt")),
            secret_forms(&text, &secret).as_bytes(),
        );
        write_private(
            &self.directory.join(format!("{name}.png")),
            &qr_picture(&text),
        );
        assert!(
            appears(&self.directory.join(format!("{name}-done")), STEP).await,
            "the script never said the phone had taken in the invitation"
        );
        let status = calls::owner_status(client, invited.invitation_id)
            .await
            .expect("the invitation's status");
        let locked = status
            .owner
            .0
            .as_ref()
            .and_then(|view| view.candidate.0.as_ref())
            .is_some();
        self.say(
            &format!("{name}-result.txt"),
            &format!("candidate_locked={}\n", u8::from(locked)),
        );
        let _ = calls::cancel(self.environment, client, invited.invitation_id, false).await;
    }

    /// A direct invitation the phone scans: the host says the value it shows and approves the phone
    /// once the script says its value matched.
    async fn direct(&self) {
        let mut client = self.host.client().await;
        let client = &mut client;
        let invited = self.invite(client).await;
        let payload = payload_for(&invited, &self.peer);
        let secret = *payload.secret.expose();
        let text = text_of(payload);
        write_private(
            &self.directory.join("secrets-direct.txt"),
            secret_forms(&text, &secret).as_bytes(),
        );
        self.say("direct-length.txt", &format!("{}\n", text.len()));
        write_private(&self.directory.join("direct.png"), &qr_picture(&text));
        let value = self
            .candidate_value(client, invited.invitation_id)
            .await
            .expect("the phone redeemed the invitation");
        self.say("host-value.txt", &format!("{value}\n"));
        assert!(
            appears(&self.directory.join("approve"), STEP).await,
            "the script never approved the phone"
        );
        calls::confirm_candidate(
            self.environment,
            client,
            invited.invitation_id,
            &Signer::OwnerDevice(&self.owner),
        )
        .await
        .expect("the owner approves the phone");
        self.say("paired.txt", "paired=1\n");
    }

    /// A code QR that names another service: a listener of this suite, which counts what reaches it.
    async fn code(&self, connections: &Arc<AtomicUsize>, port: u16) {
        let fixture: serde_json::Value = serde_json::from_str(FIXTURES).expect("the fixtures");
        let text = fixture["qr"]["code"]["text"]
            .as_str()
            .expect("the code text");
        let QrPayload::Code(fixed) = QrPayload::from_text(text).expect("the fixture reads") else {
            panic!("the fixture's code QR is a code payload");
        };
        let origin = RendezvousOrigin::new(format!("https://{}:{port}", self.service_peer))
            .expect("an origin the phone is asked to use");
        let code_text = fixed.code.to_secret_text();
        let named = QrPayload::Code(CodeQrPayload {
            rendezvous_origin: origin,
            code: fixed.code,
        })
        .to_text()
        .expect("a payload that is text")
        .to_string();
        write_private(
            &self.directory.join("secrets-code.txt"),
            code_forms(&named, &code_text).as_bytes(),
        );
        write_private(&self.directory.join("code.png"), &qr_picture(&named));
        self.say(
            "connections.txt",
            &format!("{}\n", connections.load(Ordering::SeqCst)),
        );
        let end = Instant::now() + STEP;
        let mut last = usize::MAX;
        while Instant::now() < end && !self.directory.join("code-done").exists() {
            let now = connections.load(Ordering::SeqCst);
            if now != last {
                last = now;
                self.say("connections.txt", &format!("{now}\n"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The host asks for the confirmation of an invitation, and the phone, an owner device, answers.
    async fn confirm(&self) {
        let mut client = self.host.client().await;
        let client = &mut client;
        let grant = personal_owner_grant();
        let challenge = calls::request(
            self.environment,
            client,
            ConfirmationSubject::IssueInvitation {
                mode: InviteModeKind::Direct,
                rendezvous_origin: Nullable::null(),
                grant_kind: InviteGrantKind::PersonalOwner,
                proposed_grant: grant.clone(),
            },
        )
        .await
        .expect("the owner asks");
        let id = challenge.request.confirmation_id;
        self.say("challenge.txt", &format!("{id:?}\n"));
        assert!(
            appears(&self.directory.join("confirm-cancelled"), STEP).await,
            "the script never said the prompt was cancelled"
        );
        let open = self.unanswered(client, id).await;
        let refused = calls::mutate::<_, PairInviteResult>(
            self.environment,
            client,
            Method::PairInvite,
            &PairInviteParams {
                mode: InviteMode::Direct,
                grant_kind: InviteGrantKind::PersonalOwner,
                proposed_grant: grant.clone(),
            },
        )
        .await
        .err()
        .map(|error| format!("{:?}", error.code));
        self.say(
            "challenge-open.txt",
            &format!(
                "unanswered={} refused={}\n",
                u8::from(open),
                refused.unwrap_or_default()
            ),
        );
        assert!(
            appears(&self.directory.join("confirm-go"), STEP).await,
            "the script never asked the phone to confirm"
        );
        let record = self
            .answered(id)
            .await
            .expect("the phone answered the challenge");
        let invited: PairInviteResult = calls::mutate(
            self.environment,
            client,
            Method::PairInvite,
            &PairInviteParams {
                mode: InviteMode::Direct,
                grant_kind: InviteGrantKind::PersonalOwner,
                proposed_grant: grant,
            },
        )
        .await
        .expect("the answer is spent on the invitation it confirmed");
        assert!(matches!(invited.entry, InviteEntry::Direct { .. }));
        let spent = self.answered(id).await.expect("the record is still there");
        // A host offers one invitation at a time: this one has served its purpose.
        let _ = calls::cancel(self.environment, client, invited.invitation_id, false).await;
        self.say(
            "confirm-result.txt",
            &format!("answered {record}\nafter {spent}\n"),
        );
    }

    /// A second device redeems an invitation, and the host asks the phone to confirm it.
    async fn device(&self) {
        let mut client = self.host.client().await;
        let client = &mut client;
        let invited = self.invite(client).await;
        let device = Device::create().await;
        let (_connection, _candidate, _value) = calls::redeem(&device.candidate(), &invited).await;
        let value = self
            .candidate_value(client, invited.invitation_id)
            .await
            .expect("the second device redeemed the invitation");
        let challenge = calls::request(
            self.environment,
            client,
            ConfirmationSubject::ConfirmDevice {
                invitation_id: invited.invitation_id,
            },
        )
        .await
        .expect("the owner asks");
        self.say("device-value.txt", &format!("{value}\n"));
        let record = self
            .answered(challenge.request.confirmation_id)
            .await
            .expect("the phone answered the challenge");
        let status = calls::owner_status(client, invited.invitation_id)
            .await
            .expect("the owner's view");
        let approval = status
            .owner
            .0
            .and_then(|view| view.approval.0)
            .expect("an approval");
        let _: PairConfirmResult = calls::mutate(
            self.environment,
            client,
            Method::PairConfirm,
            &PairConfirmParams {
                invitation_id: invited.invitation_id,
                approval,
            },
        )
        .await
        .expect("the answer is spent on the device it confirmed");
        self.say("device-result.txt", &format!("answered {record}\n"));
    }
}

/// Runs the host for one phone, phase by phase, until the script says it is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "started by scripts/e2e-pairing-device.sh beside a simulator or an emulator"]
async fn a_phone_scans_pairs_and_confirms_against_a_real_host() {
    let directory = PathBuf::from(std::env::var("KR_HARNESS_DIR").expect("KR_HARNESS_DIR"));
    let peer = std::env::var("KR_HARNESS_PEER").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let service_peer = std::env::var("KR_HARNESS_SERVICE_PEER").unwrap_or_else(|_| peer.clone());
    let seconds: u64 = std::env::var("KR_HARNESS_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(1800);
    let end = Instant::now() + Duration::from_secs(seconds);

    // What the second service of the `code` phase takes: connections and nothing else.
    let connections = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    let port = listener.local_addr().expect("its address").port();
    let counted = Arc::clone(&connections);
    let accepting = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    // The host holds one session, so a phone paired with it has a conversation to open: the
    // attachment picker is on that screen. The worker is kept until the run ends.
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let environment = host.environment_id;
    let run = Run {
        directory: directory.clone(),
        peer,
        service_peer,
        owner,
        host,
        environment,
    };
    run.say(
        "ready.json",
        &format!("{{\"ready\":true,\"service_port\":{port}}}\n"),
    );

    // Each phase waits for its own `go-<phase>`, so one that the script never asks for, or that
    // stops where its cases failed, holds up no other.
    let phase = |name: &'static str| {
        let run = &run;
        let connections = &connections;
        async move {
            let go = run.directory.join(format!("go-{name}"));
            while !go.exists() {
                if Instant::now() >= end || run.directory.join("finish").exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            match name {
                "control" | "paste" => run.control(name).await,
                "direct" => run.direct().await,
                "code" => run.code(connections, port).await,
                "confirm" => run.confirm().await,
                _ => run.device().await,
            }
            run.say(&format!("done-{name}"), "done\n");
        }
    };
    tokio::join!(
        phase("control"),
        phase("direct"),
        phase("code"),
        phase("confirm"),
        phase("device"),
        phase("paste")
    );
    accepting.abort();
    run.host.stop().await;
    drop(workers);
}
