//! Windows Hello as this computer's ceremony, run on Windows itself.
//!
//! The ceremony this computer offers is what Windows reports: `Available` offers Windows Hello,
//! and every other answer offers none, which the page shows as a row with no confirm button that
//! sends the person to another owner device. The first test reads that from the running system,
//! through the types the application uses, and runs on any Windows machine.
//!
//! The others make this computer the owner device of kr-controller's in-process host, which asks
//! its owner to confirm an invitation, and review that request through Windows Hello for a window
//! of this process, as the application reviews one for its own window. Windows Hello's dialog
//! needs what a person's computer has: a signed-in desktop, and Windows Hello set up for the
//! account. So those tests are ignored, and run on purpose from a terminal on that desktop. The
//! first command below needs nobody at the keyboard, because UI Automation presses the dialog's
//! buttons, as desktop automation could, and no credential is ever entered; it takes about three
//! minutes, because one test waits out a challenge's two-minute lifetime. The second needs the
//! person, who enters the account's Windows Hello PIN when the dialog asks.
//!
//! ```text
//! cargo test -p companion-tauri --test windows_hello -- --include-ignored --test-threads 1 --skip a_person_who_enters_the_pin_confirms
//! cargo test -p companion-tauri --test windows_hello -- --ignored --exact a_person_who_enters_the_pin_confirms
//! ```

#![cfg(windows)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::io::Read as _;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use companion_tauri::device::{Device, Parts};
use companion_tauri::owner::{Owner, RequestView};
use companion_tauri::verify::hello::WindowsHello;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::CandidateRoom;
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome, ReviewOutcome};
use kr_client::pairing::room::{RoomError, RoomSocket};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_ipc::client::LocalClient;
use kr_protocol::confirmation::ConfirmationSubject;
use kr_protocol::invitation::{InviteGrantKind, InviteModeKind};
use kr_protocol::pairing::{Locator, OwnerConfirmationRequest, RendezvousOrigin};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing as calls;
use net_support::{Host, proposal};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::run_return::EventLoopExtRunReturn as _;
use tao::platform::windows::{EventLoopBuilderExtWindows as _, WindowExtWindows as _};
use tao::window::WindowBuilder;
use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Win32::Foundation::HWND;

/// What Windows calls each availability, for the record a run leaves.
fn availability_name(availability: UserConsentVerifierAvailability) -> &'static str {
    match availability {
        UserConsentVerifierAvailability::Available => "Available",
        UserConsentVerifierAvailability::DeviceNotPresent => "DeviceNotPresent",
        UserConsentVerifierAvailability::NotConfiguredForUser => "NotConfiguredForUser",
        UserConsentVerifierAvailability::DisabledByPolicy => "DisabledByPolicy",
        UserConsentVerifierAvailability::DeviceBusy => "DeviceBusy",
        _ => "an answer this build does not name",
    }
}

/// A room that serves nothing: nothing here pairs.
struct NoRoom;

impl CandidateRoom for NoRoom {
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        _locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
        Box::pin(async move {
            Err(RoomError::Unreachable {
                origin: origin.as_str().to_owned(),
                reason: "a test room that serves nothing".to_owned(),
            })
        })
    }
}

/// KR-REQ-10.06: the ceremony this computer offers is the one Windows reports, never a guess, and
/// it is what the page is sent. `Available` sends `windows_hello`, which names the confirm button;
/// any other answer sends `none`, and the page shows no confirm button.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ceremony_offered_is_the_one_windows_reports() {
    let reported = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|operation| operation.get())
        .expect("Windows answers");
    println!("== Windows reports {}", availability_name(reported));

    let data = tempfile::tempdir().expect("a directory");
    let device = Device::with(
        data.path(),
        Parts {
            secrets: Arc::new(MemoryStore::new()),
            room: Arc::new(NoRoom),
            bind: Some("127.0.0.1:0".parse().expect("loopback")),
            clock: Arc::new(DeviceClock::current().expect("a clock")),
        },
        || {},
    )
    .expect("the device opens");
    let ceremony = Arc::new(WindowsHello::for_window(HWND(std::ptr::null_mut())));
    let owner = Owner::new(device, ceremony, || {});
    let sent = serde_json::to_value(owner.view()).expect("serialises");
    println!("== the page is sent {sent}");
    let offered = if reported == UserConsentVerifierAvailability::Available {
        "windows_hello"
    } else {
        "none"
    };
    assert_eq!(sent["ceremony"], offered);
}

/// A window of this process, with its message loop on a thread of its own, for Windows Hello's
/// dialog to belong to. It closes when it is dropped.
struct TestWindow {
    hwnd: isize,
    proxy: EventLoopProxy<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestWindow {
    fn open() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut event_loop = EventLoopBuilder::<()>::with_user_event()
                .with_any_thread(true)
                .build();
            let window = WindowBuilder::new()
                .with_title("KalaReach")
                .build(&event_loop)
                .expect("a window");
            sender
                .send((window.hwnd(), event_loop.create_proxy()))
                .expect("the test waits for its window");
            event_loop.run_return(move |event, _, control_flow| {
                let _ = &window;
                *control_flow = match event {
                    Event::UserEvent(()) => ControlFlow::Exit,
                    _ => ControlFlow::Wait,
                };
            });
        });
        let (hwnd, proxy) = receiver.recv().expect("the window opens");
        Self {
            hwnd,
            proxy,
            thread: Some(thread),
        }
    }

    /// Windows Hello for this window, as the application builds it for its own.
    fn ceremony(&self) -> WindowsHello {
        WindowsHello::for_window(HWND(self.hwnd as *mut core::ffi::c_void))
    }
}

impl Drop for TestWindow {
    fn drop(&mut self) {
        let _ = self.proxy.send_event(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// UI Automation on Windows Hello's dialog, in Windows PowerShell. It waits for the dialog,
/// records its texts and buttons, and then either presses every button but Cancel and then
/// Cancel (`press`), or presses nothing (`watch`); either way it records when the dialog goes,
/// waiting at most `$seconds` after it appeared.
const AUTOMATION: &str = r#"param([string]$mode, [int]$seconds)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$element = [System.Windows.Automation.AutomationElement]
$scope = [System.Windows.Automation.TreeScope]
$type = [System.Windows.Automation.ControlType]
$invoke = [System.Windows.Automation.InvokePattern]::Pattern
$clock = [System.Diagnostics.Stopwatch]::StartNew()
function Find-Dialog {
  $class = New-Object System.Windows.Automation.PropertyCondition($element::ClassNameProperty, 'Credential Dialog Xaml Host')
  $found = $element::RootElement.FindFirst($scope::Children, $class)
  if ($found) { return $found }
  foreach ($broker in @(Get-Process CredentialUIBroker -ErrorAction SilentlyContinue)) {
    $owned = New-Object System.Windows.Automation.PropertyCondition($element::ProcessIdProperty, $broker.Id)
    $found = $element::RootElement.FindFirst($scope::Children, $owned)
    if ($found) { return $found }
  }
  $null
}
function Find-All($root, $controlType) {
  $condition = New-Object System.Windows.Automation.PropertyCondition($element::ControlTypeProperty, $controlType)
  @($root.FindAll($scope::Descendants, $condition))
}
$dialog = $null
while (-not $dialog -and $clock.Elapsed.TotalSeconds -lt 30) {
  $dialog = Find-Dialog
  if (-not $dialog) { Start-Sleep -Milliseconds 200 }
}
if (-not $dialog) { '== no dialog'; exit 2 }
$seen = $clock.ElapsedMilliseconds
"== dialog $($dialog.Current.Name)"
foreach ($text in Find-All $dialog ($type::Text)) { "== text $($text.Current.Name)" }
$buttons = Find-All $dialog ($type::Button)
foreach ($button in $buttons) { "== button $($button.Current.Name), enabled $($button.Current.IsEnabled)" }
if ($mode -eq 'press') {
  foreach ($button in $buttons) {
    $name = 'a button that went'
    try {
      $name = $button.Current.Name
      if ($name -eq 'Cancel') { continue }
      $button.GetCurrentPattern($invoke).Invoke()
      "== pressed $name"
    } catch {
      "== could not press ${name}: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds 1
    if (-not (Find-Dialog)) { "== gone after $name"; exit 0 }
    "== still up after $name"
  }
  $open = Find-Dialog
  $cancel = Find-All $open ($type::Button) | Where-Object { $_.Current.Name -eq 'Cancel' } | Select-Object -First 1
  if (-not $cancel) { '== no Cancel button'; exit 3 }
  $cancel.GetCurrentPattern($invoke).Invoke()
  '== pressed Cancel'
}
while ($clock.ElapsedMilliseconds - $seen -lt $seconds * 1000) {
  if (-not (Find-Dialog)) { "== gone $($clock.ElapsedMilliseconds - $seen) ms after it was seen"; exit 0 }
  Start-Sleep -Milliseconds 200
}
"== still up after $seconds seconds"
exit 4
"#;

/// The automation, running beside a test.
struct Automation {
    child: Child,
    output: std::thread::JoinHandle<String>,
    _script: tempfile::TempDir,
}

impl Automation {
    fn start(mode: &str, seconds: u64) -> Self {
        let script = tempfile::tempdir().expect("a directory");
        let path = script.path().join("dialog.ps1");
        std::fs::write(&path, AUTOMATION).expect("the script is written");
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&path)
            .arg(mode)
            .arg(seconds.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Windows PowerShell starts");
        let (mut out, mut err) = (
            child.stdout.take().expect("its output"),
            child.stderr.take().expect("its errors"),
        );
        // Read as it is written, so a full pipe never holds the automation up.
        let errors = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            text
        });
        let output = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = out.read_to_string(&mut text);
            text + &errors.join().unwrap_or_default()
        });
        Self {
            child,
            output,
            _script: script,
        }
    }

    /// Waits for the automation to end, at most `within`, and returns what it recorded.
    fn finish(mut self, within: Duration) -> String {
        let deadline = Instant::now() + within;
        while self.child.try_wait().expect("the automation").is_none() {
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.output.join().unwrap_or_default()
    }
}

/// Windows Hello, recording each reason it is given: the message Windows prints in its dialog.
struct Recorded {
    hello: WindowsHello,
    reasons: std::sync::Mutex<Vec<String>>,
}

impl Ceremony for Recorded {
    fn kind(&self) -> CeremonyKind {
        self.hello.kind()
    }

    fn verify<'a>(&'a self, reason: &'a str, within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.reasons
            .lock()
            .expect("the record")
            .push(reason.to_owned());
        self.hello.verify(reason, within)
    }
}

/// This computer as the owner device of an in-process host, reviewing with Windows Hello for a
/// window of its own, with the request the host has just asked its owner to confirm listed.
struct Asked {
    host: Host,
    client: LocalClient,
    owner: Arc<Owner>,
    ceremony: Arc<Recorded>,
    request: RequestView,
    challenge: OwnerConfirmationRequest,
    _data: tempfile::TempDir,
}

impl Asked {
    async fn new(window: &TestWindow) -> Self {
        let owner_keys = DeviceKeys::generate().expect("keys");
        let host = Host::start(&owner_keys).await;
        let mut client = host.client().await;
        let data = tempfile::tempdir().expect("a directory");
        let device: Arc<Device> = support::owner_device(&host, &owner_keys, data.path());
        let ceremony = Arc::new(Recorded {
            hello: window.ceremony(),
            reasons: std::sync::Mutex::new(Vec::new()),
        });
        let owner = Owner::new(device, ceremony.clone(), || {});
        owner.start();
        let challenge = calls::request(
            host.environment_id,
            &mut client,
            ConfirmationSubject::IssueInvitation {
                mode: InviteModeKind::Direct,
                rendezvous_origin: Nullable::null(),
                grant_kind: InviteGrantKind::SessionInvitation,
                proposed_grant: proposal(&[ActionRight::SessionView]),
            },
        )
        .await
        .expect("the local owner asks")
        .request;
        let request = support::listed(&owner, |request| request.checkable).await;
        Self {
            host,
            client,
            owner,
            ceremony,
            request,
            challenge,
            _data: data,
        }
    }

    /// The message Windows Hello was given for the review, exactly: the one line its dialog
    /// prints.
    fn message(&self) -> String {
        self.ceremony
            .reasons
            .lock()
            .expect("the record")
            .last()
            .cloned()
            .expect("the review asked Windows Hello")
    }

    /// Whether the host recorded an answer to its challenge.
    fn answered(&self) -> bool {
        self.host
            .network()
            .pairing()
            .rows()
            .acceptance(self.challenge.confirmation_id)
            .expect("readable")
            .is_some()
    }

    /// Whether the host still holds its challenge open for an answer.
    async fn still_asking(&mut self) -> bool {
        calls::pending(&mut self.client)
            .await
            .expect("readable")
            .pending
            .iter()
            .any(|pending| {
                pending.request.confirmation_id == self.challenge.confirmation_id
                    && !pending.answered
            })
    }
}

/// A window, and Windows Hello for it, which has to be set up here.
fn windows_hello() -> TestWindow {
    let window = TestWindow::open();
    assert_eq!(
        window.ceremony().kind(),
        CeremonyKind::WindowsHello,
        "Windows Hello is set up for this account"
    );
    window
}

/// KR-REQ-10.06: reviewing a host's request raises Windows Hello's dialog, which belongs to this
/// computer's window and prints the request's sentence. Pressing the dialog's buttons through UI
/// Automation, as desktop automation could, with no credential entered, confirms nothing: the
/// dialog closes on its own buttons, Cancel last, the review answers "not confirmed" well before
/// the challenge runs out, the host records no answer, and its challenge is still waiting for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "raises Windows Hello's dialog: needs a signed-in desktop with Windows Hello set up"]
async fn pressing_the_dialogs_buttons_without_a_credential_confirms_nothing() {
    let window = windows_hello();
    let mut asked = Asked::new(&window).await;
    let automation = Automation::start("press", 30);
    let started = Instant::now();
    let outcome = asked
        .owner
        .review(&asked.request.reference)
        .await
        .expect("reviewed");
    let answered_in = started.elapsed();
    let record = automation.finish(Duration::from_secs(60));
    println!("{record}");
    assert_eq!(outcome, ReviewOutcome::NotConfirmed);
    assert!(
        answered_in < Duration::from_secs(60),
        "the dialog answered, not the time: {answered_in:?}"
    );
    assert!(record.contains("== dialog "), "the dialog was raised");
    let message = asked.message();
    assert!(
        record
            .lines()
            .any(|line| line.starts_with("== text ") && line.contains(&message)),
        "the dialog prints {message:?}"
    );
    assert!(
        record.contains("== pressed Cancel") || record.contains("== gone after "),
        "one of its own buttons closed it"
    );
    assert!(record.contains("== gone "), "the dialog closed");
    assert!(!asked.answered(), "no completion reached the host");
    assert!(asked.still_asking().await, "the challenge is unanswered");
    asked.host.stop().await;
}

/// KR-REQ-10.06: a dialog nobody answers is cancelled when the challenge's time runs out: the
/// review answers "not confirmed" at that moment, the dialog goes with it, so no late answer can
/// reach a signature, and the host records no answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "raises Windows Hello's dialog: needs a signed-in desktop with Windows Hello set up"]
async fn a_dialog_left_past_the_challenges_time_is_cancelled_and_not_confirmed() {
    let window = windows_hello();
    let asked = Asked::new(&window).await;
    let automation = Automation::start("watch", 180);
    let outcome = asked
        .owner
        .review(&asked.request.reference)
        .await
        .expect("reviewed");
    let answered_at = kr_ipc::now_ms().get();
    let record = automation.finish(Duration::from_secs(60));
    println!("{record}");
    assert_eq!(outcome, ReviewOutcome::NotConfirmed);
    let expires_at = asked.challenge.expires_at_ms.get();
    assert!(
        answered_at >= expires_at && answered_at < expires_at + 5_000,
        "answered when the challenge ran out: {answered_at} against {expires_at}"
    );
    assert!(record.contains("== dialog "), "the dialog was raised");
    assert!(!record.contains("== pressed"), "nothing pressed it");
    assert!(record.contains("== gone "), "the dialog was cancelled");
    assert!(!asked.answered(), "no completion reached the host");
    asked.host.stop().await;
}

/// KR-REQ-10.06: the person at this computer enters the account's Windows Hello PIN in the
/// dialog, the review answers "confirmed", and the host records exactly that answer, from this
/// owner device's presence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the person at this computer to enter the account's Windows Hello PIN"]
async fn a_person_who_enters_the_pin_confirms() {
    let window = windows_hello();
    let mut asked = Asked::new(&window).await;
    println!("== enter this account's Windows Hello PIN in the dialog");
    let outcome = asked
        .owner
        .review(&asked.request.reference)
        .await
        .expect("reviewed");
    assert_eq!(outcome, ReviewOutcome::Confirmed);
    let acceptance = asked
        .host
        .network()
        .pairing()
        .rows()
        .acceptance(asked.challenge.confirmation_id)
        .expect("readable")
        .expect("the host recorded the answer");
    assert_eq!(acceptance.channel, "owner_device_presence");
    assert!(!asked.still_asking().await, "the challenge is answered");
    asked.host.stop().await;
}
