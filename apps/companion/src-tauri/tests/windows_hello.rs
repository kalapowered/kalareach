//! Windows Hello as this computer's ceremony, run on Windows itself.
//!
//! The ceremony this computer offers is what Windows reports: `Available` offers Windows Hello,
//! and every other answer offers none, which the page shows as a row with no confirm button that
//! sends the person to another owner device. The first test reads that from the running system,
//! through the types the application uses, and runs on any Windows machine.
//!
//! The others raise Windows Hello's own dialog for a window of this process, so they need what a
//! person's computer has: a signed-in desktop, and Windows Hello set up for the account. They are
//! ignored, and run on purpose from a terminal on that desktop. The first command needs nobody at
//! the keyboard, because UI Automation presses the dialog's buttons, as desktop automation could,
//! and no credential is ever entered. The second needs the person, who enters the account's
//! Windows Hello PIN when the dialog asks.
//!
//! ```text
//! cargo test -p companion-tauri --test windows_hello -- --include-ignored --test-threads 1 --skip a_person_who_enters_the_pin_confirms
//! cargo test -p companion-tauri --test windows_hello -- --ignored --exact a_person_who_enters_the_pin_confirms
//! ```

#![cfg(windows)]

use std::io::Read as _;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use companion_tauri::device::{Device, Parts};
use companion_tauri::owner::Owner;
use companion_tauri::verify::hello::WindowsHello;
use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::CandidateRoom;
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::owner::{Ceremony as _, CeremonyKind, CeremonyOutcome};
use kr_client::pairing::room::{RoomError, RoomSocket};
use kr_crypto::store::MemoryStore;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::run_return::EventLoopExtRunReturn as _;
use tao::platform::windows::{EventLoopBuilderExtWindows as _, WindowExtWindows as _};
use tao::window::WindowBuilder;
use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Win32::Foundation::HWND;

/// The sentence the dialogs print, as a confirmation's description would read.
const REASON: &str = "Confirm that the test host may pair a new device that can view sessions.";

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
/// Cancel (`press`), or presses nothing (`watch`); either way it records when the dialog goes.
const AUTOMATION: &str = r#"param([string]$mode)
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
while ($clock.ElapsedMilliseconds - $seen -lt 60000) {
  if (-not (Find-Dialog)) { "== gone $($clock.ElapsedMilliseconds - $seen) ms after it was seen"; exit 0 }
  Start-Sleep -Milliseconds 200
}
'== still up after a minute'
exit 4
"#;

/// The automation, running beside a test.
struct Automation {
    child: Child,
    output: std::thread::JoinHandle<String>,
    _script: tempfile::TempDir,
}

impl Automation {
    fn start(mode: &str) -> Self {
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

/// KR-REQ-10.06: Windows Hello's dialog belongs to this computer's window and prints the
/// confirmation's sentence. Pressing its buttons through UI Automation, as desktop automation
/// could, with no credential entered, confirms nothing: the dialog closes on its own Cancel
/// button, and the answer is "not confirmed", well before the challenge's time runs out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "raises Windows Hello's dialog: needs a signed-in desktop with Windows Hello set up"]
async fn pressing_the_dialogs_buttons_without_a_credential_confirms_nothing() {
    const WITHIN: Duration = Duration::from_secs(60);
    let window = TestWindow::open();
    let ceremony = window.ceremony();
    assert_eq!(
        ceremony.kind(),
        CeremonyKind::WindowsHello,
        "Windows Hello is set up"
    );
    let automation = Automation::start("press");
    let started = Instant::now();
    let outcome = ceremony.verify(REASON, WITHIN).await;
    let answered = started.elapsed();
    let record = automation.finish(Duration::from_secs(30));
    println!("{record}");
    assert_eq!(outcome, CeremonyOutcome::NotConfirmed);
    assert!(
        answered < WITHIN,
        "the dialog answered, not the time: {answered:?}"
    );
    assert!(record.contains("== dialog "), "the dialog was raised");
    assert!(
        record
            .lines()
            .any(|line| line.starts_with("== text ") && line.contains(REASON)),
        "the dialog prints the sentence"
    );
    assert!(record.contains("== gone "), "the dialog closed");
}

/// KR-REQ-10.06: a dialog nobody answers is cancelled when the challenge's time runs out, the
/// answer is "not confirmed", and the dialog goes with it, so no late answer can reach a signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "raises Windows Hello's dialog: needs a signed-in desktop with Windows Hello set up"]
async fn a_dialog_left_past_the_challenges_time_is_cancelled_and_not_confirmed() {
    const WITHIN: Duration = Duration::from_secs(8);
    let window = TestWindow::open();
    let ceremony = window.ceremony();
    assert_eq!(
        ceremony.kind(),
        CeremonyKind::WindowsHello,
        "Windows Hello is set up"
    );
    let automation = Automation::start("watch");
    let started = Instant::now();
    let outcome = ceremony.verify(REASON, WITHIN).await;
    let answered = started.elapsed();
    let record = automation.finish(Duration::from_secs(30));
    println!("{record}");
    assert_eq!(outcome, CeremonyOutcome::NotConfirmed);
    assert!(
        answered >= WITHIN && answered < WITHIN + Duration::from_secs(5),
        "answered when the time ran out: {answered:?}"
    );
    assert!(record.contains("== dialog "), "the dialog was raised");
    assert!(!record.contains("== pressed"), "nothing pressed it");
    assert!(record.contains("== gone "), "the dialog was cancelled");
}

/// KR-REQ-10.06: the person at this computer enters the account's Windows Hello PIN in the
/// dialog, and the answer is "confirmed", the one answer that lets this computer sign.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs the person at this computer to enter the account's Windows Hello PIN"]
async fn a_person_who_enters_the_pin_confirms() {
    let window = TestWindow::open();
    let ceremony = window.ceremony();
    assert_eq!(
        ceremony.kind(),
        CeremonyKind::WindowsHello,
        "Windows Hello is set up"
    );
    println!("== enter this account's Windows Hello PIN in the dialog");
    let outcome = ceremony
        .verify(
            "Enter your PIN to confirm this test of KalaReach.",
            Duration::from_secs(120),
        )
        .await;
    assert_eq!(outcome, CeremonyOutcome::Confirmed);
}
