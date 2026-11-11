//! Which part of a launch changes whether the platform refuses an unlisted program to a boundary
//! account, shown on a Windows guest.
//!
//! Each round installs the boundary with the broker's launcher changed in one way (a registry value
//! that only the `testing` build reads), lets the installation's own proof run, and records how many
//! launches and how many seconds it took until the policy first refused the unlisted program to each
//! of the two accounts, with the state of the application-identity service and the time of the first
//! refusal the application-control log holds. The round ends with the boundary removed.
//!
//! The cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored
//! afterwards, with `KR_BOUNDARY_BIN` naming the directory that holds the setup program and the
//! signed payload.

#![cfg(all(windows, feature = "testing"))]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kr_boundary_windows::win::applocker::Channel;
use kr_boundary_windows::win::{account, registry};

const KEY: &str = r"SOFTWARE\KalaReach\BoundaryTest";
const CLEAR: &str = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;

/// The ways the launcher is changed, one at a time, and the figure the registry value takes.
const ROUNDS: &[(&str, u32)] = &[
    ("the launcher as it is", 0x00),
    ("without the job attribute", 0x01),
    ("without the handle list", 0x02),
    ("with the default process and thread descriptors", 0x04),
    ("created not suspended", 0x08),
    ("with the default error mode", 0x10),
    ("with the old environment block", 0x20),
    ("with all six taken back, as the old launcher was", 0x3f),
];

fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the setup program and its payload"),
    )
}

fn setup(arguments: &[&str], answer: &str) -> (i32, String) {
    let mut child = Command::new(bin().join("kr-boundary-setup.exe"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the setup program starts");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code().unwrap_or(-1), text)
}

fn tool(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program).args(arguments).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The lines of the installer's output that say what the proof showed for each account.
fn proof_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            line.contains("an unlisted program was refused")
                || line.contains("the proof failed")
                || line.starts_with("krb-")
        })
        .map(|line| line.chars().take(900).collect())
        .collect()
}

fn service_state() -> String {
    tool("sc.exe", &["query", "AppIDSvc"])
        .lines()
        .filter(|line| line.contains("STATE"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The time of the oldest refusal the application-control log holds, as the log's own text gives it.
fn first_refusal() -> String {
    tool(
        "wevtutil.exe",
        &[
            "qe",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "/q:*[System[(EventID=8004)]]",
            "/c:1",
            "/rd:false",
            "/f:text",
        ],
    )
    .lines()
    .filter(|line| line.contains("Date:") || line.contains("Event ID:"))
    .map(str::trim)
    .collect::<Vec<_>>()
    .join(" ")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_policy_refuses_an_unlisted_program_in_every_creation_form_or_the_form_is_named() {
    let name = format!(
        "krperson{}",
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    );
    let person = account::create(&name).expect("the person's account is made");
    let payload = bin().join("payload");
    for (what, bits) in ROUNDS {
        let key = registry::create(KEY).unwrap();
        key.set_dword("Variant", *bits).unwrap();
        key.set_dword("ProofBoundSeconds", 150).unwrap();
        let started = std::time::Instant::now();
        let (code, text) = setup(
            &[
                "install",
                "--payload",
                payload.to_str().unwrap(),
                "--person",
                &person.to_text(),
            ],
            "yes\n",
        );
        println!("== round: {what} (variant {bits:#x})");
        println!(
            "   the installation took {:.0} s and ended with {code}",
            started.elapsed().as_secs_f32()
        );
        for line in proof_lines(&text) {
            println!("   {line}");
        }
        println!("   application-identity service: {}", service_state());
        println!("   first refusal in the log: {}", first_refusal());
        let (removed, _) = setup(&["remove"], "yes\n");
        println!("   removal ended with {removed}");
        let _ = Channel::new(&std::env::temp_dir()).set(CLEAR);
    }
    let _ = registry::delete_key(KEY);
    let _ = account::delete(&name);
}
