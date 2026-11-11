//! The installation, its removal and what each leaves on the computer, shown on a Windows guest.
//!
//! These cases install the boundary for real: they make accounts, a service and an
//! application-control policy for the whole computer, and they remove them. They run only in a
//! disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored afterwards, with the
//! variables and payload directories the guest's runner sets up:
//!
//! - `KR_BOUNDARY_BIN` names a directory that holds `kr-boundary-setup.exe`, a `payload`
//!   directory with the broker and the credential helper signed by the publisher the setup
//!   program was built to accept, a `payload-other` directory with both signed by another
//!   publisher and a `payload-unsigned` directory with both unsigned;
//! - the setup program is built with the `testing` feature, which lets a case make any step of
//!   an installation fail.
//!
//! Each case ends with the computer as it found it, whether it passes or fails.

#![cfg(windows)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kr_boundary_windows::env::{Kind, QualifiedGit, RootPaths, build_env};
use kr_boundary_windows::frame::{Class, Request, Response};
use kr_boundary_windows::manifest::{InstallState, Manifest, ObjectKind, Prior};
use kr_boundary_windows::messages;
use kr_boundary_windows::policy::{self, Policy, RULE_ALLOW_ALL};
use kr_boundary_windows::quote::quote_command_line;
use kr_boundary_windows::win::applocker::Channel;
use kr_boundary_windows::win::ffi::{self, Sid};
use kr_boundary_windows::win::install::{self, CHECKOUT, CONNECT, Paths, SERVICE, STEPS};
use kr_boundary_windows::win::launch::{Outcome, TokenSpec, VerifiedPath};
use kr_boundary_windows::win::proof::{Run, run_captured};
use kr_boundary_windows::win::{account, acl, boot, registry, service, token};

const CLEAR: &str = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;
const SPECIAL_ACCOUNTS: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the setup program and its payloads"),
    )
}

fn channel() -> Channel {
    Channel::new(&std::env::temp_dir())
}

/// What a case compares before and after: everything the installation may change.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    policy: Policy,
    appid_start: u32,
    appid_running: bool,
    accounts: [bool; 2],
    service: bool,
    program_dir: bool,
    data_dir: bool,
    hidden: Vec<String>,
}

fn snapshot() -> Snapshot {
    let paths = Paths::system();
    let manager = service::manager().unwrap();
    let appid = manager
        .open("AppIDSvc")
        .unwrap()
        .expect("the Application Identity service exists");
    let (_, policy) = channel().effective().unwrap();
    let mut hidden = registry::open(SPECIAL_ACCOUNTS)
        .unwrap()
        .map(|key| key.value_names().unwrap())
        .unwrap_or_default();
    hidden.sort();
    Snapshot {
        policy,
        appid_start: appid.configuration().unwrap().0,
        appid_running: appid.status().unwrap().running(),
        accounts: [
            account::find(CHECKOUT).is_some(),
            account::find(CONNECT).is_some(),
        ],
        // A service that is deleted but still listed because a handle to it is open is gone.
        service: manager
            .open(SERVICE)
            .unwrap()
            .is_some_and(|service| !service.marked_for_deletion().unwrap()),
        program_dir: paths.program.exists(),
        data_dir: paths.data.exists(),
        hidden,
    }
}

/// Runs the setup program with an answer on its input, and returns its exit code and output.
fn setup(arguments: &[&str], answer: &str, environment: &[(&str, &str)]) -> (i32, String) {
    let mut command = Command::new(bin().join("kr-boundary-setup.exe"));
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("the setup program starts");
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
    println!(
        "--- kr-boundary-setup {} -> {:?}\n{text}",
        arguments.join(" "),
        output.status.code()
    );
    (output.status.code().unwrap_or(-1), text)
}

/// The person the broker serves in a case, and the cleanup that puts the computer back.
struct Case {
    name: String,
    person: Sid,
}

impl Case {
    fn new() -> Case {
        assert!(
            token::current_is_administrator().unwrap(),
            "the case must run elevated"
        );
        let name = format!(
            "krperson{}",
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        );
        let person = account::create(&name).expect("the person's account is made");
        Case { name, person }
    }

    fn payload(&self, directory: &str, environment: &[(&str, &str)]) -> (i32, String) {
        let payload = bin().join(directory);
        setup(
            &[
                "install",
                "--payload",
                payload.to_str().unwrap(),
                "--person",
                &self.person.to_text(),
            ],
            "yes\n",
            environment,
        )
    }

    fn install(&self) -> (i32, String) {
        self.payload("payload", &[])
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = setup(&["remove"], "yes\n", &[]);
        let _ = channel().set(CLEAR);
        let _ = account::delete(&self.name);
    }
}

fn sc(arguments: &[&str]) -> String {
    let output = Command::new("sc.exe").args(arguments).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn privileges_in(text: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .split_whitespace()
        .filter(|word| word.starts_with("Se") && word.ends_with("Privilege"))
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn installation_lays_down_and_removal_restores() {
    let case = Case::new();
    let paths = Paths::system();
    let before = snapshot();
    assert!(
        before.policy.is_unconfigured(),
        "the guest starts with no application control"
    );

    let (code, output) = case.install();
    assert_eq!(code, 0, "the installation succeeds: {output}");

    // The order: the platform's application control is started and reported before the policy is
    // written, reported again after it, and only then is the unlisted program started.
    let mut at = 0;
    for line in [
        messages::APPLICATION_CONTROL_STARTING,
        "application control has started",
        "the policy is written",
        "the platform has applied the policy",
        "an unlisted program was refused",
    ] {
        let found = output[at..]
            .find(line)
            .unwrap_or_else(|| panic!("{line:?} comes next in: {output}"));
        at += found + line.len();
    }
    // The first launch of the proof meets a policy that is in force: it passes within a few launches.
    for line in output
        .lines()
        .filter(|l| l.contains("an unlisted program was refused"))
    {
        let launches: u32 = line
            .split("after ")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("the proof line names its launches: {line}"));
        eprintln!("proof line: {line}");
        assert!(launches <= 5, "the proof passed at once: {line}");
    }

    // Every object is there, as the manifest says.
    let manifest = Manifest::load(&paths.manifest).unwrap();
    assert_eq!(manifest.state, InstallState::Installed);
    assert_eq!(manifest.persons, [case.person.to_text()]);
    let mut sids = Vec::new();
    for name in [CHECKOUT, CONNECT] {
        let sid = Sid::of_account(name).expect("the account exists");
        assert_eq!(
            manifest
                .find(ObjectKind::Account, name)
                .unwrap()
                .detail
                .as_deref(),
            Some(sid.to_text().as_str())
        );
        let rights = account::rights_of(&sid).unwrap();
        for right in account::DENY_RIGHTS {
            assert!(
                rights.iter().any(|held| held == right),
                "{name} holds {right}: {rights:?}"
            );
        }
        assert!(
            account::hidden_from_sign_in(name).unwrap(),
            "{name} is off the sign-in screen"
        );
        sids.push(sid);
    }
    let manager = service::manager().unwrap();
    // This handle stays open through the removal, as a services console's would: the removal must
    // finish although the service manager keeps the deleted service listed until the handle closes.
    let broker = manager.open(SERVICE).unwrap().expect("the service exists");
    let (start, path) = broker.configuration().unwrap();
    assert_eq!(start, 2, "the service starts with Windows");
    assert_eq!(
        path,
        format!(
            "\"{}\"",
            paths.program.join("kr-boundary-broker.exe").display()
        )
    );
    assert!(broker.status().unwrap().running());
    assert_eq!(
        privileges_in(&sc(&["qprivs", SERVICE])),
        [
            "SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege",
            "SeChangeNotifyPrivilege",
            "SeImpersonatePrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeRestorePrivilege",
            "SeTcbPrivilege"
        ],
        "the service holds the privileges it uses and no others"
    );
    // The access list is the part before the audit list, which every service carries for everyone.
    let security = sc(&["sdshow", SERVICE]);
    let access = security.split("S:").next().unwrap_or_default();
    assert!(
        access.contains(&format!("(A;;CCLCLORC;;;{})", case.person.to_text())),
        "the person may only look at the service: {security}"
    );
    assert!(
        !access.contains(";;;WD)") && !access.contains(";;;AU)"),
        "no one else may reach the service: {security}"
    );

    // The files are the administrators' and match the recorded digests.
    assert_eq!(
        acl::changeable_by_others(&paths.program, false).unwrap(),
        None
    );
    assert_eq!(acl::changeable_by_others(&paths.data, false).unwrap(), None);
    assert!(
        !acl::describe(&paths.data).unwrap().contains(";;;BU)"),
        "no one else may read the data directory"
    );
    for object in manifest.of_kind(ObjectKind::File) {
        let file = Path::new(&object.id);
        assert_eq!(acl::changeable_by_others(file, false).unwrap(), None);
        let bytes = std::fs::read(file).unwrap();
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes));
        assert_eq!(object.detail.as_deref(), Some(digest.as_str()));
    }

    // The journal's directory and the parent of the private roots are the administrators' alone and
    // empty; the directory Git's own settings point at holds nothing but empty names.
    for directory in [&paths.journal, &paths.run] {
        assert!(directory.is_dir(), "{} exists", directory.display());
        assert_eq!(acl::changeable_by_others(directory, false).unwrap(), None);
        let described = acl::describe(directory).unwrap();
        for everyone in [";;;BU)", ";;;WD)", ";;;AU)"] {
            assert!(
                !described.contains(everyone),
                "no account but the administrators and the system is named on {}: {described}",
                directory.display()
            );
        }
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0);
    }
    assert_eq!(
        std::fs::metadata(paths.git.join("config")).unwrap().len(),
        0,
        "the global configuration Git is pointed at is empty"
    );
    for part in ["hooks", "template"] {
        let directory = paths.git.join(part);
        assert!(directory.is_dir(), "{} exists", directory.display());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    }
    assert_eq!(acl::changeable_by_others(&paths.git, false).unwrap(), None);
    assert!(
        kr_boundary_windows::win::walk::DirHandle::open_anchor(&paths.run)
            .unwrap()
            .is_ok(),
        "the directory of the private roots is a directory the walk accepts as its anchor"
    );
    // The boot marker is made under the service's key, which only the system and the
    // administrators can write, and is the same on the next read.
    let first = boot::marker().unwrap();
    assert!(first.trusted, "the marker is believed: {:?}", first.reason);
    assert!(first.made, "the first read since the start made it");
    assert!(
        uuid::Uuid::parse_str(&first.id).is_ok(),
        "the marker is a GUID: {}",
        first.id
    );
    let second = boot::marker().unwrap();
    assert_eq!(
        (second.id.as_str(), second.made),
        (first.id.as_str(), false)
    );
    // No hive of an account's is loaded, no profile folder is made, and neither a window station nor
    // a desktop of ours exists: the boundary's tokens run with none of them.
    let loaded = Command::new("reg.exe")
        .args(["query", "HKU"])
        .output()
        .unwrap();
    let loaded = String::from_utf8_lossy(&loaded.stdout).into_owned();
    for (name, sid) in [CHECKOUT, CONNECT].iter().zip(&sids) {
        assert!(
            !loaded.contains(&sid.to_text()),
            "no hive of {name} is loaded: {loaded}"
        );
        assert!(
            !Path::new(&format!(r"C:\Users\{name}")).exists(),
            "no profile folder of {name} is made"
        );
    }
    let stations = kr_boundary_windows::win::ffi::window_station_names().unwrap();
    assert!(
        stations
            .iter()
            .all(|name| !name.to_lowercase().contains("kalareach")
                && !name.to_lowercase().contains("krb")),
        "no window station of ours exists: {stations:?}"
    );

    // The policy is what was written, and the Application Identity service is on.
    let (_, effective) = channel().effective().unwrap();
    let wanted = Policy::installed(&sids[0].to_text(), &sids[1].to_text());
    assert!(
        effective.differences(&wanted).is_empty(),
        "{:?}",
        effective.differences(&wanted)
    );
    let appid = manager.open("AppIDSvc").unwrap().unwrap();
    assert_eq!(appid.configuration().unwrap().0, 2);
    assert!(appid.status().unwrap().running());

    // What was there before is recorded once.
    let prior = Prior::load(&paths.prior).unwrap();
    assert_eq!(prior.appid_start_type, before.appid_start);
    assert!(Policy::parse(&prior.policy_xml).unwrap().is_unconfigured());

    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "the removal succeeds: {output}");
    assert_eq!(
        snapshot(),
        before,
        "the computer is as it was before the installation"
    );
}

/// The programs of an ordinary account outside an administrator's narrow rule must still run once the
/// removal has taken the boundary's rules away: the allow-all rule stays beside that rule.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn removal_keeps_an_administrators_later_rule_and_the_rule_that_lets_others_run() {
    let case = Case::new();
    let before = snapshot();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");

    // An administrator adds a narrow rule of their own.
    let (xml, _) = channel().effective().unwrap();
    let theirs = "22222222-2222-2222-2222-222222222222";
    let rule = format!(
        r#"<FilePathRule Id="{theirs}" Name="Administrator tools" Description="d" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\Tools\*" /></Conditions></FilePathRule>"#
    );
    channel()
        .set(&xml.replace("</RuleCollection>", &format!("{rule}</RuleCollection>")))
        .unwrap();

    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
    assert!(
        output.contains("administrator's rule"),
        "the removal says what it kept: {output}"
    );

    let after = snapshot();
    let exe = &after.policy.collections["Exe"];
    let ids: Vec<&str> = exe.rules.keys().map(String::as_str).collect();
    assert_eq!(
        ids,
        [theirs, RULE_ALLOW_ALL],
        "the deny rules are gone and the allow-all rule and the administrator's stay"
    );
    assert_eq!(exe.mode, policy::Mode::Enabled);
    assert_eq!(after.accounts, [false, false]);
    assert!(!after.service && !after.program_dir && !after.data_dir);
    assert_eq!(
        after.appid_start, before.appid_start,
        "the start type is back"
    );

    // A program of an ordinary account, outside the administrator's rule, still runs.
    let folder =
        PathBuf::from(r"C:\Users\Public").join(format!("krcase-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&folder).unwrap();
    let copy = folder.join("outside.exe");
    std::fs::copy(r"C:\Windows\System32\hostname.exe", &copy).unwrap();
    let ordinary = token::baseline_token(&case.name).unwrap();
    let environment = build_env(
        Kind::Proof,
        &RootPaths {
            system: r"C:\Windows".to_owned(),
            boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
            private_root: folder.display().to_string(),
        },
        None,
        &QualifiedGit {
            dir: r"C:\Program Files\Git".to_owned(),
        },
    )
    .unwrap();
    let outcome = run_captured(
        Run {
            token: TokenSpec::Boundary(&ordinary),
            group: None,
            program: VerifiedPath::new(&copy).unwrap(),
            command_line: quote_command_line(&["outside.exe"]),
            cwd: &folder,
            env: &environment,
        },
        std::time::Duration::from_secs(30),
    )
    .unwrap()
    .outcome;
    let _ = std::fs::remove_dir_all(&folder);
    assert_eq!(
        outcome,
        Outcome::Ran(0),
        "an ordinary account's program outside the rule runs"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn existing_application_control_stops_the_installation_and_changes_nothing() {
    let case = Case::new();
    let existing = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="44444444-4444-4444-4444-444444444444" Name="Allow everything" Description="d" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#;
    channel().set(existing).unwrap();
    let before = snapshot();
    assert!(!before.policy.is_unconfigured());
    let (code, output) = case.install();
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains("already enforces application control"),
        "{output}"
    );
    assert_eq!(snapshot(), before, "nothing was changed");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn payloads_that_are_unsigned_wrongly_signed_or_links_are_refused() {
    let case = Case::new();
    let before = snapshot();
    for (directory, why) in [
        ("payload-unsigned", "does not carry a signature that holds"),
        ("payload-other", "is signed by CN=Other Test Publisher"),
    ] {
        let (code, output) = case.payload(directory, &[]);
        assert_ne!(code, 0, "{directory}: {output}");
        assert!(output.contains(why), "{directory}: {output}");
        assert_eq!(snapshot(), before, "{directory}: nothing remains");
    }
    // A payload file that is a link is refused before it is read.
    let linked = bin().join("payload-linked");
    let _ = std::fs::remove_dir_all(&linked);
    std::fs::create_dir_all(&linked).unwrap();
    for name in ["kr-boundary-broker.exe", "kr-boundary-credential.exe"] {
        let target = bin().join("payload").join(name);
        std::os::windows::fs::symlink_file(&target, linked.join(name)).unwrap();
    }
    let (code, output) = case.payload("payload-linked", &[]);
    let _ = std::fs::remove_dir_all(&linked);
    assert_ne!(code, 0, "{output}");
    assert!(output.contains("is a link, not a file"), "{output}");
    assert_eq!(snapshot(), before, "nothing remains");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_failure_at_any_step_is_undone_to_the_earlier_state() {
    let case = Case::new();
    let before = snapshot();
    for step in STEPS {
        let (code, output) = case.payload("payload", &[("KR_BOUNDARY_FAIL_AFTER", step)]);
        assert_ne!(code, 0, "{step}: {output}");
        assert!(
            output.contains(&format!("injected after the {step} step")),
            "{step}: {output}"
        );
        assert!(
            output.contains("the earlier state is back"),
            "{step}: {output}"
        );
        assert_eq!(
            snapshot(),
            before,
            "after a failure at the {step} step the computer is as it was"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn entry_states_are_told_apart_and_a_repair_enrols_another_person() {
    let case = Case::new();
    let before = snapshot();

    // An account of the installation's names that it did not make: refused, naming it.
    account::create(CHECKOUT).unwrap();
    let (code, output) = case.install();
    account::delete(CHECKOUT).unwrap();
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains(CHECKOUT) && output.contains("did not make it"),
        "{output}"
    );
    assert_eq!(snapshot(), before);

    // Installed: a second install is refused, and a repair by another person enrols that person.
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let (code, output) = case.install();
    assert_ne!(code, 0, "{output}");
    assert!(output.contains("already installed"), "{output}");

    let other_name = format!("krother{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let other = account::create(&other_name).unwrap();
    let payload = bin().join("payload");
    let (code, output) = setup(
        &[
            "repair",
            "--payload",
            payload.to_str().unwrap(),
            "--person",
            &other.to_text(),
        ],
        "yes\n",
        &[],
    );
    assert_eq!(code, 0, "{output}");
    let manifest = Manifest::load(&Paths::system().manifest).unwrap();
    assert_eq!(manifest.persons, [case.person.to_text(), other.to_text()]);
    assert!(sc(&["sdshow", SERVICE]).contains(&format!("(A;;CCLCLORC;;;{})", other.to_text())));

    let (code, output) = setup(&["remove"], "yes\n", &[]);
    let _ = account::delete(&other_name);
    assert_eq!(code, 0, "{output}");
    assert_eq!(snapshot(), before);
}

/// Run by a startup task after the guest's Windows restarts with the boundary installed: the broker
/// that the service manager started with Windows proves the boundary inside its bound.
#[test]
#[ignore = "runs after a restart of the guest with the boundary installed (see the file's header)"]
fn after_a_restart_the_brokers_proof_passes_inside_its_bound() {
    let uptime = std::time::Duration::from_millis(ffi::uptime_millis());
    let mut session = install::open_session().expect("the broker started with Windows");
    for class in [Class::Checkout, Class::Connect] {
        let begun = std::time::Instant::now();
        match install::ask(&mut session, &Request::Prove { class }).expect("the broker answers") {
            Response::Proof { ready, detail } => {
                eprintln!(
                    "{class:?}: ready {ready} after {:.1} s, asked {:.0} s after the start of Windows: {detail}",
                    begun.elapsed().as_secs_f32(),
                    uptime.as_secs_f32()
                );
                assert!(ready, "the proof passes: {detail}");
            }
            other => panic!("the broker answered a proof with {other:?}"),
        }
    }
}
