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
#![allow(unsafe_code)]

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

/// A case that installs, or that binds the broker's pipe, starts from a machine with no
/// installation on it: the service, the two boundary accounts, the data directory, the program
/// directory and the pipe's name are all absent. A case that failed before its own cleanup, or a
/// run that was cut short, leaves some of them, and every later case then fails for that and not
/// for what it shows: this fails first, with one text, so that the run is void and never a verdict
/// on the product.
fn require_clean_machine() {
    let mut left = Vec::new();
    if service::manager().unwrap().open(SERVICE).unwrap().is_some() {
        left.push("the broker's service".to_owned());
    }
    for name in [CHECKOUT, CONNECT] {
        if Sid::of_account(name).is_ok() {
            left.push(format!("the account {name}"));
        }
    }
    let paths = Paths::system();
    if paths.data.exists() {
        left.push("the data directory".to_owned());
    }
    if paths.program.exists() {
        left.push("the program directory".to_owned());
    }
    if std::fs::metadata(kr_boundary_windows::win::pipe::NAME).is_ok() {
        left.push("the broker's pipe".to_owned());
    }
    assert!(
        left.is_empty(),
        "the machine is not clean: {}",
        left.join(", ")
    );
}

impl Case {
    fn new() -> Case {
        require_clean_machine();
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
    assert_eq!(
        acl::changeable_by_others(paths.data_parent(), false).unwrap(),
        None,
        "the folder above the data directory is the system's own too"
    );
    assert!(
        !acl::describe(&paths.data).unwrap().contains(";;;BU)"),
        "no one else may read the data directory"
    );
    assert!(
        acl::describe(paths.data_parent()).unwrap().contains("D:P"),
        "the folder above the data directory takes nothing from its own parent"
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

    // A proof whose deadline has passed fails and takes no success.
    let manifest = Manifest::load(&paths.manifest).unwrap();
    let stop = kr_boundary_windows::win::pipe::Stop::new().unwrap();
    let late = kr_boundary_windows::win::proof::prove(
        &manifest,
        Class::Checkout,
        &paths.staging,
        std::time::Instant::now(),
        &stop,
    );
    assert!(!late.ready, "{}", late.detail);
    assert!(late.detail.contains("deadline"), "{}", late.detail);

    // A search that ends at its own deadline still reads the log's last words, from the time kept
    // for them, and ends inside the proof's deadline: the manifest names the wrong identifier for
    // the account, so no event of the log ever matches and the search has to give up.
    let mut wrong = Manifest::load(&paths.manifest).unwrap();
    wrong
        .objects
        .iter_mut()
        .find(|object| object.kind == ObjectKind::Account && object.id == CHECKOUT)
        .expect("the checkout account is recorded")
        .detail = Some("S-1-5-21-1-2-3-1999".to_owned());
    let bound = std::time::Duration::from_secs(30);
    let began = std::time::Instant::now();
    let gave_up = kr_boundary_windows::win::proof::prove(
        &wrong,
        Class::Checkout,
        &paths.staging,
        began + bound,
        &stop,
    );
    let took = began.elapsed();
    assert!(!gave_up.ready, "{}", gave_up.detail);
    assert!(
        gave_up
            .detail
            .contains("the application-control log last said"),
        "the log's last words are read from the reserved time: {}",
        gave_up.detail
    );
    assert!(
        gave_up.detail.contains("launches in"),
        "the search made its launches: {}",
        gave_up.detail
    );
    assert!(
        took <= bound,
        "the proof ended inside its deadline: {took:?}"
    );

    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "the removal succeeds: {output}");
    assert_eq!(
        snapshot(),
        before,
        "the computer is as it was before the installation"
    );
    // The service manager keeps the deleted service's key until the last handle to it closes. The
    // handle this case held through the removal is closed first, and the case waits until the key is
    // gone, so that what follows starts with no service key at all.
    drop(broker);
    let service_key = r"SYSTEM\CurrentControlSet\Services\KalaReachBoundary";
    let key_gone = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while registry::open(service_key).unwrap().is_some() {
        assert!(
            std::time::Instant::now() < key_gone,
            "the service's key is still there after its last handle closed"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    // Without the service there is no marker, and asking for one makes no key: a volatile service
    // key left behind would stop the next installation from storing the service's settings.
    assert!(boot::marker().is_err());
    assert!(
        registry::open(service_key).unwrap().is_none(),
        "no service key was made by asking for the marker"
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
        std::time::Instant::now() + std::time::Duration::from_secs(30),
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

/// A folder under `%ProgramData%` as the system's setup leaves it for a new one: with the list it
/// inherits, which lets ordinary accounts add to it. The Administrators own it, as they own
/// everything the installation makes, whichever token the case runs under: a folder owned by the
/// token's default owner is refused for its owner before its list is read, and a case that expects
/// the list would pass for the wrong reason.
fn inherited_folder() -> PathBuf {
    let folder = PathBuf::from(r"C:\ProgramData").join(format!(
        "krparent-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    owned_dir(&folder);
    folder
}

/// Makes a folder that the Administrators own, as the installation's own folders are, so that a
/// refusal of it is for what the case names and not for an owner that the token's default chose.
fn owned_dir(path: impl AsRef<Path>) {
    std::fs::create_dir(path.as_ref()).unwrap();
    give_to(path.as_ref(), "Administrators");
}

/// Writes a file that the Administrators own, for the same reason as [`owned_dir`].
#[cfg(feature = "testing")]
fn owned_file(path: impl AsRef<Path>, bytes: &[u8]) {
    std::fs::write(path.as_ref(), bytes).unwrap();
    give_to(path.as_ref(), "Administrators");
}

/// Gives a file or a directory to another account, as the tool does for a person.
fn give_to(path: &Path, who: &str) {
    let done = Command::new("icacls")
        .arg(path)
        .args(["/setowner", who])
        .output()
        .unwrap();
    assert!(done.status.success(), "{done:?}");
}

fn paths_under(folder: &Path) -> Paths {
    Paths {
        data: folder.join("Boundary"),
        ..Paths::system()
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_folder_above_the_data_directory_that_others_own_may_write_in_or_have_replaced_by_a_link_is_refused()
 {
    require_clean_machine();
    // Absent: nothing to refuse, and the installation makes it with its own list.
    let absent = PathBuf::from(r"C:\ProgramData").join("krparent-absent");
    assert!(!absent.exists());
    install::check_data_parent(&paths_under(&absent)).expect("an absent folder is made later");

    // A folder with the inherited list lets ordinary accounts add to it.
    let inherited = inherited_folder();
    let refused = install::check_data_parent(&paths_under(&inherited)).unwrap_err();
    let text = refused.to_string();
    assert!(
        text.contains("holds the boundary's data"),
        "what the folder is: {text}"
    );
    assert!(text.contains("is refused because"), "why: {text}");
    assert!(text.contains("Remove the folder"), "what to do: {text}");
    assert!(text.contains("holds no data directory"), "{text}");

    // The same refusal for a folder that holds the data directory, with its manifest, journals and
    // roots, never says to remove it: it says what to correct.
    owned_dir(inherited.join("Boundary"));
    let text = install::check_data_parent(&paths_under(&inherited))
        .unwrap_err()
        .to_string();
    assert!(text.contains("is refused because"), "why: {text}");
    assert!(!text.contains("Remove the folder"), "{text}");
    assert!(!text.contains("remove the folder"), "{text}");
    assert!(text.contains("Do not remove it"), "{text}");
    assert!(text.contains("Correct it instead"), "{text}");
    assert!(text.contains("protected list"), "{text}");
    std::fs::remove_dir(inherited.join("Boundary")).unwrap();

    // The same folder, with the installation's own list, is accepted.
    acl::set_protected(
        &inherited,
        &kr_boundary_windows::win::sd::descriptor(
            kr_boundary_windows::win::sd::SdKind::DataParent,
            &kr_boundary_windows::win::sd::Principals::default(),
        )
        .unwrap(),
    )
    .unwrap();
    install::check_data_parent(&paths_under(&inherited)).expect("a protected folder is accepted");

    // A folder that a non-administrator owns is refused whatever its list says.
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    let status = Command::new("icacls")
        .arg(&inherited)
        .args(["/setowner", &name])
        .output()
        .unwrap();
    assert!(status.status.success(), "{status:?}");
    let refused = install::check_data_parent(&paths_under(&inherited)).unwrap_err();
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    let _ = account::delete(&name);
    let _ = std::fs::remove_dir_all(&inherited);

    // A link in its place is refused, though what it points at is the system's own and the link's
    // own list is the installation's (it is made inside a folder that hands that list on), so that
    // the refusal of a link is the only refusal.
    let container = inherited_folder();
    acl::set_protected(&container, &data_parent_descriptor()).unwrap();
    let target = inherited_folder();
    acl::set_protected(&target, &data_parent_descriptor()).unwrap();
    let link = container.join("link");
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let refused = install::check_data_parent(&paths_under(&link)).unwrap_err();
    assert!(
        refused.to_string().contains("it is a link or not a folder"),
        "{refused}"
    );
    let _ = std::fs::remove_dir(&link);
    let _ = std::fs::remove_dir_all(&container);
    let _ = std::fs::remove_dir_all(&target);
}

fn data_parent_descriptor() -> kr_boundary_windows::win::sd::OwnedSd {
    kr_boundary_windows::win::sd::descriptor(
        kr_boundary_windows::win::sd::SdKind::DataParent,
        &kr_boundary_windows::win::sd::Principals::default(),
    )
    .unwrap()
}

/// A handle on a folder, opened by the case as another program would: any sharing, and the rights
/// named.
#[cfg(feature = "testing")]
fn open_folder(folder: &Path, access: u32) -> ffi::Handle {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let wide = ffi::wide_path(folder);
    // SAFETY: the path is NUL-terminated; the call keeps nothing of it.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    ffi::Handle::new(raw, "opening a folder").unwrap()
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_parent_folder_is_checked_on_one_handle_that_is_held_and_an_entry_of_an_unknown_type_is_refused()
 {
    require_clean_machine();
    use kr_boundary_windows::win::sd::{self, SdKind};
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_LIST_DIRECTORY: u32 = 1;
    let folder = inherited_folder();
    let protected = sd::descriptor(SdKind::DataParent, &sd::Principals::default()).unwrap();
    acl::set_protected(&folder, &protected).unwrap();

    // The folder the installation itself makes passes the check on a handle.
    let own = open_folder(&folder, FILE_LIST_DIRECTORY | READ_CONTROL);
    assert_eq!(acl::changeable_by_others_on(&own, false).unwrap(), None);
    drop(own);

    // A handle that another program already holds with the right to delete the folder makes the
    // check refuse: it could rename the folder after the check.
    let holder = open_folder(&folder, DELETE);
    let refused = install::check_data_parent(&paths_under(&folder)).unwrap_err();
    assert!(
        refused.to_string().contains("holds it open"),
        "the folder is refused while a handle that can delete it is open: {refused}"
    );
    drop(holder);

    // The handle the check keeps blocks a rename or a delete of the folder while it is held, and
    // the folder can be moved once it is closed.
    let held = install::check_data_parent(&paths_under(&folder))
        .unwrap()
        .expect("the folder is there");
    let moved = folder.with_extension("moved");
    assert!(
        std::fs::rename(&folder, &moved).is_err(),
        "the held folder cannot be renamed"
    );
    assert!(
        std::fs::remove_dir(&folder).is_err(),
        "the held folder cannot be deleted"
    );
    drop(held);
    std::fs::rename(&folder, &moved).expect("the closed folder moves");
    std::fs::rename(&moved, &folder).unwrap();

    // An entry that allows by a condition is a type the check does not read: refused, not skipped.
    let conditional = sd::descriptor_from_text(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(XA;OICI;FA;;;WD;(@User.Title==\"x\"))",
    )
    .unwrap();
    acl::set_protected(&folder, &conditional).unwrap();
    let refused = install::check_data_parent(&paths_under(&folder)).unwrap_err();
    assert!(
        refused.to_string().contains("type"),
        "a callback entry is refused: {refused}"
    );
    let handle = open_folder(&folder, FILE_LIST_DIRECTORY | READ_CONTROL);
    assert!(
        acl::changeable_by_others_on(&handle, false)
            .unwrap()
            .is_some_and(|finding| finding.contains("type")),
        "the handle form refuses it too"
    );
    drop(handle);

    // A plain user's allow entry is refused with the user named.
    let users = sd::descriptor_from_text("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
        .unwrap();
    acl::set_protected(&folder, &users).unwrap();
    let handle = open_folder(&folder, FILE_LIST_DIRECTORY | READ_CONTROL);
    let finding = acl::changeable_by_others_on(&handle, false)
        .unwrap()
        .unwrap();
    assert!(finding.contains("S-1-5-32-545"), "{finding}");
    // With replacement_only a right that only adds beside the folder does not count.
    let adds = sd::descriptor_from_text("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x6;;;BU)")
        .unwrap();
    acl::set_protected(&folder, &adds).unwrap();
    drop(handle);
    let handle = open_folder(&folder, FILE_LIST_DIRECTORY | READ_CONTROL);
    assert!(
        acl::changeable_by_others_on(&handle, false)
            .unwrap()
            .is_some()
    );
    assert_eq!(acl::changeable_by_others_on(&handle, true).unwrap(), None);
    drop(handle);
    let _ = std::fs::remove_dir_all(&folder);
}

/// The privileges that a running process's token holds, each with whether it is enabled, by name.
fn token_privileges_of_process(pid: u32) -> Vec<(String, bool)> {
    use windows_sys::Win32::Foundation::{HANDLE, LUID};
    use windows_sys::Win32::Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken};
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    // SAFETY: opens a process for a limited query; the result is checked.
    let process = unsafe {
        ffi::Handle::new(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid),
            "the service's process",
        )
        .unwrap()
    };
    let mut raw: HANDLE = std::ptr::null_mut();
    // SAFETY: the process handle is open and the out-parameter is local.
    assert_ne!(
        unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut raw) },
        0,
        "the service's token is opened for reading"
    );
    let token = ffi::Handle::new(raw, "the service's token").unwrap();
    let mut size = 0_u32;
    // SAFETY: asks for the size only.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenPrivileges,
            std::ptr::null_mut(),
            0,
            &raw mut size,
        );
    }
    let mut buffer = vec![0_u64; (size as usize).div_ceil(8)];
    // SAFETY: the buffer is at least `size` bytes.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenPrivileges,
                buffer.as_mut_ptr().cast(),
                size,
                &raw mut size,
            )
        },
        0
    );
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES: a count and that many entries.
    let privileges = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    // SAFETY: the entries follow the count and there are `PrivilegeCount` of them.
    let entries: &[LUID_AND_ATTRIBUTES] = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    entries
        .iter()
        .map(|entry| {
            let luid: LUID = entry.Luid;
            let mut length = 0_u32;
            // SAFETY: asks for the length of the name only.
            unsafe {
                LookupPrivilegeNameW(
                    std::ptr::null(),
                    &raw const luid,
                    std::ptr::null_mut(),
                    &raw mut length,
                );
            }
            let mut name = vec![0_u16; length as usize + 1];
            length = name.len() as u32;
            // SAFETY: the buffer is `length` units long.
            assert_ne!(
                unsafe {
                    LookupPrivilegeNameW(
                        std::ptr::null(),
                        &raw const luid,
                        name.as_mut_ptr(),
                        &raw mut length,
                    )
                },
                0
            );
            (
                String::from_utf16_lossy(&name[..length as usize]),
                entry.Attributes & SE_PRIVILEGE_ENABLED != 0,
            )
        })
        .collect()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_running_services_own_token_holds_the_privileges_the_installer_requires_and_no_others() {
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let manager = service::manager().unwrap();
    let broker = manager.open(SERVICE).unwrap().unwrap();
    let status = broker.status().unwrap();
    assert!(status.running(), "the broker's service is running");
    let held = token_privileges_of_process(status.pid);
    let names: Vec<&str> = held.iter().map(|(name, _)| name.as_str()).collect();
    println!("the running service's token holds {held:?}");

    // Every privilege the installer requires is held; the two that a walk enables on a thread's
    // copy of the token are held disabled, and the process token never has them enabled.
    for required in install::BROKER_PRIVILEGES {
        assert!(
            names.contains(&required),
            "{required} is required and the service's token lacks it: {names:?}"
        );
    }
    for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
        assert_eq!(
            held.iter()
                .find(|(held, _)| held == name)
                .map(|(_, on)| *on),
            Some(false),
            "{name} is held disabled"
        );
    }
    // And nothing beyond the list: the service manager takes away every privilege that the list
    // does not name, so none that could matter is there, the debug privilege (which a scheduled
    // task's system token has enabled, and the guest runner's token with it) least of all.
    for name in &names {
        assert!(
            install::BROKER_PRIVILEGES.contains(name),
            "{name} is held although the installer does not require it: {names:?}"
        );
    }

    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_data_directory_is_made_with_its_own_protected_list_and_one_that_is_there_is_checked_on_its_handle()
 {
    require_clean_machine();
    use kr_boundary_windows::win::sd;
    const READ_CONTROL: u32 = 0x0002_0000;
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";

    // The directory that the installation makes is protected, owned by the administrators and names
    // the system and the administrators alone, as soon as the making call returns: before the
    // protection step, so that no one holds a handle on a directory that took the folder's list.
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_under(&folder);
    // Made under a token whose default owner is the user, so that a descriptor that loses its owner
    // is caught under the system's own token too.
    let holds = with_the_users_own_default_owner(|| install::make_data_directory(&paths).unwrap());
    let handle = open_folder(&paths.data, READ_CONTROL);
    let made = sd::summary_of_handle(&handle).unwrap();
    drop(handle);
    assert_eq!(made.owner, ADMINISTRATORS);
    assert!(made.protected, "the directory took nothing from the folder");
    let named: Vec<&str> = made
        .entries
        .as_ref()
        .unwrap()
        .iter()
        .map(|entry| entry.sid.as_str())
        .collect();
    assert_eq!(named, [SYSTEM, ADMINISTRATORS]);

    // The two handles are held: neither the folder nor the directory can be renamed or deleted
    // while the protection step runs, and the step works on the handle.
    let moved = paths.data.with_extension("moved");
    assert!(std::fs::rename(&paths.data, &moved).is_err());
    assert!(std::fs::remove_dir(&paths.data).is_err());
    assert!(std::fs::rename(&folder, folder.with_extension("moved")).is_err());
    holds.protect().unwrap();
    drop(holds);
    std::fs::rename(&paths.data, &moved).expect("the directory moves once it is let go");
    std::fs::rename(&moved, &paths.data).unwrap();

    // A directory that is there is the installation's own: accepted.
    install::make_data_directory(&paths).expect("the installation's own directory is accepted");

    // An entry that only a child inherits, for another principal, makes the folder refused before
    // anything is made in it.
    let inheriting =
        sd::descriptor_from_text("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;BU)")
            .unwrap();
    let other = inherited_folder();
    acl::set_protected(&other, &inheriting).unwrap();
    let refused = install::make_data_directory(&paths_under(&other)).unwrap_err();
    assert!(refused.to_string().contains(USERS), "{refused}");
    assert!(
        !paths_under(&other).data.exists(),
        "nothing was made under the refused folder"
    );
    let _ = std::fs::remove_dir_all(&other);

    // A directory that is there and has another account's entry is refused, whatever the entry's
    // right: a person could read what the broker keeps there, or change it.
    for entry in [
        "(A;OICI;0x1301bf;;;BU)",
        "(A;;0x1200a9;;;BU)",
        "(A;OICIIO;0x100;;;BU)",
    ] {
        let text = format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){entry}");
        acl::set_protected(&paths.data, &sd::descriptor_from_text(&text).unwrap()).unwrap();
        let refused = install::make_data_directory(&paths).unwrap_err();
        let text = refused.to_string();
        assert!(
            text.contains("boundary's data directory"),
            "{entry}: {text}"
        );
        assert!(text.contains(USERS), "{entry}: {text}");
    }
    acl::set_protected(&paths.data, &data_parent_descriptor()).unwrap();

    // A directory that another account owns is refused whatever its list says.
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    let status = Command::new("icacls")
        .arg(&paths.data)
        .args(["/setowner", &name])
        .output()
        .unwrap();
    assert!(status.status.success(), "{status:?}");
    let refused = install::make_data_directory(&paths).unwrap_err();
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    let _ = account::delete(&name);
    let _ = std::fs::remove_dir_all(&paths.data);

    // A link in its place is refused although its own list is the installation's (it is made in a
    // folder that hands that list on), and a file is not a directory.
    let target = inherited_folder();
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&paths.data)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let refused = install::make_data_directory(&paths).unwrap_err();
    assert!(refused.to_string().contains("is a link"), "{refused}");
    let _ = std::fs::remove_dir(&paths.data);
    let _ = std::fs::remove_dir_all(&target);
    owned_file(&paths.data, b"not a directory");
    assert!(install::make_data_directory(&paths).is_err());
    let _ = std::fs::remove_file(&paths.data);
    let _ = std::fs::remove_dir_all(&folder);
}

/// The installation's places, all beneath one folder of the case's own.
#[cfg(feature = "testing")]
fn paths_in(folder: &Path) -> Paths {
    let data = folder.join("Boundary");
    let program = folder.join("Program");
    Paths {
        git: program.join("git"),
        program_top: folder.to_owned(),
        program,
        staging: data.join("staging"),
        journal: data.join("journal"),
        run: data.join("run"),
        manifest: data.join("manifest.json"),
        prior: data.join("prior.json"),
        data,
    }
}

/// A data directory with its manifest and its three directories, as an installation leaves it.
#[cfg(feature = "testing")]
fn installed_data_directory(paths: &Paths) {
    use install::DataChild;
    let mut holds = install::make_data_directory(paths).unwrap();
    holds.protect().unwrap();
    let mut manifest = Manifest::begin();
    for path in [&paths.data, &paths.staging, &paths.journal, &paths.run] {
        manifest.record(ObjectKind::Directory, &path.display().to_string(), None);
    }
    manifest.save(&paths.manifest).unwrap();
    for which in [DataChild::Staging, DataChild::Journal, DataChild::Run] {
        holds.directory(which).unwrap();
    }
}

/// The owner and the list of an object, read as another program would read them.
#[cfg(feature = "testing")]
fn summary_of(path: &Path) -> kr_boundary_windows::win::sd::Summary {
    const READ_CONTROL: u32 = 0x0002_0000;
    kr_boundary_windows::win::sd::summary_of_handle(&open_folder(path, READ_CONTROL)).unwrap()
}

/// The removal's last step deletes the leftover replacement of the manifest with the other records,
/// and when something cannot be removed it says what stayed, with the reason, instead of reporting
/// that the installation is removed.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_removal_deletes_a_leftover_replacement_and_names_what_stayed_when_the_data_directory_cannot_go()
 {
    require_clean_machine();
    use std::os::windows::fs::OpenOptionsExt;
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    std::fs::remove_dir(&paths.run).unwrap();
    std::fs::remove_dir(&paths.journal).unwrap();
    let replacement = paths.data.join(format!("manifest-{}.new", "ef".repeat(16)));
    owned_file(&replacement, b"half");
    // Held open and shared with nobody, the replacement cannot be deleted: the removal names it and
    // the data directory that therefore stays.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&replacement)
        .unwrap();
    let stayed = install::remove_records(&paths);
    let shown = replacement.display().to_string();
    assert!(
        stayed.iter().any(|line| line.contains(&shown)),
        "the replacement is named: {stayed:?}"
    );
    assert!(
        stayed
            .iter()
            .any(|line| line.contains(&paths.data.display().to_string())),
        "the data directory is named: {stayed:?}"
    );
    assert!(
        paths.staging.exists(),
        "staging goes last: it stays while a record stays"
    );
    drop(held);
    // Without the hold the replacement goes with the rest, and nothing is left to name.
    assert!(install::remove_records(&paths).is_empty());
    assert!(!paths.data.exists(), "the data directory is gone");
    let _ = std::fs::remove_dir_all(&folder);
}

/// The whole removal can be run again after a failure in its middle. Another program holds the
/// manifest open, so the last step cannot delete it and the removal fails and names it; the manifest
/// is still read by a second removal, which reads the policy records through the channel and needs
/// the staging directory that the first left in place. Once the program lets go, the second removal
/// finishes and the computer is as it was.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_removal_that_could_not_delete_a_record_is_run_again_whole_and_finishes() {
    use std::os::windows::fs::OpenOptionsExt;
    let case = Case::new();
    let before = snapshot();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let manifest = Paths::system().manifest;
    // Shared for reading and writing and not for deleting: the removal reads the manifest, and the
    // call that deletes it fails.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(&manifest)
        .unwrap();
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    drop(held);
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains(&manifest.display().to_string()),
        "the record that stayed is named: {output}"
    );
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(snapshot(), before, "the second removal finished");
}

/// A refusal in the program directory names a remedy that cures its reason, in a repair and in a
/// removal alike: a link or a second name for a file is removed, and only an owner or a list is
/// corrected. A directory that an account owns is refused in both before anything is changed.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_program_directory_refusal_names_the_remedy_for_its_reason_in_a_repair_and_in_a_removal() {
    require_clean_machine();
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    fresh::directory_all(
        &paths.program,
        SdKind::AdminDir,
        &Principals {
            users_may_read: true,
            ..Principals::default()
        },
    )
    .unwrap();
    let both = |what: &str| -> [String; 2] {
        [
            install::entry(&paths).err().expect(what).to_string(),
            install::remove(&paths, true).expect_err(what).to_string(),
        ]
    };

    // A link is removed; a change of owner or list does not cure it.
    let target = inherited_folder();
    let junction = paths.program.join("linked");
    let linked = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{linked:?}");
    for text in both("a link") {
        assert!(text.contains("it is a link"), "{text}");
        assert!(text.contains("Remove "), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
    }
    std::fs::remove_dir(&junction).unwrap();

    // A file with a second name is removed as well.
    let first = paths.program.join("first.exe");
    owned_file(&first, b"x");
    std::fs::hard_link(&first, paths.program.join("second.exe")).unwrap();
    for text in both("a second name") {
        assert!(text.contains("more than one name"), "{text}");
        assert!(text.contains("Remove "), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
    }
    std::fs::remove_file(paths.program.join("second.exe")).unwrap();
    std::fs::remove_file(&first).unwrap();

    // An owner that is not the installation's is corrected, and the directory is not removed.
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    give_to(&paths.program, &name);
    for text in both("an account-owned program directory") {
        assert!(
            text.contains(&owner.to_text()),
            "the refusal is for the owner: {text}"
        );
        assert!(text.contains("Make the Administrators group"), "{text}");
        assert!(text.contains("Do not remove it"), "{text}");
    }
    give_to(&paths.program, "Administrators");
    let _ = account::delete(&name);
    let _ = std::fs::remove_dir_all(&target);
    let _ = std::fs::remove_dir_all(&folder);
}

/// The program directory holds the names the installation gives it, each of its own kind: the two
/// programs are files; Git's settings are a directory with an empty configuration and two empty
/// directories. A name that is not given, a name of the wrong kind and a configuration that holds
/// anything are refused in a repair and in a removal alike, with the entry to remove and nothing
/// else; the complete layout, with an empty configuration, is accepted.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_program_directory_holds_only_the_names_the_installation_gives_each_of_its_kind_and_an_empty_configuration()
 {
    require_clean_machine();
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let readable = Principals {
        users_may_read: true,
        ..Principals::default()
    };
    fresh::directory_all(&paths.program, SdKind::AdminDir, &readable).unwrap();
    let both = |what: &str| -> [String; 2] {
        [
            install::entry(&paths).err().expect(what).to_string(),
            install::remove(&paths, true).expect_err(what).to_string(),
        ]
    };
    let refused = |what: &str, why: &str| {
        for text in both(what) {
            assert!(text.contains(why), "{what}: {text}");
            assert!(text.contains("Remove "), "{what}: {text}");
            assert!(
                !text.contains("Make the Administrators group"),
                "a change of owner or list does not cure it: {text}"
            );
        }
    };
    // Whatever else the check of the directory finds, it finds nothing in the names.
    let accepted = |what: &str| {
        for text in [
            install::entry(&paths).err().map(|error| error.to_string()),
            install::remove(&paths, true)
                .err()
                .map(|error| error.to_string()),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                !text.contains("boundary's program directory"),
                "{what}: {text}"
            );
        }
    };
    let broker = paths.program.join("kr-boundary-broker.exe");
    let credential = paths.program.join("kr-boundary-credential.exe");
    let config = paths.git.join("config");
    let hooks = paths.git.join("hooks");
    accepted("an empty program directory");

    // A name that the installation does not give there.
    let stray = paths.program.join("stray.txt");
    owned_file(&stray, b"x");
    refused("a name that is not given", "does not give that name there");
    std::fs::remove_file(&stray).unwrap();

    // A program that is a directory, and Git's directory that is a file.
    owned_dir(&broker);
    refused(
        "a program that is a directory",
        "it is a directory, not a file",
    );
    std::fs::remove_dir(&broker).unwrap();
    owned_file(&paths.git, b"x");
    refused(
        "Git's directory that is a file",
        "it is a file, not a directory",
    );
    std::fs::remove_file(&paths.git).unwrap();

    // The complete layout, with an empty configuration, is accepted.
    owned_file(&broker, b"x");
    owned_file(&credential, b"x");
    fresh::directory_at(&paths.git, SdKind::AdminDir, &readable).unwrap();
    fresh::directory_at(&hooks, SdKind::AdminDir, &readable).unwrap();
    fresh::directory_at(&paths.git.join("template"), SdKind::AdminDir, &readable).unwrap();
    drop(fresh::file_at(&config, SdKind::ProgramFile, true).unwrap());
    accepted("the complete layout");

    // A configuration that holds anything is not the empty one the manifest records.
    std::fs::write(&config, b"[core]\n").unwrap();
    refused("a configuration that holds settings", "it holds settings");
    std::fs::write(&config, b"").unwrap();
    accepted("the configuration emptied again");

    // The configuration that is a directory, and the hooks that are a file.
    std::fs::remove_file(&config).unwrap();
    owned_dir(&config);
    refused(
        "a configuration that is a directory",
        "it is a directory, not a file",
    );
    std::fs::remove_dir(&config).unwrap();
    drop(fresh::file_at(&config, SdKind::ProgramFile, true).unwrap());
    std::fs::remove_dir(&hooks).unwrap();
    owned_file(&hooks, b"x");
    refused("hooks that are a file", "it is a file, not a directory");
    std::fs::remove_file(&hooks).unwrap();
    fresh::directory_at(&hooks, SdKind::AdminDir, &readable).unwrap();

    // The empty directories hold nothing.
    owned_file(hooks.join("pre-commit"), b"x");
    refused("a hook", "does not give that name there");
    std::fs::remove_file(hooks.join("pre-commit")).unwrap();
    accepted("the hooks emptied again");
    let _ = std::fs::remove_dir_all(&folder);
}

/// The refusal of the folder above the data directory offers the remedy that its reason and what the
/// folder's handle shows allow. A folder that another account owns, or a link, was not made by the
/// installation: the text says so, offers to move it aside, and neither removes it nor corrects its
/// content into place, whether or not a data directory is in it. A folder that the system's class owns
/// and whose data directory cannot be looked up offers no removal. A folder that another program holds
/// open is cured by closing that program, and not by a change of owner or list.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_data_parents_refusal_offers_only_the_remedy_that_its_reason_and_its_handle_allow() {
    require_clean_machine();
    use std::os::windows::fs::OpenOptionsExt;
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    let never = |text: &str, said: &[&str]| {
        for said in said {
            assert!(!text.contains(said), "`{said}` in {text}");
        }
    };

    // Another account owns it: with or without a data directory in it, the installation did not
    // make it.
    let foreign = inherited_folder();
    give_to(&foreign, &name);
    for with_data in [false, true] {
        if with_data {
            owned_dir(foreign.join("Boundary"));
        }
        let text = install::check_data_parent(&paths_under(&foreign))
            .unwrap_err()
            .to_string();
        assert!(text.contains(&owner.to_text()), "{text}");
        assert!(
            text.contains("The installation did not make this folder"),
            "{text}"
        );
        assert!(text.contains("Move the folder aside"), "{text}");
        assert!(
            text.contains("unless you know that your own installation wrote it"),
            "{text}"
        );
        never(
            &text,
            &[
                "Remove the folder",
                "remove the folder",
                "Correct it instead",
                "loses nothing",
            ],
        );
    }

    // A link is not the installation's either.
    let target = inherited_folder();
    let link = PathBuf::from(r"C:\ProgramData").join(format!(
        "krparent-link-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let text = install::check_data_parent(&paths_under(&link))
        .unwrap_err()
        .to_string();
    assert!(text.contains("it is a link or not a folder"), "{text}");
    assert!(text.contains("Move the folder aside"), "{text}");
    never(
        &text,
        &[
            "Remove the folder",
            "remove the folder",
            "Correct it instead",
        ],
    );
    std::fs::remove_dir(&link).unwrap();

    // The system's class owns it and the data directory cannot be looked up (a name too long for
    // the file system answers with something other than not found): removal is not offered.
    let folder = inherited_folder();
    let unreadable = Paths {
        data: folder.join("a".repeat(300)),
        ..Paths::system()
    };
    let text = install::check_data_parent(&unreadable)
        .unwrap_err()
        .to_string();
    assert!(text.contains("could not be read"), "{text}");
    assert!(text.contains("Correct it instead"), "{text}");
    never(
        &text,
        &["Remove the folder", "remove the folder", "loses nothing"],
    );

    // Another program holds it open and shares nothing: that is cured by closing the program.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000)
        .open(&folder)
        .unwrap();
    let text = install::check_data_parent(&paths_under(&folder))
        .unwrap_err()
        .to_string();
    drop(held);
    assert!(text.contains("another program holds it open"), "{text}");
    assert!(
        text.contains("Close the program that holds it open"),
        "{text}"
    );
    assert!(text.contains("Do not remove it"), "{text}");
    never(
        &text,
        &["Remove the folder", "protected list", "Correct it instead"],
    );

    let _ = account::delete(&name);
    let _ = std::fs::remove_dir_all(&foreign);
    let _ = std::fs::remove_dir_all(&target);
    let _ = std::fs::remove_dir_all(&folder);
}

/// Every folder above the program directory that the installation did not make is read part by part
/// before the program directory is used: one that another account can add to, rename or delete in,
/// or whose list it can change, and one that is a link, is refused in a repair and in a removal
/// alike, with the folder named, and a plain protected folder is accepted.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_folder_above_the_program_directory_that_others_can_change_or_that_is_a_link_is_refused() {
    require_clean_machine();
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let mut paths = paths_in(&folder);
    installed_data_directory(&paths);
    let above = inherited_folder();
    paths.program = above.join("Program");
    paths.program_top = above.clone();
    paths.git = paths.program.join("git");
    let refused = |paths: &Paths, what: &str| -> [String; 2] {
        [
            install::entry(paths).err().expect(what).to_string(),
            install::remove(paths, true).expect_err(what).to_string(),
        ]
    };

    // The folder keeps the list it inherited, which lets ordinary accounts add to it.
    for text in refused(&paths, "a folder that others can change") {
        assert!(
            text.contains("is a folder above the boundary's program directory"),
            "{text}"
        );
        assert!(text.contains(&above.display().to_string()), "{text}");
        assert!(
            text.contains("Do not remove the program directory"),
            "{text}"
        );
    }

    // With the installation's own protected list it is accepted, in a repair and in a removal.
    acl::set_protected(&above, &data_parent_descriptor()).unwrap();
    install::entry(&paths).expect("a protected folder is accepted");

    // A link at the folder is refused whatever its target's list says, and the target is not read.
    let link = folder.join("linked-above");
    let linked = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&above)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{linked:?}");
    paths.program = link.join("Program");
    paths.program_top = link.clone();
    paths.git = paths.program.join("git");
    for text in refused(&paths, "a link above the program directory") {
        assert!(text.contains("it is a link or not a folder"), "{text}");
        assert!(text.contains(&link.display().to_string()), "{text}");
    }
    std::fs::remove_dir(&link).unwrap();
    let _ = std::fs::remove_dir_all(&above);
    let _ = std::fs::remove_dir_all(&folder);
}

/// Two refusals of the program directory that a change of owner or list cannot cure get a remedy of
/// their own, in a repair and in a removal alike. A program directory on a volume that is not NTFS
/// is refused for its volume, and the text says that nothing in it can be corrected. A folder above
/// the program directory that cannot be opened to be checked (another program holds it open) is
/// refused with the words for that, and not with the owner and the list to correct.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_volume_that_is_not_used_and_a_parent_that_cannot_be_opened_have_remedies_of_their_own() {
    require_clean_machine();
    use std::os::windows::fs::OpenOptionsExt;
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let mut paths = paths_in(&folder);
    installed_data_directory(&paths);
    let both = |paths: &Paths, what: &str| -> [String; 2] {
        [
            install::entry(paths).err().expect(what).to_string(),
            install::remove(paths, true).expect_err(what).to_string(),
        ]
    };

    // A parent that another program holds open and shares with nobody cannot be opened.
    let above = inherited_folder();
    paths.program = above.join("Program");
    paths.program_top = above.clone();
    paths.git = paths.program.join("git");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000)
        .open(&above)
        .unwrap();
    let refused = both(&paths, "a parent that cannot be opened");
    drop(held);
    for text in refused {
        assert!(text.contains("could not be opened to be checked"), "{text}");
        assert!(text.contains("close that program"), "{text}");
        assert!(text.contains(&above.display().to_string()), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&above);

    // A program directory on a volume that is not NTFS: a small FAT volume in a virtual disk.
    let disk = folder.join("fat.vhd");
    let diskpart = |lines: &[String]| {
        let script = folder.join("diskpart.txt");
        std::fs::write(&script, lines.join("\r\n")).unwrap();
        let done = Command::new("diskpart")
            .arg("/s")
            .arg(&script)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&script);
        assert!(done.status.success(), "{done:?}");
    };
    diskpart(&[
        format!(
            "create vdisk file=\"{}\" maximum=128 type=expandable",
            disk.display()
        ),
        "attach vdisk".to_owned(),
        "create partition primary".to_owned(),
        "format fs=fat32 quick label=krfat".to_owned(),
        "assign letter=Y".to_owned(),
    ]);
    let program = PathBuf::from(r"Y:\Program");
    std::fs::create_dir(&program).unwrap();
    paths.program = program.clone();
    // No folder above the program directory is read: the volume is what is refused.
    paths.program_top = program.clone();
    paths.git = program.join("git");
    let refused = both(&paths, "a volume that is not used");
    diskpart(&[
        format!("select vdisk file=\"{}\"", disk.display()),
        "detach vdisk".to_owned(),
    ]);
    for text in refused {
        assert!(
            text.contains("is on a volume that the installation does not use"),
            "{text}"
        );
        assert!(text.contains("NTFS"), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
        assert!(!text.contains("Close the program"), "{text}");
        assert!(
            text.contains("Do not remove the program directory"),
            "{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&folder);
}

/// The installation's places are the system's own, not what the environment of the session that
/// runs the setup program says: an unelevated session of the same account can set its own
/// variables, and the elevated installation runs the PowerShell and lays the programs down there.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_installation_takes_the_system_folders_from_the_system_and_not_from_the_environment() {
    let names = [
        "ProgramFiles",
        "ProgramData",
        "SystemRoot",
        "windir",
        // The system's folders may be stored as text that names these, and expanded from the
        // environment of the process that asks.
        "SystemDrive",
        "ALLUSERSPROFILE",
    ];
    let before = Paths::system();
    let saved: Vec<_> = names
        .iter()
        .map(|name| (*name, std::env::var_os(name)))
        .collect();
    for name in names {
        // SAFETY: the guest's cases run on one test thread, and the variables are put back below.
        unsafe { std::env::set_var(name, r"C:\Planted") };
    }
    let after = Paths::system();
    let root = ffi::system_windows_directory();
    for (name, value) in saved {
        match value {
            // SAFETY: as above.
            Some(value) => unsafe { std::env::set_var(name, value) },
            // SAFETY: as above.
            None => unsafe { std::env::remove_var(name) },
        }
    }
    assert_eq!(after.program, before.program);
    assert_eq!(after.data, before.data);
    assert!(
        !after.program.starts_with(r"C:\Planted"),
        "{:?}",
        after.program
    );
    assert!(!after.data.starts_with(r"C:\Planted"), "{:?}", after.data);
    assert!(
        !root.unwrap().starts_with(r"C:\Planted"),
        "the Windows directory is the platform's"
    );
}

/// Git is started by the elevated installer with an emptied environment: a trace variable of the
/// session that started the installer, which names a file for Git to make or append to, makes no
/// file. The control starts the same Git with the variable and shows that it does make the file.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn git_started_by_the_installer_sees_no_variable_of_the_session_that_started_it() {
    let names = ["GIT_TRACE2_EVENT", "GIT_TRACE2", "GIT_TRACE"];
    let trace = std::env::temp_dir().join(format!(
        "krtrace-{}.txt",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let git = Path::new(r"C:\Program Files\Git")
        .join("mingw64")
        .join("bin")
        .join("git.exe");
    let control = Command::new(&git)
        .arg("--version")
        .env("GIT_TRACE2_EVENT", &trace)
        .output()
        .unwrap();
    assert!(control.status.success(), "{control:?}");
    assert!(trace.exists(), "Git makes the file that the variable names");
    std::fs::remove_file(&trace).unwrap();
    for name in names {
        // SAFETY: the guest's cases run on one test thread, and the variables are removed below.
        unsafe { std::env::set_var(name, &trace) };
    }
    let qualified = install::qualify_git();
    for name in names {
        // SAFETY: as above.
        unsafe { std::env::remove_var(name) };
    }
    let made = trace.exists();
    let _ = std::fs::remove_file(&trace);
    assert!(
        !made,
        "the installer's Git made the file that the session named"
    );
    qualified.expect("Git is qualified");
}

/// With no manifest there is no installation whose records a leftover could be: a refusal of what
/// is left says to remove it, and does not say to correct what cannot be corrected away.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn with_no_manifest_the_refusal_of_leftover_content_says_to_remove_it() {
    require_clean_machine();
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let first = paths.data.join(format!("manifest-{}.new", "ab".repeat(16)));
    let second = paths.data.join(format!("manifest-{}.new", "cd".repeat(16)));
    owned_file(&first, b"x");
    std::fs::hard_link(&first, &second).unwrap();
    // With the manifest, the file that has two names is a record to correct.
    let text = install::make_data_directory(&paths)
        .expect_err("a file with two names")
        .to_string();
    assert!(text.contains("more than one name"), "{text}");
    assert!(text.contains("Do not remove"), "{text}");
    // Without it, there is nothing the file could be a record of. The inspection stops earlier,
    // at the directory that no manifest records and that is not empty, so the refusal names that
    // directory and not the file's two names.
    std::fs::remove_file(&paths.manifest).unwrap();
    let text = install::make_data_directory(&paths)
        .expect_err("what is left with no manifest")
        .to_string();
    assert!(
        text.contains("no manifest records this directory"),
        "{text}"
    );
    assert!(text.contains("Remove "), "{text}");
    assert!(!text.contains("Do not remove"), "{text}");
    let _ = std::fs::remove_dir_all(&folder);
}

/// Runs `work` on a thread that impersonates a copy of this process's token whose default owner is
/// the token's own user. Under the guest's usual token, the system's, an object made with no owner
/// in its descriptor is owned by the Administrators group anyway; under the copy it is owned by the
/// user, so a descriptor that loses its owner fails a case without any setting of the guest's.
#[cfg(feature = "testing")]
fn with_the_users_own_default_owner<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation,
        SetTokenInformation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_OWNER, TOKEN_QUERY,
        TokenImpersonation, TokenOwner,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let user = token::current_user().unwrap();
    let mut process: HANDLE = std::ptr::null_mut();
    // SAFETY: the call opens this process's own token for the two rights named; the handle is
    // owned below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut process,
        )
    };
    assert_ne!(opened, 0, "this process's token is opened");
    let process = ffi::Handle::new(process, "this process's token").unwrap();
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: the source token is open for duplication; the copy is owned below.
    let duplicated = unsafe {
        DuplicateTokenEx(
            process.raw(),
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        )
    };
    assert_ne!(duplicated, 0, "the token is copied");
    let copy = ffi::Handle::new(copy, "the copy of the token").unwrap();
    let owner = TOKEN_OWNER {
        Owner: user.as_ptr(),
    };
    // SAFETY: the copy is open with the right to change it, and the structure names an identifier
    // that outlives the call.
    let set = unsafe {
        SetTokenInformation(
            copy.raw(),
            TokenOwner,
            (&raw const owner).cast(),
            size_of::<TOKEN_OWNER>() as u32,
        )
    };
    assert_ne!(set, 0, "the token's default owner is its own user");
    let token = copy.raw() as usize;
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                // SAFETY: the copy outlives the thread, which the scope joins.
                let began = unsafe { ImpersonateLoggedOnUser(token as HANDLE) };
                assert_ne!(began, 0, "the copy is impersonated");
                let result = work();
                // SAFETY: ends the impersonation this thread began.
                unsafe {
                    RevertToSelf();
                }
                result
            })
            .join()
            .unwrap()
    })
}

/// Every object the installation makes names the Administrators group as its owner in the call that
/// makes it. Under a token whose default owner is not that group, an object whose descriptor lost
/// its owner would be owned by the user, and this case fails; under the system's own token it would
/// pass whatever the descriptor says, because that token's default owner is the Administrators.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn every_object_the_installation_makes_names_the_administrators_as_owner_under_a_token_that_does_not()
 {
    require_clean_machine();
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    let user = token::current_user().unwrap().to_text();
    assert_ne!(user, ADMINISTRATORS, "the user is not the group");
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_under(&folder);
    let group = Sid::parse("S-1-5-21-1111-2222-3333-1001").unwrap();
    let readable = Principals {
        users_may_read: true,
        ..Principals::default()
    };
    with_the_users_own_default_owner(|| {
        // The control: with no owner given, the object is the user's, so the check below can fail.
        let plain = folder.join("plain.txt");
        std::fs::write(&plain, b"x").unwrap();
        assert_eq!(
            summary_of(&plain).owner,
            user,
            "under this token an object that names no owner is the user's"
        );
        let owner_of = |path: &Path, what: &str| {
            assert_eq!(summary_of(path).owner, ADMINISTRATORS, "{what}");
        };
        for kind in [SdKind::AdminFile, SdKind::ProgramFile] {
            let (file, path) = fresh::named_file(&folder, "kind", ".bin", kind).unwrap();
            drop(file);
            owner_of(&path, &format!("a file of kind {kind:?}"));
        }
        let unlisted = folder.join("unlisted.exe");
        drop(
            fresh::file_with(
                &unlisted,
                SdKind::ProofProgram,
                &Principals {
                    group: Some(group.clone()),
                    ..Principals::default()
                },
                true,
            )
            .unwrap(),
        );
        owner_of(&unlisted, "the proof's program");
        let record = folder.join("record.json");
        drop(fresh::record_file(&record, true).unwrap());
        owner_of(&record, "a record");
        let named = fresh::directory(&folder, "dir", SdKind::AdminDir, &readable).unwrap();
        owner_of(&named, "a directory made at a random name");
        let at = folder.join("at");
        fresh::directory_at(&at, SdKind::AdminDir, &readable).unwrap();
        owner_of(&at, "a directory made at a path");
        let all = folder.join("all").join("below");
        fresh::directory_all(&all, SdKind::AdminDir, &readable).unwrap();
        owner_of(&all, "a directory made with its parents");
        owner_of(
            all.parent().unwrap(),
            "the parent of a directory made with its parents",
        );
        let held = install::make_data_directory(&paths).unwrap();
        held.protect().unwrap();
        owner_of(&paths.data, "the data directory");
    });
    let _ = std::fs::remove_dir_all(&folder);
}

/// `Channel::set` hands the policy to PowerShell in a file that did not exist: a random name in the
/// channel's directory, owned by the administrators, with a protected list of the system and the
/// administrators alone. The case reads the file while PowerShell has it. When the call is over,
/// whether PowerShell took the policy or refused it, nothing is left in the directory.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_channel_hands_the_policy_to_powershell_in_a_new_file_of_the_administrators_and_removes_it() {
    require_clean_machine();
    use std::collections::BTreeMap;
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    let folder = inherited_folder();
    let (xml, in_force) = channel().effective().unwrap();
    let setting = {
        let channel = Channel::new(&folder);
        let xml = xml.clone();
        // Under a token whose default owner is the user, so that a file that names no owner is
        // caught under the system's own token too.
        std::thread::spawn(move || with_the_users_own_default_owner(|| channel.set(&xml)))
    };
    let mut seen = BTreeMap::new();
    while !setting.is_finished() {
        if let Ok(entries) = std::fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if seen.contains_key(&name) {
                    continue;
                }
                // A file that is gone by the time it is opened is not seen on this round.
                let path = entry.path();
                if let Ok(summary) = std::panic::catch_unwind(|| summary_of(&path)) {
                    seen.insert(name, summary);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    setting.join().unwrap().expect("the policy is set");
    // PowerShell's own directory of the run (`shell-` and 32 hexadecimal digits) is made in the
    // same folder and removed with the file: it is not the policy file, which the names below are.
    seen.retain(|name, _| {
        !name
            .strip_prefix("shell-")
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    });
    assert!(
        !seen.is_empty(),
        "the file was there while PowerShell had it"
    );
    for (name, summary) in &seen {
        assert!(
            name.strip_prefix("policy-")
                .and_then(|rest| rest.strip_suffix(".xml"))
                .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())),
            "the name is `policy-` and 32 hexadecimal digits: {name}"
        );
        assert_eq!(summary.owner, ADMINISTRATORS, "{name}'s owner");
        assert!(
            summary.protected,
            "{name}'s list takes nothing from the folder"
        );
        let sids: Vec<&str> = summary
            .entries
            .as_ref()
            .unwrap()
            .iter()
            .map(|entry| entry.sid.as_str())
            .collect();
        assert_eq!(sids, [SYSTEM, ADMINISTRATORS], "{name}'s entries");
    }
    assert_eq!(
        std::fs::read_dir(&folder).unwrap().count(),
        0,
        "nothing is left in the directory"
    );
    assert_eq!(channel().effective().unwrap().1, in_force);

    // PowerShell refuses what is not a policy, and the file it was given is gone all the same.
    Channel::new(&folder)
        .set("this is not a policy")
        .expect_err("a text that is not a policy is refused");
    assert_eq!(
        std::fs::read_dir(&folder).unwrap().count(),
        0,
        "a refused policy leaves nothing in the directory"
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn what_is_inside_a_data_directory_that_exists_is_checked_on_its_own_handle_before_any_step_uses_it()
 {
    require_clean_machine();
    use install::DataChild;
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    // Whatever is refused, what the person does leaves the manifest and the journal in place, and
    // the text says one remedy: an entry that the layout does not give is to be removed; a record
    // that the layout gives and that the system's class owns is to be corrected, and is never to be
    // removed; one that another account owns, or a link, is not the installation's: it is moved
    // aside, and is neither removed nor corrected into place.
    let refusal = |words: &str| {
        let refused = install::make_data_directory(&paths).expect_err("the directory is refused");
        let text = refused.to_string();
        assert!(text.contains(words), "{text}");
        text
    };
    let removal_text = |text: &str| {
        assert!(
            text.contains("Remove ") && text.contains("and nothing else"),
            "{text}"
        );
        assert!(!text.contains("Do not remove"), "{text}");
        assert!(text.contains("stay where they are"), "{text}");
    };
    let correction_text = |text: &str| {
        assert!(text.contains("Correct what the reason names"), "{text}");
        assert!(text.contains("Do not remove"), "{text}");
        assert!(!text.contains("Remove "), "{text}");
        assert!(text.contains("stay where they are"), "{text}");
    };
    let moved_aside_text = |text: &str| {
        assert!(text.contains("did not make"), "{text}");
        assert!(text.contains("Move it aside"), "{text}");
        assert!(text.contains("do not remove it"), "{text}");
        assert!(!text.contains("Remove "), "{text}");
        assert!(!text.contains("Correct what the reason names"), "{text}");
    };
    let refused_with = |words: &str| {
        let text = refusal(words);
        assert!(
            [
                text.contains("Remove "),
                text.contains("Do not remove"),
                text.contains("Move it aside")
            ]
            .iter()
            .filter(|said| **said)
            .count()
                == 1,
            "one remedy: {text}"
        );
    };
    let removal_with = |words: &str| removal_text(&refusal(words));
    let correction_with = |words: &str| correction_text(&refusal(words));
    let moved_aside_with = |words: &str| moved_aside_text(&refusal(words));

    // A directory that the installation made is accepted, with journal files of an earlier run in
    // it, and each of its directories is made with its own protected list in the creating call and
    // is held: nothing renames or deletes it while the installation works in it.
    installed_data_directory(&paths);
    let journal_file = paths.journal.join(format!("{}.journal", "ab".repeat(16)));
    owned_file(&journal_file, b"rows");
    let mut holds = install::make_data_directory(&paths).expect("an installation's own directory");
    for path in [&paths.staging, &paths.journal, &paths.run] {
        let made = summary_of(path);
        assert!(made.protected, "{}", path.display());
        let named: Vec<&str> = made
            .entries
            .as_ref()
            .unwrap()
            .iter()
            .map(|entry| entry.sid.as_str())
            .collect();
        assert_eq!(named, [SYSTEM, ADMINISTRATORS], "{}", path.display());
        assert!(
            std::fs::rename(path, path.with_extension("moved")).is_err(),
            "{} is held",
            path.display()
        );
    }
    holds.directory(DataChild::Journal).unwrap();
    drop(holds);

    // A directory that is there with a list that passes the check but is not protected is
    // protected on its handle, and what is in it keeps its own list: the call propagates to
    // nothing. (`acl::set_protected` always sets the protected flag, so the tool turns inheritance
    // back on.)
    let inherited = Command::new("icacls")
        .arg(&paths.staging)
        .arg("/inheritance:e")
        .output()
        .unwrap();
    assert!(inherited.status.success(), "{inherited:?}");
    assert!(!summary_of(&paths.staging).protected);
    let child = paths
        .staging
        .join(format!("policy-{}.xml", "cd".repeat(16)));
    owned_file(&child, b"policy");
    let child_before = summary_of(&child);
    let mut holds = install::make_data_directory(&paths).unwrap();
    holds.directory(DataChild::Staging).unwrap();
    drop(holds);
    assert!(summary_of(&paths.staging).protected);
    assert_eq!(
        summary_of(&child),
        child_before,
        "protecting the directory on its handle changes nothing in it"
    );
    std::fs::remove_file(&child).unwrap();

    // A child that another account owns is refused, and its list is as it was.
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    let status = Command::new("icacls")
        .arg(&paths.journal)
        .args(["/setowner", &name])
        .output()
        .unwrap();
    assert!(status.status.success(), "{status:?}");
    let before = summary_of(&paths.journal);
    let refused = install::make_data_directory(&paths).expect_err("a child that is owned");
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    assert_eq!(summary_of(&paths.journal).entries, before.entries);
    let _ = Command::new("icacls")
        .arg(&paths.journal)
        .args(["/setowner", "Administrators"])
        .output();
    let _ = account::delete(&name);
    install::make_data_directory(&paths).expect("the owner is back");

    // A journal file that another account owns is refused, as is a file that is not a journal's.
    let owned = Command::new("icacls")
        .arg(&journal_file)
        .args(["/setowner", "Users"])
        .output()
        .unwrap();
    assert!(owned.status.success(), "{owned:?}");
    moved_aside_with("S-1-5-32-545");
    let _ = Command::new("icacls")
        .arg(&journal_file)
        .args(["/setowner", "Administrators"])
        .output();
    owned_file(paths.journal.join("notes.txt"), b"x");
    removal_with("notes.txt");
    std::fs::remove_file(paths.journal.join("notes.txt")).unwrap();

    // A journal file of the system's class with a second name is a record to correct, and is never
    // removed.
    let second_name = paths.journal.join(format!("{}.journal", "cd".repeat(16)));
    std::fs::hard_link(&journal_file, &second_name).unwrap();
    correction_with("more than one name");
    std::fs::remove_file(&second_name).unwrap();

    // A link at a child's name is refused, and the tree it leads to keeps its list.
    let target = inherited_folder();
    let targets_list = summary_of(&target);
    std::fs::remove_dir(&paths.run).unwrap();
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&paths.run)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    moved_aside_with("it is a link");
    assert_eq!(summary_of(&target), targets_list);
    std::fs::remove_dir(&paths.run).unwrap();
    let _ = std::fs::remove_dir_all(&target);
    installed_data_directory(&paths);

    // An entry that the installation did not make is refused, whatever it is.
    owned_file(paths.data.join("stray.txt"), b"x");
    removal_with("stray.txt");
    std::fs::remove_file(paths.data.join("stray.txt")).unwrap();
    owned_dir(paths.data.join("stray"));
    removal_with("stray");
    std::fs::remove_dir(paths.data.join("stray")).unwrap();

    // The manifest is a file with one owner and one name, and a link in its place is refused.
    let copy = folder.join("copy.json");
    std::fs::copy(&paths.manifest, &copy).unwrap();
    std::fs::remove_file(&paths.manifest).unwrap();
    let linked = Command::new("cmd")
        .args(["/c", "mklink"])
        .arg(&paths.manifest)
        .arg(&copy)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{linked:?}");
    moved_aside_with("it is a link");
    match install::entry(&paths) {
        Err(error) => assert!(error.to_string().contains("it is a link"), "{error}"),
        Ok(_) => panic!("the manifest is read through a link"),
    }
    std::fs::remove_file(&paths.manifest).unwrap();
    std::fs::copy(&copy, &paths.manifest).unwrap();
    std::fs::remove_file(&copy).unwrap();

    // A directory that no manifest records must be empty: the manifest, when it names the
    // directory's children and not the directory, is refused; with no manifest, only an empty
    // directory is accepted.
    let mut unrecorded = Manifest::begin();
    for path in [&paths.staging, &paths.journal, &paths.run] {
        unrecorded.record(ObjectKind::Directory, &path.display().to_string(), None);
    }
    unrecorded.save(&paths.manifest).unwrap();
    refused_with("no manifest records");
    let mut no_staging = Manifest::begin();
    for path in [&paths.data, &paths.journal, &paths.run] {
        no_staging.record(ObjectKind::Directory, &path.display().to_string(), None);
    }
    no_staging.save(&paths.manifest).unwrap();
    install::make_data_directory(&paths).expect("an empty directory needs no record");
    owned_file(paths.staging.join("leftover"), b"x");
    removal_with("leftover");
    std::fs::remove_file(paths.staging.join("leftover")).unwrap();
    let named = paths
        .staging
        .join(format!("policy-{}.xml", "ef".repeat(16)));
    owned_file(&named, b"x");
    refused_with("no manifest records");
    std::fs::remove_file(&named).unwrap();
    std::fs::remove_file(&paths.manifest).unwrap();
    refused_with("no manifest records");
    std::fs::remove_file(&journal_file).unwrap();
    for which in [&paths.staging, &paths.journal, &paths.run] {
        std::fs::remove_dir(which).unwrap();
    }
    let _ = std::fs::remove_file(paths.data.join("manifest.new"));
    install::make_data_directory(&paths).expect("an empty directory needs no manifest");

    // An empty directory with the accepted list is one a new installation takes as it is: the
    // refusal's own remedy can be done.
    assert!(
        matches!(install::entry(&paths), Ok(install::Entry::Fresh)),
        "an empty data directory that passed its check is a fresh installation's"
    );

    // A directory that separates names that differ only by case is refused: the listing and the
    // checks take such names for one.
    let flagged = Command::new("fsutil")
        .args(["file", "setCaseSensitiveInfo"])
        .arg(&paths.data)
        .arg("enable")
        .output()
        .unwrap();
    assert!(
        flagged.status.success(),
        "the guest cannot make a directory case-sensitive: {flagged:?}"
    );
    refused_with("differ only by case");
    let _ = Command::new("fsutil")
        .args(["file", "setCaseSensitiveInfo"])
        .arg(&paths.data)
        .arg("disable")
        .output();
    install::make_data_directory(&paths).expect("the flag is off");
    let _ = std::fs::remove_dir_all(&folder);
}

/// Writes a journal file in the directory that names the private root: a begin row and the root's
/// intent, which is all the installation reads of an unfinished invocation. A finished one also
/// verifies its release and ends with no leftover, and no longer names the root as work. The journal
/// is the invocation's whose identifier is the byte, repeated. Returns the file's path.
#[cfg(feature = "testing")]
fn journal_naming(journals: &Path, root: &str, id: u8, finished: bool) -> PathBuf {
    use kr_boundary_windows::filekey::FileKey;
    use kr_boundary_windows::journal::rows::{RootName, Row};
    use kr_boundary_windows::win::journal::Journal;
    use kr_boundary_windows::win::launch::InvocationId;
    let mut journal = Journal::create(journals, InvocationId([id; 16])).unwrap();
    let mut rows = vec![
        Row::Begin {
            invocation: format!("{id:02x}").repeat(16),
            boot_marker: "11111111-1111-1111-1111-111111111111".to_owned(),
            session_luid: 7,
            group_sid: "S-1-9-1-2-3-4".to_owned(),
            client_sid: "S-1-5-21-1-2-3-1000".to_owned(),
            client_pid: 4242,
            client_creation_time: 99,
            chain: vec![FileKey::ntfs(0xabcd, 5)],
            tree_path: r"C:\work\tree".to_owned(),
        },
        Row::RootIntent {
            name: RootName::parse(root).unwrap(),
        },
    ];
    if finished {
        rows.push(Row::ReleaseVerified {
            objects: 0,
            leftovers: 0,
        });
        // The tracker refuses an end while the root it began is not recorded as removed.
        rows.push(Row::RootRemoved);
        rows.push(Row::End { root_leftovers: 0 });
    }
    for row in &rows {
        journal.append(row).unwrap();
    }
    drop(journal);
    // The file is made by the journal's own open call, with the token's default owner; the
    // broker's journals are the Administrators', and a case that names the root must be refused
    // for the root and not for the file's owner.
    let file = journals.join(format!("{}.journal", format!("{id:02x}").repeat(16)));
    give_to(&file, "Administrators");
    file
}

/// A broker begins an invocation between the installation's two reads of what is in use: it writes
/// the intent row of its root and makes the root. The installation lists the private roots first
/// and reads the journal after, so the new root is not in the listing and is not refused; read the
/// other way round, it would be listed and not named, and a root in use would be refused.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_root_that_a_broker_makes_between_the_listing_of_the_roots_and_the_journal_read_is_not_refused()
{
    require_clean_machine();
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let first = "ab".repeat(16);
    let second = "cd".repeat(16);
    // A root that an unfinished journal names is in use, and the journal is read for it.
    owned_dir(paths.run.join(&first));
    journal_naming(&paths.journal, &first, 7, false);
    install::make_data_directory(&paths).expect("a root that a journal names");

    let between = paths.clone();
    let second_root = second.clone();
    install::testing::after_the_first_of_the_two_reads(move || {
        journal_naming(&between.journal, &second_root, 9, false);
        owned_dir(between.run.join(&second_root));
    });
    install::make_data_directory(&paths).expect("a root made between the two reads is in use");
    assert!(paths.run.join(&second).exists(), "the seam ran");
    install::make_data_directory(&paths).expect("both roots are named now");
    let _ = std::fs::remove_dir_all(&folder);
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn what_is_below_staging_and_run_is_checked_on_its_own_handle_and_what_is_foreign_is_not_touched() {
    require_clean_machine();
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let refused_with = |words: &str| {
        let refused = install::make_data_directory(&paths).expect_err("the directory is refused");
        let text = refused.to_string();
        assert!(text.contains(words), "{text}");
        assert!(text.contains("Remove "), "{text}");
        assert!(text.contains("stay where they are"), "{text}");
    };

    // What an installation's own run leaves is accepted: a policy file made new, and a scratch
    // directory (readable by every account) with a file in it.
    let (mut made, policy) =
        fresh::named_file(&paths.staging, "policy", ".xml", SdKind::AdminFile).unwrap();
    made.write_all(b"policy").unwrap();
    drop(made);
    let scratch = fresh::directory(
        &paths.staging,
        "proof",
        SdKind::AdminDir,
        &Principals {
            users_may_read: true,
            ..Principals::default()
        },
    )
    .unwrap();
    let inner = scratch.join("unlisted.exe");
    owned_file(&inner, b"x");
    install::make_data_directory(&paths).expect("the remnants of an installation's own run");

    // A file in staging that another account owns is refused before anything is written, and it is
    // as it was: not rewritten, not given to anybody.
    let name = format!("krowner{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
    let owner = account::create(&name).unwrap();
    give_to(&policy, &name);
    let before = summary_of(&policy);
    let shown = policy.file_name().unwrap().to_string_lossy().into_owned();
    refused_with(&shown);
    let refused = install::make_data_directory(&paths).expect_err("a file that is owned");
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    assert_eq!(std::fs::read(&policy).unwrap(), b"policy");
    assert_eq!(summary_of(&policy), before);
    give_to(&policy, "Administrators");

    // A file whose owner is right but whose list names another account, with a right to read only,
    // is refused the same way and is as it was.
    let clean = summary_of(&policy);
    let granted = Command::new("icacls")
        .arg(&policy)
        .args(["/grant", &format!("{name}:R")])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");
    let listed = summary_of(&policy);
    assert_ne!(listed, clean, "the list now names the account");
    refused_with(&shown);
    let refused = install::make_data_directory(&paths).expect_err("a list that names an account");
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    assert_eq!(std::fs::read(&policy).unwrap(), b"policy");
    assert_eq!(summary_of(&policy), listed, "the file is as it was");
    let removed = Command::new("icacls")
        .arg(&policy)
        .args(["/remove:g", &name])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{removed:?}");
    assert_eq!(summary_of(&policy), clean, "the list is as it began");

    // The name an earlier build gave the policy file is not one the installation gives now.
    let legacy = paths.staging.join("policy.xml");
    owned_file(&legacy, b"x");
    refused_with("policy.xml");
    std::fs::remove_file(&legacy).unwrap();

    // A file with a second name, and a file that another account owns inside a scratch directory.
    let second = paths
        .staging
        .join(format!("policy-{}.xml", "ab".repeat(16)));
    std::fs::hard_link(&policy, &second).unwrap();
    refused_with("more than one name");
    std::fs::remove_file(&second).unwrap();
    give_to(&inner, &name);
    refused_with("unlisted.exe");
    give_to(&inner, "Administrators");

    // A directory in run that no journal names is refused, with the entry to remove. One that a
    // journal names as unfinished work and another account owns is refused with the owner to
    // correct, and one that the administrators own is a private root; nothing is looked at inside
    // it, whatever it holds.
    let root = paths.run.join("ab".repeat(16));
    owned_dir(&root);
    refused_with("no journal names it");
    let unfinished = journal_naming(&paths.journal, &"ab".repeat(16), 7, false);
    give_to(&root, &name);
    let text = install::make_data_directory(&paths)
        .expect_err("a root that another account owns")
        .to_string();
    assert!(text.contains(&"ab".repeat(16)), "{text}");
    assert!(text.contains(&owner.to_text()), "{text}");
    assert!(text.contains("did not make"), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert!(!text.contains("Remove "), "{text}");
    give_to(&root, "Administrators");
    std::fs::write(root.join("anything"), b"x").unwrap();
    install::make_data_directory(&paths).expect("a private root the administrators own");
    std::fs::remove_file(root.join("anything")).unwrap();

    // A root that only a finished journal names is no unfinished work: it is refused as one that no
    // journal names, with the entry to remove.
    std::fs::remove_file(&unfinished).unwrap();
    let finished = journal_naming(&paths.journal, &"ab".repeat(16), 8, true);
    refused_with("no journal names it");
    std::fs::remove_file(&finished).unwrap();
    std::fs::remove_dir(&root).unwrap();

    // A proof directory holds the unlisted program and nothing else: another name, even a file
    // that is as protected as the program, is refused.
    let stray = scratch.join("notes.txt");
    owned_file(&stray, b"x");
    refused_with("notes.txt");
    std::fs::remove_file(&stray).unwrap();
    install::make_data_directory(&paths).expect("the proof directory holds only its program");

    // A record the layout gives that another account owns is not the installation's: it is refused
    // with the account named and the entry to move aside, never with its removal and never with a
    // correction of its owner into place: the manifest, the journal directory and the replacement.
    give_to(&paths.journal, &name);
    let text = install::make_data_directory(&paths)
        .expect_err("a journal directory that is owned")
        .to_string();
    assert!(text.contains("journal"), "{text}");
    assert!(!text.contains("Remove "), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    give_to(&paths.journal, "Administrators");
    give_to(&paths.manifest, &name);
    let text = install::make_data_directory(&paths)
        .expect_err("a manifest that is owned")
        .to_string();
    assert!(text.contains("manifest.json"), "{text}");
    assert!(!text.contains("Remove "), "{text}");
    // The text names the account that owns it, says that the installation did not make it and not
    // to correct it into place, and says not to remove it.
    assert!(text.contains(&owner.to_text()), "{text}");
    assert!(text.contains("did not make"), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("do not remove it"), "{text}");
    give_to(&paths.manifest, "Administrators");
    install::make_data_directory(&paths).expect("the records are the administrators' again");

    // The manifest's replacement that a crash left has a name the layout gives, so it is refused as
    // a record is when another account owns it, and what is there is not removed.
    let replacement = paths.data.join(format!("manifest-{}.new", "ef".repeat(16)));
    std::fs::write(&replacement, b"half").unwrap();
    give_to(&replacement, "Administrators");
    install::make_data_directory(&paths).expect("a replacement the administrators own");
    give_to(&replacement, &name);
    let text = install::make_data_directory(&paths)
        .expect_err("a replacement that is owned")
        .to_string();
    assert!(
        text.contains(&format!("manifest-{}.new", "ef".repeat(16))),
        "{text}"
    );
    assert!(!text.contains("Remove "), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert_eq!(std::fs::read(&replacement).unwrap(), b"half");
    give_to(&replacement, "Administrators");
    std::fs::remove_file(&replacement).unwrap();
    install::make_data_directory(&paths).expect("the replacement is gone");

    // A link at a scratch directory's name is refused, and the tree it leads to keeps its list.
    let target = inherited_folder();
    let targets_list = summary_of(&target);
    let junction = paths.staging.join(format!("proof-{}", "cd".repeat(16)));
    let linked = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{linked:?}");
    refused_with("it is a link");
    assert_eq!(summary_of(&target), targets_list);
    std::fs::remove_dir(&junction).unwrap();
    install::make_data_directory(&paths).expect("the link is gone");

    let _ = account::delete(&name);
    let _ = std::fs::remove_dir_all(&target);
    let _ = std::fs::remove_dir_all(&folder);
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_file_that_another_program_reads_by_path_is_made_new_and_owned_by_the_administrators() {
    require_clean_machine();
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{Principals, SdKind};
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";
    let sids = |summary: &kr_boundary_windows::win::sd::Summary| -> Vec<String> {
        summary
            .entries
            .as_ref()
            .unwrap()
            .iter()
            .map(|entry| entry.sid.clone())
            .collect()
    };
    let folder = inherited_folder();

    // The file's owner, its protected flag and its two entries are those of the creating call.
    let path = with_the_users_own_default_owner(|| {
        let (mut file, path) =
            fresh::named_file(&folder, "policy", ".xml", SdKind::AdminFile).unwrap();
        file.write_all(b"policy").unwrap();
        path
    });
    let made = summary_of(&path);
    assert_eq!(made.owner, ADMINISTRATORS);
    assert!(made.protected);
    assert_eq!(sids(&made), [SYSTEM, ADMINISTRATORS]);

    // The name is random: another file made the same way has another.
    let (_other, other_path) =
        fresh::named_file(&folder, "policy", ".xml", SdKind::AdminFile).unwrap();
    assert_ne!(other_path, path);

    // Anything at the name stops the call, and what is there is as it was.
    let again = fresh::file_at(&path, SdKind::AdminFile, true).expect_err("the name is taken");
    assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists, "{again}");
    assert_eq!(std::fs::read(&path).unwrap(), b"policy");
    let target = folder.join("target.txt");
    std::fs::write(&target, b"x").unwrap();
    let link = folder.join("linked.xml");
    let linked = Command::new("cmd")
        .args(["/c", "mklink"])
        .arg(&link)
        .arg(&target)
        .output()
        .unwrap();
    assert!(linked.status.success(), "{linked:?}");
    fresh::file_at(&link, SdKind::AdminFile, true).expect_err("a link at the name is not followed");
    assert_eq!(std::fs::read(&target).unwrap(), b"x");

    // A directory is made with the same owner and its own list in the call.
    let directory = with_the_users_own_default_owner(|| {
        fresh::directory(
            &folder,
            "proof",
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )
        .unwrap()
    });
    let scratch = summary_of(&directory);
    assert_eq!(scratch.owner, ADMINISTRATORS);
    assert!(scratch.protected);
    assert_eq!(sids(&scratch), [SYSTEM, ADMINISTRATORS, USERS]);
    let _ = std::fs::remove_dir_all(&folder);
}

/// The proof's program is readable and runnable through the invocation's group that the token of the
/// account under proof carries, and a program file of the installation by every account: neither
/// gives a reader a write, a delete or a change of the list, and a plain file names no reader.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_proofs_program_and_the_program_files_give_their_readers_read_and_run_and_nothing_more() {
    require_clean_machine();
    use kr_boundary_windows::win::ffi::Sid;
    use kr_boundary_windows::win::fresh;
    use kr_boundary_windows::win::sd::{self, Principals, SdKind};
    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";
    const GROUP: &str = "S-1-5-21-1111-2222-3333-1001";
    const FULL: u32 = 0x001f_01ff;
    const READ_AND_RUN: u32 = 0x0012_00a9;
    let named = Principals {
        group: Some(Sid::parse(GROUP).unwrap()),
        ..Principals::default()
    };

    // The text of each kind.
    assert_eq!(
        sd::descriptor_text(SdKind::ProofProgram, &named).unwrap(),
        format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{GROUP})")
    );
    sd::descriptor_text(SdKind::ProofProgram, &Principals::default())
        .expect_err("the proof's program names the invocation's group, and none is given");
    assert_eq!(
        sd::descriptor_text(SdKind::ProgramFile, &Principals::default()).unwrap(),
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
    );
    assert_eq!(
        sd::descriptor_text(
            SdKind::AdminFile,
            &Principals {
                users_may_read: true,
                ..named.clone()
            }
        )
        .unwrap(),
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "a plain file names no reader, whatever the principals say"
    );

    // The files the kinds make carry that list from the call that makes them.
    let folder = inherited_folder();
    let entries = |path: &std::path::Path| -> Vec<(String, u32)> {
        let made = summary_of(path);
        assert_eq!(made.owner, ADMINISTRATORS);
        assert!(made.protected);
        made.entries
            .unwrap()
            .iter()
            .map(|entry| {
                assert_eq!(
                    (entry.kind, entry.flags),
                    (0, 0),
                    "an allow entry, not inherited"
                );
                (entry.sid.clone(), entry.mask)
            })
            .collect()
    };
    let proof = folder.join("unlisted.exe");
    with_the_users_own_default_owner(|| {
        drop(fresh::file_with(&proof, SdKind::ProofProgram, &named, true).unwrap());
    });
    assert_eq!(
        entries(&proof),
        [
            (SYSTEM.to_owned(), FULL),
            (ADMINISTRATORS.to_owned(), FULL),
            (GROUP.to_owned(), READ_AND_RUN)
        ]
    );
    let program = folder.join("program.exe");
    with_the_users_own_default_owner(|| {
        drop(fresh::file_at(&program, SdKind::ProgramFile, true).unwrap());
    });
    assert_eq!(
        entries(&program),
        [
            (SYSTEM.to_owned(), FULL),
            (ADMINISTRATORS.to_owned(), FULL),
            (USERS.to_owned(), READ_AND_RUN)
        ]
    );
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_installation_stops_before_it_lays_anything_down_when_the_parent_folder_is_not_its_own() {
    let case = Case::new();
    let parent = Paths::system().data_parent().to_path_buf();
    assert!(
        !parent.exists(),
        "the guest has no such folder to begin with"
    );
    owned_dir(&parent);
    let before = snapshot();
    let (code, output) = case.install();
    let _ = std::fs::remove_dir_all(&parent);
    assert_ne!(code, 0, "{output}");
    assert!(output.contains("is refused because"), "{output}");
    assert!(output.contains("Remove the folder"), "{output}");
    assert_eq!(snapshot(), before, "nothing was changed");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_removal_reads_the_journal_and_the_private_roots_first_and_refuses_with_nothing_changed() {
    use kr_boundary_windows::journal::rows::Row;
    use kr_boundary_windows::win::journal::Journal;
    use kr_boundary_windows::win::launch::InvocationId;
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let paths = Paths::system();
    let installed = snapshot();
    // What only the removal's first check can show: it refuses before the broker is touched. A
    // removal that went on would put the broker in its maintenance state first, and a later step
    // that refuses would find the broker there.
    let untouched = || {
        let mut connection = install::open_session().expect("the broker still serves");
        match install::ask(&mut connection, &Request::Status {}).unwrap() {
            Response::Status { maintenance } => assert!(
                !maintenance,
                "the removal refused before it put the broker in maintenance"
            ),
            other => panic!("{other:?}"),
        }
    };
    const REFUSAL: &str = "unfinished work is recorded, so nothing was changed";

    // An unfinished invocation in the journal.
    let id = InvocationId([5; 16]);
    let mut journal = Journal::create(&paths.journal, id).unwrap();
    journal
        .append(&Row::Begin {
            invocation: hex::encode(id.0),
            boot_marker: "boot".to_owned(),
            session_luid: 1,
            group_sid: "S-1-9-1-2-3-4".to_owned(),
            client_sid: case.person.to_text(),
            client_pid: 1,
            client_creation_time: 1,
            chain: Vec::new(),
            tree_path: r"C:\work\project".to_owned(),
        })
        .unwrap();
    drop(journal);
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains(r"C:\work\project"),
        "the project is named: {output}"
    );
    assert!(output.contains(REFUSAL), "{output}");
    assert_eq!(snapshot(), installed, "the removal changed nothing");
    assert!(paths.manifest.exists() && paths.journal.exists());
    untouched();

    // The same invocation, finished, but carrying a leftover of its private root that the sweep
    // still holds: its slot is free and the removal is still held, because a leftover is work.
    let (mut journal, _) = Journal::resume(&paths.journal, id, "boot").unwrap();
    for row in [
        Row::Leftover {
            object: r"tmp\held".to_owned(),
            reason: "in use".to_owned(),
            class: kr_boundary_windows::journal::rows::LeftoverClass::Root,
            snapshot: None,
        },
        Row::ReleaseVerified {
            objects: 0,
            leftovers: 0,
        },
        Row::End { root_leftovers: 1 },
    ] {
        journal.append(&row).unwrap();
    }
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains(REFUSAL)
            && output.contains("Finished")
            && output.contains(r"C:\work\project"),
        "a finished invocation with a root leftover holds the removal: {output}"
    );
    assert_eq!(snapshot(), installed, "the removal changed nothing");
    untouched();
    // Once the leftover is cleared the finished journal is no work. A private root that is still
    // there holds the removal.
    journal
        .append(&Row::LeftoverCleared {
            key: r"tmp\held".to_owned(),
        })
        .unwrap();
    drop(journal);
    let root = paths.run.join("0123456789abcdef0123456789abcdef");
    owned_dir(&root);
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_ne!(code, 0, "{output}");
    assert!(
        output.contains(REFUSAL)
            && output.contains("a private root 0123456789abcdef0123456789abcdef")
            && !output.contains("the invocation"),
        "only the root holds it now: {output}"
    );
    assert_eq!(snapshot(), installed, "the removal changed nothing");
    untouched();

    // With the root gone the removal runs and takes the finished journal with it.
    std::fs::remove_dir(&root).unwrap();
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
}

/// The calls the installation made on the Application Identity service, as the test build of the
/// setup program records them in the file that `KR_BOUNDARY_CALL_LOG` names.
fn recorded_calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The newest record number of the application-control log, read by the case itself.
fn newest_log_record() -> u64 {
    let output = Command::new("wevtutil")
        .args([
            "qe",
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "/c:1",
            "/rd:true",
            "/f:xml",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.split("<EventRecordID>")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .and_then(|number| number.parse().ok())
        .unwrap_or(0)
}

/// What the installation recorded of the policy's write and of the event it took for the platform's
/// report of it: the record the write began after and the record of the event.
fn policy_records(calls: &[String]) -> (u64, u64) {
    let number = |prefix: &str| -> u64 {
        calls
            .iter()
            .find_map(|call| call.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("the installation recorded no {prefix:?}: {calls:?}"))
            .trim()
            .parse()
            .unwrap()
    };
    (
        number("policy written after record "),
        number("policy applied by record "),
    )
}

fn call_log() -> PathBuf {
    let log = std::env::temp_dir().join(format!(
        "krcalls-{}.txt",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let _ = std::fs::remove_file(&log);
    log
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_application_identity_service_that_already_runs_is_never_stopped_and_the_event_after_the_write_is_awaited()
 {
    let case = Case::new();
    let manager = service::manager().unwrap();
    let appid = manager.open("AppIDSvc").unwrap().unwrap();
    let original = snapshot();
    assert!(
        !original.appid_running,
        "the guest begins with the service stopped"
    );
    appid.start().unwrap();
    appid
        .wait_for(false, std::time::Duration::from_secs(60))
        .unwrap();
    let log_before_install = newest_log_record();
    let log = call_log();
    let (code, output) = case.payload(
        "payload",
        &[("KR_BOUNDARY_CALL_LOG", log.to_str().unwrap())],
    );
    assert_eq!(code, 0, "{output}");
    let calls = recorded_calls(&log);
    assert!(
        !calls
            .iter()
            .any(|call| call == "appid stop" || call == "appid start"),
        "a running service is neither stopped nor started: {calls:?}"
    );
    // What the record numbers show and what they do not. The record the writing process read right
    // before it wrote is not before everything the log held when the installation began, and the
    // event the installation took has a higher number: it stands later in the log than that read.
    // That is the log's order and not the cause. An application that the service had started before
    // the write can log its own event after the read, and a cleared log restarts its numbers (the
    // wait then fails closed). The proof that the policy refuses an unlisted program is what shows
    // that the policy is in force; these numbers show only that the wait did not take an event that
    // the log already held before the write.
    let (after_record, applied_record) = policy_records(&calls);
    assert!(
        after_record >= log_before_install,
        "the record was read by the installation, after the case's own read: {after_record} < {log_before_install}"
    );
    assert!(
        applied_record > after_record,
        "the event stands later in the log than the record read before the write: {applied_record} <= {after_record}"
    );
    assert!(output.contains("already running"), "{output}");
    assert!(
        !output.contains("application control has started"),
        "no first event of an earlier life is waited for or trusted: {output}"
    );
    let written = output
        .find("the policy is written")
        .expect("the policy is written");
    let applied = output
        .find("the platform has applied the policy")
        .expect("the event after the write is awaited");
    assert!(written < applied, "{output}");
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
    assert!(
        manager
            .open("AppIDSvc")
            .unwrap()
            .unwrap()
            .status()
            .unwrap()
            .running(),
        "the removal leaves a service it did not start running"
    );
    appid.stop().unwrap();
    appid
        .wait_for(true, std::time::Duration::from_secs(60))
        .unwrap();
    assert_eq!(snapshot(), original);
    let _ = std::fs::remove_file(&log);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_stopped_application_identity_service_is_started_once_and_its_first_event_comes_before_the_write()
 {
    let case = Case::new();
    let original = snapshot();
    assert!(
        !original.appid_running,
        "the guest begins with the service stopped"
    );
    let log_before_install = newest_log_record();
    let log = call_log();
    let (code, output) = case.payload(
        "payload",
        &[("KR_BOUNDARY_CALL_LOG", log.to_str().unwrap())],
    );
    assert_eq!(code, 0, "{output}");
    let calls = recorded_calls(&log);
    assert_eq!(
        calls.iter().filter(|call| *call == "appid start").count(),
        1,
        "{calls:?}"
    );
    let (after_record, applied_record) = policy_records(&calls);
    assert!(after_record >= log_before_install, "{calls:?}");
    assert!(
        applied_record > after_record,
        "the event stands later in the log than the record read before the write: {applied_record} <= {after_record}"
    );
    assert!(!calls.iter().any(|call| call == "appid stop"), "{calls:?}");
    let started = output
        .find("application control has started")
        .expect("the service's first event is awaited");
    let written = output
        .find("the policy is written")
        .expect("the policy is written");
    assert!(started < written, "{output}");
    let (code, output) = setup(&["remove"], "yes\n", &[]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(snapshot(), original);
    let _ = std::fs::remove_file(&log);
}

/// Whether this process's token is the system's own: whose entry in the pipe's list is `GA`, so
/// that a request for more than the grant is not refused to it.
#[cfg(feature = "testing")]
fn runs_as_the_system() -> bool {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut process: HANDLE = std::ptr::null_mut();
    // SAFETY: opens this process's own token for the one right named; the handle is owned below.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut process) };
    assert_ne!(opened, 0, "this process's token is opened");
    let process = ffi::Handle::new(process, "this process's token").unwrap();
    let mut buffer = vec![0_u8; 512];
    let mut length = 0_u32;
    // SAFETY: the buffer is the length given and the token is open.
    let read = unsafe {
        GetTokenInformation(
            process.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &raw mut length,
        )
    };
    assert_ne!(read, 0, "the token's user is read");
    // SAFETY: the buffer holds a TOKEN_USER whose identifier points into the same buffer.
    let user = unsafe { Sid::from_ptr((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid) };
    user.to_text() == "S-1-5-18"
}

/// Opens the broker's pipe asking for exactly `access`, the way the installer's client does, and
/// closes it at once. A pipe whose instances are all taken, or that has none for a moment between
/// one client and the next, is waited for a few seconds.
#[cfg(feature = "testing")]
fn open_the_brokers_pipe_with(access: u32) -> Result<(), u32> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    };
    let name = ffi::wide(kr_boundary_windows::win::pipe::NAME);
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // SAFETY: the name is NUL-terminated; the result is checked.
        let opened = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if opened != INVALID_HANDLE_VALUE {
            drop(ffi::Handle::new(opened, "the broker's pipe").unwrap());
            return Ok(());
        }
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        // Between one client and the next, the broker's loop has no instance for a moment.
        if !matches!(code, ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND)
            || std::time::Instant::now() >= until
        {
            return Err(code);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// A client of the broker's pipe holds the pipe's one grant and nothing else when it is an
/// elevated administrator (the Administrators entry) and is the system with its own: the installer's
/// `connect` opens the pipe, sends one request and reads its answer, and, when the answer is late,
/// its deadline cancels the read on that handle.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn a_client_that_holds_only_the_pipes_grant_connects_and_a_request_and_its_answer_cross_it() {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    let stop = Stop::new().unwrap();
    require_clean_machine();
    let mut listener = Listener::bind(&[], std::sync::Arc::clone(&stop)).unwrap();
    let server = std::thread::spawn({
        let stop = std::sync::Arc::clone(&stop);
        move || {
            let Some(mut connection) = listener.accept().unwrap() else {
                return;
            };
            let request: Request = kr_boundary_windows::frame::read(&mut connection).unwrap();
            assert!(matches!(request, Request::Prove { .. }), "{request:?}");
            let answer = Response::Proof {
                ready: true,
                detail: "answered".to_owned(),
            };
            kr_boundary_windows::frame::write(&mut connection, &answer).unwrap();
            // The next request is not answered: the client's deadline ends its read.
            let _ = kr_boundary_windows::frame::read::<_, Request>(&mut connection);
            while !stop.is_set() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    });
    let mut connection = pipe::connect(std::process::id()).expect("the client opens the pipe");
    kr_boundary_windows::frame::write(
        &mut connection,
        &Request::Prove {
            class: Class::Checkout,
        },
    )
    .expect("the request crosses");
    let answer: Response =
        kr_boundary_windows::frame::read(&mut connection).expect("the answer comes");
    assert!(
        matches!(&answer, Response::Proof { ready: true, detail } if detail == "answered"),
        "{answer:?}"
    );
    connection.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    ));
    kr_boundary_windows::frame::write(
        &mut connection,
        &Request::Prove {
            class: Class::Connect,
        },
    )
    .expect("the second request crosses");
    let late = kr_boundary_windows::frame::read::<_, Response>(&mut connection)
        .expect_err("nothing answers the second request")
        .to_string();
    assert!(late.contains("deadline"), "{late}");
    stop.set();
    drop(connection);
    server.join().unwrap();
}

/// The pipe's grant leaves out the right to make another instance of its name (the append bit),
/// and a request for more than the grant, by generic rights or by that bit, is refused to a client
/// that holds only the grant. The system's own entry is `GA`, which refuses nothing: there the case
/// has nothing to show.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated administrator's session that is not the system, in a disposable Windows guest (see the file's header)"]
fn a_client_that_holds_only_the_pipes_grant_is_refused_more_than_the_grant_and_makes_no_instance() {
    use kr_boundary_windows::pipe_access::{CLIENT, CREATE_INSTANCE};
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT};
    if runs_as_the_system() {
        println!("skipped: this session is the system, whose own entry (GA) refuses nothing");
        return;
    }
    let stop = Stop::new().unwrap();
    require_clean_machine();
    let mut listener = Listener::bind(&[], std::sync::Arc::clone(&stop)).unwrap();
    // A broker that takes each client and lets it go, so that the next one finds an instance.
    let server = std::thread::spawn(move || {
        while let Ok(Some(held)) = listener.accept() {
            drop(held);
        }
    });
    assert_eq!(
        open_the_brokers_pipe_with(CLIENT),
        Ok(()),
        "the grant itself is enough to open the pipe"
    );
    assert_eq!(
        open_the_brokers_pipe_with(GENERIC_READ | GENERIC_WRITE),
        Err(5),
        "the generic rights ask for the append bit and more than the grant"
    );
    assert_eq!(
        open_the_brokers_pipe_with(CLIENT | CREATE_INSTANCE),
        Err(5),
        "the grant and the right to make an instance are refused"
    );
    let name = ffi::wide(pipe::NAME);
    // SAFETY: the name is NUL-terminated; the result is checked and the default descriptor is
    // the caller's.
    let made = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            pipe::MAX_INSTANCES,
            4096,
            4096,
            0,
            std::ptr::null(),
        )
    };
    // SAFETY: reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    if made != INVALID_HANDLE_VALUE {
        drop(ffi::Handle::new(made, "an instance of the broker's pipe").unwrap());
    }
    stop.set();
    server.join().unwrap();
    assert_eq!(
        (made == INVALID_HANDLE_VALUE).then_some(code),
        Some(5),
        "no client makes another instance of the pipe's name"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_answer_that_does_not_come_by_the_deadline_is_not_waited_for() {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
    require_clean_machine();
    let mut listener = Listener::bind(&[system], std::sync::Arc::clone(&stop)).unwrap();
    // A broker that accepts and never answers: it holds the connection until it is told to stop.
    let server = std::thread::spawn({
        let stop = std::sync::Arc::clone(&stop);
        move || {
            let held = listener.accept();
            while !stop.is_set() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            drop(held);
        }
    });
    let mut connection = pipe::connect(std::process::id()).unwrap();
    let bound = std::time::Duration::from_secs(2);
    let begun = std::time::Instant::now();
    connection.set_deadline(Some(begun + bound));
    let refused = install::ask(&mut connection, &Request::Status {});
    let elapsed = begun.elapsed();
    stop.set();
    server.join().unwrap();
    let text = refused.expect_err("nothing answered").to_string();
    assert!(text.contains("deadline"), "{text}");
    assert!(
        // The wait is in whole milliseconds, rounded down: a millisecond of slack at the bottom.
        elapsed + std::time::Duration::from_millis(5) >= bound
            && elapsed < bound + std::time::Duration::from_secs(5),
        "the wait ended at the deadline: {elapsed:?}"
    );
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_cancelled_receive_that_does_not_end_gives_the_call_back_at_the_deadline_and_the_connection_takes_no_more()
 {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop, testing};
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
    require_clean_machine();
    let mut listener = Listener::bind(&[system], std::sync::Arc::clone(&stop)).unwrap();
    // A broker that accepts and never answers, and keeps the connection until told to stop.
    let server = std::thread::spawn({
        let stop = std::sync::Arc::clone(&stop);
        move || {
            let held = listener.accept();
            while !stop.is_set() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            drop(held);
        }
    });
    let mut connection = pipe::connect(std::process::id()).unwrap();
    let bound = std::time::Duration::from_secs(1);
    let begun = std::time::Instant::now();
    connection.set_deadline(Some(begun + bound));
    // The platform does not end the transfer that was cancelled: the wait for it is bounded by the
    // deadline and a short grace, not by the transfer.
    testing::skip_next_cancel();
    let refused = install::ask(&mut connection, &Request::Status {});
    let elapsed = begun.elapsed();
    let text = refused.expect_err("nothing answered").to_string();
    assert!(text.contains("deadline"), "{text}");
    assert!(
        elapsed >= bound && elapsed < bound + std::time::Duration::from_millis(600),
        "the call came back at the deadline and the grace of 100 ms: {elapsed:?}"
    );
    // The transfer is still pending, so nothing more is taken on that connection.
    let again = install::ask(&mut connection, &Request::Status {})
        .expect_err("the connection takes no more")
        .to_string();
    assert!(again.contains("did not end"), "{again}");
    drop(connection);
    stop.set();
    server.join().unwrap();
}

#[test]
fn the_proof_cycle_is_counted_from_before_the_service_starts() {
    use std::time::{Duration, Instant};
    let bound = Duration::from_secs(300);
    let before = Instant::now();
    let cycle = install::ProofCycle::begin(bound, Duration::from_secs(10), || {
        std::thread::sleep(Duration::from_millis(700));
        Ok(())
    })
    .unwrap();
    // The broker takes its own instant after its service has started, so the installation's
    // deadline must come before the broker's: it is counted from before the start, whatever the
    // start took.
    assert!(
        cycle.deadline() < before + bound + Duration::from_millis(300),
        "the deadline is counted from before the start"
    );
    // A start that fails is the error of the cycle.
    assert!(
        install::ProofCycle::begin(bound, Duration::from_secs(10), || {
            Err(install::Error::Failed("no start".to_owned()))
        })
        .is_err()
    );
}

/// A broker that answers each proof when the case says: it answers the proof for each class after a
/// delay, and counts the proofs that were asked of it. It stands for a broker whose cycle ends
/// before the installation's deadline would, and whose answer after the end belongs to a later cycle.
#[cfg(feature = "testing")]
fn stand_in_broker(
    checkout_after: std::time::Duration,
    connect_after: std::time::Duration,
) -> (
    std::thread::JoinHandle<()>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<kr_boundary_windows::win::pipe::Stop>,
) {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    use std::sync::atomic::Ordering;
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
    require_clean_machine();
    let mut listener = Listener::bind(&[system], std::sync::Arc::clone(&stop)).unwrap();
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread = std::thread::spawn({
        let stop = std::sync::Arc::clone(&stop);
        let asked = std::sync::Arc::clone(&asked);
        move || {
            let Some(mut connection) = listener.accept().unwrap() else {
                return;
            };
            while let Ok(request) = kr_boundary_windows::frame::read::<_, Request>(&mut connection)
            {
                let Request::Prove { class } = request else {
                    continue;
                };
                asked.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(match class {
                    Class::Checkout => checkout_after,
                    Class::Connect => connect_after,
                });
                let answer = Response::Proof {
                    ready: true,
                    detail: format!("{class:?} is ready"),
                };
                if kr_boundary_windows::frame::write(&mut connection, &answer).is_err() {
                    return;
                }
            }
            while !stop.is_set() {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    });
    (thread, asked, stop)
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_answer_of_a_later_cycle_is_never_accepted_and_no_proof_is_asked_near_the_end() {
    use kr_boundary_windows::win::pipe;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    let bound = Duration::from_secs(4);
    let margin = Duration::from_secs(1);

    // The proof for the second class is answered after the installation's deadline, as a later cycle
    // would answer it: the installation stops reading at the deadline and takes no answer after it.
    let (server, asked, stop) = stand_in_broker(Duration::from_millis(500), Duration::from_secs(5));
    let mut connection = pipe::connect(std::process::id()).unwrap();
    let cycle = install::ProofCycle::begin(bound, margin, || Ok(())).unwrap();
    let began = Instant::now();
    let refused = cycle.prove(&mut connection).unwrap_err().to_string();
    let elapsed = began.elapsed();
    drop(connection);
    stop.set();
    server.join().unwrap();
    assert!(refused.contains("deadline"), "{refused}");
    // The bound is the installation's deadline, counted from the cycle's beginning; the wait ends at
    // it, and the read that sees the deadline takes a few milliseconds more. The late answer comes
    // a second after the deadline, so a margin of half a second tells a wait that ended at the
    // deadline from one that ended at the answer.
    assert!(
        elapsed < bound + Duration::from_millis(500),
        "the wait ended at the installation's deadline, not at the late answer: {elapsed:?}"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 2);

    // The first answer comes inside the margin, so the second proof is not asked at all: a request
    // that late could be answered only by a cycle of the broker's that the installation did not ask
    // for.
    let (server, asked, stop) = stand_in_broker(Duration::from_millis(3200), Duration::ZERO);
    let mut connection = pipe::connect(std::process::id()).unwrap();
    let cycle = install::ProofCycle::begin(bound, margin, || Ok(())).unwrap();
    let refused = cycle.prove(&mut connection).unwrap_err().to_string();
    drop(connection);
    stop.set();
    server.join().unwrap();
    assert!(
        refused.contains("left before the proof for Connect"),
        "{refused}"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1, "only the first was asked");

    // Both inside the cycle: accepted.
    let (server, asked, stop) =
        stand_in_broker(Duration::from_millis(200), Duration::from_millis(200));
    let mut connection = pipe::connect(std::process::id()).unwrap();
    install::ProofCycle::begin(bound, margin, || Ok(()))
        .unwrap()
        .prove(&mut connection)
        .unwrap();
    drop(connection);
    stop.set();
    server.join().unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// How long the process has existed.
fn process_age(pid: u32) -> std::time::Duration {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess};
    let ticks =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    // SAFETY: opens a process for a limited query and reads its times; each result is checked.
    unsafe {
        let raw = OpenProcess(0x1000, 0, pid);
        let process = ffi::Handle::new(raw, "the broker's process").unwrap();
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        assert_ne!(
            GetProcessTimes(
                process.raw(),
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user
            ),
            0
        );
        let mut now = zero;
        GetSystemTimeAsFileTime(&raw mut now);
        std::time::Duration::from_nanos((ticks(now) - ticks(created)) * 100)
    }
}

#[cfg(feature = "testing")]
#[test]
fn an_unlisted_program_that_runs_after_an_earlier_refusal_fails_the_proof() {
    use kr_boundary_windows::win::launch::{LaunchError, REFUSED_BY_POLICY};
    use kr_boundary_windows::win::proof::{Captured, testing};
    let ran = || {
        Ok(Captured {
            outcome: Outcome::Ran(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    };
    assert_eq!(
        testing::judge(Err(LaunchError::NotStarted(REFUSED_BY_POLICY)), false),
        Ok(true)
    );
    assert_eq!(
        testing::judge(ran(), false),
        Ok(false),
        "a run before any refusal is the policy not yet binding"
    );
    let failed = testing::judge(ran(), true).unwrap_err();
    assert!(failed.contains("after it was refused"), "{failed}");
    assert!(
        testing::judge(Err(LaunchError::NotStarted(1326)), false).is_err(),
        "an error that is not the policy's refusal is no refusal"
    );
}

/// Run by a startup task after the guest's Windows restarts with the boundary installed: the broker
/// that the service manager started with Windows proves the boundary inside its bound, which is
/// measured from the broker's own start.
#[test]
#[ignore = "runs after a restart of the guest with the boundary installed (see the file's header)"]
fn after_a_restart_the_brokers_proof_passes_inside_its_bound() {
    let uptime = std::time::Duration::from_millis(ffi::uptime_millis());
    let mut session = install::open_session().expect("the broker started with Windows");
    let broker = service::manager()
        .unwrap()
        .open(SERVICE)
        .unwrap()
        .unwrap()
        .status()
        .unwrap()
        .pid;
    for class in [Class::Checkout, Class::Connect] {
        let begun = std::time::Instant::now();
        match install::ask(&mut session, &Request::Prove { class }).expect("the broker answers") {
            Response::Proof { ready, detail } => {
                let age = process_age(broker);
                eprintln!(
                    "{class:?}: ready {ready} after {:.1} s, asked {:.0} s after the start of Windows, answered {:.0} s after the broker's start: {detail}",
                    begun.elapsed().as_secs_f32(),
                    uptime.as_secs_f32(),
                    age.as_secs_f32()
                );
                assert!(ready, "the proof passes: {detail}");
                assert!(
                    age <= kr_boundary_windows::win::broker::PROOF_BOUND,
                    "the proof for {class:?} was answered {age:?} after the broker's start, past its deadline"
                );
            }
            other => panic!("the broker answered a proof with {other:?}"),
        }
    }
}
