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
/// inherits, which lets ordinary accounts add to it.
fn inherited_folder() -> PathBuf {
    let folder = PathBuf::from(r"C:\ProgramData").join(format!(
        "krparent-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&folder).unwrap();
    folder
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
    let holds = install::make_data_directory(&paths).unwrap();
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
    std::fs::write(&paths.data, b"not a directory").unwrap();
    assert!(install::make_data_directory(&paths).is_err());
    let _ = std::fs::remove_file(&paths.data);
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
    std::fs::create_dir(&parent).unwrap();
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
    std::fs::create_dir(&root).unwrap();
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

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_answer_that_does_not_come_by_the_deadline_is_not_waited_for() {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
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
        elapsed >= bound && elapsed < bound + std::time::Duration::from_secs(5),
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
        elapsed >= bound && elapsed < bound + std::time::Duration::from_secs(2),
        "the call came back at the deadline and the grace: {elapsed:?}"
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
    assert!(
        elapsed < bound,
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
