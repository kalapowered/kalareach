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
use kr_boundary_windows::win::pipe::Kind as Pipe;
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
    let paths = Paths::system().expect("the system's folders are read");
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
    /// Set by a case whose correct end keeps rules of the application-control policy (an
    /// administrator's own rule, or a policy that was there before): the cleanup check then leaves
    /// the policy and the Application Identity service's state that goes with it out.
    policy_stays: std::cell::Cell<bool>,
}

/// A case that installs, or that binds the broker's pipe, starts from a machine with no
/// installation on it: the service, the two boundary accounts, the data directory, the program
/// directory and the pipe's name are all absent. A case that failed before its own cleanup, or a
/// run that was cut short, leaves some of them, and every later case then fails for that and not
/// for what it shows: this fails first, with one text, so that the run is void and never a verdict
/// on the product.
fn require_clean_machine() {
    let left = machine_problems(true, false);
    assert!(
        left.is_empty(),
        "the machine is not clean: {}",
        left.join(", ")
    );
}

/// The Application Identity service's state that the cases compare with: the state the run began
/// with, and after a case that correctly ends with it changed, the state that case left.
static RUN_START: std::sync::Mutex<Option<(bool, u32)>> = std::sync::Mutex::new(None);

/// The Application Identity service's state, which a run begins with: whether it runs and how it
/// starts.
fn appid_state() -> (bool, u32) {
    let appid = service::manager()
        .unwrap()
        .open("AppIDSvc")
        .unwrap()
        .expect("the Application Identity service exists");
    (
        appid.status().unwrap().running(),
        appid.configuration().unwrap().0,
    )
}

/// What a machine with no installation on it does not have: the broker's service (a service marked
/// for deletion counts only when `strict`), the two accounts and their entries among the hidden
/// accounts, the data directory and the folder above it, the program directory, the pipe's name,
/// any rule of the application-control policy, and the Application Identity service in another
/// state than the run began with. Where `policy_stays`, the policy's rules and that service's state
/// are left out, because the case's correct end keeps them.
fn machine_problems(strict: bool, policy_stays: bool) -> Vec<String> {
    let began = *RUN_START.lock().unwrap().get_or_insert_with(appid_state);
    let mut left = Vec::new();
    let service = service::manager().unwrap().open(SERVICE).unwrap();
    if service.is_some_and(|service| strict || !service.marked_for_deletion().unwrap()) {
        left.push("the broker's service".to_owned());
    }
    for name in [CHECKOUT, CONNECT] {
        if Sid::of_account(name).is_ok() {
            left.push(format!("the account {name}"));
        }
    }
    let hidden = registry::open(SPECIAL_ACCOUNTS)
        .unwrap()
        .map(|key| key.value_names().unwrap())
        .unwrap_or_default();
    for name in [CHECKOUT, CONNECT] {
        if hidden.iter().any(|hidden| hidden == name) {
            left.push(format!("the hidden-account entry of {name}"));
        }
    }
    let paths = Paths::system().expect("the system's folders are read");
    if paths.data.exists() {
        left.push("the data directory".to_owned());
    }
    if paths.data_parent().exists() {
        left.push("the folder above the data directory".to_owned());
    }
    if paths.program.exists() {
        left.push("the program directory".to_owned());
    }
    if [Pipe::Persons, Pipe::Administrators]
        .iter()
        .any(|kind| std::fs::metadata(kind.name()).is_ok())
    {
        left.push("the broker's pipe".to_owned());
    }
    if !policy_stays && !channel().effective().unwrap().1.is_unconfigured() {
        left.push("rules of the application-control policy".to_owned());
    }
    let now = appid_state();
    if !policy_stays && now != began {
        left.push(format!(
            "the Application Identity service (running {}, start type {}) is not as the run began (running {}, start type {})",
            now.0, now.1, began.0, began.1
        ));
    }
    left
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
        Case {
            name,
            person,
            policy_stays: std::cell::Cell::new(false),
        }
    }

    /// Says that this case ends with rules of the policy still in force, as it should, so that its
    /// cleanup does not count them as left by the removal.
    fn leaves_policy_in_place(&self) {
        self.policy_stays.set(true);
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
        let (removal_code, removal_output) = setup(&["remove"], "yes\n", &[]);
        // A case whose body removed the installation itself leaves nothing for this removal, which
        // then says so and refuses: that is the right end, and the check below reads the machine.
        let removal_code = if removal_output.contains("nothing is installed") {
            0
        } else {
            removal_code
        };
        // What the removal left, read before the policy is cleared here: a case that ends with
        // something of the installation still on the machine fails itself, and the next case's
        // "not clean" is not the only sign of it.
        let left = machine_problems(false, self.policy_stays.get());
        if self.policy_stays.get() {
            // The removal keeps the service running while a rule stays, and the case's own end is
            // right: the state it leaves is what the next case begins with.
            *RUN_START.lock().unwrap() = Some(appid_state());
        }
        let _ = channel().set(CLEAR);
        let _ = account::delete(&self.name);
        if !std::thread::panicking() {
            assert_eq!(
                removal_code, 0,
                "the case's own removal failed: {removal_output}"
            );
            assert!(
                left.is_empty(),
                "the removal left on the machine: {}",
                left.join(", ")
            );
        }
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
    let paths = Paths::system().expect("the system's folders are read");
    let before = snapshot();
    assert!(
        before.policy.is_unconfigured(),
        "the guest starts with no application control"
    );
    // The order below is the one of a service that the installation starts. A service that already
    // runs takes the other path, which another case follows, so a run that finds it running is void.
    assert!(
        !before.appid_running,
        "the machine is not clean: the Application Identity service is running"
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
    case.leaves_policy_in_place();
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
    case.leaves_policy_in_place();
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
    let manifest = Manifest::load(
        &Paths::system()
            .expect("the system's folders are read")
            .manifest,
    )
    .unwrap();
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
    give_to(path.as_ref(), "*S-1-5-32-544");
}

/// Writes a file that the Administrators own, for the same reason as [`owned_dir`].
#[cfg(feature = "testing")]
fn owned_file(path: impl AsRef<Path>, bytes: &[u8]) {
    std::fs::write(path.as_ref(), bytes).unwrap();
    give_to(path.as_ref(), "*S-1-5-32-544");
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
        ..Paths::system().expect("the system's folders are read")
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
    // A link at the directory's own name is refused with the remedy of a directory that the
    // installation did not make: moved aside, and neither corrected into place nor removed.
    for refused in [
        install::make_data_directory(&paths).unwrap_err(),
        install::entry(&paths)
            .err()
            .expect("a link at the data directory"),
    ] {
        let text = refused.to_string();
        assert!(text.contains("it is a link"), "{text}");
        assert!(text.contains("did not make"), "{text}");
        assert!(text.contains("Move it aside"), "{text}");
        assert!(text.contains("do not remove it"), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
    }
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
/// is still read by a second removal, which reads the policy records through the channel and makes
/// the staging directory again, since the first took it. Once the program lets go, the second
/// removal finishes and the computer is as it was.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_removal_that_could_not_delete_a_record_is_run_again_whole_and_finishes() {
    use std::os::windows::fs::OpenOptionsExt;
    let case = Case::new();
    let before = snapshot();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let manifest = Paths::system()
        .expect("the system's folders are read")
        .manifest;
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

/// Every record that stays after a failed removal has the manifest beside it, so the whole removal
/// is run again until it ends clean. The earlier-state record, a replacement of the manifest and a
/// file in `staging` are each held open in turn, shared for reading and writing and not for
/// deleting: the first removal fails and names what stayed, the manifest and `staging` stay with
/// it, and once the program lets go the second removal reads the manifest, reaches the cleanup of
/// the records again and ends with the computer as it was.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_removal_that_could_not_delete_the_earlier_state_record_a_replacement_or_staging_is_run_again_whole()
 {
    use std::os::windows::fs::OpenOptionsExt;
    let case = Case::new();
    let before = snapshot();
    let paths = Paths::system().expect("the system's folders are read");
    let hex = "ab".repeat(16);
    let held_in_turn = [
        ("the earlier-state record", paths.prior.clone()),
        (
            "a replacement of the manifest",
            paths.data.join(format!("manifest-{hex}.new")),
        ),
        (
            "a file in staging",
            paths.staging.join(format!("policy-{hex}.xml")),
        ),
    ];
    for (what, record) in held_in_turn {
        let (code, output) = case.install();
        assert_eq!(code, 0, "{what}: {output}");
        if !record.exists() {
            owned_file(&record, b"x");
        }
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&record)
            .unwrap();
        let (code, output) = setup(&["remove"], "yes\n", &[]);
        drop(held);
        assert_ne!(code, 0, "{what}: {output}");
        // A file inside `staging` is not removed alone: the directory that holds it is the one the
        // removal could not delete, and the one it names.
        let named = if record.starts_with(&paths.staging) {
            paths.staging.clone()
        } else {
            record.clone()
        };
        assert!(
            output.contains(&named.display().to_string()),
            "{what}: what stayed is named ({}): {output}",
            named.display()
        );
        assert!(
            paths.manifest.is_file(),
            "{what}: the manifest stays with what stayed"
        );
        assert!(
            paths.staging.exists(),
            "{what}: staging stays while a record stays"
        );
        assert!(output.contains("run the removal again"), "{what}: {output}");
        let (code, output) = setup(&["remove"], "yes\n", &[]);
        assert_eq!(code, 0, "{what}: {output}");
        assert_eq!(snapshot(), before, "{what}: the second removal finished");
    }
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
        assert!(text.contains("itself"), "{text}");
        assert!(text.contains("not what it points to"), "{text}");
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
    give_to(&paths.program, "*S-1-5-32-544");
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
    // Whatever else the check of the directory finds, it finds nothing in the names. Only the
    // entry is run: the removal makes the same check, but where it finds nothing it goes on to
    // remove the installation the manifest records, program directory included, and the next
    // step of this case would have nothing to look at. Every refusal above is shown for both.
    let accepted = |what: &str| {
        if let Err(error) = install::entry(&paths) {
            assert!(
                !error.to_string().contains("boundary's program directory"),
                "{what}: {error}"
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
    // The text fits the file: the installation makes it, empty, and a repair makes it again. It
    // does not say that the installation never makes it there.
    for text in both("a configuration that holds settings") {
        assert!(text.contains("the installation makes it empty"), "{text}");
        assert!(
            !text.contains("not something that the installation makes there"),
            "{text}"
        );
    }
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
        ..Paths::system().expect("the system's folders are read")
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

/// A folder above the data directory that cannot be opened to be checked, for a reason that is no
/// program holding it open, shows nothing of who made it: it is told to be moved aside, and neither
/// corrected into place nor removed.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_parent_folder_that_cannot_be_opened_is_told_to_be_moved_aside_and_not_to_be_corrected_or_removed()
 {
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let icacls = |arguments: &[&str]| {
        let done = Command::new("icacls")
            .arg(&folder)
            .args(arguments)
            .output()
            .unwrap();
        assert!(done.status.success(), "{done:?}");
    };
    // Neither the system nor the Administrators group may list it, so the check's open is refused
    // with an access error and not with a sharing violation.
    icacls(&["/deny", "*S-1-5-18:(RD)", "*S-1-5-32-544:(RD)"]);
    let refused = install::check_data_parent(&paths_under(&folder));
    icacls(&["/remove:d", "*S-1-5-18", "*S-1-5-32-544"]);
    let text = refused.unwrap_err().to_string();
    assert!(text.contains("could not be opened to be checked"), "{text}");
    assert!(text.contains("Move the folder aside"), "{text}");
    for other in [
        "Remove the folder",
        "remove the folder",
        "Correct it instead",
        "Close the program",
    ] {
        assert!(!text.contains(other), "one remedy: {text}");
    }
    let _ = std::fs::remove_dir_all(&folder);
}

/// A record's remedy comes from what its own handle shows, never from the words of the reason that
/// refused it. A manifest that another account owns and that has a second name is moved out and is
/// not corrected into place, since correcting it would make another account's file the
/// installation's record; a directory that cannot be opened to be checked shows nothing of who made
/// it, so it is neither corrected nor removed.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_records_remedy_comes_from_what_its_handle_shows_and_what_cannot_be_read_is_neither_corrected_nor_removed()
 {
    use std::os::windows::fs::OpenOptionsExt;
    const ADMINISTRATORS: &str = "*S-1-5-32-544";
    const USERS: &str = "*S-1-5-32-545";
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let refusal = || {
        install::make_data_directory(&paths)
            .expect_err("a refused record")
            .to_string()
    };
    let set_owner = |path: &Path, who: &str| {
        let done = Command::new("icacls")
            .arg(path)
            .args(["/setowner", who])
            .output()
            .unwrap();
        assert!(done.status.success(), "{done:?}");
    };

    let second_name = folder.join("second-name.json");
    std::fs::hard_link(&paths.manifest, &second_name).unwrap();
    set_owner(&paths.manifest, USERS);
    let text = refusal();
    assert!(text.contains("more than one name"), "{text}");
    assert!(text.contains("did not make"), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("do not remove it"), "{text}");
    for other in ["Correct what the reason names", "Remove "] {
        assert!(!text.contains(other), "{text}");
    }
    set_owner(&paths.manifest, ADMINISTRATORS);
    std::fs::remove_file(&second_name).unwrap();
    install::make_data_directory(&paths).expect("the manifest is the installation's own again");

    // Another program holds the journal's directory open and shares it with nobody, so it cannot
    // be opened to be checked.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x0200_0000)
        .open(&paths.journal)
        .unwrap();
    let text = refusal();
    drop(held);
    assert!(text.contains("could not be opened to be checked"), "{text}");
    assert!(text.contains("Nothing shows who made"), "{text}");
    assert!(
        text.contains("Close the program that holds it open"),
        "{text}"
    );
    for other in [
        "Correct what the reason names",
        "Remove ",
        "Do not remove",
        "Move it aside",
    ] {
        assert!(!text.contains(other), "{text}");
    }
    install::make_data_directory(&paths).expect("the directory can be opened again");
    let _ = std::fs::remove_dir_all(&folder);
}

/// The move-aside remedy holds at the next run. A record that the person moves out of the data
/// directory, as the text says, is absent at the next run and is made new; a record's name beside
/// the original would be a name that the layout does not give. A manifest that is moved out leaves
/// a directory with no manifest, which the next run refuses, naming what else is in it and never the
/// manifest that was moved out.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_record_moved_out_of_the_data_directory_as_the_text_says_is_not_met_again_as_something_to_remove()
 {
    use install::DataChild;
    let folder = inherited_folder();
    acl::set_protected(&folder, &data_parent_descriptor()).unwrap();
    let paths = paths_in(&folder);
    installed_data_directory(&paths);
    let saved = folder.join("saved");
    std::fs::create_dir(&saved).unwrap();

    // A link at the journal's name: the text says to move it out of the data directory.
    let target = inherited_folder();
    std::fs::write(target.join("kept.txt"), b"x").unwrap();
    std::fs::remove_dir(&paths.journal).unwrap();
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&paths.journal)
        .arg(&target)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let text = install::make_data_directory(&paths)
        .expect_err("a link at the journal's name")
        .to_string();
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("out of the data directory"), "{text}");
    std::fs::rename(&paths.journal, saved.join("journal")).unwrap();
    let mut holds = install::make_data_directory(&paths)
        .expect("the next run finds no journal and does not refuse");
    holds.directory(DataChild::Journal).unwrap();
    assert!(paths.journal.is_dir(), "the journal is made new");
    assert!(summary_of(&paths.journal).protected);
    assert!(
        target.join("kept.txt").is_file(),
        "what the link led to is untouched"
    );
    drop(holds);

    // A link at the manifest's name: the text says what the next run finds once it is moved out.
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
    let text = install::make_data_directory(&paths)
        .expect_err("a link at the manifest's name")
        .to_string();
    assert!(text.contains("Move it aside"), "{text}");
    assert!(
        text.contains("The directory then holds no manifest"),
        "{text}"
    );
    std::fs::rename(&paths.manifest, saved.join("manifest.json")).unwrap();
    let next = install::make_data_directory(&paths)
        .expect_err("a directory with content and no manifest")
        .to_string();
    assert!(
        next.contains("no manifest records this directory"),
        "{next}"
    );
    assert!(
        !next.contains(&saved.join("manifest.json").display().to_string()),
        "{next}"
    );
    assert!(!next.contains("Do not remove"), "{next}");
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
        assert!(text.contains("it is a link or a mounted folder"), "{text}");
        assert!(
            text.contains("does not go through a link or a mounted folder at or above its trees"),
            "{text}"
        );
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
        assert!(
            text.contains("could not be opened or read to be checked"),
            "{text}"
        );
        assert!(
            text.contains("Close the program that holds it open"),
            "{text}"
        );
        assert!(text.contains("program directory"), "{text}");
        assert!(text.contains(&above.display().to_string()), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&above);

    // A program directory on a volume that is not NTFS: a small FAT volume in a virtual disk.
    let disk = folder.join("fat.vhd");
    // The disk is detached when the case ends in any way, also when an assertion fails before the
    // case's own detach: an attached disk would keep `Y:` in use for every later run.
    struct Detach {
        script: PathBuf,
        disk: PathBuf,
    }
    impl Drop for Detach {
        fn drop(&mut self) {
            let lines = [
                format!("select vdisk file=\"{}\"", self.disk.display()),
                "detach vdisk".to_owned(),
            ];
            let _ = std::fs::write(&self.script, lines.join("\r\n"));
            let _ = Command::new("diskpart")
                .arg("/s")
                .arg(&self.script)
                .output();
            let _ = std::fs::remove_file(&self.script);
        }
    }
    let _detach = Detach {
        script: folder.join("detach.txt"),
        disk: disk.clone(),
    };
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
    // The program directory is its own top, so the walk reads the folders above it from the volume's
    // root down: `Y:\` is the first folder opened. The volume of each folder is asked before its
    // attributes are read (a FAT volume does not answer that query), so the root is refused for its
    // volume, with the words for a volume that the installation does not use, before anything else
    // about it is read; the program directory's own open would refuse the same volume next.
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
        assert!(text.contains("the volume uses FAT32"), "{text}");
        assert!(text.contains(r"Y:\ is a folder above"), "{text}");
        assert!(!text.contains("Make the Administrators group"), "{text}");
        assert!(!text.contains("Close the program"), "{text}");
        assert!(text.contains("This layout is not supported"), "{text}");
        assert!(!text.contains("Move "), "{text}");
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
    let before = Paths::system().expect("the system's folders are read");
    let saved: Vec<_> = names
        .iter()
        .map(|name| (*name, std::env::var_os(name)))
        .collect();
    for name in names {
        // SAFETY: the guest's cases run on one test thread, and the variables are put back below.
        unsafe { std::env::set_var(name, r"C:\Planted") };
    }
    let after = Paths::system().expect("the system's folders are read");
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
    // The run's exit status and its one line are read: the version recorded is Git's own.
    let git = qualified.expect("Git is qualified");
    assert!(git.version.starts_with("git version "), "{}", git.version);
    assert!(!git.version.contains('\n'), "{}", git.version);
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
    // With the manifest, the file that has two names is not the installation's: its handle shows
    // that, so it is moved aside and never corrected into place.
    let text = install::make_data_directory(&paths)
        .expect_err("a file with two names")
        .to_string();
    assert!(text.contains("more than one name"), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("did not make"), "{text}");
    // Without it, nothing is listed and every name is read by its own handle. Only the two
    // replacements are left, so the first entry read is one of them: its handle shows two names,
    // so it is moved aside and not removed.
    std::fs::remove_file(&paths.manifest).unwrap();
    for entry in std::fs::read_dir(&paths.data).unwrap() {
        let path = entry.unwrap().path();
        if path != first && path != second {
            if path.is_dir() {
                std::fs::remove_dir_all(&path).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
        }
    }
    let text = install::make_data_directory(&paths)
        .expect_err("what is left with no manifest")
        .to_string();
    assert!(text.contains("manifest-"), "{text}");
    assert!(text.contains("Move it aside"), "{text}");
    assert!(text.contains("did not make"), "{text}");
    assert!(text.contains("out of the data directory"), "{text}");
    assert!(!text.contains("Remove "), "{text}");
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
        .args(["/setowner", "*S-1-5-32-544"])
        .output();
    let _ = account::delete(&name);
    install::make_data_directory(&paths).expect("the owner is back");

    // A journal file that another account owns is refused, as is a file that is not a journal's.
    let owned = Command::new("icacls")
        .arg(&journal_file)
        .args(["/setowner", "*S-1-5-32-545"])
        .output()
        .unwrap();
    assert!(owned.status.success(), "{owned:?}");
    moved_aside_with("S-1-5-32-545");
    let _ = Command::new("icacls")
        .arg(&journal_file)
        .args(["/setowner", "*S-1-5-32-544"])
        .output();
    owned_file(paths.journal.join("notes.txt"), b"x");
    removal_with("notes.txt");
    std::fs::remove_file(paths.journal.join("notes.txt")).unwrap();

    // A journal file with a second name is not the installation's: its handle shows that, whoever
    // owns it, so it is moved out and neither corrected into place nor removed.
    let second_name = paths.journal.join(format!("{}.journal", "cd".repeat(16)));
    std::fs::hard_link(&journal_file, &second_name).unwrap();
    moved_aside_with("more than one name");
    std::fs::remove_file(&second_name).unwrap();

    // A journal file that the system's class owns, with another account's entry in its list, is a
    // record to correct, and is never removed.
    let granted = Command::new("icacls")
        .arg(&journal_file)
        .args(["/grant", "*S-1-5-32-545:(R)"])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");
    correction_with("its permission list has an entry for");
    let revoked = Command::new("icacls")
        .arg(&journal_file)
        .args(["/remove:g", "*S-1-5-32-545"])
        .output()
        .unwrap();
    assert!(revoked.status.success(), "{revoked:?}");

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
    let text = refusal("differ only by case");
    assert!(text.contains("Turn the flag off"), "{text}");
    for other in [
        "Remove ",
        "Do not remove",
        "Move it aside",
        "emptied",
        "removed",
    ] {
        assert!(!text.contains(other), "one remedy: {text}");
    }
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
    give_to(&file, "*S-1-5-32-544");
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
    assert_eq!(
        install::testing::listing_the_function_ran_after(),
        Some("run"),
        "it ran after the listing of the roots, not after the listing of staging or of the journal"
    );
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
    // An entry whose own handle shows that the installation did not make it is moved aside and
    // never named for removal.
    let moved_aside_with = |words: &str| {
        let refused = install::make_data_directory(&paths).expect_err("the directory is refused");
        let text = refused.to_string();
        assert!(text.contains(words), "{text}");
        assert!(text.contains("Move it aside"), "{text}");
        assert!(text.contains("did not make"), "{text}");
        assert!(!text.contains("Remove "), "{text}");
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
    moved_aside_with(&shown);
    let refused = install::make_data_directory(&paths).expect_err("a file that is owned");
    assert!(refused.to_string().contains(&owner.to_text()), "{refused}");
    assert_eq!(std::fs::read(&policy).unwrap(), b"policy");
    assert_eq!(summary_of(&policy), before);
    give_to(&policy, "*S-1-5-32-544");

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
    moved_aside_with("more than one name");
    std::fs::remove_file(&second).unwrap();
    give_to(&inner, &name);
    moved_aside_with("unlisted.exe");
    give_to(&inner, "*S-1-5-32-544");

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
    give_to(&root, "*S-1-5-32-544");
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
    give_to(&paths.journal, "*S-1-5-32-544");
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
    give_to(&paths.manifest, "*S-1-5-32-544");
    install::make_data_directory(&paths).expect("the records are the administrators' again");

    // The manifest's replacement that a crash left has a name the layout gives, so it is refused as
    // a record is when another account owns it, and what is there is not removed.
    let replacement = paths.data.join(format!("manifest-{}.new", "ef".repeat(16)));
    std::fs::write(&replacement, b"half").unwrap();
    give_to(&replacement, "*S-1-5-32-544");
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
    give_to(&replacement, "*S-1-5-32-544");
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
    moved_aside_with("it is a link");
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
    let parent = Paths::system()
        .expect("the system's folders are read")
        .data_parent()
        .to_path_buf();
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
    let paths = Paths::system().expect("the system's folders are read");
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
    // Once the leftover is cleared the finished journal is no work. A private root that no journal
    // names is not unfinished work either: the removal refuses it on its own, names it to remove,
    // and changes nothing.
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
        output.contains("no journal names it as unfinished work")
            && output.contains("0123456789abcdef0123456789abcdef")
            && output.contains("Remove ")
            && !output.contains(REFUSAL)
            && !output.contains("the invocation"),
        "only the root refuses it now, and no journal names it: {output}"
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
///
/// A log that is not there fails the case: a recorder that did not work must not read as a program
/// that made no call.
fn recorded_calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_else(|failure| panic!("the recorder wrote no call log at {log:?}: {failure}"))
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
        "the machine is not clean: the Application Identity service is running"
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

/// A computer whose owner already runs the Application Identity service, set to start with Windows,
/// keeps it that way: the installation neither starts it, nor stops it, nor changes its start type,
/// records the state it found, proves the policy, and the removal leaves the service as it was. The
/// case starts from that state and does not make it: a run that finds the service stopped, or not
/// automatic, is void.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_application_identity_service_that_runs_and_starts_with_windows_is_left_as_it_was_by_the_installation_and_the_removal()
 {
    let case = Case::new();
    let paths = Paths::system().expect("the system's folders are read");
    let before = snapshot();
    assert!(
        before.appid_running && before.appid_start == 2,
        "the machine is not clean: the Application Identity service is not running and set to start with Windows"
    );
    assert!(
        before.policy.is_unconfigured(),
        "the guest starts with no application control"
    );
    let log = call_log();
    let (code, output) = case.payload(
        "payload",
        &[("KR_BOUNDARY_CALL_LOG", log.to_str().unwrap())],
    );
    assert_eq!(code, 0, "the installation succeeds: {output}");
    assert!(output.contains("already running"), "{output}");
    for account in [CHECKOUT, CONNECT] {
        assert!(
            output
                .lines()
                .any(|line| line.contains(account)
                    && line.contains("an unlisted program was refused")),
            "the proof passes for {account}: {output}"
        );
    }
    let calls = recorded_calls(&log);
    assert!(
        !calls.iter().any(|call| call.starts_with("appid ")),
        "a service that runs and starts with Windows is neither started, stopped nor set: {calls:?}"
    );
    // The record of the earlier state says what was found.
    let prior = Prior::load(&paths.prior).unwrap();
    assert!(
        prior.appid_running,
        "the record says the service was running"
    );
    assert_eq!(
        prior.appid_start_type, 2,
        "and that it started with Windows"
    );
    let installed = snapshot();
    assert!(
        installed.appid_running && installed.appid_start == 2,
        "the installation leaves the service as it found it: {installed:?}"
    );

    // The removal records its calls in the same file, so that what it did not do to the service shows.
    // The installation's own lines are in the log, so the recorder works; the removal's recorder is
    // shown working by the case of the stopped service, whose removal records the stop it makes.
    let before_removal = recorded_calls(&log).len();
    assert!(
        before_removal > 0,
        "the recorder wrote the installation's calls"
    );
    let (code, output) = setup(
        &["remove"],
        "yes\n",
        &[("KR_BOUNDARY_CALL_LOG", log.to_str().unwrap())],
    );
    assert_eq!(code, 0, "the removal succeeds: {output}");
    let calls = recorded_calls(&log);
    assert!(
        calls.len() >= before_removal,
        "the call log is only added to: {calls:?}"
    );
    assert!(
        !calls[before_removal..]
            .iter()
            .any(|call| call.starts_with("appid ")),
        "the removal makes no call on a service it did not start: {calls:?}"
    );
    assert_eq!(
        snapshot(),
        before,
        "the computer is as it was, the service running and set to start with Windows"
    );
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
        "the machine is not clean: the Application Identity service is running"
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
    // The removal records its calls in the same file. The service was stopped and the installation
    // started it, so the removal stops it again, and that line shows the removal's recorder works.
    let (code, output) = setup(
        &["remove"],
        "yes\n",
        &[("KR_BOUNDARY_CALL_LOG", log.to_str().unwrap())],
    );
    assert_eq!(code, 0, "{output}");
    let calls = recorded_calls(&log);
    assert_eq!(
        calls.iter().filter(|call| *call == "appid stop").count(),
        1,
        "the removal stops the service that the installation started, once: {calls:?}"
    );
    assert_eq!(snapshot(), original);
    let _ = std::fs::remove_file(&log);
}

/// Whether this process's token is the system's own: whose entry in the pipe's list is `GA`, so
/// that a request for more than the grant is not refused to it, and that it may make a second
/// instance of the pipe.
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
    let name = ffi::wide(Pipe::Persons.name());
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
/// elevated administrator (the Administrators entry): the installer's `connect` opens the pipe,
/// sends one request and reads its answer, and, when the answer is late, its deadline cancels the
/// read on that handle. The server runs as the system, which alone may make the pipe's next
/// instance, and the client is a caller whose own entry of the list is the Administrators group's.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_client_that_holds_only_the_pipes_grant_connects_and_a_request_and_its_answer_cross_it() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    let stop = Stop::new().unwrap();
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
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
    let mut connection = with_token_without(&[SYSTEM_SID], || connect_here(Pipe::Persons))
        .expect("the client opens the pipe");
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
/// has nothing to show. The pipe here is the first instance alone, made with the grant's list.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated administrator's session that is not the system, in a disposable Windows guest (see the file's header)"]
fn a_client_that_holds_only_the_pipes_grant_is_refused_more_than_the_grant_and_makes_no_instance() {
    use kr_boundary_windows::pipe_access::{CLIENT, CREATE_INSTANCE};
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT};
    if runs_as_the_system() {
        println!("skipped: this session is the system, whose own entry (GA) refuses nothing");
        return;
    }
    require_clean_machine();
    let first = pipe_granting_administrators(CLIENT);
    let name = ffi::wide(Pipe::Persons.name());
    // SAFETY: the name is NUL-terminated; the result is checked and the default descriptor is
    // the caller's.
    let made = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            Pipe::Persons.instances(),
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
    assert_eq!(
        (made == INVALID_HANDLE_VALUE).then_some(code),
        Some(5),
        "no client makes another instance of the pipe's name"
    );
    assert_eq!(
        open_the_brokers_pipe_with(GENERIC_READ | GENERIC_WRITE),
        Err(5),
        "the generic rights ask for the append bit and more than the grant"
    );
    // A client's open does not check the append bit, so the grant with that bit added is not
    // refused here; the bit is checked when another instance of the name is made, above.
    assert_eq!(
        open_the_brokers_pipe_with(CLIENT | CREATE_INSTANCE),
        Ok(()),
        "an open that adds the append bit to the grant is not refused"
    );
    drop(first);
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_answer_that_does_not_come_by_the_deadline_is_not_waited_for() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut listener =
        Listener::bind(Pipe::Persons, &[system], std::sync::Arc::clone(&stop)).unwrap();
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
    let mut connection = connect_here(Pipe::Persons).unwrap();
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
    use kr_boundary_windows::win::pipe::{Listener, Stop, testing};
    let stop = Stop::new().unwrap();
    let system = Sid::parse("S-1-5-18").unwrap();
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut listener =
        Listener::bind(Pipe::Persons, &[system], std::sync::Arc::clone(&stop)).unwrap();
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
    let mut connection = connect_here(Pipe::Persons).unwrap();
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
    let mut listener =
        Listener::bind(Pipe::Persons, &[system], std::sync::Arc::clone(&stop)).unwrap();
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
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    // The stand-in broker's pipe names the system alone, so an account of another token cannot
    // open it.
    if needs_the_system() {
        return;
    }
    let bound = Duration::from_secs(4);
    let margin = Duration::from_secs(1);

    // The proof for the second class is answered after the installation's deadline, as a later cycle
    // would answer it: the installation stops reading at the deadline and takes no answer after it.
    let (server, asked, stop) = stand_in_broker(Duration::from_millis(500), Duration::from_secs(5));
    let mut connection = connect_here(Pipe::Persons).unwrap();
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
    let mut connection = connect_here(Pipe::Persons).unwrap();
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
    let mut connection = connect_here(Pipe::Persons).unwrap();
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

/// A client that connects to the waiting instance and goes before the server's wait for it ends only
/// that connection: the listener goes on and serves the next client.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_client_that_connects_and_goes_before_the_server_waits_for_it_does_not_end_the_listener() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
    drop(connect_here(Pipe::Persons).expect("the first client opens the pipe"));
    let _stop_when_dropped = StopWhenDropped(std::sync::Arc::clone(&stop));
    let server = std::thread::spawn(move || {
        listener
            .accept()
            .map(|connection| connection.is_some())
            .map_err(|failure| failure.to_string())
    });
    let second = std::thread::spawn(|| connect_here(Pipe::Persons).map(drop));
    let accepted = ends_within(server, 20)
        .unwrap_or_else(|failure| Err(format!("the accept did not return: {failure}")));
    stop.set();
    let second = second.join().unwrap();
    assert_eq!(
        accepted,
        Ok(true),
        "the first client's going ends its connection only; the second client's open: {second:?}"
    );
}

/// An open of a pipe whose connections are all in use waits for one and then says so, with the
/// platform's error after the words and no full stop before it. Only the administrators' pipe adds
/// that other elevated sessions may hold it: the persons' pipe is held by persons, and its words do
/// not name sessions. Nothing accepts a connection here, so the first client holds the one
/// instance that listens and the broker's own end holds the other.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_pipe_whose_connections_are_all_in_use_says_so_and_only_the_administrators_pipe_names_sessions()
{
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    for (kind, names_sessions) in [(Pipe::Administrators, true), (Pipe::Persons, false)] {
        let stop = Stop::new().unwrap();
        let _stop_when_dropped = StopWhenDropped(std::sync::Arc::clone(&stop));
        let listener = Listener::bind(kind, &[], stop).unwrap();
        let first = connect_here(kind).expect("the first client opens the pipe");
        let Err(busy) = connect_here(kind) else {
            panic!("a client opened a pipe whose connections are all in use");
        };
        let text = busy.to_string();
        assert_eq!(busy.code, 231, "{text}");
        assert!(
            text.contains("every connection the broker serves was in use for 10 seconds"),
            "{text}"
        );
        assert_eq!(
            text.contains("other elevated sessions may hold the administrators' pipe"),
            names_sessions,
            "{text}"
        );
        assert!(!text.contains(".:"), "{text}");
        assert!(text.ends_with(": Windows error 231"), "{text}");
        drop((first, listener));
    }
}

/// The listener holds an instance of its own from the bind to its end, so that with every client gone
/// and no accept pending, no other account can make the first instance of the pipe's name.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_listener_keeps_the_pipes_name_with_every_client_gone_and_no_accept_pending() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
    let client = connect_here(Pipe::Persons).expect("the client opens the pipe");
    let served = listener.accept().unwrap().expect("a client is accepted");
    drop(client);
    drop(served);
    // Any account's call that makes the first instance of the name, as the system's does here, fails.
    let taken = Listener::bind(Pipe::Persons, &[], Stop::new().unwrap());
    assert!(
        taken.is_err(),
        "the name is free between two connections: another account could make its first instance"
    );
    stop.set();
}

/// Clients that connect and send nothing do not stop the service: the first frame of a connection has
/// a deadline, so that seven of them, one more than the connections served at once, are closed and a
/// real client is served once the deadline has passed.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn seven_clients_that_send_nothing_do_not_stop_the_service_and_a_real_client_is_served_after_one_deadline()
 {
    use kr_boundary_windows::win::pipe;
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let manager = service::manager().unwrap();
    let broker = manager.open(SERVICE).unwrap().unwrap();
    let pid = broker.status().unwrap().pid;
    let held = pipe::ServerProcess::open(pid).expect("the service's process is opened");
    let silent: Vec<_> = (0..7)
        .map(|number| {
            pipe::connect_held(Pipe::Persons, &held)
                .unwrap_or_else(|failure| panic!("silent client {number}: {failure}"))
        })
        .collect();
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(40);
    let served = loop {
        match install::open_session() {
            Ok(session) => break Some(session),
            Err(_) if std::time::Instant::now() < give_up => {}
            Err(failure) => panic!("no real client was served after the silent ones: {failure}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    drop(served);
    drop(silent);
    assert!(
        broker.status().unwrap().running(),
        "the silent clients stopped the service"
    );
}

/// Runs `work` on a thread that impersonates a copy of this process's token in which the named
/// identifiers are deny-only: they give the copy no right, as for a caller that is not that account
/// or not in that group. Under the system's token, naming the system's own identifier leaves the
/// Administrators entry of the pipe's list as the copy's grant, and naming that group too leaves the
/// entry of the people.
#[cfg(feature = "testing")]
fn with_token_without<T: Send>(disabled: &[&str], work: impl FnOnce() -> T + Send) -> T {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf,
        SID_AND_ATTRIBUTES, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
        TokenImpersonation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let identifiers: Vec<Sid> = disabled
        .iter()
        .map(|text| Sid::parse(text).unwrap())
        .collect();
    let entries: Vec<SID_AND_ATTRIBUTES> = identifiers
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_ptr(),
            Attributes: 0,
        })
        .collect();
    let mut process: HANDLE = std::ptr::null_mut();
    // SAFETY: opens this process's own token for the two rights named; the handle is owned below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut process,
        )
    };
    assert_ne!(opened, 0, "this process's token is opened");
    let process = ffi::Handle::new(process, "this process's token").unwrap();
    let mut restricted: HANDLE = std::ptr::null_mut();
    // SAFETY: the source token is open for duplication, the entries name identifiers that outlive
    // the call, and the new token is owned below.
    let made = unsafe {
        CreateRestrictedToken(
            process.raw(),
            0,
            entries.len() as u32,
            entries.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &raw mut restricted,
        )
    };
    assert_ne!(made, 0, "the identifiers are made deny-only");
    let restricted = ffi::Handle::new(restricted, "the restricted token").unwrap();
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: the restricted token is open with every right; the copy is owned below.
    let duplicated = unsafe {
        DuplicateTokenEx(
            restricted.raw(),
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        )
    };
    assert_ne!(duplicated, 0, "the token is copied");
    let copy = ffi::Handle::new(copy, "the copy of the token").unwrap();
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

/// The system's identifier and the Administrators group's.
#[cfg(feature = "testing")]
const SYSTEM_SID: &str = "S-1-5-18";
#[cfg(feature = "testing")]
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The broker's own loop, run in this process for the people of everyone, the way the service runs
/// it: its pipe is bound by the loop, and it ends when the stop is set. The value sets the stop when
/// it is dropped, whatever way the case ends, and waits a short time for the loop's thread, so that
/// no case leaves a loop and its pipe behind for the next one.
#[cfg(feature = "testing")]
struct ServedLoop {
    stop: std::sync::Arc<kr_boundary_windows::win::pipe::Stop>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

#[cfg(feature = "testing")]
fn serve_in_process() -> ServedLoop {
    use kr_boundary_windows::win::broker;
    use kr_boundary_windows::win::pipe::Stop;
    require_clean_machine();
    let stop = Stop::new().unwrap();
    let thread = std::thread::spawn({
        let stop = std::sync::Arc::clone(&stop);
        move || {
            let everyone = Sid::parse("S-1-1-0").unwrap();
            broker::testing::serve(
                Manifest::begin(),
                Paths::system().expect("the system's folders are read"),
                &[everyone],
                stop,
            )
        }
    });
    ServedLoop {
        stop,
        thread: Some(thread),
    }
}

#[cfg(feature = "testing")]
impl ServedLoop {
    /// Waits for the loop to end by itself for at most `seconds`, and returns what it returned.
    fn ends_within(&mut self, seconds: u64) -> Result<Result<(), String>, String> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        while self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            if std::time::Instant::now() >= until {
                return Err(format!(
                    "the loop had not ended {seconds} seconds after the stop"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(self
            .thread
            .take()
            .expect("the loop's result is read once")
            .join()
            .unwrap())
    }

    /// Sets the stop, and waits for the loop to end for at most `seconds`.
    fn stops_within(&mut self, seconds: u64) -> Result<Result<(), String>, String> {
        self.stop.set();
        self.ends_within(seconds)
    }
}

#[cfg(feature = "testing")]
impl Drop for ServedLoop {
    fn drop(&mut self) {
        self.stop.set();
        if self.thread.is_some() {
            let _ = self.ends_within(20);
        }
    }
}

/// Connects to the broker's pipe that this process itself serves, holding its own process while the
/// pipe's server is checked.
fn connect_here(kind: Pipe) -> ffi::Result<kr_boundary_windows::win::pipe::Connection> {
    use kr_boundary_windows::win::pipe;
    let me = pipe::ServerProcess::open(std::process::id())?;
    pipe::connect_held(kind, &me)
}

/// A client of the loop, opened as a caller whose token has the named identifiers deny-only: the
/// system and the Administrators group both make a person who is not an administrator, the system
/// alone makes an elevated administrator, and none is the system.
#[cfg(feature = "testing")]
fn client_without(kind: Pipe, disabled: &[&str]) -> kr_boundary_windows::win::pipe::Connection {
    with_token_without(disabled, || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match connect_here(kind) {
                Ok(connection) => return connection,
                Err(failure) if std::time::Instant::now() >= until => {
                    panic!("the loop's pipe could not be opened: {failure}")
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    })
}

/// Says hello on a connection and reads the answer, within ten seconds.
#[cfg(feature = "testing")]
fn say_hello(connection: &mut kr_boundary_windows::win::pipe::Connection) {
    connection.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    ));
    let said = install::ask(
        connection,
        &Request::Hello {
            version: kr_boundary_windows::frame::VERSION,
        },
    )
    .expect("hello is answered");
    assert!(matches!(said, Response::Hello { .. }), "{said:?}");
    connection.set_deadline(None);
}

/// An administrator's request to the loop, within the bound the installer's own open has: a new
/// connection, hello and the status, each waiting for the loop to take it.
#[cfg(feature = "testing")]
fn an_administrators_status_within_thirty_seconds() -> Result<Response, String> {
    let mut connection = client_without(Pipe::Administrators, &[SYSTEM_SID]);
    connection.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    ));
    let said = install::ask(
        &mut connection,
        &Request::Hello {
            version: kr_boundary_windows::frame::VERSION,
        },
    )
    .map_err(|failure| format!("hello: {failure}"))?;
    if !matches!(said, Response::Hello { .. }) {
        return Err(format!("hello was answered with {said:?}"));
    }
    install::ask(&mut connection, &Request::Status {})
        .map_err(|failure| format!("status: {failure}"))
}

/// A stop that comes while clients are connected ends the loop: a person who said hello and waits,
/// an administrator who said hello and waits and a client that has not sent a byte are each served by
/// a thread, and a thread whose read the stop interrupted must end with it, so that the service
/// leaves its stopping state and a removal can delete it.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_stop_with_a_client_connected_ends_the_service() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let mut person = client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID]);
    say_hello(&mut person);
    let mut administrator = client_without(Pipe::Administrators, &[SYSTEM_SID]);
    say_hello(&mut administrator);
    let silent = client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID]);
    let ended = served.stops_within(20);
    drop((person, administrator, silent));
    assert_eq!(
        ended.expect("the service ends with its clients still connected"),
        Ok(())
    );
}

/// Six connections of a person who is not an administrator that say hello and then nothing do not
/// hold every slot: an administrator's request is served inside the bound that the installer's open
/// has, because the connection of a person is closed when it has asked for nothing for its bound.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn six_connections_that_say_hello_and_then_nothing_do_not_hold_off_an_administrators_request() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let began = std::time::Instant::now();
    let holders: Vec<_> = (0..6)
        .map(|_| {
            let mut connection = client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID]);
            say_hello(&mut connection);
            connection
        })
        .collect();
    // The case shows what it means to only if the six are all inside their bound of five seconds
    // at once, which is a condition of the case and not of the product.
    assert!(
        began.elapsed() < std::time::Duration::from_secs(3),
        "the six connections were not made within three seconds: {:?}",
        began.elapsed()
    );
    let answer = an_administrators_status_within_thirty_seconds();
    let ended = served.stops_within(20);
    drop(holders);
    assert!(
        matches!(answer, Ok(Response::Status { .. })),
        "the administrator's request waited behind the six connections: {answer:?}"
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// Six connections of a person who is not an administrator that ask for the status again and again
/// and read no answer do not hold every slot either: the write of an answer has a bound, so that the
/// thread whose client reads nothing ends and an administrator's request is served.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn six_connections_that_ask_and_read_no_answer_do_not_hold_off_an_administrators_request() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let began = std::time::Instant::now();
    let flooders: Vec<_> = (0..6)
        .map(|_| {
            let mut connection = client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID]);
            say_hello(&mut connection);
            // The loop answers each request into the pipe's buffer; when that is full its write
            // waits, and then the requests fill the buffer in the other direction until this write
            // times out.
            let mut asked = 0_u32;
            loop {
                connection.set_deadline(Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                ));
                if kr_boundary_windows::frame::write(&mut connection, &Request::Status {}).is_err()
                {
                    break;
                }
                asked += 1;
                assert!(asked < 100_000, "the pipe's buffers never filled");
            }
            connection.set_deadline(None);
            connection
        })
        .collect();
    // The six are all inside the bound of an answer's write, ten seconds, at once.
    assert!(
        began.elapsed() < std::time::Duration::from_secs(8),
        "the six connections were not filled within eight seconds: {:?}",
        began.elapsed()
    );
    let answer = an_administrators_status_within_thirty_seconds();
    let ended = served.stops_within(20);
    drop(flooders);
    assert!(
        matches!(answer, Ok(Response::Status { .. })),
        "the administrator's request waited behind the six connections: {answer:?}"
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// A refill that fails, and the try after it that fails too, neither ends the listener nor drops the
/// client that just connected: the instance in hand serves it, and the next call makes the waiting
/// instance again.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_refill_that_fails_once_neither_ends_the_listener_nor_drops_the_client_in_hand() {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
    let first = connect_here(Pipe::Persons).expect("the first client opens the pipe");
    let _restored = RefillsRestored;
    pipe::testing::fail_refills(2);
    let served = listener
        .accept()
        .expect("the failed refill does not end the listener")
        .expect("the client in hand is served");
    let _stop_when_dropped = StopWhenDropped(std::sync::Arc::clone(&stop));
    let server = std::thread::spawn(move || {
        listener
            .accept()
            .map(|connection| connection.is_some())
            .map_err(|failure| failure.to_string())
    });
    let second = std::thread::spawn(|| connect_here(Pipe::Persons).map(drop));
    let accepted = ends_within(server, 20)
        .unwrap_or_else(|failure| Err(format!("the second accept did not return: {failure}")));
    stop.set();
    let second = second.join().unwrap();
    drop((first, served));
    assert_eq!(
        accepted,
        Ok(true),
        "the refill is tried again; the second client's open: {second:?}"
    );
}

/// At the stop the listener keeps its instance: the name stays held while the workers end, until the
/// listener is dropped, so that no other account can make the first instance in between.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_stop_does_not_free_the_pipes_name_before_the_listener_ends() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    // Nothing shows from outside that the thread has reached its wait for a client, so the stop is
    // set after a longer and longer pause of spinning, with no sleep: a stop that comes before the
    // wait begins ends `accept` at its first check and shows nothing, and one that comes after it
    // begins drops the instance where the listener is wrong. Twenty tries reach both orders.
    for tries in 0..20_u32 {
        let stop = Stop::new().unwrap();
        let mut listener =
            Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
        let waiting = std::thread::spawn(move || {
            let result = listener.accept().map(|connection| connection.is_some());
            (listener, result)
        });
        for _ in 0..tries * 20_000 {
            std::hint::spin_loop();
        }
        stop.set();
        let (listener, result) =
            ends_within(waiting, 20).expect("the thread that waits for a client ends at the stop");
        assert!(
            matches!(result, Ok(false)),
            "the stop ends the wait: {result:?}"
        );
        // Any account's call that makes the first instance of the name, as the system's does here,
        // fails.
        let taken = Listener::bind(Pipe::Persons, &[], Stop::new().unwrap());
        let held = taken.is_err();
        drop(listener);
        assert!(
            held,
            "the name was free after the stop while the listener was still alive (try {tries})"
        );
    }
}

/// A pipe of the broker's name whose list grants the system everything and the Administrators group
/// exactly `grant`, held as its first instance: it lets a case ask what an open needs of the list.
#[cfg(feature = "testing")]
fn pipe_granting_administrators(grant: u32) -> ffi::Handle {
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    let list = ffi::wide(&format!("D:P(A;;GA;;;SY)(A;;{grant:#x};;;BA)"));
    let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the text is NUL-terminated and the descriptor is an out-parameter freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            list.as_ptr(),
            1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(converted, 0, "the permission list is read");
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = ffi::wide(Pipe::Persons.name());
    // SAFETY: the name is NUL-terminated and the attributes outlive the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            8,
            64 * 1024,
            64 * 1024,
            0,
            &raw const attributes,
        )
    };
    assert_ne!(pipe, INVALID_HANDLE_VALUE, "the pipe is made");
    // SAFETY: the descriptor came from the conversion call and is freed once.
    unsafe {
        LocalFree(descriptor);
    }
    ffi::Handle::new(pipe, "the pipe").unwrap()
}

/// The grant of the pipe's list is the least that the installer's client needs: through the
/// product's own `connect`, a caller whose own entry of the list is the Administrators group's opens
/// the pipe, writes a request and cancels a read that is late when the list grants the client's
/// rights, and is refused with access denied (error 5) when the list lacks any one of them. The
/// open itself asks for the pipe's attributes and the wait on top of reading and writing, so those
/// are part of the grant. Only error 5 counts as a right that is needed.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn the_pipes_grant_is_the_least_that_an_open_and_the_clients_calls_need() {
    use kr_boundary_windows::frame::FrameError;
    use kr_boundary_windows::pipe_access::CLIENT;
    require_clean_machine();
    let mut grants = vec![CLIENT];
    grants.extend(
        (0..32)
            .map(|bit| 1_u32 << bit)
            .filter(|bit| CLIENT & bit != 0)
            .map(|bit| CLIENT & !bit),
    );
    let mut table = Vec::new();
    for grant in grants {
        let _pipe = pipe_granting_administrators(grant);
        let calls = || -> Result<(), String> {
            let mut connection = connect_here(Pipe::Persons)
                .map_err(|failure| format!("the open: error {}", failure.code))?;
            connection.set_deadline(Some(
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            ));
            kr_boundary_windows::frame::write(&mut connection, &Request::Status {})
                .map_err(|failure| format!("the write: {failure}"))?;
            match kr_boundary_windows::frame::read::<_, Response>(&mut connection) {
                Err(FrameError::Io(failure)) if failure.kind() == std::io::ErrorKind::TimedOut => {
                    Ok(())
                }
                other => Err(format!("the read that is late: {other:?}")),
            }
        };
        // The system's entry (GA) would grant the open whatever the Administrators entry says, so
        // under the system the caller has its own identifier deny-only.
        let outcome = if runs_as_the_system() {
            with_token_without(&[SYSTEM_SID], calls)
        } else {
            calls()
        };
        table.push((grant, outcome));
    }
    let summary: Vec<String> = table
        .iter()
        .map(|(grant, outcome)| format!("{grant:#x}: {outcome:?}"))
        .collect();
    assert_eq!(
        table[0].1,
        Ok(()),
        "the client's grant opens the pipe and its calls work: {summary:?}"
    );
    for (grant, outcome) in &table[1..] {
        assert_eq!(
            outcome.as_ref().err().map(String::as_str),
            Some("the open: error 5"),
            "a list that grants {grant:#x}, one right fewer than the client's, must refuse the open: {summary:?}"
        );
    }
}

/// An administrator's connection is not closed at the bound of a person's: it waits longer than that
/// bound without a request and is then served, as the installer's session is when its removal writes
/// the policy between its first request and its last.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_administrators_connection_stays_open_past_the_bound_of_a_persons() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let mut administrator = client_without(Pipe::Administrators, &[SYSTEM_SID]);
    say_hello(&mut administrator);
    std::thread::sleep(std::time::Duration::from_secs(8));
    administrator.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    ));
    let answer = install::ask(&mut administrator, &Request::Status {});
    let ended = served.stops_within(20);
    drop(administrator);
    assert!(
        matches!(answer, Ok(Response::Status { .. })),
        "the administrator's connection was closed while it was idle: {answer:?}"
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// Whether this case has nothing to show under this token, which it says in the run's output so that
/// the table reads "skipped" and not "passed": the loop and the listener make the pipe's first
/// instance with the system's entry alone, and no other account's token may do that.
fn needs_the_system() -> bool {
    if runs_as_the_system() {
        return false;
    }
    eprintln!("SKIPPED: not run under this token: only the system may make the broker's pipe");
    true
}

/// Sets the stop when it is dropped, so that no thread of a case waits on for a client however the
/// case ends.
struct StopWhenDropped(std::sync::Arc<kr_boundary_windows::win::pipe::Stop>);

impl Drop for StopWhenDropped {
    fn drop(&mut self) {
        self.0.set();
    }
}

/// The result of a thread that ends by itself within `seconds`, or the reason that it did not. A
/// thread that does not end is left to the stop that the case sets as it ends.
fn ends_within<T>(thread: std::thread::JoinHandle<T>, seconds: u64) -> Result<T, String> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while !thread.is_finished() {
        if std::time::Instant::now() >= until {
            return Err(format!("the thread had not ended in {seconds} seconds"));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(thread.join().unwrap())
}

/// A client of the loop opened like [`client_without`], that gives the reason instead of a panic when
/// no open succeeds within `seconds`.
#[cfg(feature = "testing")]
fn try_client_without(
    kind: Pipe,
    disabled: &[&str],
    seconds: u64,
) -> Result<kr_boundary_windows::win::pipe::Connection, String> {
    with_token_without(disabled, || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        loop {
            match connect_here(kind) {
                Ok(connection) => return Ok(connection),
                Err(failure) if std::time::Instant::now() >= until => {
                    return Err(failure.to_string());
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    })
}

/// Puts the listener's seam for failed refills back to none however the case ends: the counter is
/// shared by the whole process.
#[cfg(feature = "testing")]
struct RefillsRestored;

#[cfg(feature = "testing")]
impl Drop for RefillsRestored {
    fn drop(&mut self) {
        kr_boundary_windows::win::pipe::testing::fail_refills(0);
    }
}

/// What a pipe's driver says of this end: its quotas, what waits to be read here and what is left of
/// the quota for writing, or the failing status.
#[cfg(feature = "testing")]
fn pipe_information(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<windows_sys::Wdk::Storage::FileSystem::FILE_PIPE_LOCAL_INFORMATION, i32> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_PIPE_LOCAL_INFORMATION, FilePipeLocalInformation, NtQueryInformationFile,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    // SAFETY: a zeroed record is a valid start.
    let mut status: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut info = FILE_PIPE_LOCAL_INFORMATION::default();
    // SAFETY: the handle is open, and the buffer is the record that the class fills.
    let answer = unsafe {
        NtQueryInformationFile(
            handle,
            &raw mut status,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_PIPE_LOCAL_INFORMATION>() as u32,
            FilePipeLocalInformation,
        )
    };
    if answer == 0 { Ok(info) } else { Err(answer) }
}

/// How much of the quota for writing on this end is in use: what this end has written that the other
/// end has not read, and what a read of the other end that waits reserves for the data that it
/// expects. The driver counts both.
#[cfg(feature = "testing")]
fn quota_in_use_by_the_other_end(handle: windows_sys::Win32::Foundation::HANDLE) -> u32 {
    let info = pipe_information(handle)
        .unwrap_or_else(|status| panic!("reading what a pipe holds: status {status:#x}"));
    info.OutboundQuota.saturating_sub(info.WriteQuotaAvailable)
}

/// The control of [`quota_in_use_by_the_other_end`], on a pipe that this case reads itself: what is
/// written and not read is counted, and once it is read the count is zero; a read that waits for
/// ninety bytes is counted as ninety, and once the bytes come it is zero again. Without this a
/// reading would show nothing about a server.
#[cfg(feature = "testing")]
fn the_quota_in_use_follows_what_is_written_and_what_a_waiting_read_expects() {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: both pointers are to locals; the call makes two handles that are checked.
    assert_ne!(
        unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) },
        0
    );
    let (read, write) = (
        std::sync::Arc::new(ffi::Handle::new(read, "a pipe's read end").unwrap()),
        ffi::Handle::new(write, "a pipe's write end").unwrap(),
    );
    let write_all = |bytes: &[u8]| {
        let mut moved = 0_u32;
        // SAFETY: the buffer and the handle are valid for the call.
        let written = unsafe {
            WriteFile(
                write.raw(),
                bytes.as_ptr(),
                bytes.len() as u32,
                &raw mut moved,
                std::ptr::null_mut(),
            )
        };
        assert!(
            written != 0 && moved as usize == bytes.len(),
            "the probe's pipe takes the bytes"
        );
    };
    let read_some = |read: &ffi::Handle, wanted: u32| {
        let mut buffer = vec![0_u8; wanted as usize];
        let mut moved = 0_u32;
        // SAFETY: the buffer and the handle are valid for the call.
        let taken = unsafe {
            ReadFile(
                read.raw(),
                buffer.as_mut_ptr(),
                wanted,
                &raw mut moved,
                std::ptr::null_mut(),
            )
        };
        assert!(taken != 0, "the probe's pipe gives bytes");
        moved
    };
    write_all(b"0123456789abcd");
    assert_eq!(
        quota_in_use_by_the_other_end(write.raw()),
        14,
        "the bytes that nobody read are counted"
    );
    assert_eq!(read_some(&read, 14), 14);
    assert_eq!(
        quota_in_use_by_the_other_end(write.raw()),
        0,
        "the bytes that were read are no longer counted"
    );
    // A read that waits for ninety bytes. The bytes are written whatever the readings were, so that
    // the thread ends on every path.
    let waiting = std::thread::spawn({
        let read = std::sync::Arc::clone(&read);
        move || read_some(&read, 90)
    });
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut seen = 0;
    while seen != 90 && std::time::Instant::now() < until {
        seen = quota_in_use_by_the_other_end(write.raw());
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    write_all(&[b'x'; 90]);
    assert_eq!(waiting.join().unwrap(), 90);
    assert_eq!(
        seen, 90,
        "a read that waits for ninety bytes is counted as ninety"
    );
    assert_eq!(
        quota_in_use_by_the_other_end(write.raw()),
        0,
        "once the bytes came the waiting read counts no more"
    );
}

/// A client that has sent part of a frame when the stop comes does not keep the service from
/// stopping. The frame announces a hundred bytes and carries ten; the client waits until the quota
/// in use on its end is the ninety bytes that the server's read of the rest of the frame waits for,
/// so the server is in that read when the stop comes, and the service must end within three
/// seconds, under the five that the read waits for the rest.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_client_in_the_middle_of_a_frame_does_not_hold_the_service_at_a_stop() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    the_quota_in_use_follows_what_is_written_and_what_a_waiting_read_expects();
    let mut served = serve_in_process();
    let client = RawClient::open(persons_pipe_name(), &[SYSTEM_SID, ADMINISTRATORS_SID]);
    let mut hello = Vec::new();
    kr_boundary_windows::frame::write(
        &mut hello,
        &Request::Hello {
            version: kr_boundary_windows::frame::VERSION,
        },
    )
    .unwrap();
    assert!(
        raw_transfer(client.0.raw(), true, hello).is_some(),
        "hello is written"
    );
    assert!(
        raw_transfer(client.0.raw(), false, vec![0; 4096]).is_some_and(|said| !said.is_empty()),
        "hello is answered"
    );
    // A frame that announces a hundred bytes of body and carries ten.
    let mut part = 100_u32.to_le_bytes().to_vec();
    part.extend_from_slice(b"0123456789");
    assert!(
        raw_transfer(client.0.raw(), true, part).is_some(),
        "the part of the frame is written"
    );
    // The server has taken the header and the ten bytes of the body when what its read of the rest
    // reserves is all that is in use. It must be there well inside the five seconds that the read
    // waits, and the stop comes then.
    let begun = std::time::Instant::now();
    let until = begun + std::time::Duration::from_secs(3);
    let mut readings = Vec::new();
    loop {
        let in_use = quota_in_use_by_the_other_end(client.0.raw());
        if readings.last() != Some(&in_use) {
            readings.push(in_use);
        }
        if in_use == 90 {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "the server's read of the rest of the frame was not there in three seconds: quota in use {readings:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    eprintln!(
        "EVIDENCE: quota in use on the client's end after the part of the frame, by change: {readings:?}, ninety after {:?}",
        begun.elapsed()
    );
    // The bound is under the five seconds that the connection's read waits for the rest of a
    // frame, so only the stop can have ended it.
    let ended = served.stops_within(3);
    drop(client);
    assert_eq!(
        ended.expect("the service ends with a client in the middle of a frame"),
        Ok(())
    );
}

/// A client that asks and reads no answer, so that the thread that serves it waits to write, does not
/// keep the service from stopping. The write's own bound is ten seconds and the client's last write
/// waited one second for the full buffer, so a service that ends within six seconds was ended by the
/// stop.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_client_that_reads_no_answer_does_not_hold_the_service_at_a_stop() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let mut person = client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID]);
    say_hello(&mut person);
    let mut asked = 0_u32;
    loop {
        person.set_deadline(Some(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        ));
        if kr_boundary_windows::frame::write(&mut person, &Request::Status {}).is_err() {
            break;
        }
        asked += 1;
        assert!(asked < 100_000, "the pipe's buffers never filled");
    }
    person.set_deadline(None);
    let ended = served.stops_within(6);
    drop(person);
    assert_eq!(
        ended.expect("the service ends with a client that reads no answer"),
        Ok(())
    );
}

/// A read and a write that the stop has already been set for end at once with the stop's error, though
/// their transfers could finish: a request is ready to be read and the pipe has room for an answer.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_read_and_a_write_with_the_stop_set_end_at_once_though_their_transfers_could_finish() {
    use kr_boundary_windows::frame::{self, FrameError};
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
    let mut client = connect_here(Pipe::Persons).expect("the client opens the pipe");
    frame::write(
        &mut client,
        &Request::Hello {
            version: frame::VERSION,
        },
    )
    .expect("the request is written");
    let mut served = listener
        .accept()
        .expect("the listener accepts")
        .expect("a client is accepted");
    stop.set();
    let read = frame::read::<_, Request>(&mut served);
    let written = frame::write(&mut served, &Response::Done {});
    drop((client, served, listener));
    assert!(
        matches!(&read, Err(FrameError::Io(failure)) if failure.kind() == std::io::ErrorKind::ConnectionAborted),
        "a read with the stop set and a request ready returned {read:?}"
    );
    assert!(
        matches!(&written, Err(FrameError::Io(failure)) if failure.kind() == std::io::ErrorKind::ConnectionAborted),
        "a write with the stop set and room in the pipe returned {written:?}"
    );
}

/// Seven handles of a person that are kept open with nothing sent, the most that the persons' pipe's
/// instances allow beside the broker's own, do not use up the pipe: the connections are closed at their
/// bound and the server ends are disconnected with them, so the next person's open succeeds once the
/// bound has passed, and when the service stops the pipe's name is free to make again while the
/// handles are still open.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn seven_handles_kept_open_with_nothing_sent_leave_the_persons_pipe_to_the_next_person_and_its_name_free_at_the_end()
 {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let held: Vec<_> = (0..7)
        .map(|number| {
            try_client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID], 30)
                .unwrap_or_else(|failure| panic!("handle {number} of the person: {failure}"))
        })
        .collect();
    // The first frame's bound is five seconds; the next person's open has this long after it.
    let next_person = try_client_without(Pipe::Persons, &[SYSTEM_SID, ADMINISTRATORS_SID], 20);
    let ended = served.stops_within(20);
    // The name is the service's no longer, and the person's handles are still open.
    let again = Listener::bind(Pipe::Persons, &[], Stop::new().unwrap()).map(drop);
    drop(held);
    assert!(
        next_person.is_ok(),
        "no instance was free for the next person after the bound of the silent handles: {:?}",
        next_person.as_ref().err()
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
    assert!(
        again.is_ok(),
        "the pipe's name was not free to make again while the person's handles were open: {:?}",
        again.err().map(|failure| failure.to_string())
    );
}

/// With every connection gone after a refill that failed, the listener still holds the pipe's name:
/// no other account can make its first instance.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_name_stays_the_brokers_with_every_connection_gone_after_a_failed_refill() {
    use kr_boundary_windows::win::pipe::{self, Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let _restored = RefillsRestored;
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Pipe::Persons, &[], std::sync::Arc::clone(&stop)).unwrap();
    let client = connect_here(Pipe::Persons).expect("the client opens the pipe");
    pipe::testing::fail_refills(1);
    let served = listener
        .accept()
        .expect("the failed refill does not end the listener")
        .expect("the client in hand is served");
    drop(client);
    drop(served);
    // Any account's call that makes the first instance of the name, as the system's does here, fails.
    let taken = Listener::bind(Pipe::Persons, &[], Stop::new().unwrap());
    stop.set();
    // The refusal is the first-instance flag's: error 5, and no other failure counts.
    assert_eq!(
        taken.err().map(|failure| failure.code),
        Some(5),
        "the name was free with every connection gone after a failed refill, or the bind failed for another reason"
    );
}

/// The persons' pipe's name, as the clients open it.
#[cfg(feature = "testing")]
fn persons_pipe_name() -> &'static str {
    Pipe::Persons.name()
}

/// A client of the loop's persons' pipe, opened like [`client_without`].
#[cfg(feature = "testing")]
fn persons_client(disabled: &[&str]) -> kr_boundary_windows::win::pipe::Connection {
    client_without(Pipe::Persons, disabled)
}

/// [`persons_client`] that gives the reason instead of a panic when no open succeeds within `seconds`.
#[cfg(feature = "testing")]
fn try_persons_client(
    disabled: &[&str],
    seconds: u64,
) -> Result<kr_boundary_windows::win::pipe::Connection, String> {
    try_client_without(Pipe::Persons, disabled, seconds)
}

/// A client of the loop that is opened with the platform's own calls, so that one thread can write
/// while another reads: the product's `Connection` takes `&mut self` for both.
#[cfg(feature = "testing")]
struct RawClient(std::sync::Arc<ffi::Handle>);

#[cfg(feature = "testing")]
impl RawClient {
    /// Opens the named pipe as a caller whose token has the named identifiers deny-only, asking for
    /// the rights of a client, and waits for the pipe to exist for up to thirty seconds.
    fn open(name: &str, disabled: &[&str]) -> RawClient {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
            SECURITY_SQOS_PRESENT,
        };
        let name = ffi::wide(name);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let opened = with_token_without(disabled, || {
                // SAFETY: the name is NUL-terminated; the result is checked.
                let opened = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        kr_boundary_windows::pipe_access::CLIENT,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        std::ptr::null_mut(),
                    )
                };
                (opened != INVALID_HANDLE_VALUE)
                    .then(|| ffi::Handle::new(opened, "the loop's pipe").unwrap())
            });
            if let Some(handle) = opened {
                return RawClient(std::sync::Arc::new(handle));
            }
            assert!(
                std::time::Instant::now() < until,
                "the loop's pipe could not be opened in thirty seconds"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// One overlapped transfer on the handle, waited for at most five seconds. Returns what was
/// transferred, or none when it failed or did not end in time; a transfer that did not end after its
/// cancel keeps its storage for the life of the process.
#[cfg(feature = "testing")]
fn raw_transfer(
    handle: windows_sys::Win32::Foundation::HANDLE,
    write: bool,
    mut buffer: Vec<u8>,
) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    let event = ffi::Handle::new(
        // SAFETY: an event with no name.
        unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) },
        "an event",
    )
    .ok()?;
    // SAFETY: a zeroed record is a valid start.
    let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
    overlapped.hEvent = event.raw();
    let length = buffer.len() as u32;
    // SAFETY: the buffer and the record live until the transfer ends, or for the life of the process.
    let started = unsafe {
        if write {
            WriteFile(
                handle,
                buffer.as_ptr(),
                length,
                std::ptr::null_mut(),
                &raw mut *overlapped,
            )
        } else {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                length,
                std::ptr::null_mut(),
                &raw mut *overlapped,
            )
        }
    };
    // SAFETY: reads the calling thread's last error.
    if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
        return None;
    }
    // SAFETY: the event is open.
    if unsafe { WaitForSingleObject(event.raw(), 5000) } != WAIT_OBJECT_0 {
        // SAFETY: the record is the one of the pending transfer.
        unsafe {
            CancelIoEx(handle, &raw mut *overlapped);
        }
        // SAFETY: the event is open.
        if unsafe { WaitForSingleObject(event.raw(), 5000) } != WAIT_OBJECT_0 {
            std::mem::forget((buffer, overlapped, event));
        }
        return None;
    }
    let mut count = 0_u32;
    // SAFETY: the transfer has completed.
    if unsafe { GetOverlappedResult(handle, &raw mut *overlapped, &raw mut count, 0) } == 0 {
        return None;
    }
    buffer.truncate(count as usize);
    Some(buffer)
}

/// A connection that says hello and then keeps writing `Status` requests as fast as the pipe takes
/// them on one thread while another thread reads the answers as fast as they come. The pipe then
/// holds a request and has room for an answer at every moment, so no read and no write of the thread
/// that serves the connection ever waits, and a thread that only its waits told about a stop would
/// never learn of it.
#[cfg(feature = "testing")]
struct RawStream {
    handle: std::sync::Arc<ffi::Handle>,
    bytes_read: std::sync::Arc<std::sync::atomic::AtomicU64>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "testing")]
impl RawStream {
    fn start(client: &RawClient) -> RawStream {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let bytes_read = std::sync::Arc::new(AtomicU64::new(0));
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let mut first = Vec::new();
        kr_boundary_windows::frame::write(
            &mut first,
            &Request::Hello {
                version: kr_boundary_windows::frame::VERSION,
            },
        )
        .unwrap();
        let mut block = Vec::new();
        for _ in 0..150 {
            kr_boundary_windows::frame::write(&mut block, &Request::Status {}).unwrap();
        }
        first.extend_from_slice(&block);
        let writer = std::thread::spawn({
            let handle = std::sync::Arc::clone(&client.0);
            let done = std::sync::Arc::clone(&done);
            move || {
                let mut next = first;
                while !done.load(Ordering::SeqCst) {
                    if raw_transfer(handle.raw(), true, next).is_none() {
                        return;
                    }
                    next = block.clone();
                }
            }
        });
        let reader = std::thread::spawn({
            let handle = std::sync::Arc::clone(&client.0);
            let done = std::sync::Arc::clone(&done);
            let bytes_read = std::sync::Arc::clone(&bytes_read);
            move || {
                while !done.load(Ordering::SeqCst) {
                    match raw_transfer(handle.raw(), false, vec![0; 64 * 1024]) {
                        Some(read) if !read.is_empty() => {
                            bytes_read.fetch_add(read.len() as u64, Ordering::SeqCst);
                        }
                        _ => return,
                    }
                }
            }
        });
        RawStream {
            handle: std::sync::Arc::clone(&client.0),
            bytes_read,
            done,
            threads: vec![writer, reader],
        }
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Waits until `count` bytes of answers have been read, for at most `seconds`.
    fn reaches(&self, count: u64, seconds: u64) -> Result<(), String> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        while self.bytes_read() < count {
            if std::time::Instant::now() >= until {
                return Err(format!(
                    "{} bytes of answers in {seconds} seconds, not {count}",
                    self.bytes_read()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }
}

#[cfg(feature = "testing")]
impl Drop for RawStream {
    fn drop(&mut self) {
        use windows_sys::Win32::System::IO::CancelIoEx;
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: the handle is open; this ends the transfers that wait, so that the threads end at
        // once and not at their five-second bound.
        unsafe {
            CancelIoEx(self.handle.raw(), std::ptr::null());
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Says hello and asks for the status on a connection, each within thirty seconds.
#[cfg(feature = "testing")]
fn hello_and_status(
    connection: &mut kr_boundary_windows::win::pipe::Connection,
) -> Result<Response, String> {
    connection.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(30),
    ));
    let said = install::ask(
        connection,
        &Request::Hello {
            version: kr_boundary_windows::frame::VERSION,
        },
    )
    .map_err(|failure| format!("hello: {failure}"))?;
    if !matches!(said, Response::Hello { .. }) {
        return Err(format!("hello was answered with {said:?}"));
    }
    install::ask(connection, &Request::Status {}).map_err(|failure| format!("status: {failure}"))
}

/// A client that keeps asking for the status and reading the answers while the stop comes does not keep
/// the service from stopping: every transfer of the thread that serves it finishes at once, so the
/// stop must be looked at by the read, the write and the loop, and not only by the waits.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_client_that_keeps_sending_and_reading_does_not_hold_the_service_at_a_stop() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let client = RawClient::open(persons_pipe_name(), &[SYSTEM_SID, ADMINISTRATORS_SID]);
    let stream = RawStream::start(&client);
    stream
        .reaches(200_000, 60)
        .expect("the traffic flows before the stop");
    let before = stream.bytes_read();
    let ended = served.stops_within(20);
    drop(stream);
    assert_eq!(
        ended.unwrap_or_else(|failure| panic!(
            "the service did not end with a client that keeps asking and reading ({before} bytes of answers before the stop): {failure}"
        )),
        Ok(())
    );
}

/// The service stops inside the installer's wait while a client on each pipe keeps asking for the
/// status and reading the answers: the service manager's stop reaches both loops, and the process ends.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn the_service_stops_inside_the_installers_wait_with_a_client_that_keeps_asking() {
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let manager = service::manager().unwrap();
    let broker = manager.open(SERVICE).unwrap().unwrap();
    let person = RawClient::open(persons_pipe_name(), &[]);
    let administrator = RawClient::open(Pipe::Administrators.name(), &[]);
    let streams = [RawStream::start(&person), RawStream::start(&administrator)];
    for stream in &streams {
        stream
            .reaches(200_000, 60)
            .expect("the traffic flows before the stop");
    }
    broker.stop().unwrap();
    let ended = broker.wait_for(true, std::time::Duration::from_secs(60));
    drop(streams);
    assert!(
        ended.is_ok(),
        "the service did not stop inside the installer's wait of sixty seconds: {ended:?}"
    );
    drop(case);
}

/// A refill that fails again and again never ends the loop by a count: after a thousand and one
/// failures in a row the next client is still served, once the platform makes the instance again.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_thousand_and_one_failed_refills_do_not_end_the_loop_and_it_still_serves() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let _restored = RefillsRestored;
    let mut served = serve_in_process();
    let mut first = persons_client(&[SYSTEM_SID, ADMINISTRATORS_SID]);
    say_hello(&mut first);
    kr_boundary_windows::win::pipe::testing::fail_refills(1_001);
    // This client is accepted, and every refill after it fails: the loop tries again every twenty
    // milliseconds, so the failures last about twenty seconds, with the first two clients holding the
    // name and the third's open waiting for an instance.
    let mut second = persons_client(&[SYSTEM_SID, ADMINISTRATORS_SID]);
    say_hello(&mut second);
    let third = try_persons_client(&[SYSTEM_SID, ADMINISTRATORS_SID], 60);
    let answer = third.and_then(|mut connection| hello_and_status(&mut connection));
    drop((first, second));
    let ended = served.stops_within(20);
    assert!(
        matches!(answer, Ok(Response::Status { .. })),
        "the loop did not serve a client after a thousand and one failed refills: {answer:?}"
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// An ordinary account that opens the persons' pipe in a tight loop while the service makes the pipe
/// again and again never gets a handle on the instance that the broker keeps for itself. Each bind is
/// paused after it has made the first instance and before the broker's own client end is on it, and
/// each pause has a number of its own: every open that the account makes inside one pause is counted
/// for that pause, and in every one of the hundred pauses the account is refused at least twenty
/// times and gets no handle and no other answer (the name exists and the first instance listens, so
/// neither a missing pipe nor a busy one can come). Outside the pauses, where the real list is on
/// the instance, the same account does open the pipe, so a refusal in a pause is the first
/// instance's list and not a pipe that cannot be opened. The binds all succeed, which they would not
/// if the account had taken the first instance.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_ordinary_accounts_open_in_a_tight_loop_never_gets_a_handle_before_the_keeper_is_connected() {
    use kr_boundary_windows::win::pipe::{Listener, Stop, testing};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };
    /// How many refusals the account must have had inside a pause before the bind goes on.
    const AT_WORK: u32 = 20;
    /// What the account's opens gave inside one pause, by the platform's answer.
    #[derive(Clone, Default, Debug)]
    struct Pause {
        refused: u32,
        opened: u32,
        not_found: u32,
        busy: u32,
        other: u32,
    }
    /// What the account's opens gave, in all and by pause.
    #[derive(Default)]
    struct Counts {
        /// The pauses' generation: odd while a bind is paused and even between pauses, so that
        /// pause number `n` is the generation `2n + 1`. An open belongs to a pause only if the
        /// generation was the same, and odd, before and after it.
        generation: AtomicU64,
        opened: AtomicU32,
        refused: AtomicU32,
        not_found: AtomicU32,
        busy: AtomicU32,
        other: AtomicU32,
        /// Opens that the generation shows were made between pauses.
        opened_outside_the_pauses: AtomicU32,
        pauses: Mutex<Vec<Pause>>,
    }
    impl Counts {
        fn pause(&self, number: usize, count: impl FnOnce(&mut Pause)) {
            let mut pauses = self
                .pauses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pauses.len() <= number {
                pauses.resize(number + 1, Pause::default());
            }
            count(&mut pauses[number]);
        }

        fn refused_in(&self, number: usize) -> u32 {
            self.pauses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(number)
                .map_or(0, |pause| pause.refused)
        }
    }
    /// The account's loop: ends when the case does, on every path.
    struct Opener {
        done: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Opener {
        fn finish(&mut self) {
            self.done.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }
    impl Drop for Opener {
        fn drop(&mut self) {
            self.finish();
        }
    }
    /// Clears the pause's hook however the case ends: it is a flag of the whole process.
    struct HookCleared;
    impl Drop for HookCleared {
        fn drop(&mut self) {
            testing::before_the_keepers_open(None);
        }
    }
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let counts = Arc::new(Counts::default());
    let done = Arc::new(AtomicBool::new(false));
    let (first_try, first_tried) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn({
        let done = Arc::clone(&done);
        let counts = Arc::clone(&counts);
        move || {
            let name = ffi::wide(persons_pipe_name());
            with_token_without(&[SYSTEM_SID, ADMINISTRATORS_SID], || {
                let mut told = false;
                while !done.load(Ordering::Acquire) {
                    let before = counts.generation.load(Ordering::Acquire);
                    // SAFETY: the name is NUL-terminated; the result is checked.
                    let opened = unsafe {
                        CreateFileW(
                            name.as_ptr(),
                            kr_boundary_windows::pipe_access::CLIENT,
                            0,
                            std::ptr::null(),
                            OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                            std::ptr::null_mut(),
                        )
                    };
                    // SAFETY: reads this thread's last error, set by the call above.
                    let code = (opened == INVALID_HANDLE_VALUE).then(|| unsafe { GetLastError() });
                    let after = counts.generation.load(Ordering::Acquire);
                    // An open counts for a pause only if the generation held, odd, before and after
                    // it, and for the time between pauses only if it held, even.
                    let steady = (before == after).then_some(before);
                    let pause = steady.filter(|generation| generation % 2 == 1);
                    let outside = steady.is_some_and(|generation| generation % 2 == 0);
                    match code {
                        Some(5) => {
                            counts.refused.fetch_add(1, Ordering::SeqCst);
                            if let Some(generation) = pause {
                                counts.pause((generation / 2) as usize, |pause| pause.refused += 1);
                            }
                        }
                        Some(ERROR_FILE_NOT_FOUND) => {
                            counts.not_found.fetch_add(1, Ordering::SeqCst);
                            if let Some(generation) = pause {
                                counts
                                    .pause((generation / 2) as usize, |pause| pause.not_found += 1);
                            }
                        }
                        Some(ERROR_PIPE_BUSY) => {
                            counts.busy.fetch_add(1, Ordering::SeqCst);
                            if let Some(generation) = pause {
                                counts.pause((generation / 2) as usize, |pause| pause.busy += 1);
                            }
                        }
                        Some(_) => {
                            counts.other.fetch_add(1, Ordering::SeqCst);
                            if let Some(generation) = pause {
                                counts.pause((generation / 2) as usize, |pause| pause.other += 1);
                            }
                        }
                        None => {
                            counts.opened.fetch_add(1, Ordering::SeqCst);
                            if let Some(generation) = pause {
                                counts.pause((generation / 2) as usize, |pause| pause.opened += 1);
                            }
                            if outside {
                                counts
                                    .opened_outside_the_pauses
                                    .fetch_add(1, Ordering::SeqCst);
                            }
                            // Closed at once, which is what a client that goes does.
                            drop(ffi::Handle::new(opened, "the persons' pipe").unwrap());
                        }
                    }
                    if !told {
                        told = true;
                        let _ = first_try.send(());
                    }
                }
            });
        }
    });
    let mut opener = Opener {
        done,
        thread: Some(thread),
    };
    first_tried
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the account's loop made its first open");
    let _cleared = HookCleared;
    testing::before_the_keepers_open(Some(Arc::new({
        let counts = Arc::clone(&counts);
        move || {
            // Each bind opens a pause of its own, and waits here until the account has been refused
            // enough times inside this pause to show that it is at work, for ten seconds at most.
            let generation = counts.generation.fetch_add(1, Ordering::AcqRel) + 1;
            let number = (generation / 2) as usize;
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while counts.refused_in(number) < AT_WORK && std::time::Instant::now() < until {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            counts.generation.fetch_add(1, Ordering::AcqRel);
        }
    })));
    let everyone = Sid::parse("S-1-1-0").unwrap();
    let mut failures = Vec::new();
    for number in 0..100 {
        let stop = Stop::new().unwrap();
        match Listener::bind(Pipe::Persons, std::slice::from_ref(&everyone), stop) {
            Ok(listener) => drop(listener),
            Err(failure) => failures.push(format!("bind {number}: {failure}")),
        }
    }
    opener.finish();
    let get = |count: &AtomicU32| count.load(Ordering::SeqCst);
    let pauses = counts
        .pauses
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    eprintln!(
        "EVIDENCE: the account's opens over 100 binds: opened {} (outside the pauses {}), refused {}, not found {}, busy {}, other {}; pauses {}, fewest refusals in one pause {}, most {}",
        get(&counts.opened),
        get(&counts.opened_outside_the_pauses),
        get(&counts.refused),
        get(&counts.not_found),
        get(&counts.busy),
        get(&counts.other),
        pauses.len(),
        pauses.iter().map(|pause| pause.refused).min().unwrap_or(0),
        pauses.iter().map(|pause| pause.refused).max().unwrap_or(0),
    );
    assert!(
        failures.is_empty(),
        "an open of the account took the first instance before the broker's own end was on it: {failures:?}"
    );
    assert_eq!(pauses.len(), 100, "every bind was paused once");
    for (number, pause) in pauses.iter().enumerate() {
        assert!(
            pause.refused >= AT_WORK,
            "the account was refused {} times, not {AT_WORK}, in pause {number}: {pause:?}",
            pause.refused
        );
        assert_eq!(
            (pause.opened, pause.not_found, pause.busy, pause.other),
            (0, 0, 0, 0),
            "an open in pause {number} ended with an answer that is not a refusal: {pause:?}"
        );
    }
    assert!(
        get(&counts.opened_outside_the_pauses) >= 1,
        "the account never opened the pipe outside the pauses, where its list lets it: a refusal in a pause shows nothing"
    );
    assert_eq!(
        get(&counts.other),
        0,
        "an open ended with an answer that is neither a refusal, no pipe nor a busy pipe"
    );
}

/// A proof that the stop reaches after its search for a refusal has found one, before any program
/// that follows, ends with a failure that says the service is stopping, and does not go on to run its
/// last programs as if the stop had not come.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_proof_that_the_stop_reaches_after_its_search_ends_with_a_failure_that_says_so() {
    use kr_boundary_windows::win::pipe::Stop;
    use kr_boundary_windows::win::proof;
    /// Clears the hook however the case ends: it is a flag of the whole process.
    struct HookCleared;
    impl Drop for HookCleared {
        fn drop(&mut self) {
            proof::testing::after_the_search(None);
        }
    }
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let paths = Paths::system().expect("the system's folders are read");
    let manifest = Manifest::load(&paths.manifest).unwrap_or_else(|failure| panic!("{failure}"));
    for name in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        token::enable_privilege(name).unwrap_or_else(|failure| panic!("{failure}"));
    }
    let stop = Stop::new().unwrap();
    let _cleared = HookCleared;
    let launches_at_the_stop = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    proof::testing::after_the_search(Some(Box::new({
        let stop = std::sync::Arc::clone(&stop);
        let launches_at_the_stop = std::sync::Arc::clone(&launches_at_the_stop);
        move || {
            stop.set();
            launches_at_the_stop.store(
                kr_boundary_windows::win::launch::testing::launches(),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    })));
    let proof = proof::prove(
        &manifest,
        Class::Checkout,
        &paths.staging,
        std::time::Instant::now() + std::time::Duration::from_secs(300),
        &stop,
    );
    assert!(
        !proof.ready && proof.detail.contains("stopping"),
        "a proof that the stop reached must fail and say the service is stopping: ready {}, detail {}",
        proof.ready,
        proof.detail
    );
    // The failure's words are the same wherever the stop is seen, so what shows that no program
    // followed the stop is that none was made.
    assert_eq!(
        kr_boundary_windows::win::launch::testing::launches(),
        launches_at_the_stop.load(std::sync::atomic::Ordering::SeqCst),
        "a program was started after the stop"
    );
}

/// Seven connections of one person that all keep asking and reading hold every slot of the persons'
/// pipe for as long as they like, and an elevated administrator's request is served at once all the
/// same: the administrators' pipe has instances and slots of its own, and no connection that a person
/// can make takes one of them.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn seven_active_connections_of_a_person_do_not_hold_off_an_administrators_request() {
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    // Six are served and the seventh holds the instance that waits: all seven are open together.
    let clients: Vec<_> = (0..7)
        .map(|_| RawClient::open(persons_pipe_name(), &[SYSTEM_SID, ADMINISTRATORS_SID]))
        .collect();
    let streams: Vec<_> = clients.iter().map(RawStream::start).collect();
    for (number, stream) in streams.iter().take(6).enumerate() {
        stream
            .reaches(50_000, 60)
            .unwrap_or_else(|failure| panic!("connection {number} is not active: {failure}"));
    }
    let began = std::time::Instant::now();
    let answer = an_administrators_status_within_thirty_seconds();
    let waited = began.elapsed();
    let ended = served.stops_within(20);
    drop(streams);
    assert!(
        matches!(answer, Ok(Response::Status { .. })),
        "the administrator's request waited behind the person's connections: {answer:?}"
    );
    assert!(
        waited < std::time::Duration::from_secs(10),
        "the administrator's request took {waited:?}, more than the installer's open waits"
    );
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// The persons' pipe refuses a request that changes the state or asks for a proof, whoever the caller
/// is, with the fixed words; the administrators' pipe serves the same request to an elevated
/// administrator.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_persons_pipe_refuses_a_state_change_and_a_proof_with_the_fixed_words() {
    use kr_boundary_windows::frame::{ADMINISTRATORS_ONLY, Refusal};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    // The system's own token is an elevated administrator: the pipe's kind decides, not the caller.
    let mut persons = persons_client(&[]);
    say_hello(&mut persons);
    let refused = Response::Refused {
        reason: Refusal::Caller,
        detail: ADMINISTRATORS_ONLY.to_owned(),
    };
    for request in [
        Request::Maintenance { on: true },
        Request::Prove {
            class: Class::Checkout,
        },
        Request::Release {
            class: Class::Connect,
        },
    ] {
        persons.set_deadline(Some(
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        ));
        assert_eq!(
            install::ask(&mut persons, &request).expect("the request is answered"),
            refused,
            "{request:?} on the persons' pipe"
        );
    }
    let status = install::ask(&mut persons, &Request::Status {}).expect("the status is answered");
    assert_eq!(
        status,
        Response::Status { maintenance: false },
        "the refused state change was made"
    );
    let mut administrators = client_without(Pipe::Administrators, &[]);
    say_hello(&mut administrators);
    administrators.set_deadline(Some(
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    ));
    let on = install::ask(&mut administrators, &Request::Maintenance { on: true });
    let after = install::ask(&mut administrators, &Request::Status {});
    let off = install::ask(&mut administrators, &Request::Maintenance { on: false });
    let ended = served.stops_within(20);
    assert_eq!(on.expect("answered"), Response::Done {});
    assert_eq!(
        after.expect("answered"),
        Response::Status { maintenance: true }
    );
    assert_eq!(off.expect("answered"), Response::Done {});
    assert_eq!(ended.expect("the service ends"), Ok(()));
}

/// A caller that is not an elevated administrator, a person or an administrator whose token holds the
/// Administrators group only deny-only, is refused the administrators' pipe by the pipe itself, with
/// access denied (error 5), before any worker; an elevated administrator opens it.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn the_administrators_pipe_refuses_a_person_and_an_administrator_who_is_not_elevated_with_error_5()
{
    use kr_boundary_windows::win::pipe;
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let broker = service::manager().unwrap().open(SERVICE).unwrap().unwrap();
    let pid = broker.status().unwrap().pid;
    // The service's process is held before the token changes: the open of the pipe is what each
    // token is refused or allowed.
    let held = pipe::ServerProcess::open(pid).expect("the service's process is opened");
    let elevated = pipe::connect_held(Pipe::Administrators, &held);
    let person = with_token_without(&[SYSTEM_SID, ADMINISTRATORS_SID], || {
        pipe::connect_held(Pipe::Administrators, &held)
    });
    // Under the administrator's own token the group alone is turned off, which is that
    // administrator without the elevation; under the system's token it is the system's entry that
    // would still allow the open, so there the case has only the person to show.
    let not_elevated = (!runs_as_the_system()).then(|| {
        with_token_without(&[ADMINISTRATORS_SID], || {
            pipe::connect_held(Pipe::Administrators, &held)
        })
    });
    assert!(
        elevated.is_ok(),
        "an elevated administrator is refused the administrators' pipe: {:?}",
        elevated.err()
    );
    assert_eq!(
        person.err().map(|failure| failure.code),
        Some(5),
        "a person's open of the administrators' pipe"
    );
    if let Some(refused) = not_elevated {
        assert_eq!(
            refused.err().map(|failure| failure.code),
            Some(5),
            "an administrator that is not elevated"
        );
    } else {
        eprintln!("SKIPPED: the not-elevated administrator needs the administrator's own token");
    }
    drop(case);
}

/// A stop that comes while clients keep asking on both pipes ends both loops inside the installer's
/// wait, and both names are free to make again once the service has ended.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_stop_with_clients_streaming_on_both_pipes_ends_both_loops_and_frees_both_names() {
    use kr_boundary_windows::win::pipe::{Listener, Stop};
    require_clean_machine();
    if needs_the_system() {
        return;
    }
    let mut served = serve_in_process();
    let person = RawClient::open(persons_pipe_name(), &[SYSTEM_SID, ADMINISTRATORS_SID]);
    let administrator = RawClient::open(Pipe::Administrators.name(), &[SYSTEM_SID]);
    let streams = [RawStream::start(&person), RawStream::start(&administrator)];
    for stream in &streams {
        stream
            .reaches(200_000, 60)
            .expect("the traffic flows before the stop");
    }
    let ended = served.stops_within(20);
    drop(streams);
    let persons_again = Listener::bind(Pipe::Persons, &[], Stop::new().unwrap()).map(drop);
    let administrators_again =
        Listener::bind(Pipe::Administrators, &[], Stop::new().unwrap()).map(drop);
    assert_eq!(
        ended.expect("the service ends with both pipes busy"),
        Ok(())
    );
    assert!(
        persons_again.is_ok(),
        "the persons' pipe's name is not free"
    );
    assert!(
        administrators_again.is_ok(),
        "the administrators' pipe's name is not free"
    );
}

/// The removal runs whole through the administrators' pipe while persons keep every connection of the
/// persons' pipe busy: its Maintenance, its release proofs and its stop of the service, which ends
/// the persons' connections with it, all inside the installer's own bounds.
#[cfg(feature = "testing")]
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest (see the file's header)"]
fn the_removal_runs_whole_through_the_administrators_pipe_while_persons_keep_the_persons_pipe_busy()
{
    let case = Case::new();
    let (code, output) = case.install();
    assert_eq!(code, 0, "{output}");
    let clients: Vec<_> = (0..7)
        .map(|_| RawClient::open(persons_pipe_name(), &[]))
        .collect();
    let streams: Vec<_> = clients.iter().map(RawStream::start).collect();
    for (number, stream) in streams.iter().take(6).enumerate() {
        stream
            .reaches(50_000, 60)
            .unwrap_or_else(|failure| panic!("connection {number} is not active: {failure}"));
    }
    let (removal_code, removal_output) = setup(&["remove"], "yes\n", &[]);
    drop(streams);
    assert_eq!(removal_code, 0, "{removal_output}");
    drop(case);
}
