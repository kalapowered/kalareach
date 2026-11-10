//! Whether the Windows execution policy refuses at run time what it is written to refuse.
//!
//! On Windows the execution list of a Git invocation is carried by application control: one policy,
//! put in place once by an administrator, that lets every account run every program except two
//! dedicated boundary accounts, and lets those two run only Git and the helpers Git itself starts.
//! A policy that reads correctly is not a policy that is enforced, and an engine's answer for a
//! sampled path is not what the system does when a process is created. So this case launches real
//! programs, as the real accounts, and reads what the system did.
//!
//! * The **checkout account** is the one every invocation that checks out or applies runs as. Its
//!   list holds Git's own `git.exe` and nothing else: no helper, no shell, no console host.
//! * The **connection account** is the one the clone that checks nothing out runs as. Its list is the
//!   checkout account's with the helpers Git starts to connect (`git-remote-https.exe` and
//!   `git-remote-http.exe` under its helper directory, `git-upload-pack.exe`), the shell Git builds a
//!   connection as a command string for, the secure shell program and the credential helper. The
//!   other helpers of Git's helper directory (`git-daemon.exe`, `git-imap-send.exe`, `scalar.exe`
//!   and the system's credential helper) are on neither list.
//! * An **ordinary account** stands for the person. It runs every program the boundary accounts are
//!   refused, from a place the person owns as well as from the system's, so a refusal that is the
//!   result of anything but the policy shows here too.
//!
//! Every account is started the way the broker starts it: from a logon token made without its
//! password, with the boundary accounts' own identifier marked deny-only and an invocation group of
//! their own, in a process with no console. A case that makes such a token must be the system, so
//! the case runs as SYSTEM.
//!
//! What the case requires of each boundary account: a signed system program (`cmd.exe`, and the
//! system's `hostname.exe`), a signed program copied to a place a repository could put it, a copy of
//! Git itself outside its installation and an unsigned program are all refused to create a process,
//! and each refusal is a blocked-launch event of the application-control log that names the rule
//! (and the rule is the account's own deny rule); a program planted as a hook (`post-commit.exe`)
//! and a program a repository's configuration names as a helper (a clean filter) never run, and Git
//! reports that it could not start them; every helper of Git's helper directory that is not on the
//! account's own list is refused, and the ones that are run; the shell is refused to the checkout
//! account, so a hook script that needs it and a clone that needs it never run there, and they run
//! for the connection account; neither account can make a directory in the directories its list
//! names; and Git and a clone that checks nothing out run where they are on the list. What the case
//! requires of the ordinary account: every one of those programs runs.
//!
//! The same launches in a guest where the policy is not in place all succeed, which is the case's
//! own negative control: it fails there, naming every program that ran.
//!
//! The permissions the case gives its accounts on its own window station and desktop last as long as
//! that session does.
//!
//! It makes a local account for the person, writes under `%ProgramData%` and gives the accounts it
//! launches access to its own window station and desktop. It is run as SYSTEM in a disposable guest
//! where the boundary is installed, by name:
//!
//! ```text
//! windows_enforcement --ignored --exact the_boundary_accounts_run_only_git_and_the_person_runs_everything --nocapture
//! ```
//!
//! `KR_BOUNDARY_CHECKOUT_ACCOUNT` and `KR_BOUNDARY_CONNECT_ACCOUNT` name the two accounts, and
//! `KR_GIT_ROOT` the Git installation (`C:\Program Files\Git`).

#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "launching a program as another account, naming an account's identifier and editing the \
              permissions of a window station are calls with out-parameters and handle ownership \
              that only the caller can promise; the case's own steps use them through a few \
              functions"
)]

use std::collections::BTreeSet;
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use kr_boundary_windows::win::ffi::Handle;
use kr_boundary_windows::win::token::{baseline_token, boundary_token, new_invocation_group};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetUserAdd, NetUserDel, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_WINDOW_OBJECT, SetEntriesInAclW, SetSecurityInfo,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, LookupAccountNameW, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DETACHED_PROCESS, GetCurrentProcess,
    GetCurrentThreadId, GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

/// The error a created process is refused with when application control denies the image.
const ERROR_ACCESS_DISABLED_BY_POLICY: u32 = 1260;

/// The event identifiers of the application-control log for a launch that was allowed and one that
/// was blocked.
const EVENT_ALLOWED: u32 = 8002;
const EVENT_BLOCKED: u32 = 8004;

/// The log the executable collection writes to.
const LOG: &str = "Microsoft-Windows-AppLocker/EXE and DLL";

/// How long one program may run before the case ends it.
const PROGRAM_TIME: Duration = Duration::from_secs(60);

/// How long the log may take to show an event for a launch that has already happened.
const LOG_TIME: Duration = Duration::from_secs(45);

/// One account a program is launched as.
struct Account {
    role: &'static str,
    name: String,
    sid: String,
    /// The token every launch as this account runs under.
    token: Handle,
}

/// What became of one launch.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// The system refused to create the process, with this error.
    Refused(u32),
    /// The process ran and ended with this exit code.
    Ran(u32),
    /// The process ran for too long and was ended.
    Hung,
    /// The process ended and its exit code could not be read.
    Unread,
}

impl Outcome {
    fn ran(&self) -> bool {
        matches!(self, Self::Ran(_))
    }

    fn refused(&self) -> bool {
        matches!(self, Self::Refused(code) if *code == ERROR_ACCESS_DISABLED_BY_POLICY)
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(code) => write!(formatter, "refused, error {code}"),
            Self::Ran(code) => write!(formatter, "ran, exit {code:#x}"),
            Self::Hung => formatter.write_str("did not end"),
            Self::Unread => formatter.write_str("ended and its exit code could not be read"),
        }
    }
}

/// One launch: how it ended and what it wrote.
struct Launch {
    outcome: Outcome,
    output: String,
}

/// One entry of the application-control log.
#[derive(Debug)]
struct Event {
    id: u32,
    rule: String,
    sddl: String,
    user: String,
    file: String,
}

/// An event the case expects the log to show.
struct Expected {
    id: u32,
    sid: String,
    /// The end of the image's path, upper-cased as the log writes it.
    file: String,
    /// What the rule's own definition must contain, for a refusal: the account it is scoped to.
    scoped_to: Option<String>,
    what: String,
}

/// What the case made outside itself: the directory it writes in and the person's account. Both are
/// taken away when this goes, however the case ends.
struct Cleanup {
    root: PathBuf,
    person: Option<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(name) = &self.person {
            delete_account(name);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The whole case.
struct Case {
    _cleanup: Cleanup,
    git_root: PathBuf,
    git: PathBuf,
    exec_path: PathBuf,
    root: PathBuf,
    checkout: Account,
    connect: Account,
    person: Account,
    failures: Vec<String>,
    expected: Vec<Expected>,
    watermark: u64,
    counter: u32,
}

/// The application-control policy, qualified in a guest: for each boundary account a program
/// planted as a hook and a program a repository's configuration names as a clean filter never run,
/// and Git reports that it could not start them; a hook script does not run for the checkout
/// account, whose list holds no shell, and does for the connection account's; the person's account
/// runs every one of them.
#[test]
#[ignore = "needs an elevated session in a disposable Windows guest where the application-control \
            policy and the two boundary accounts are in place, and it changes that guest's accounts \
            and window station; run it by name with --ignored (see the module documentation)"]
fn the_boundary_accounts_run_only_git_and_the_person_runs_everything() {
    let mut case = Case::start();
    case.programs();
    case.git_and_its_helpers();
    case.helpers_a_repository_names();
    case.clone_then_checkout();
    case.git_installation_is_not_writable();
    case.finish();
}

/// The three accounts a program is launched as, in the order the output is read.
const ALL: [Who; 3] = [Who::Checkout, Who::Connect, Who::Person];

impl Case {
    /// Checks what the case needs, makes the person's account and the fixtures, and reads the
    /// newest event so that only this case's events are looked at.
    fn start() -> Self {
        assert!(
            elevated(),
            "this case changes accounts and permissions and must run elevated"
        );
        let service = output_of(Command::new("sc.exe").args(["query", "AppIDSvc"]));
        assert!(
            service.contains("RUNNING"),
            "the Application Identity service is not running, so no application-control policy is \
             enforced:\n{service}"
        );
        let smart_app_control = Command::new("reg.exe")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
                "/v",
                "VerifiedAndReputablePolicyState",
            ])
            .output()
            .expect("reg.exe starts");
        assert!(
            smart_app_control.status.success(),
            "Smart App Control's state could not be read, so the case cannot tell it from this \
             policy:\n{}{}",
            String::from_utf8_lossy(&smart_app_control.stdout),
            String::from_utf8_lossy(&smart_app_control.stderr)
        );
        assert!(
            String::from_utf8_lossy(&smart_app_control.stdout)
                .split_whitespace()
                .last()
                == Some("0x0"),
            "Smart App Control is on or evaluating, so it can refuse the unsigned program for a \
             reason that is not this policy:\n{}",
            String::from_utf8_lossy(&smart_app_control.stdout)
        );

        let git_root = PathBuf::from(
            std::env::var_os("KR_GIT_ROOT").unwrap_or_else(|| r"C:\Program Files\Git".into()),
        );
        let git = git_root.join(r"mingw64\bin\git.exe");
        assert!(git.is_file(), "{} is not Git's program", git.display());
        let exec_path = PathBuf::from(
            output_of(Command::new(&git).arg("--exec-path"))
                .trim()
                .replace('/', "\\"),
        );

        let checkout = boundary_account(
            "checkout",
            &std::env::var("KR_BOUNDARY_CHECKOUT_ACCOUNT")
                .unwrap_or_else(|_| "krb-checkout".into()),
        );
        let connect = boundary_account(
            "connect",
            &std::env::var("KR_BOUNDARY_CONNECT_ACCOUNT").unwrap_or_else(|_| "krb-connect".into()),
        );
        let root =
            PathBuf::from(std::env::var_os("ProgramData").expect("the program data directory"))
                .join(format!("kr-enforcement-{}", uuid::Uuid::new_v4().simple()));
        let mut cleanup = Cleanup {
            root: root.clone(),
            person: None,
        };
        std::fs::create_dir_all(root.join("tmp")).expect("the fixture directory");
        std::fs::create_dir_all(root.join("home")).expect("the home directory");
        run_checked(
            Command::new("icacls.exe")
                .arg(&root)
                .args(["/grant", "Users:(OI)(CI)(M)"]),
        );
        give_session_access(&checkout.sid);
        give_session_access(&connect.sid);

        let person = person_account(&mut cleanup);
        let case = Self {
            _cleanup: cleanup,
            git_root,
            git,
            exec_path,
            root,
            checkout,
            connect,
            person,
            failures: Vec::new(),
            expected: Vec::new(),
            watermark: newest_record(),
            counter: 0,
        };
        give_session_access(&case.person.sid);
        case.plant_fixtures();
        case
    }

    /// Writes the programs and repositories every launch uses.
    fn plant_fixtures(&self) {
        let planted = self.root.join("planted");
        std::fs::create_dir_all(&planted).expect("the planted directory");

        // A signed program from the system, copied to a place a repository could put a file, and a
        // copy of Git's own program there too: image identity is the path, so a signed program that
        // is not where the policy names it is refused.
        let system = PathBuf::from(std::env::var_os("SystemRoot").expect("the system root"))
            .join("System32");
        std::fs::copy(system.join("hostname.exe"), planted.join("hostname.exe"))
            .expect("a copy of a signed program");
        std::fs::copy(&self.git, planted.join("git.exe")).expect("a copy of Git's program");

        // An unsigned program that records that it ran next to itself.
        let source = planted.join("recorder.cs");
        std::fs::write(
            &source,
            "class Recorder { static int Main() { \
             var me = System.Reflection.Assembly.GetEntryAssembly().Location; \
             System.IO.File.WriteAllText(me + \".ran\", \"ran\"); return 0; } }",
        )
        .expect("the source of the unsigned program");
        let csc = PathBuf::from(std::env::var_os("SystemRoot").expect("the system root"))
            .join(r"Microsoft.NET\Framework64\v4.0.30319\csc.exe");
        run_checked(
            Command::new(csc)
                .args(["/nologo", "/target:exe"])
                .arg(format!("/out:{}", planted.join("recorder.exe").display()))
                .arg(&source),
        );

        // A repository whose configuration names the unsigned program as the clean filter of every
        // file, and requires the filter to succeed. A program is the only kind of helper this
        // platform's Git can start without a shell, which is what makes it the binary hook.
        let filtered = self.root.join("filtered");
        self.git_as_admin(&["init", "-q", &filtered.to_string_lossy()]);
        std::fs::write(filtered.join(".gitattributes"), "* filter=planted\n").expect("attributes");
        let recorder = planted
            .join("recorder.exe")
            .to_string_lossy()
            .replace('\\', "/");
        self.git_as_admin(&[
            "-C",
            &filtered.to_string_lossy(),
            "config",
            "filter.planted.clean",
            &recorder,
        ]);
        self.git_as_admin(&[
            "-C",
            &filtered.to_string_lossy(),
            "config",
            "filter.planted.required",
            "true",
        ]);

        // A repository with a hook that is a shell script.
        let scripted = self.root.join("scripted");
        self.git_as_admin(&["init", "-q", &scripted.to_string_lossy()]);
        std::fs::write(
            scripted.join(".git").join("hooks").join("post-commit"),
            "#!/bin/sh\n: > \"$0.ran\"\n",
        )
        .expect("a hook script");

        // A repository with a hook that is a program. Git for Windows looks for a hook by its name
        // and by its name with `.exe`, and starts the program it finds.
        let hooked = self.root.join("hooked");
        self.git_as_admin(&["init", "-q", &hooked.to_string_lossy()]);
        std::fs::copy(
            planted.join("recorder.exe"),
            hooked.join(".git").join("hooks").join("post-commit.exe"),
        )
        .expect("a hook that is a program");

        // A bare repository to clone from.
        let source_repository = self.root.join("source.git");
        self.git_as_admin(&["init", "-q", "--bare", &source_repository.to_string_lossy()]);
        std::fs::write(scripted.join("seed.txt"), "seed\n").expect("a file to commit");
        self.git_as_admin(&["-C", &scripted.to_string_lossy(), "add", "seed.txt"]);
        self.git_as_admin(&[
            "-C",
            &scripted.to_string_lossy(),
            "-c",
            "user.name=case",
            "-c",
            "user.email=case@example.invalid",
            "commit",
            "-q",
            "-m",
            "seed",
        ]);
        let _ = std::fs::remove_file(scripted.join(".git").join("hooks").join("post-commit.ran"));
        self.git_as_admin(&[
            "-C",
            &scripted.to_string_lossy(),
            "push",
            "-q",
            &source_repository.to_string_lossy(),
            "HEAD:refs/heads/main",
        ]);
    }

    /// Runs Git as this elevated account, for the fixtures.
    fn git_as_admin(&self, arguments: &[&str]) {
        run_checked(Command::new(&self.git).args(arguments));
    }

    /// The environment every launch is given: nothing but what Git and the system need.
    fn environment(&self) -> Vec<(String, String)> {
        let system_root = std::env::var("SystemRoot").expect("the system root");
        vec![
            ("SystemRoot".to_owned(), system_root.clone()),
            (
                "SystemDrive".to_owned(),
                std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()),
            ),
            (
                "TEMP".to_owned(),
                self.root.join("tmp").to_string_lossy().into_owned(),
            ),
            (
                "TMP".to_owned(),
                self.root.join("tmp").to_string_lossy().into_owned(),
            ),
            (
                "HOME".to_owned(),
                self.root.join("home").to_string_lossy().into_owned(),
            ),
            (
                "PATH".to_owned(),
                format!(
                    "{}\\mingw64\\bin;{}\\usr\\bin;{system_root}\\System32",
                    self.git_root.display(),
                    self.git_root.display()
                ),
            ),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
            ("GIT_CONFIG_COUNT".to_owned(), "1".to_owned()),
            ("GIT_CONFIG_KEY_0".to_owned(), "safe.directory".to_owned()),
            ("GIT_CONFIG_VALUE_0".to_owned(), "*".to_owned()),
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ]
    }

    /// Launches one program as one account, records what happened and prints it.
    fn launch(
        &mut self,
        who: Who,
        what: &str,
        program: &Path,
        arguments: &str,
        directory: &Path,
    ) -> Launch {
        self.counter += 1;
        let output_path = self.root.join(format!("output-{}.txt", self.counter));
        let account = match who {
            Who::Checkout => &self.checkout,
            Who::Connect => &self.connect,
            Who::Person => &self.person,
        };
        let line = if arguments.is_empty() {
            format!("\"{}\"", program.display())
        } else {
            format!("\"{}\" {arguments}", program.display())
        };
        let launch = create_process_as(
            account,
            program,
            &line,
            directory,
            &self.environment(),
            &output_path,
        );
        let shown = launch
            .output
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join(" | ");
        println!(
            "{:<9} {:<52} {}{}",
            account.role,
            what,
            launch.outcome,
            if shown.is_empty() {
                String::new()
            } else {
                format!("   [{shown}]")
            }
        );
        launch
    }

    /// Notes a failed expectation, and prints it where the run's output is read.
    fn fail(&mut self, message: String) {
        println!("FAIL      {message}");
        self.failures.push(message);
    }

    fn expect(&mut self, holds: bool, message: impl FnOnce() -> String) {
        if !holds {
            let message = message();
            self.fail(message);
        }
    }

    /// Expects the application-control log to show a blocked launch of this image by this account,
    /// under a rule scoped to that account.
    fn expect_blocked(&mut self, who: Who, file_end: &str, what: &str) {
        let sid = self.account(who).sid.clone();
        self.expected.push(Expected {
            id: EVENT_BLOCKED,
            sid: sid.clone(),
            file: file_end.to_uppercase(),
            scoped_to: Some(sid),
            what: format!("{} account: {what}", self.account(who).role),
        });
    }

    /// Expects the log to show an allowed launch of this image by this account.
    fn expect_allowed(&mut self, who: Who, file_end: &str, what: &str) {
        let sid = self.account(who).sid.clone();
        self.expected.push(Expected {
            id: EVENT_ALLOWED,
            sid,
            file: file_end.to_uppercase(),
            scoped_to: None,
            what: format!("{} account: {what}", self.account(who).role),
        });
    }

    fn account(&self, who: Who) -> &Account {
        match who {
            Who::Checkout => &self.checkout,
            Who::Connect => &self.connect,
            Who::Person => &self.person,
        }
    }

    /// Requires a program to be refused to a boundary account, by a rule the log names, and to run
    /// for the person.
    fn refused_or_ran(&mut self, who: Who, launch: &Launch, what: &str, blocked: &str) {
        let role = self.account(who).role;
        if who == Who::Person {
            self.expect(launch.outcome == Outcome::Ran(0), || {
                format!("{role}: {what} {}", launch.outcome)
            });
        } else {
            self.expect(launch.outcome.refused(), || {
                format!(
                    "{role}: {what} {}, and was not refused by policy",
                    launch.outcome
                )
            });
            self.expect_blocked(who, blocked, what);
        }
    }

    /// A system program, signed programs and an unsigned one, in the places a repository could put
    /// them, and in a place the person owns.
    fn programs(&mut self) {
        println!("--- programs: system, signed and planted, unsigned and planted");
        let system = PathBuf::from(std::env::var_os("SystemRoot").expect("the system root"))
            .join("System32");
        let planted = self.root.join("planted");
        let directory = self.root.clone();
        let programs = [
            (
                "cmd.exe (signed, system)",
                system.join("cmd.exe"),
                "/c exit 0",
                r"%SYSTEM32%\CMD.EXE",
            ),
            (
                "hostname.exe (signed, system)",
                system.join("hostname.exe"),
                "",
                r"%SYSTEM32%\HOSTNAME.EXE",
            ),
            (
                "hostname.exe (signed, beside a repository)",
                planted.join("hostname.exe"),
                "",
                r"\PLANTED\HOSTNAME.EXE",
            ),
            (
                "git.exe (signed, beside a repository)",
                planted.join("git.exe"),
                "--version",
                r"\PLANTED\GIT.EXE",
            ),
            (
                "recorder.exe (unsigned, beside a repository)",
                planted.join("recorder.exe"),
                "",
                r"\PLANTED\RECORDER.EXE",
            ),
        ];
        for who in ALL {
            let _ = std::fs::remove_file(planted.join("recorder.exe.ran"));
            for (what, path, arguments, blocked) in &programs {
                let launch = self.launch(who, what, path, arguments, &directory);
                self.refused_or_ran(who, &launch, what, blocked);
            }
            let recorded = planted.join("recorder.exe.ran").exists();
            let role = self.account(who).role;
            self.expect(recorded == (who == Who::Person), || {
                format!("{role}: the unsigned program recorded that it ran: {recorded}")
            });
        }

        // The person's own place: a directory the ordinary account owns, where a program that
        // account puts is the account's own doing and the policy has to let it run.
        let own = self.root.join("owned-by-the-person");
        std::fs::create_dir_all(&own).expect("the person's directory");
        let owned = own.join("recorder.exe");
        std::fs::copy(planted.join("recorder.exe"), &owned).expect("a program in the directory");
        for path in [&own, &owned] {
            run_checked(
                Command::new("icacls.exe")
                    .arg(path)
                    .args(["/setowner", &self.person.name]),
            );
        }
        let launch = self.launch(
            Who::Person,
            "recorder.exe (unsigned, in a directory the person owns)",
            &owned,
            "",
            &own,
        );
        let recorded = own.join("recorder.exe.ran").exists();
        self.expect(launch.outcome == Outcome::Ran(0) && recorded, || {
            format!(
                "person: the program in a directory the person owns {} and recorded={recorded}",
                launch.outcome
            )
        });
    }

    /// Git runs for both boundary accounts. A helper under its helper directory runs only for the
    /// account whose list holds it and for the person, and a helper on neither list is refused to
    /// both boundary accounts.
    fn git_and_its_helpers(&mut self) {
        println!("--- Git, the helpers on a list and the helpers on neither");
        let directory = self.root.clone();
        let git = self.git.clone();
        let helper = self.exec_path.join("git-remote-https.exe");
        for who in ALL {
            let version = self.launch(who, "git.exe --version", &git, "--version", &directory);
            let inside = self.launch(
                who,
                "git.exe rev-parse --git-dir (in a repository)",
                &git,
                "-C scripted rev-parse --git-dir",
                &directory,
            );
            let remote = self.launch(
                who,
                "git-remote-https.exe (a helper of Git)",
                &helper,
                "",
                &directory,
            );
            let role = self.account(who).role;
            self.expect(
                version.outcome == Outcome::Ran(0) && version.output.contains("git version"),
                || {
                    format!(
                        "{role}: git --version {} {:?}",
                        version.outcome, version.output
                    )
                },
            );
            self.expect(inside.outcome == Outcome::Ran(0), || {
                format!(
                    "{role}: git rev-parse {} {:?}",
                    inside.outcome, inside.output
                )
            });
            if who == Who::Checkout {
                self.expect(remote.outcome.refused(), || {
                    format!(
                        "{role}: the connection helper {}, and was not refused by policy",
                        remote.outcome
                    )
                });
                self.expect_blocked(
                    who,
                    r"\GIT-CORE\GIT-REMOTE-HTTPS.EXE",
                    "the connection helper is named as blocked",
                );
            } else {
                self.expect(
                    remote.outcome.ran() && remote.output.contains("usage"),
                    || {
                        format!(
                            "{role}: the connection helper {} {:?}",
                            remote.outcome, remote.output
                        )
                    },
                );
            }
            if who != Who::Person {
                self.expect_allowed(who, r"\MINGW64\BIN\GIT.EXE", "Git is named as allowed");
            }
            if who == Who::Connect {
                self.expect_allowed(
                    who,
                    r"\GIT-CORE\GIT-REMOTE-HTTPS.EXE",
                    "the connection helper is named as allowed",
                );
            }
            // The helpers of Git's helper directory that no list holds.
            for name in [
                "git-daemon.exe",
                "git-imap-send.exe",
                "scalar.exe",
                "git-credential-wincred.exe",
            ] {
                let path = self.exec_path.join(name);
                assert!(
                    path.is_file(),
                    "{} is not in Git's helper directory",
                    path.display()
                );
                // The daemon listens until it is ended when it has nothing to refuse, so it is asked for
                // its usage, which it answers at once.
                let arguments = if name == "git-daemon.exe" {
                    "--help"
                } else {
                    ""
                };
                let launch = self.launch(who, name, &path, arguments, &directory);
                if who == Who::Person {
                    self.expect(launch.outcome.ran(), || {
                        format!("{role}: {name} {}", launch.outcome)
                    });
                } else {
                    self.expect(launch.outcome.refused(), || {
                        format!(
                            "{role}: {name} {}, and was not refused by policy",
                            launch.outcome
                        )
                    });
                    self.expect_blocked(
                        who,
                        &format!(r"\GIT-CORE\{}", name.to_uppercase()),
                        &format!("{name} is named as blocked"),
                    );
                }
            }
        }
    }

    /// A program the repository's configuration names as a helper, and a hook script.
    fn helpers_a_repository_names(&mut self) {
        println!("--- helpers a repository names: a program (a clean filter) and a hook script");
        let directory = self.root.clone();
        let git = self.git.clone();
        let ran_filter = self.root.join("planted").join("recorder.exe.ran");
        let filtered = self.root.join("filtered");
        let scripted = self.root.join("scripted");
        let ran_hook = scripted.join(".git").join("hooks").join("post-commit.ran");
        let ran_binary_hook = self
            .root
            .join("hooked")
            .join(".git")
            .join("hooks")
            .join("post-commit.exe.ran");
        for who in ALL {
            let _ = std::fs::remove_file(&ran_binary_hook);
            let binary_hook = self.launch(
                who,
                "git commit (the repository's hook is a program)",
                &git,
                "-C hooked -c user.name=case -c user.email=case@example.invalid commit -q --allow-empty -m hook",
                &directory,
            );
            let binary_hook_ran = ran_binary_hook.exists();
            let _ = std::fs::remove_file(&ran_binary_hook);

            let _ = std::fs::remove_file(&ran_filter);
            let _ = std::fs::remove_file(filtered.join(".git").join("index"));
            std::fs::write(filtered.join("file.txt"), uuid::Uuid::new_v4().to_string())
                .expect("a file to add");
            let add = self.launch(
                who,
                "git add (the repository's clean filter is a program)",
                &git,
                "-C filtered add file.txt",
                &directory,
            );
            let filter_ran = ran_filter.exists();
            let _ = std::fs::remove_file(&ran_filter);

            let _ = std::fs::remove_file(&ran_hook);
            let commit = self.launch(
                who,
                "git commit (the repository's hook is a shell script)",
                &git,
                "-C scripted -c user.name=case -c user.email=case@example.invalid commit -q --allow-empty -m hook",
                &directory,
            );
            let hook_ran = ran_hook.exists();
            let _ = std::fs::remove_file(&ran_hook);

            let role = self.account(who).role;
            if who == Who::Person {
                self.expect(
                    binary_hook.outcome == Outcome::Ran(0) && binary_hook_ran,
                    || {
                        format!(
                            "{role}: the hook that is a program {} and ran={binary_hook_ran}",
                            binary_hook.outcome
                        )
                    },
                );
                self.expect(add.outcome == Outcome::Ran(0) && filter_ran, || {
                    format!(
                        "{role}: the program named as a filter {} and ran={filter_ran}",
                        add.outcome
                    )
                });
                self.expect(commit.outcome == Outcome::Ran(0) && hook_ran, || {
                    format!(
                        "{role}: the hook script {} and ran={hook_ran}",
                        commit.outcome
                    )
                });
                continue;
            }
            // Git has to have ended for its diagnostic to be the whole of what it said, and for the
            // hook not to be one that has not run yet.
            self.expect(
                binary_hook.outcome.ran()
                    && !binary_hook_ran
                    && binary_hook.output.contains("cannot spawn"),
                || {
                    format!(
                        "{role}: the hook that is a program: Git {}, ran={binary_hook_ran} and Git said {:?}",
                        binary_hook.outcome, binary_hook.output
                    )
                },
            );
            self.expect_blocked(
                who,
                r"\HOOKS\POST-COMMIT.EXE",
                "the program planted as a hook is named as blocked",
            );
            self.expect(!filter_ran, || {
                format!("{role}: the program named as a clean filter ran")
            });
            self.expect(
                matches!(add.outcome, Outcome::Ran(code) if code != 0)
                    && add.output.contains("cannot spawn"),
                || {
                    format!(
                        "{role}: git add {} {:?}, which is not Git reporting that it could not start its required filter",
                        add.outcome, add.output
                    )
                },
            );
            self.expect_blocked(
                who,
                r"\PLANTED\RECORDER.EXE",
                "the program named as a filter is named as blocked",
            );
            // The hook script needs the shell: only the connection account's list holds it.
            self.expect(
                commit.outcome.ran()
                    && hook_ran == (who == Who::Connect)
                    && (who == Who::Connect || commit.output.contains("cannot spawn")),
                || {
                    format!(
                        "{role}: the hook script: Git {}, ran={hook_ran} and Git said {:?}, which the shell on its list does not allow",
                        commit.outcome, commit.output
                    )
                },
            );
            if who == Who::Connect {
                self.expect_allowed(who, r"\USR\BIN\SH.EXE", "the shell is named as allowed");
            } else {
                self.expect_blocked(who, r"\USR\BIN\SH.EXE", "the shell is named as blocked");
            }
        }
    }

    /// The clone that checks nothing out needs the shell and the programs it starts, so only the
    /// connection account's list holds them; the checkout that follows is the other account's.
    fn clone_then_checkout(&mut self) {
        println!("--- a clone that checks nothing out, then the checkout of it");
        let directory = self.root.clone();
        let git = self.git.clone();
        let source = self.root.join("source.git");
        for who in ALL {
            let destination = self.root.join(format!("clone-{}", self.account(who).role));
            let clone = self.launch(
                who,
                "git clone --no-checkout (a local path)",
                &git,
                &format!(
                    "clone --no-checkout -q \"{}\" \"{}\"",
                    source.display(),
                    destination.display()
                ),
                &directory,
            );
            let made = destination.join(".git").join("HEAD").exists();
            let role = self.account(who).role;
            if who == Who::Checkout {
                self.expect(
                    !made
                        && matches!(clone.outcome, Outcome::Ran(code) if code != 0)
                        && clone.output.contains("sh.exe"),
                    || {
                        format!(
                            "{role}: the clone {} and made={made} {:?}, which a list with no shell does not allow",
                            clone.outcome, clone.output
                        )
                    },
                );
                self.expect_blocked(
                    who,
                    r"\USR\BIN\SH.EXE",
                    "the shell the clone needs is named as blocked",
                );
                continue;
            }
            self.expect(clone.outcome == Outcome::Ran(0) && made, || {
                format!(
                    "{role}: the clone {} and made={made} {:?}",
                    clone.outcome, clone.output
                )
            });
            if who == Who::Connect {
                self.expect_allowed(
                    who,
                    r"\BIN\GIT-UPLOAD-PACK.EXE",
                    "the program that serves the repository is named as allowed",
                );
                let checkout = self.launch(
                    Who::Checkout,
                    "git checkout of that clone (the checkout account)",
                    &git,
                    &format!("-C \"{}\" checkout -q main", destination.display()),
                    &directory,
                );
                let landed = destination.join("seed.txt").exists();
                self.expect(checkout.outcome == Outcome::Ran(0) && landed, || {
                    format!(
                        "checkout: the checkout of the clone {} {:?}",
                        checkout.outcome, checkout.output
                    )
                });
            }
        }
    }

    /// A path rule on Git's installation holds only while neither boundary account can write there:
    /// a program either account could put in a listed directory would be on the list. This shows the
    /// top of each listed directory and nothing below it: neither account can make a directory
    /// there.
    fn git_installation_is_not_writable(&mut self) {
        println!("--- neither boundary account can make a directory in a directory on the lists");
        let directory = self.root.clone();
        let git = self.git.clone();
        let listed = [
            self.exec_path.clone(),
            self.git.parent().expect("Git's directory").to_owned(),
            self.git_root.join("usr").join("bin"),
        ];
        for who in [Who::Checkout, Who::Connect] {
            for place in &listed {
                // A name of this launch alone, required to be free before the launch: a directory
                // found there afterwards was made by the launch, and only that one is removed. A
                // link or a file of that name counts as taken, and so does a name that cannot be
                // told apart from taken because the lookup failed. This holds in the disposable
                // guest the case runs in, and claims nothing about another machine.
                let probe = place.join(format!("kr-write-check-{}", uuid::Uuid::new_v4().simple()));
                match std::fs::symlink_metadata(&probe) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => panic!(
                        "{} exists before the launch that would make it",
                        probe.display()
                    ),
                    Err(error) => panic!(
                        "whether {} exists could not be told before the launch that would make it: {error}",
                        probe.display()
                    ),
                }
                let launch = self.launch(
                    who,
                    "git init inside a directory on the lists",
                    &git,
                    &format!("init -q \"{}\"", probe.display()),
                    &directory,
                );
                let made = probe.exists();
                if made {
                    let _ = std::fs::remove_dir_all(&probe);
                }
                let role = self.account(who).role;
                self.expect(
                    !made && matches!(launch.outcome, Outcome::Ran(code) if code != 0),
                    || {
                        format!(
                            "{role}: in {} the directory was made={made} and Git {}",
                            place.display(),
                            launch.outcome
                        )
                    },
                );
            }
        }
    }

    /// Reads the log for every event the case expects, requires them, and ends the case.
    fn finish(mut self) {
        println!("--- the application-control log");
        let deadline = Instant::now() + LOG_TIME;
        let mut events;
        loop {
            events = events_after(self.watermark);
            if assign(&events, &self.expected)
                .iter()
                .all(std::option::Option::is_some)
                || Instant::now() >= deadline
            {
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        println!("{} events were written during the case", events.len());
        let mut rules: BTreeSet<String> = BTreeSet::new();
        let expected = std::mem::take(&mut self.expected);
        let assigned = assign(&events, &expected);
        for (wanted, at) in expected.iter().zip(assigned) {
            match at.map(|at| &events[at]) {
                None => self.fail(format!(
                    "the log shows no event {} of its own for: {}",
                    wanted.id, wanted.what
                )),
                Some(event) => {
                    println!(
                        "event {} | {} | {} | {}",
                        event.id, event.rule, event.file, wanted.what
                    );
                    if let Some(sid) = &wanted.scoped_to {
                        let scoped = event.sddl.contains(&format!(";;;{sid};"))
                            && event.sddl.starts_with("D:(XD");
                        if !scoped {
                            self.fail(format!(
                                "the rule that blocked it is not a deny rule scoped to {sid}: {} ({})",
                                event.rule, event.sddl
                            ));
                        }
                        rules.insert(event.rule.clone());
                    }
                }
            }
        }
        if !expected.is_empty() {
            self.expect(rules.len() == 2, || {
                format!("the two boundary accounts were refused under {} rule(s), not their two own: {rules:?}", rules.len())
            });
        }
        assert!(
            self.failures.is_empty(),
            "the policy did not hold at run time:\n  {}",
            self.failures.join("\n  ")
        );
    }
}

/// Which account a program is launched as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Checkout,
    Connect,
    Person,
}

/// Pairs each event the case expected with an event of its own in the log.
///
/// Two expectations that name the same image need two events: one launch cannot answer for two.
fn assign(events: &[Event], expected: &[Expected]) -> Vec<Option<usize>> {
    let mut taken = vec![false; events.len()];
    expected
        .iter()
        .map(|wanted| {
            let at = events.iter().enumerate().position(|(index, event)| {
                !taken[index]
                    && event.id == wanted.id
                    && event.user == wanted.sid
                    && event.file.to_uppercase().ends_with(&wanted.file)
            })?;
            taken[at] = true;
            Some(at)
        })
        .collect()
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Returns whether this process holds an elevated token.
fn elevated() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: the out-parameter is this function's own for the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0_u32;
    // SAFETY: the token is open, and the buffer is a structure of the size the call is told.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("a small size"),
            &raw mut length,
        )
    };
    // SAFETY: the handle was opened above and nothing else holds it.
    unsafe {
        CloseHandle(token);
    }
    read != 0 && elevation.TokenIsElevated != 0
}

/// Runs a command and returns its standard output and standard error, whatever its status.
///
/// A query that finds nothing, such as a registry value that is not there, ends with a status the
/// case does not treat as a failure; a caller that needs the command to have worked checks what
/// came back.
fn output_of(command: &mut Command) -> String {
    let output = command.output().expect("the command starts");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_checked(command: &mut Command) {
    let output = command.output().expect("the command starts");
    assert!(
        output.status.success(),
        "{command:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A password only this process knows.
fn password() -> String {
    format!("{}aA1!", uuid::Uuid::new_v4().simple())
}

/// Returns the identifier of an account as text.
fn sid_text(account: &str) -> Option<String> {
    let name = wide(account);
    let mut sid_length = 0_u32;
    let mut domain_length = 0_u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: the first call only asks for the sizes it needs.
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &raw mut sid_length,
            null_mut(),
            &raw mut domain_length,
            &raw mut kind,
        );
    }
    if sid_length == 0 {
        return None;
    }
    let mut sid = vec![0_u32; (sid_length as usize).div_ceil(4)];
    let mut domain = vec![0_u16; domain_length as usize];
    // SAFETY: both buffers are the sizes the first call asked for.
    let found = unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_length,
            domain.as_mut_ptr(),
            &raw mut domain_length,
            &raw mut kind,
        )
    };
    if found == 0 {
        return None;
    }
    let mut text: *mut u16 = null_mut();
    // SAFETY: the buffer holds the identifier the call just wrote, and the text is an out-parameter
    // the platform allocates and this function frees.
    unsafe {
        if ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &raw mut text) == 0 {
            return None;
        }
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        Some(value)
    }
}

/// Returns a boundary account the installation made, with the token the broker would start Git
/// under: made without the account's password.
fn boundary_account(role: &'static str, name: &str) -> Account {
    let sid = sid_text(name).unwrap_or_else(|| {
        panic!("the {role} boundary account {name} does not exist: the boundary is not installed")
    });
    let token = boundary_token(name, &new_invocation_group())
        .unwrap_or_else(|error| panic!("the {role} boundary account's token: {error}"));
    Account {
        role,
        name: name.to_owned(),
        sid,
        token,
    }
}

/// Makes the ordinary account the person stands for.
fn person_account(cleanup: &mut Cleanup) -> Account {
    let name = format!(
        "krperson{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let password = password();
    let mut account = wide(&name);
    let mut secret = wide(&password);
    let info = USER_INFO_1 {
        usri1_name: account.as_mut_ptr(),
        usri1_password: secret.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: null_mut(),
        usri1_comment: null_mut(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
        usri1_script_path: null_mut(),
    };
    // SAFETY: the structure and the strings it points at are this function's own for the call.
    let status = unsafe { NetUserAdd(null(), 1, (&raw const info).cast(), null_mut()) };
    assert_eq!(
        status, NERR_Success,
        "the ordinary account could not be made"
    );
    cleanup.person = Some(name.clone());
    let sid = sid_text(&name).expect("the ordinary account has an identifier");
    let token = baseline_token(&name).expect("the ordinary account's token");
    Account {
        role: "person",
        name,
        sid,
        token,
    }
}

fn delete_account(name: &str) {
    let account = wide(name);
    // SAFETY: the name is this function's own NUL-terminated buffer.
    let status = unsafe { NetUserDel(null(), account.as_ptr()) };
    if status != NERR_Success {
        eprintln!("the account {name} could not be removed (status {status})");
    }
}

/// Gives an account full access to this process's window station and desktop.
///
/// A process another account runs is attached to the creator's window station, and a console or
/// graphical program that cannot open it fails before it starts. The case's creator runs in a
/// service session, so without this nothing Git starts could initialise.
fn give_session_access(sid: &str) {
    let text = wide(sid);
    let mut identifier: PSID = null_mut();
    // SAFETY: the text is this function's own buffer and the identifier is an out-parameter freed below.
    let converted = unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut identifier) };
    assert!(converted != 0, "{sid} is not an identifier");
    // SAFETY: the two handles belong to the calling process and thread and stay open.
    let objects: [HANDLE; 2] = unsafe {
        [
            GetProcessWindowStation().cast(),
            GetThreadDesktop(GetCurrentThreadId()).cast(),
        ]
    };
    for object in objects {
        let mut existing: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the out-parameters are this function's own and are freed below.
        let read = unsafe {
            GetSecurityInfo(
                object,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut existing,
                null_mut(),
                &raw mut descriptor,
            )
        };
        assert_eq!(
            read, 0,
            "the session object's permissions could not be read"
        );
        // SAFETY: a zeroed entry is a valid starting point for the structure.
        let mut entry: EXPLICIT_ACCESS_W = unsafe { zeroed() };
        entry.grfAccessPermissions = GENERIC_ALL;
        entry.grfAccessMode = GRANT_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: identifier.cast(),
        };
        let mut updated: *mut ACL = null_mut();
        // SAFETY: the entry, the identifier and the list read above are this function's own.
        let built = unsafe { SetEntriesInAclW(1, &raw const entry, existing, &raw mut updated) };
        assert_eq!(
            built, 0,
            "the session object's new permissions could not be built"
        );
        // SAFETY: the handle is open, the list was just built, and both allocations are freed once.
        let written = unsafe {
            let written = SetSecurityInfo(
                object,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated,
                null(),
            );
            LocalFree(updated.cast());
            LocalFree(descriptor.cast());
            written
        };
        assert_eq!(
            written, 0,
            "the session object's permissions could not be written"
        );
    }
    // SAFETY: the identifier was allocated by the conversion above.
    unsafe {
        LocalFree(identifier.cast());
    }
}

/// Launches a program as an account, with its output written to a file, and says what became of it.
fn create_process_as(
    account: &Account,
    program: &Path,
    command: &str,
    directory: &Path,
    environment: &[(String, String)],
    output_path: &Path,
) -> Launch {
    let application = wide_path(program);
    let mut line = wide(command);
    let directory = wide_path(directory);
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in environment {
        block.extend(OsStr::new(&format!("{name}={value}")).encode_wide());
        block.push(0);
    }
    block.push(0);

    let sink = File::create(output_path).expect("the file a program writes to");
    let nul = File::open("NUL").expect("the empty input");
    for handle in [&sink, &nul] {
        // SAFETY: the handle belongs to a file this function holds open.
        unsafe {
            SetHandleInformation(
                handle.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            );
        }
    }
    // SAFETY: a zeroed structure is a valid starting point, and the handles stay open for the call.
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).expect("a small size");
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = nul.as_raw_handle();
    startup.hStdOutput = sink.as_raw_handle();
    startup.hStdError = sink.as_raw_handle();
    // SAFETY: a zeroed structure is a valid out-parameter.
    let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: every pointer is to a buffer this function owns for the call, and the command line is
    // the mutable buffer the call requires.
    let created = unsafe {
        CreateProcessAsUserW(
            account.token.raw(),
            application.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            directory.as_ptr(),
            &raw const startup,
            &raw mut information,
        )
    };
    if created == 0 {
        let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Launch {
            outcome: Outcome::Refused(u32::try_from(error).unwrap_or(0)),
            output: String::new(),
        };
    }
    // SAFETY: both handles came from the call above and are this function's to close.
    let outcome = unsafe {
        let waited = WaitForSingleObject(
            information.hProcess,
            u32::try_from(PROGRAM_TIME.as_millis()).expect("a small time"),
        );
        let outcome = if waited == WAIT_OBJECT_0 {
            let mut code = 0_u32;
            if GetExitCodeProcess(information.hProcess, &raw mut code) == 0 {
                Outcome::Unread
            } else {
                Outcome::Ran(code)
            }
        } else {
            TerminateProcess(information.hProcess, 1);
            Outcome::Hung
        };
        CloseHandle(information.hProcess);
        CloseHandle(information.hThread);
        outcome
    };
    drop(sink);
    drop(nul);
    let output = std::fs::read_to_string(output_path).unwrap_or_default();
    Launch { outcome, output }
}

/// Reads events from the application-control log, newest first, as the XML the tool prints.
///
/// A query that fails ends the case. Reading a failed query as an empty log would put the mark that
/// separates this case's events from older ones at zero, and an older event of the same account
/// could then answer for a launch this case made.
fn query_log(count: &str, filter: Option<&str>) -> String {
    let mut command = Command::new("wevtutil.exe");
    command.args(["qe", LOG, "/rd:true", count, "/f:xml", "/e:Events"]);
    if let Some(filter) = filter {
        command.arg(filter);
    }
    let output = command.output().expect("the event-log tool starts");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the application-control log could not be read ({}): {text}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

/// Returns the record number of the newest event in the log, or zero for a log with no event.
fn newest_record() -> u64 {
    let text = query_log("/c:1", None);
    match element(&text, "EventRecordID") {
        Some(record) => record
            .parse()
            .unwrap_or_else(|_| panic!("the newest record number {record:?} is not a number")),
        None => {
            assert!(
                !text.contains("</Event>"),
                "the newest event of the log has no record number: {text}"
            );
            0
        }
    }
}

/// Returns the blocked and allowed launches the log recorded after a record.
fn events_after(watermark: u64) -> Vec<Event> {
    let text = query_log(
        "/c:20000",
        Some("/q:*[System[(EventID=8002 or EventID=8004)]]"),
    );
    text.split("</Event>")
        .filter_map(|chunk| {
            let record: u64 = element(chunk, "EventRecordID")?.parse().ok()?;
            if record <= watermark {
                return None;
            }
            Some(Event {
                id: element(chunk, "EventID")?.parse().ok()?,
                rule: element(chunk, "RuleName").unwrap_or_default().to_owned(),
                sddl: unescape(element(chunk, "RuleSddl").unwrap_or_default()),
                user: element(chunk, "TargetUser").unwrap_or_default().to_owned(),
                file: unescape(element(chunk, "FilePath").unwrap_or_default()),
            })
        })
        .collect()
}

/// Returns the text of the first element with exactly this name.
fn element<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    loop {
        let start = from + text[from..].find(&format!("<{name}"))?;
        let after = start + 1 + name.len();
        if matches!(text[after..].chars().next()?, '>' | ' ') {
            let open = text[after..].find('>')? + after + 1;
            let close = text[open..].find(&format!("</{name}>"))? + open;
            return Some(&text[open..close]);
        }
        from = after;
    }
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
